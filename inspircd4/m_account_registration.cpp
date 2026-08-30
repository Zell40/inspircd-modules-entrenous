/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 * Provides the IRCv3 draft/account-registration capability (REGISTER / VERIFY).
 * The ircd only does the client protocol; account creation is performed by
 * services over ENCAP ACCREG (same split as m_sasl).
 *
 * Copyright (C) 2026
 *
 * This file is part of InspIRCd. InspIRCd is free software: you can
 * redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/// $ModAuthor: ergo.chat IRCv3 port
/// $ModConfig: <accountregistration target="services.example.net" beforeconnect="yes" emailrequired="no" customaccountname="no" minpasswordlength="1" maxpasswordlength="300" accountrequired="no" timeout="15s">
/// $ModDesc: Provides the IRCv3 draft/account-registration capability (REGISTER/VERIFY).
/// $ModDepends: core 4

#include "inspircd.h"
#include "modules/account.h"
#include "modules/cap.h"
#include "modules/ircv3_replies.h"
#include "modules/isupport.h"
#include "modules/server.h"
#include "modules/ssl.h"
#include "stringutils.h"

/*
 * S2S protocol (ENCAP), modelled on SASL.
 *
 * ircd → services:
 *   ENCAP <target> ACCREG <uid> REGISTER <account> <email> <ip> <host> <S|P> <certfp|*> :<password-b64>
 *   ENCAP <target> ACCREG <uid> VERIFY <account> :<code>
 *   ENCAP <target> ACCREG <uid> ABORT :*
 *
 * services → ircd:
 *   ENCAP * ACCREG <uid> SUCCESS <account> :<message>
 *   ENCAP * ACCREG <uid> VERIFICATION_REQUIRED <account> :<message>
 *   ENCAP * ACCREG <uid> FAIL <REGISTER|VERIFY> <CODE> [<context> ...] :<message>
 *
 * On SUCCESS, services MUST also log the user in (METADATA accountname / SVSLOGIN)
 * so numeric 900 and account-notify are emitted by m_account.
 */

enum class AccRegWait
{
	None,
	Register,
	Verify
};

struct AccRegState final
{
	AccRegWait waiting = AccRegWait::None;
	bool register_sent = false;
	bool account_required_sent = false;
	std::string account;
	time_t waiting_since = 0;
};

static std::string accreg_target;

class ServerTracker final
	: public ServerProtocol::LinkEventListener
{
private:
	bool online = false;

	void Update(const Server* server, bool linked)
	{
		if (accreg_target == "*")
			return;

		if (InspIRCd::Match(server->GetName(), accreg_target))
		{
			ServerInstance->Logs.Debug(MODNAME, "Account-registration target \"{}\" {}",
				accreg_target, linked ? "came online" : "went offline");
			online = linked;
		}
	}

	void OnServerLink(const Server* server) override
	{
		Update(server, true);
	}

	void OnServerSplit(const Server* server, bool error) override
	{
		Update(server, false);
	}

public:
	ServerTracker(Module* mod)
		: ServerProtocol::LinkEventListener(mod)
	{
		Reset();
	}

	void Reset()
	{
		if (accreg_target == "*")
		{
			online = true;
			return;
		}

		online = false;
		ProtocolInterface::ServerList servers;
		ServerInstance->PI->GetServerList(servers);
		for (const auto& server : servers)
		{
			if (InspIRCd::Match(server.servername, accreg_target))
			{
				online = true;
				break;
			}
		}
	}

	bool IsOnline() const { return online; }
};

class AccRegCap final
	: public Cap::Capability
{
private:
	std::string capvalue;
	const ServerTracker& servertracker;

	bool OnList(LocalUser* user) override
	{
		if (GetProtocol(user) == Cap::CAP_LEGACY)
			return false;
		return servertracker.IsOnline();
	}

	bool OnRequest(LocalUser* user, bool adding) override
	{
		return OnList(user);
	}

	const std::string* GetValue(LocalUser* user) const override
	{
		return capvalue.empty() ? nullptr : &capvalue;
	}

public:
	AccRegCap(Module* mod, const ServerTracker& tracker)
		: Cap::Capability(mod, "draft/account-registration")
		, servertracker(tracker)
	{
	}

	void SetValueString(const std::string& newvalue)
	{
		if (capvalue == newvalue)
			return;
		capvalue = newvalue;
		NotifyValueChange();
	}
};

static void SendAccReg(LocalUser* user, const std::vector<std::string>& parameters)
{
	CommandBase::Params params;
	params.push_back(user->uuid);
	params.insert(params.end(), parameters.begin(), parameters.end());
	ServerInstance->PI->SendEncapsulatedData(accreg_target, "ACCREG", params);
}

class CommandRegister final
	: public SplitCommand
{
public:
	Account::API accountapi;
	SimpleExtItem<AccRegState>& stateext;
	AccRegCap& cap;
	IRCv3::Replies::Fail& fail;
	bool beforeconnect = true;
	bool emailrequired = false;
	bool customaccountname = false;
	size_t minpasswordlength = 1;
	size_t maxpasswordlength = 300;
	UserCertificateAPI sslapi;

	CommandRegister(Module* Creator, SimpleExtItem<AccRegState>& ext, AccRegCap& Cap, IRCv3::Replies::Fail& Fail)
		: SplitCommand(Creator, "REGISTER", 3)
		, accountapi(Creator)
		, stateext(ext)
		, cap(Cap)
		, fail(Fail)
		, sslapi(Creator)
	{
		works_before_reg = true;
		syntax = "{<account>|*} {<email>|*} <password>";
	}

	CmdResult HandleLocal(LocalUser* user, const Params& parameters) override
	{
		if (!cap.IsEnabled(user))
		{
			fail.Send(user, this, "NO_CAPABILITY", "draft/account-registration",
				"You must request the draft/account-registration capability to use this command");
			return CmdResult::FAILURE;
		}

		if (!cap.IsActive() || accreg_target.empty())
		{
			fail.Send(user, this, "TEMPORARILY_UNAVAILABLE", "*",
				"Account registration is currently unavailable");
			return CmdResult::FAILURE;
		}

		if (!(user->connected & User::CONN_NICK))
		{
			fail.Send(user, this, "NEED_NICK", "*",
				"You must choose a nickname before registering");
			return CmdResult::FAILURE;
		}

		if (!user->IsFullyConnected() && !beforeconnect)
		{
			fail.Send(user, this, "COMPLETE_CONNECTION_REQUIRED",
				"You must complete the connection before registering your account");
			return CmdResult::FAILURE;
		}

		if (accountapi && accountapi->GetAccountName(user))
		{
			fail.Send(user, this, "ALREADY_AUTHENTICATED", *accountapi->GetAccountName(user),
				"You are already logged into an account");
			return CmdResult::FAILURE;
		}

		AccRegState* state = stateext.Get(user);
		if (state && (state->register_sent || state->waiting != AccRegWait::None))
		{
			fail.Send(user, this, "ALREADY_AUTHENTICATED", state->account.empty() ? user->nick : state->account,
				"You have already registered or attempted to register");
			return CmdResult::FAILURE;
		}

		std::string account = parameters[0];
		if (account == "*")
			account = user->nick;

		if (!ServerInstance->IsNick(account))
		{
			fail.Send(user, this, "BAD_ACCOUNT_NAME", account,
				"Username invalid or not given");
			return CmdResult::FAILURE;
		}

		if (!customaccountname && !irc::equals(account, user->nick))
		{
			fail.Send(user, this, "ACCOUNT_NAME_MUST_BE_NICK", account,
				"You may only register your nickname as your account name");
			return CmdResult::FAILURE;
		}

		const std::string& email = parameters[1];
		if (emailrequired)
		{
			if (email == "*" || email.find('@') == std::string::npos || email[0] == '@' || email.back() == '@')
			{
				fail.Send(user, this, "INVALID_EMAIL", account,
					"A valid e-mail address is required");
				return CmdResult::FAILURE;
			}
		}

		const std::string& password = parameters[2];
		if (password == "*" || password.empty() || password[0] == ':')
		{
			fail.Send(user, this, "UNACCEPTABLE_PASSWORD", account,
				"Password was invalid");
			return CmdResult::FAILURE;
		}
		if (password.length() < minpasswordlength)
		{
			fail.Send(user, this, "WEAK_PASSWORD", account,
				"Password is too short");
			return CmdResult::FAILURE;
		}
		if (password.length() > maxpasswordlength)
		{
			fail.Send(user, this, "UNACCEPTABLE_PASSWORD", account,
				"Password is too long");
			return CmdResult::FAILURE;
		}

		if (!ServerInstance->PI)
		{
			fail.Send(user, this, "TEMPORARILY_UNAVAILABLE", account,
				"Account registration is currently unavailable");
			return CmdResult::FAILURE;
		}

		std::string certfp = "*";
		if (sslapi)
		{
			const auto fingerprints = sslapi->GetFingerprints(user);
			if (!fingerprints.empty())
				certfp = fingerprints.front();
		}

		std::vector<std::string> payload;
		payload.push_back("REGISTER");
		payload.push_back(account);
		payload.push_back(email);
		payload.push_back(user->GetAddress());
		payload.push_back(user->GetRealHost());
		payload.push_back(sslapi && sslapi->IsSecure(user) ? "S" : "P");
		payload.push_back(certfp);
		payload.push_back(Base64::Encode(password, nullptr, '='));
		SendAccReg(user, payload);

		if (!state)
		{
			stateext.Set(user, AccRegState());
			state = stateext.Get(user);
		}
		state->waiting = AccRegWait::Register;
		state->waiting_since = ServerInstance->Time();
		state->account = account;
		state->register_sent = true;
		return CmdResult::SUCCESS;
	}
};

class CommandVerify final
	: public SplitCommand
{
public:
	Account::API accountapi;
	SimpleExtItem<AccRegState>& stateext;
	AccRegCap& cap;
	IRCv3::Replies::Fail& fail;
	bool beforeconnect = true;

	CommandVerify(Module* Creator, SimpleExtItem<AccRegState>& ext, AccRegCap& Cap, IRCv3::Replies::Fail& Fail)
		: SplitCommand(Creator, "VERIFY", 2)
		, accountapi(Creator)
		, stateext(ext)
		, cap(Cap)
		, fail(Fail)
	{
		works_before_reg = true;
		syntax = "{<account>|*} <code>";
	}

	CmdResult HandleLocal(LocalUser* user, const Params& parameters) override
	{
		if (!cap.IsEnabled(user))
		{
			fail.Send(user, this, "NO_CAPABILITY", "draft/account-registration",
				"You must request the draft/account-registration capability to use this command");
			return CmdResult::FAILURE;
		}

		if (!user->IsFullyConnected() && !beforeconnect)
		{
			fail.Send(user, this, "COMPLETE_CONNECTION_REQUIRED",
				"You must complete the connection before verifying your account");
			return CmdResult::FAILURE;
		}

		if (accountapi && accountapi->GetAccountName(user))
		{
			fail.Send(user, this, "ALREADY_AUTHENTICATED", *accountapi->GetAccountName(user),
				"You are already logged into an account");
			return CmdResult::FAILURE;
		}

		if (!(user->connected & User::CONN_NICK))
		{
			fail.Send(user, this, "NEED_NICK", "*",
				"You must choose a nickname before verifying");
			return CmdResult::FAILURE;
		}

		std::string account = parameters[0];
		if (account == "*")
			account = user->nick;

		AccRegState* state = stateext.Get(user);
		if (state && state->waiting != AccRegWait::None)
		{
			fail.Send(user, this, "TEMPORARILY_UNAVAILABLE", account,
				"A registration request is already in progress");
			return CmdResult::FAILURE;
		}

		std::vector<std::string> payload;
		payload.push_back("VERIFY");
		payload.push_back(account);
		payload.push_back(parameters[1]);
		SendAccReg(user, payload);

		if (!state)
		{
			stateext.Set(user, AccRegState());
			state = stateext.Get(user);
		}
		state->waiting = AccRegWait::Verify;
		state->waiting_since = ServerInstance->Time();
		state->account = account;
		return CmdResult::SUCCESS;
	}
};

class CommandAccReg final
	: public Command
{
public:
	SimpleExtItem<AccRegState>& stateext;
	CommandRegister& cmdregister;
	CommandVerify& cmdverify;
	IRCv3::Replies::Fail& fail;
	ClientProtocol::EventProvider& registerev;
	ClientProtocol::EventProvider& verifyev;

	CommandAccReg(Module* Creator, SimpleExtItem<AccRegState>& ext, CommandRegister& CmdRegister,
		CommandVerify& CmdVerify, IRCv3::Replies::Fail& Fail,
		ClientProtocol::EventProvider& RegisterEv, ClientProtocol::EventProvider& VerifyEv)
		: Command(Creator, "ACCREG", 3)
		, stateext(ext)
		, cmdregister(CmdRegister)
		, cmdverify(CmdVerify)
		, fail(Fail)
		, registerev(RegisterEv)
		, verifyev(VerifyEv)
	{
		access_needed = CmdAccess::SERVER;
	}

	void SendClientReply(LocalUser* user, const std::string& command, const std::string& status,
		const std::string& account, const std::string& message)
	{
		ClientProtocol::Message msg(command.c_str(), ServerInstance->Config->GetServerName());
		msg.PushParam(status);
		msg.PushParam(account);
		msg.PushParam(message);
		ClientProtocol::EventProvider& evprov = irc::equals(command, "VERIFY") ? verifyev : registerev;
		ClientProtocol::Event ev(evprov, msg);
		user->Send(ev);
	}

	void SendFail(LocalUser* user, const Params& parameters)
	{
		// ACCREG <uid> FAIL <REGISTER|VERIFY> <CODE> [<ctx> ...] :<message>
		if (parameters.size() < 5)
			return;

		Command* cmd = irc::equals(parameters[2], "VERIFY")
			? static_cast<Command*>(&cmdverify)
			: static_cast<Command*>(&cmdregister);

		const std::string& code = parameters[3];
		if (parameters.size() == 5)
			fail.Send(user, cmd, code, parameters[4]);
		else if (parameters.size() == 6)
			fail.Send(user, cmd, code, parameters[4], parameters[5]);
		else
			fail.Send(user, cmd, code, parameters[4], parameters.back());
	}

	CmdResult Handle(User* user, const Params& parameters) override
	{
		auto* target = ServerInstance->Users.FindUUID(parameters[0]);
		auto* localuser = IS_LOCAL(target);
		if (!localuser)
		{
			ServerInstance->Logs.Debug(MODNAME, "User not found in ACCREG ENCAP event: {}", parameters[0]);
			return CmdResult::FAILURE;
		}

		AccRegState* state = stateext.Get(localuser);
		const AccRegWait was = state ? state->waiting : AccRegWait::None;
		if (state)
			state->waiting = AccRegWait::None;

		const std::string& action = parameters[1];
		if (irc::equals(action, "SUCCESS"))
		{
			if (parameters.size() < 4)
				return CmdResult::FAILURE;

			const std::string command = (was == AccRegWait::Verify) ? "VERIFY" : "REGISTER";
			SendClientReply(localuser, command, "SUCCESS", parameters[2], parameters[3]);
			return CmdResult::SUCCESS;
		}

		if (irc::equals(action, "VERIFICATION_REQUIRED"))
		{
			if (parameters.size() < 4)
				return CmdResult::FAILURE;
			SendClientReply(localuser, "REGISTER", "VERIFICATION_REQUIRED", parameters[2], parameters[3]);
			return CmdResult::SUCCESS;
		}

		if (irc::equals(action, "FAIL"))
		{
			SendFail(localuser, parameters);
			return CmdResult::SUCCESS;
		}

		ServerInstance->Logs.Debug(MODNAME, "Services sent an unknown ACCREG action \"{}\"", action);
		return CmdResult::FAILURE;
	}

	RouteDescriptor GetRouting(User* user, const Params& parameters) override
	{
		return ROUTE_BROADCAST;
	}
};

class ModuleAccountRegistration final
	: public Module
	, public ISupport::EventListener
{
private:
	SimpleExtItem<AccRegState> stateext;
	ServerTracker servertracker;
	AccRegCap cap;
	IRCv3::Replies::Fail fail;
	CommandRegister cmdregister;
	CommandVerify cmdverify;
	ClientProtocol::EventProvider registerev;
	ClientProtocol::EventProvider verifyev;
	CommandAccReg accreg;
	Account::API accountapi;
	unsigned long timeout = 15;
	bool accountrequired = false;

public:
	ModuleAccountRegistration()
		: Module(VF_NONE, "Provides the IRCv3 draft/account-registration capability.")
		, ISupport::EventListener(this)
		, stateext(this, "accreg-state", ExtensionType::USER)
		, servertracker(this)
		, cap(this, servertracker)
		, fail(this)
		, cmdregister(this, stateext, cap, fail)
		, cmdverify(this, stateext, cap, fail)
		, registerev(this, "REGISTER")
		, verifyev(this, "VERIFY")
		, accreg(this, stateext, cmdregister, cmdverify, fail, registerev, verifyev)
		, accountapi(this)
	{
	}

	void init() override
	{
		if (!ServerInstance->Modules.Find("account") || !ServerInstance->Modules.Find("cap"))
		{
			ServerInstance->Logs.Normal(MODNAME, "WARNING: the cap and account modules are not loaded! "
				"draft/account-registration will not function correctly until they are loaded.");
		}
	}

	void ReadConfig(ConfigStatus& status) override
	{
		const auto& tag = ServerInstance->Config->ConfValue("accountregistration");

		const std::string target = tag->getString("target");
		if (target.empty())
			throw ModuleException(this, "<accountregistration:target> must be set to the name of your services server!");

		cmdregister.beforeconnect = tag->getBool("beforeconnect", true);
		cmdverify.beforeconnect = cmdregister.beforeconnect;
		cmdregister.emailrequired = tag->getBool("emailrequired");
		cmdregister.customaccountname = tag->getBool("customaccountname");
		cmdregister.minpasswordlength = tag->getNum<size_t>("minpasswordlength", 1, 1, 300);
		cmdregister.maxpasswordlength = tag->getNum<size_t>("maxpasswordlength", 300, cmdregister.minpasswordlength, 400);
		accountrequired = tag->getBool("accountrequired");
		timeout = tag->getDuration("timeout", 15, 3, 120);

		accreg_target = target;
		servertracker.Reset();

		std::vector<std::string> tokens;
		if (cmdregister.beforeconnect)
			tokens.push_back("before-connect");
		if (cmdregister.emailrequired)
			tokens.push_back("email-required");
		if (cmdregister.customaccountname)
			tokens.push_back("custom-account-name");
		tokens.push_back("min-password-length=" + ConvToStr(cmdregister.minpasswordlength));
		tokens.push_back("max-password-length=" + ConvToStr(cmdregister.maxpasswordlength));

		std::string value;
		for (size_t i = 0; i < tokens.size(); ++i)
		{
			if (i)
				value.push_back(',');
			value.append(tokens[i]);
		}
		cap.SetValueString(value);
	}

	void OnBuildISupport(ISupport::TokenMap& tokens) override
	{
		if (accountrequired)
			tokens["draft/ACCOUNTREQUIRED"] = "";
	}

	ModResult OnCheckReady(LocalUser* user) override
	{
		AccRegState* state = stateext.Get(user);
		if (!state || state->waiting == AccRegWait::None)
			return MOD_RES_PASSTHRU;

		if (ServerInstance->Time() - state->waiting_since >= static_cast<time_t>(timeout))
		{
			const std::string account = state->account.empty() ? "*" : state->account;
			if (state->waiting == AccRegWait::Verify)
			{
				fail.Send(user, &cmdverify, "TEMPORARILY_UNAVAILABLE", account,
					"Services did not respond to the verification request");
			}
			else
			{
				fail.Send(user, &cmdregister, "TEMPORARILY_UNAVAILABLE", account,
					"Services did not respond to the registration request");
			}
			state->waiting = AccRegWait::None;
			SendAccReg(user, { "ABORT", "*" });
			return MOD_RES_PASSTHRU;
		}

		// Hold connection registration until services reply (REGISTER/VERIFY round-trip).
		return MOD_RES_DENY;
	}

	ModResult OnPreChangeConnectClass(LocalUser* user, const std::shared_ptr<ConnectClass>& klass,
		std::optional<Numeric::Numeric>& errnum) override
	{
		if (!klass->config->getBool("requireaccount") && !insp::equalsci(klass->config->getString("requireaccount"), "nick"))
			return MOD_RES_PASSTHRU;

		if (accountapi && accountapi->GetAccountName(user))
			return MOD_RES_PASSTHRU;

		AccRegState* state = stateext.Get(user);
		if (state && state->account_required_sent)
			return MOD_RES_PASSTHRU;

		fail.Send(user, nullptr, "ACCOUNT_REQUIRED",
			"You must log in with SASL or REGISTER to join this server");
		if (!state)
		{
			stateext.Set(user, AccRegState());
			state = stateext.Get(user);
		}
		state->account_required_sent = true;
		return MOD_RES_PASSTHRU;
	}

	void OnUserDisconnect(LocalUser* user) override
	{
		AccRegState* state = stateext.Get(user);
		if (state && state->waiting != AccRegWait::None)
			SendAccReg(user, { "ABORT", "*" });
	}
};

MODULE_INIT(ModuleAccountRegistration)

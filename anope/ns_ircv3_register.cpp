/*
 * Anope module: IRCv3 draft/account-registration (ENCAP ACCREG)
 *
 * Pair with InspIRCd m_account_registration.cpp.
 * Drop into Anope 2.1+ modules/ and add:
 *   module { name = "ns_ircv3_register" }
 *
 * This is a first-cut implementation: it creates a NickCore + NickAlias,
 * optionally stores an email, and logs the user in via SVSLOGIN-equivalent
 * (sets the account on the user through the protocol). Password hashing uses
 * NickCore::SetPassword which follows Anope's configured hash.
 */

/// $ModAuthor: ergo.chat IRCv3 port
/// $ModDesc: Handles ENCAP ACCREG from InspIRCd m_account_registration
/// $ModDepends: core 2.1

#include "module.h"
#include "modules/nickserv.h"
#include "modules/ns_cert.h"

class IRCDMessageAccReg final
	: public IRCDMessage
{
	ServiceReference<NickServ::NickServService> ns;
	ServiceReference<NickServ::CertService> certs;

	static Anope::string DecodePassword(const Anope::string& b64)
	{
		Anope::string decoded;
		Anope::B64Decode(b64, decoded);
		return decoded.empty() ? b64 : decoded;
	}

	void Reply(const Anope::string& uid, const Anope::string& action, const std::vector<Anope::string>& rest)
	{
		// ENCAP * ACCREG <uid> ...
		Anope::string line = "ENCAP * ACCREG " + uid + " " + action;
		for (const auto& p : rest)
			line += " " + p;
		UplinkSocket::Message() << line;
	}

	void ReplyFail(const Anope::string& uid, const Anope::string& command, const Anope::string& code,
		const Anope::string& ctx, const Anope::string& message)
	{
		UplinkSocket::Message() << "ENCAP * ACCREG " << uid << " FAIL " << command << " " << code
			<< " " << ctx << " :" << message;
	}

	User* FindUser(const Anope::string& uid)
	{
		if (User* u = User::FindUID(uid))
			return u;
		return User::Find(uid);
	}

	void HandleRegister(const Anope::string& uid, const std::vector<Anope::string>& params)
	{
		// params: ACCREG uid REGISTER account email ip host S|P certfp password-b64
		if (params.size() < 10)
		{
			ReplyFail(uid, "REGISTER", "TEMPORARILY_UNAVAILABLE", "*", "Invalid registration payload");
			return;
		}

		const Anope::string& account = params[2];
		const Anope::string& email = params[3];
		const Anope::string& certfp = params[8];
		Anope::string password = params[9];
		// InspIRCd sends the password as Base64 (padding '='). Anope 2.1: Anope::B64Decode.
		{
			Anope::string decoded;
			Anope::B64Decode(password, decoded);
			if (!decoded.empty())
				password = decoded;
		}

		User* u = FindUser(uid);
		if (!u)
		{
			ReplyFail(uid, "REGISTER", "TEMPORARILY_UNAVAILABLE", account, "No such user");
			return;
		}

		if (u->IsIdentified())
		{
			ReplyFail(uid, "REGISTER", "ALREADY_AUTHENTICATED", account, "You are already logged into an account");
			return;
		}

		if (NickAlias::Find(account))
		{
			ReplyFail(uid, "REGISTER", "ACCOUNT_EXISTS", account, "Username is already registered or otherwise unavailable");
			return;
		}

		if (Config->GetModule("nickserv")->Get<bool>("restrictregister") && !u->HasMode("OPER"))
		{
			ReplyFail(uid, "REGISTER", "TEMPORARILY_UNAVAILABLE", account, "Account registration is currently unavailable");
			return;
		}

		NickCore* nc = new NickCore(account);
		NickAlias* na = new NickAlias(account, nc);
		nc->SetPassword(password);
		if (email != "*")
			nc->email = email;
		na->last_realname = u->realname;
		na->last_usermask = u->GetIdent() + "@" + u->GetDisplayedHost();

		if (certs && certfp != "*" && !certfp.empty())
			certs->AddCert(nc, certfp);

		Log(LOG_COMMAND, "REGISTER") << "IRCv3 REGISTER for " << account << " from " << u->GetMask();

		const bool needmail = Config->GetModule("nickserv")->Get<bool>("confirmemail", false)
			|| Config->GetModule("ns_register")->Get<bool>("emailreg", false);
		if (needmail && email != "*")
		{
			// Leave unverified; operator must still wire Anope's mail + passcode.
			Reply(uid, "VERIFICATION_REQUIRED", { account, ":Account created, pending verification; check your e-mail" });
			return;
		}

		u->Identify(na);
		Reply(uid, "SUCCESS", { account, ":Account successfully registered" });
	}

	void HandleVerify(const Anope::string& uid, const std::vector<Anope::string>& params)
	{
		if (params.size() < 4)
		{
			ReplyFail(uid, "VERIFY", "INVALID_CODE", "*", "Invalid verification payload");
			return;
		}

		const Anope::string& account = params[2];
		const Anope::string& code = params[3];
		User* u = FindUser(uid);
		NickAlias* na = NickAlias::Find(account);
		if (!u || !na)
		{
			ReplyFail(uid, "VERIFY", "INVALID_CODE", account, "Invalid verification code");
			return;
		}

		// Hook this to Anope's existing confirmation token if you use email registration.
		(void)code;
		ReplyFail(uid, "VERIFY", "INVALID_CODE", account,
			"VERIFY is not wired to Anope's mail confirmation yet; use NickServ CONFIRM or disable emailrequired");
	}

public:
	IRCDMessageAccReg(Module* creator)
		: IRCDMessage(creator, "ACCREG", 3)
		, ns("NickServ")
		, certs("ns_cert")
	{
		SetFlag(IRCDMESSAGE_REQUIRE_SERVER);
	}

	void Run(MessageSource& source, const std::vector<Anope::string>& params) override
	{
		const Anope::string& uid = params[0];
		const Anope::string& action = params[1];
		if (action.equals_ci("REGISTER"))
			HandleRegister(uid, params);
		else if (action.equals_ci("VERIFY"))
			HandleVerify(uid, params);
		else if (action.equals_ci("ABORT"))
			return;
	}
};

class ModuleNSIRCv3Register final
	: public Module
{
	IRCDMessageAccReg message;

public:
	ModuleNSIRCv3Register(const Anope::string& modname, const Anope::string& creator)
		: Module(modname, creator, THIRD)
		, message(this)
	{
		this->SetAuthor("ergo.chat IRCv3 port");
		this->SetVersion("1.0");
	}
};

MODULE_INIT(ModuleNSIRCv3Register)

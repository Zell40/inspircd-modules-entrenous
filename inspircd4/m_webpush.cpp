/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 * Provides IRCv3 soju.im/webpush and draft/webpush (WEBPUSH REGISTER/UNREGISTER).
 * Subscriptions are stored per account (or nick if requireaccount=no). Encrypted
 * Web Push (RFC 8291) is sent for PMs, nick highlights, and INVITEs.
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

/// $ModAuthor: Entre Nous IRCv3 port
/// $ModConfig: <webpush vapidfile="webpush-vapid.pem" contact="mailto:admin@example.net" requireaccount="yes" persistfile="webpush.db" maxsubscriptions="5" ttl="86400" expiration="30d" pushaway="yes" pushoffline="yes" pushalways="no" testonregister="yes" httptimeout="15s">
/// $ModDesc: Provides IRCv3 soju.im/webpush and draft/webpush (Web Push notifications).
/// $ModDepends: core 4
/// $CompilerFlags: find_compiler_flags("openssl" "")
/// $LinkerFlags: find_linker_flags("openssl" "-lssl -lcrypto")
/// $PackageInfo: require_system("alpine") openssl-dev pkgconf
/// $PackageInfo: require_system("arch") openssl pkgconf
/// $PackageInfo: require_system("darwin") openssl pkg-config
/// $PackageInfo: require_system("debian~") libssl-dev pkg-config
/// $PackageInfo: require_system("rhel~") openssl-devel pkgconfig

#include "inspircd.h"
#include "modules/account.h"
#include "modules/cap.h"
#include "modules/ircv3_replies.h"
#include "modules/ircv3_servertime.h"
#include "modules/isupport.h"
#include "threadsocket.h"
#include "timeutils.h"
#include "utility/string.h"

#include <fstream>
#include <mutex>

#include "webpush_crypto.h"

static constexpr const char* CAP_SOJU = "soju.im/webpush";
static constexpr const char* CAP_DRAFT = "draft/webpush";
static constexpr const char* PING_PAYLOAD = "PING webpush";

struct Subscription final
{
	std::string endpoint;
	std::string p256dh; // raw 65-byte public key
	std::string auth;   // raw 16-byte secret
	std::string nick;
	std::string uuid;
	time_t updated = 0;
	time_t last_success = 0;
};

struct OwnerRecord final
{
	std::vector<Subscription> subs;
};

enum class PushJobKind
{
	TestRegister,
	Notify
};

struct PushJob final
{
	PushJobKind kind = PushJobKind::Notify;
	std::string uuid;
	std::string owner;
	std::string endpoint;
	std::string p256dh;
	std::string auth;
	std::string keys_param;
	std::string plaintext;
	std::string urgency = "normal";
};

struct PushReply final
{
	PushJobKind kind = PushJobKind::Notify;
	std::string uuid;
	std::string owner;
	std::string endpoint;
	std::string keys_param;
	std::string p256dh;
	std::string auth;
	WebPush::HttpResult result;
};

class ModuleWebPush;

class WebPushCap final
	: public Cap::Capability
{
	bool OnList(LocalUser* user) override
	{
		return GetProtocol(user) != Cap::CAP_LEGACY;
	}

public:
	WebPushCap(Module* mod, const std::string& capname)
		: Cap::Capability(mod, capname)
	{
	}
};

class PushWorker final
	: public SocketThread
{
	ModuleWebPush* parent;

	void OnStart() override;
	void OnNotify() override;

public:
	PushWorker(ModuleWebPush* mod)
		: parent(mod)
	{
	}
};

class CommandWebPush final
	: public SplitCommand
{
public:
	ModuleWebPush& mod;
	IRCv3::Replies::Fail& fail;
	IRCv3::Replies::Warn& warn;
	IRCv3::Replies::Note& note;
	WebPushCap& cap_soju;
	WebPushCap& cap_draft;

	CommandWebPush(Module* Creator, ModuleWebPush& Mod, IRCv3::Replies::Fail& Fail,
		IRCv3::Replies::Warn& Warn, IRCv3::Replies::Note& Note,
		WebPushCap& CapSoju, WebPushCap& CapDraft);

	CmdResult HandleLocal(LocalUser* user, const Params& parameters) override;
};

class ModuleWebPush final
	: public Module
	, public ISupport::EventListener
	, public Account::EventListener
	, public Timer
{
public:
	Account::API accountapi;
	WebPushCap cap_soju;
	WebPushCap cap_draft;
	IRCv3::Replies::Fail fail;
	IRCv3::Replies::Warn warn;
	IRCv3::Replies::Note note;
	ClientProtocol::EventProvider webpushev;
	CommandWebPush cmd;
	PushWorker* worker = nullptr;

	std::mutex vapid_mutex;
	WebPush::VapidKeys vapid;
	std::string contact;
	int ttl = 86400;
	int http_timeout = 15;
	std::string urgency_high = "high";
	std::string urgency_normal = "normal";

	std::mutex queue_mutex;
	std::deque<PushJob> inbox;
	std::deque<PushReply> outbox;

	std::map<std::string, OwnerRecord, irc::insensitive_swo> owners;
	std::map<std::string, std::string, irc::insensitive_swo> lastnick_account; // nick -> owner key
	bool dirty = false;

	std::string vapidfile;
	std::string persistfile;
	bool requireaccount = true;
	bool pushaway = true;
	bool pushoffline = true;
	bool pushalways = false;
	bool testonregister = true;
	size_t maxsubscriptions = 5;
	time_t expiration = 30 * 24 * 3600;
	unsigned long saveperiod = 30;

	std::map<std::string, std::pair<time_t, unsigned int>> push_window;
	unsigned int max_per_minute = 30;

	ModuleWebPush()
		: Module(VF_NONE, "Provides the IRCv3 soju.im/webpush and draft/webpush capabilities.")
		, ISupport::EventListener(this)
		, Account::EventListener(this)
		, Timer(30, true)
		, accountapi(this)
		, cap_soju(this, CAP_SOJU)
		, cap_draft(this, CAP_DRAFT)
		, fail(this)
		, warn(this)
		, note(this)
		, webpushev(this, "WEBPUSH")
		, cmd(this, *this, fail, warn, note, cap_soju, cap_draft)
	{
	}

	~ModuleWebPush() override
	{
		if (worker)
		{
			worker->Stop();
			DrainReplies();
			delete worker;
			worker = nullptr;
		}
		SaveSubscriptions();
	}

	void init() override
	{
		OPENSSL_init_ssl(0, nullptr);
		if (!ServerInstance->Modules.Find("cap"))
		{
			ServerInstance->Logs.Normal(MODNAME, "WARNING: the cap module is not loaded! "
				"webpush will not be advertised until it is loaded.");
		}
		worker = new PushWorker(this);
		worker->Start();
	}

	void ReadConfig(ConfigStatus& status) override
	{
		const auto& tag = ServerInstance->Config->ConfValue("webpush");
		requireaccount = tag->getBool("requireaccount", true);
		pushaway = tag->getBool("pushaway", true);
		pushoffline = tag->getBool("pushoffline", true);
		pushalways = tag->getBool("pushalways", false);
		testonregister = tag->getBool("testonregister", true);
		maxsubscriptions = tag->getNum<size_t>("maxsubscriptions", 5, 1, 50);
		ttl = static_cast<int>(tag->getDuration("ttl", 86400, 0, 7 * 24 * 3600));
		http_timeout = static_cast<int>(tag->getDuration("httptimeout", 15, 3, 60));
		expiration = static_cast<time_t>(tag->getDuration("expiration", 30 * 24 * 3600, 3600, 365 * 24 * 3600UL));
		saveperiod = tag->getDuration("saveperiod", 30, 5, 3600);
		max_per_minute = tag->getNum<unsigned int>("maxperminute", 30, 1, 600);
		contact = tag->getString("contact");
		if (contact.empty())
			contact = "mailto:webpush@" + ServerInstance->Config->ServerName;
		if (contact.compare(0, 7, "mailto:") != 0 && contact.compare(0, 8, "https://") != 0)
			throw ModuleException(this, "<webpush:contact> must be a mailto: or https: URI (RFC 8292).");

		vapidfile = ServerInstance->Config->Paths.PrependData(tag->getString("vapidfile", "webpush-vapid.pem", 1));
		persistfile = ServerInstance->Config->Paths.PrependData(tag->getString("persistfile", "webpush.db", 1));

		{
			std::lock_guard<std::mutex> lock(vapid_mutex);
			if (!WebPush::LoadVapidPem(vapid, vapidfile))
			{
				if (!WebPush::GenerateVapid(vapid) || !WebPush::SaveVapidPem(vapid, vapidfile))
					throw ModuleException(this, "Unable to load or create VAPID key file: " + vapidfile);
				ServerInstance->Logs.Normal(MODNAME, "Generated new VAPID key pair in {}", vapidfile);
			}
		}

		if (status.initial)
			LoadSubscriptions();

		SetInterval(saveperiod);
	}

	void OnBuildISupport(ISupport::TokenMap& tokens) override
	{
		std::lock_guard<std::mutex> lock(vapid_mutex);
		if (!vapid.public_b64url.empty())
			tokens["VAPID"] = vapid.public_b64url;
	}

	void OnAccountChange(User* user, const std::string& account) override
	{
		auto* local = IS_LOCAL(user);
		if (!local || account.empty())
			return;
		const std::string from = "n:" + user->nick;
		const std::string to = OwnerKey(local);
		if (from == to)
			return;
		auto it = owners.find(from);
		if (it == owners.end())
			return;
		OwnerRecord& dest = owners[to];
		for (auto& sub : it->second.subs)
			dest.subs.push_back(std::move(sub));
		owners.erase(it);
		TrimOwner(dest);
		dirty = true;
	}

	bool Tick() override
	{
		if (dirty)
			SaveSubscriptions();
		ExpireSubscriptions();
		return true;
	}

	ModResult OnPreCommand(std::string& command, CommandBase::Params& parameters, LocalUser* user, bool validated) override
	{
		if (!validated || !pushoffline || parameters.empty())
			return MOD_RES_PASSTHRU;
		if (!irc::equals(command, "PRIVMSG") && !irc::equals(command, "NOTICE"))
			return MOD_RES_PASSTHRU;

		const std::string& target = parameters[0];
		if (target.empty() || target[0] == '#' || target[0] == '&')
			return MOD_RES_PASSTHRU;
		if (ServerInstance->Users.FindNick(target))
			return MOD_RES_PASSTHRU;

		auto nickit = lastnick_account.find(target);
		if (nickit == lastnick_account.end())
			return MOD_RES_PASSTHRU;
		if (parameters.size() < 2)
			return MOD_RES_PASSTHRU;

		auto ownerit = owners.find(nickit->second);
		if (ownerit == owners.end() || ownerit->second.subs.empty())
			return MOD_RES_PASSTHRU;

		std::string_view ctcpname;
		if (IsCTCPText(parameters[1], ctcpname) && !irc::equals(ctcpname, "ACTION"))
			return MOD_RES_PASSTHRU;

		PushToOwner(ownerit->first, ownerit->second, user, command, target, parameters[1], {}, "high", true);
		return MOD_RES_PASSTHRU;
	}

	void OnUserPostMessage(User* user, const MessageTarget& target, const MessageDetails& details) override
	{
		std::string_view ctcpname;
		if (details.IsCTCP(ctcpname) && !irc::equals(ctcpname, "ACTION"))
			return;

		const std::string command = (details.type == MessageType::NOTICE) ? "NOTICE" : "PRIVMSG";
		if (target.type == MessageTarget::TYPE_USER)
		{
			User* dest = target.Get<User>();
			auto* local = IS_LOCAL(dest);
			if (!local || dest == user)
				return;
			const std::string owner = OwnerKey(local);
			if (owner.empty())
				return;
			auto it = owners.find(owner);
			if (it == owners.end())
				return;
			if (!ShouldNotifyUser(local, it->second, /*direct=*/true))
				return;
			PushToOwner(owner, it->second, user, command, dest->nick, details.text, details.tags_out, "high", false);
		}
		else if (target.type == MessageTarget::TYPE_CHANNEL)
		{
			Channel* chan = target.Get<Channel>();
			for (const auto& membpair : chan->GetUsers())
			{
				User* member = membpair.first;
				auto* local = IS_LOCAL(member);
				if (!local || member == user)
					continue;
				const std::string owner = OwnerKey(local);
				if (owner.empty())
					continue;
				auto it = owners.find(owner);
				if (it == owners.end())
					continue;
				if (!ShouldNotifyUser(local, it->second, /*direct=*/false))
					continue;
				if (!IsHighlight(details.text, member->nick) && !IsHighlight(details.text, local->nick))
					continue;
				PushToOwner(owner, it->second, user, command, chan->name, details.text, details.tags_out, "normal", false);
			}
		}
	}

	void OnUserInvite(User* source, User* dest, Channel* channel, time_t timeout,
		ModeHandler::Rank notifyrank, CUList& notifyexcepts) override
	{
		(void)timeout;
		(void)notifyrank;
		(void)notifyexcepts;
		auto* local = IS_LOCAL(dest);
		if (!local || dest == source)
			return;
		const std::string owner = OwnerKey(local);
		if (owner.empty())
			return;
		auto it = owners.find(owner);
		if (it == owners.end())
			return;
		if (!ShouldNotifyUser(local, it->second, /*direct=*/true))
			return;
		PushToOwner(owner, it->second, source, "INVITE", dest->nick, channel->name, {}, "high", false);
	}

	void OnUserDisconnect(LocalUser* user) override
	{
		const std::string owner = OwnerKey(user);
		if (owner.empty())
			return;
		lastnick_account[user->nick] = owner;
		auto it = owners.find(owner);
		if (it != owners.end())
		{
			for (auto& sub : it->second.subs)
			{
				if (sub.uuid == user->uuid)
					sub.uuid.clear();
			}
		}
	}

	bool HasWebPushCap(LocalUser* user) const
	{
		return cap_soju.IsEnabled(user) || cap_draft.IsEnabled(user);
	}

	std::string OwnerKey(LocalUser* user)
	{
		if (accountapi)
		{
			const std::string* acct = accountapi->GetAccountName(user);
			if (acct && !acct->empty())
				return "a:" + *acct;
		}
		if (requireaccount)
			return {};
		return "n:" + user->nick;
	}

	static bool IsCTCPText(const std::string& text, std::string_view& name)
	{
		if (text.size() < 2 || text[0] != '\x01')
			return false;
		size_t end = text.find('\x01', 1);
		size_t sp = text.find(' ', 1);
		size_t stop = std::min(end == std::string::npos ? text.size() : end, sp == std::string::npos ? text.size() : sp);
		name = std::string_view(text.data() + 1, stop - 1);
		return true;
	}

	static bool IsWordBoundary(unsigned char c)
	{
		if (c >= 128)
			return true;
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))
			return false;
		if (c == '-' || c == '_' || c == '|')
			return false;
		return true;
	}

	static bool IsHighlight(const std::string& text, const std::string& nick)
	{
		if (nick.empty() || text.size() < nick.size())
			return false;
		for (size_t i = 0; i + nick.size() <= text.size(); ++i)
		{
			if (!irc::equals(std::string_view(text.data() + i, nick.size()), nick))
				continue;
			const bool left = (i == 0) || IsWordBoundary(static_cast<unsigned char>(text[i - 1]));
			const bool right = (i + nick.size() == text.size())
				|| IsWordBoundary(static_cast<unsigned char>(text[i + nick.size()]));
			if (left && right)
				return true;
		}
		return false;
	}

	bool ShouldNotifyUser(LocalUser* user, const OwnerRecord& rec, bool direct)
	{
		(void)direct;
		if (pushalways)
			return true;
		bool registrar_online = false;
		for (const auto& sub : rec.subs)
		{
			if (!sub.uuid.empty() && ServerInstance->Users.FindUUID(sub.uuid))
			{
				registrar_online = true;
				break;
			}
		}
		if (!registrar_online)
			return true;
		if (pushaway && user->IsAway())
			return true;
		return false;
	}

	bool RateLimitOk(const std::string& owner)
	{
		time_t now = ServerInstance->Time();
		auto& w = push_window[owner];
		if (now - w.first >= 60)
		{
			w.first = now;
			w.second = 0;
		}
		if (w.second >= max_per_minute)
			return false;
		++w.second;
		return true;
	}

	void Enqueue(PushJob job)
	{
		if (!worker)
			return;
		worker->LockQueue();
		inbox.push_back(std::move(job));
		worker->UnlockQueueWakeup();
	}

	void DrainReplies();

	void PushToOwner(const std::string& owner, OwnerRecord& rec, User* source,
		const std::string& command, const std::string& target, const std::string& text,
		const ClientProtocol::TagMap& tags, const std::string& urgency, bool force)
	{
		if (!force && !RateLimitOk(owner))
			return;

		std::string msgid;
		std::string account;
		auto mit = tags.find("msgid");
		if (mit != tags.end())
			msgid = mit->second.value;
		auto ait = tags.find("account");
		if (ait != tags.end())
			account = ait->second.value;
		else if (accountapi)
		{
			const std::string* an = accountapi->GetAccountName(source);
			if (an)
				account = *an;
		}

		std::string line = FormatPushLine(source, command, target, text, msgid, account);
		if (line.size() > 3500)
			line.resize(3500);

		const time_t now = ServerInstance->Time();
		for (auto& sub : rec.subs)
		{
			if (expiration && now - sub.updated > expiration)
				continue;
			PushJob job;
			job.kind = PushJobKind::Notify;
			job.owner = owner;
			job.endpoint = sub.endpoint;
			job.p256dh = sub.p256dh;
			job.auth = sub.auth;
			job.plaintext = line;
			job.urgency = urgency;
			Enqueue(std::move(job));
		}
	}

	std::string FormatPushLine(User* source, const std::string& command, const std::string& target,
		const std::string& text, const std::string& msgid, const std::string& account)
	{
		std::string tags;
		auto addtag = [&tags](const std::string& k, const std::string& v)
		{
			if (v.empty())
				return;
			if (!tags.empty())
				tags.push_back(';');
			tags.append(k);
			tags.push_back('=');
			tags.append(v);
		};
		addtag("time", IRCv3::ServerTime::FormatTime(ServerInstance->Time()));
		addtag("msgid", msgid);
		addtag("account", account);

		std::string line;
		if (!tags.empty())
		{
			line.push_back('@');
			line.append(tags);
			line.push_back(' ');
		}
		line.push_back(':');
		line.append(source->GetMask());
		line.push_back(' ');
		line.append(command);
		line.push_back(' ');
		if (irc::equals(command, "INVITE"))
		{
			line.append(target);
			line.push_back(' ');
			line.append(text);
		}
		else
		{
			line.append(target);
			line.append(" :");
			line.append(text);
		}
		return line;
	}

	void SendWebPushMsg(LocalUser* user, const std::string& subcmd, const std::string& endpoint,
		const std::string& extra = {})
	{
		ClientProtocol::Message msg("WEBPUSH", ServerInstance->Config->GetServerName());
		msg.PushParam(subcmd);
		msg.PushParam(endpoint);
		if (!extra.empty())
			msg.PushParam(extra);
		ClientProtocol::Event ev(webpushev, msg);
		user->Send(ev);
	}

	bool ParseKeys(const std::string& raw, std::string& p256dh, std::string& auth)
	{
		std::string p256_b64;
		std::string auth_b64;
		irc::sepstream stream(raw, ';');
		std::string token;
		while (stream.GetToken(token))
		{
			size_t eq = token.find('=');
			if (eq == std::string::npos || eq == 0)
				return false;
			std::string k = token.substr(0, eq);
			std::string v = token.substr(eq + 1);
			if (irc::equals(k, "p256dh"))
				p256_b64 = v;
			else if (irc::equals(k, "auth"))
				auth_b64 = v;
		}
		if (p256_b64.empty() || auth_b64.empty())
			return false;
		if (!WebPush::B64Decode(p256_b64, p256dh) || !WebPush::B64Decode(auth_b64, auth))
			return false;
		if ((p256dh.size() != 65 && p256dh.size() != 33) || auth.size() != 16)
			return false;
		if (p256dh.size() == 33)
		{
			EC_KEY* key = WebPush::EcKeyFromUncompressed(
				reinterpret_cast<const unsigned char*>(p256dh.data()), p256dh.size());
			if (!key || !WebPush::EcPublicUncompressed(key, p256dh))
			{
				EC_KEY_free(key);
				return false;
			}
			EC_KEY_free(key);
		}
		return true;
	}

	void TrimOwner(OwnerRecord& rec)
	{
		while (rec.subs.size() > maxsubscriptions)
			rec.subs.erase(rec.subs.begin());
	}

	void ExpireSubscriptions()
	{
		const time_t now = ServerInstance->Time();
		for (auto it = owners.begin(); it != owners.end(); )
		{
			auto& subs = it->second.subs;
			subs.erase(std::remove_if(subs.begin(), subs.end(), [&](const Subscription& s)
			{
				return expiration && now - s.updated > expiration;
			}), subs.end());
			if (subs.empty())
				it = owners.erase(it);
			else
				++it;
		}
	}

	void RemoveEndpoint(const std::string& owner, const std::string& endpoint)
	{
		auto it = owners.find(owner);
		if (it == owners.end())
			return;
		auto& subs = it->second.subs;
		subs.erase(std::remove_if(subs.begin(), subs.end(), [&](const Subscription& s)
		{
			return s.endpoint == endpoint;
		}), subs.end());
		if (subs.empty())
			owners.erase(it);
		dirty = true;
	}

	Subscription* FindSub(OwnerRecord& rec, const std::string& endpoint)
	{
		for (auto& sub : rec.subs)
		{
			if (sub.endpoint == endpoint)
				return &sub;
		}
		return nullptr;
	}

	void LoadSubscriptions()
	{
		std::ifstream in(persistfile.c_str());
		if (!in)
			return;
		std::string line;
		while (std::getline(in, line))
		{
			if (line.empty() || line[0] == '#')
				continue;
			irc::sepstream stream(line, '\t');
			std::string owner, endpoint, p256b64, authb64, nick, uuid, updated, lastok;
			if (!stream.GetToken(owner) || !stream.GetToken(endpoint) || !stream.GetToken(p256b64)
				|| !stream.GetToken(authb64) || !stream.GetToken(nick) || !stream.GetToken(uuid)
				|| !stream.GetToken(updated) || !stream.GetToken(lastok))
			{
				continue;
			}
			Subscription sub;
			sub.endpoint = endpoint;
			if (!WebPush::B64Decode(p256b64, sub.p256dh) || !WebPush::B64Decode(authb64, sub.auth))
				continue;
			sub.nick = (nick == "*") ? "" : nick;
			sub.uuid = (uuid == "*") ? "" : uuid;
			sub.updated = ConvToNum<time_t>(updated);
			sub.last_success = ConvToNum<time_t>(lastok);
			owners[owner].subs.push_back(std::move(sub));
		}
		ServerInstance->Logs.Normal(MODNAME, "Loaded {} webpush owner(s) from {}", owners.size(), persistfile);
	}

	void SaveSubscriptions()
	{
		if (persistfile.empty())
			return;
		const std::string tmp = persistfile + ".tmp";
		std::ofstream out(tmp.c_str(), std::ios::trunc);
		if (!out)
		{
			ServerInstance->Logs.Normal(MODNAME, "Unable to write {}", tmp);
			return;
		}
		out << "# m_webpush subscriptions v1\n";
		for (const auto& [owner, rec] : owners)
		{
			for (const auto& sub : rec.subs)
			{
				out << owner << '\t' << sub.endpoint << '\t'
					<< WebPush::B64Encode(sub.p256dh, WebPush::B64URL, false) << '\t'
					<< WebPush::B64Encode(sub.auth, WebPush::B64URL, false) << '\t'
					<< (sub.nick.empty() ? "*" : sub.nick) << '\t'
					<< (sub.uuid.empty() ? "*" : sub.uuid) << '\t'
					<< sub.updated << '\t' << sub.last_success << '\n';
			}
		}
		out.close();
		if (rename(tmp.c_str(), persistfile.c_str()) != 0)
			ServerInstance->Logs.Normal(MODNAME, "Unable to replace {}", persistfile);
		else
			dirty = false;
	}
};

CommandWebPush::CommandWebPush(Module* Creator, ModuleWebPush& Mod, IRCv3::Replies::Fail& Fail,
	IRCv3::Replies::Warn& Warn, IRCv3::Replies::Note& Note,
	WebPushCap& CapSoju, WebPushCap& CapDraft)
	: SplitCommand(Creator, "WEBPUSH", 2)
	, mod(Mod)
	, fail(Fail)
	, warn(Warn)
	, note(Note)
	, cap_soju(CapSoju)
	, cap_draft(CapDraft)
{
	syntax = { "{REGISTER|UNREGISTER} <endpoint> [<keys>]" };
}

CmdResult CommandWebPush::HandleLocal(LocalUser* user, const Params& parameters)
{
	if (!mod.HasWebPushCap(user))
	{
		fail.Send(user, this, "NO_CAPABILITY", CAP_SOJU,
			"You must request soju.im/webpush or draft/webpush to use this command");
		return CmdResult::FAILURE;
	}

	const std::string& subcmd = parameters[0];
	const std::string& endpoint = parameters[1];
	std::string host, port, path;
	if (!WebPush::ParseHttpsUrl(endpoint, host, port, path)
		|| WebPush::HostIsInternalLiteral(host))
	{
		fail.Send(user, this, "INVALID_PARAMS", subcmd, endpoint,
			"Endpoint must be an https URL that does not target a private address");
		return CmdResult::FAILURE;
	}

	const std::string owner = mod.OwnerKey(user);
	if (owner.empty())
	{
		fail.Send(user, this, "FORBIDDEN", subcmd, endpoint,
			"You must be logged into an account to use Web Push");
		return CmdResult::FAILURE;
	}

	if (irc::equals(subcmd, "UNREGISTER"))
	{
		mod.RemoveEndpoint(owner, endpoint);
		mod.SendWebPushMsg(user, "UNREGISTER", endpoint);
		return CmdResult::SUCCESS;
	}

	if (!irc::equals(subcmd, "REGISTER"))
	{
		fail.Send(user, this, "INVALID_PARAMS", subcmd, endpoint, "Unknown WEBPUSH subcommand");
		return CmdResult::FAILURE;
	}

	if (parameters.size() < 3)
	{
		fail.Send(user, this, "INVALID_PARAMS", "REGISTER", endpoint,
			"WEBPUSH REGISTER requires an endpoint and keys");
		return CmdResult::FAILURE;
	}

	std::string p256dh;
	std::string auth;
	if (!mod.ParseKeys(parameters[2], p256dh, auth))
	{
		fail.Send(user, this, "INVALID_PARAMS", "REGISTER", endpoint,
			"Invalid p256dh/auth subscription keys");
		return CmdResult::FAILURE;
	}

	OwnerRecord& rec = mod.owners[owner];
	if (Subscription* existing = mod.FindSub(rec, endpoint))
	{
		existing->p256dh = p256dh;
		existing->auth = auth;
		existing->nick = user->nick;
		existing->uuid = user->uuid;
		existing->updated = ServerInstance->Time();
		mod.dirty = true;
		mod.lastnick_account[user->nick] = owner;
		mod.SendWebPushMsg(user, "REGISTER", endpoint, parameters[2]);
		return CmdResult::SUCCESS;
	}

	if (rec.subs.size() >= mod.maxsubscriptions)
	{
		fail.Send(user, this, "MAX_REGISTRATIONS", "REGISTER", endpoint,
			"Too many Web Push subscriptions");
		return CmdResult::FAILURE;
	}

	if (mod.testonregister)
	{
		PushJob job;
		job.kind = PushJobKind::TestRegister;
		job.uuid = user->uuid;
		job.owner = owner;
		job.endpoint = endpoint;
		job.p256dh = p256dh;
		job.auth = auth;
		job.keys_param = parameters[2];
		job.plaintext = PING_PAYLOAD;
		job.urgency = "high";
		mod.Enqueue(std::move(job));
		return CmdResult::SUCCESS;
	}

	Subscription sub;
	sub.endpoint = endpoint;
	sub.p256dh = p256dh;
	sub.auth = auth;
	sub.nick = user->nick;
	sub.uuid = user->uuid;
	sub.updated = ServerInstance->Time();
	sub.last_success = ServerInstance->Time();
	rec.subs.push_back(std::move(sub));
	mod.dirty = true;
	mod.lastnick_account[user->nick] = owner;
	mod.SendWebPushMsg(user, "REGISTER", endpoint, parameters[2]);
	note.Send(user, this, "COVERAGE",
		"Pushes are sent for highlights and PMs while you are away or another device is connected, and for DMs to your nick while you are offline");
	return CmdResult::SUCCESS;
}

void ModuleWebPush::DrainReplies()
{
	std::deque<PushReply> replies;
	{
		std::lock_guard<std::mutex> lock(queue_mutex);
		replies.swap(outbox);
	}
	for (auto& reply : replies)
	{
		if (reply.kind == PushJobKind::TestRegister)
		{
			auto* user = ServerInstance->Users.FindUUID<LocalUser>(reply.uuid);
			if (!user)
				continue;
			if (reply.result.kind != WebPush::HttpStatusKind::Ok)
			{
				fail.Send(user, &cmd, "INVALID_PARAMS", "REGISTER", reply.endpoint,
					"Test push message failed to send");
				continue;
			}
			OwnerRecord& rec = owners[reply.owner];
			if (rec.subs.size() >= maxsubscriptions && !FindSub(rec, reply.endpoint))
			{
				fail.Send(user, &cmd, "MAX_REGISTRATIONS", "REGISTER", reply.endpoint,
					"Too many Web Push subscriptions");
				continue;
			}
			Subscription* existing = FindSub(rec, reply.endpoint);
			if (!existing)
			{
				rec.subs.push_back(Subscription());
				existing = &rec.subs.back();
				existing->endpoint = reply.endpoint;
			}
			existing->p256dh = reply.p256dh;
			existing->auth = reply.auth;
			existing->nick = user->nick;
			existing->uuid = user->uuid;
			existing->updated = ServerInstance->Time();
			existing->last_success = ServerInstance->Time();
			dirty = true;
			lastnick_account[user->nick] = reply.owner;
			SendWebPushMsg(user, "REGISTER", reply.endpoint, reply.keys_param);
			note.Send(user, &cmd, "COVERAGE",
				"Pushes are sent for highlights and PMs while you are away or another device is connected, and for DMs to your nick while you are offline");
		}
		else if (reply.result.kind == WebPush::HttpStatusKind::Gone)
		{
			RemoveEndpoint(reply.owner, reply.endpoint);
			ServerInstance->Logs.Debug(MODNAME, "Removed expired webpush endpoint for {}", reply.owner);
		}
		else if (reply.result.kind == WebPush::HttpStatusKind::Ok)
		{
			auto it = owners.find(reply.owner);
			if (it != owners.end())
			{
				if (Subscription* sub = FindSub(it->second, reply.endpoint))
					sub->last_success = ServerInstance->Time();
			}
		}
		else
		{
			ServerInstance->Logs.Debug(MODNAME, "Web Push to {} failed: {}", reply.endpoint, reply.result.error);
		}
	}
}

void PushWorker::OnStart()
{
	LockQueue();
	while (!IsStopping())
	{
		if (parent->inbox.empty())
		{
			WaitForQueue();
			continue;
		}
		PushJob job = std::move(parent->inbox.front());
		parent->inbox.pop_front();
		UnlockQueue();

		std::string body;
		std::string jwt;
		std::string vapidpub;
		std::string contact;
		int ttl = 0;
		int timeout = 15;
		bool prepared = false;
		{
			std::lock_guard<std::mutex> lock(parent->vapid_mutex);
			contact = parent->contact;
			ttl = parent->ttl;
			timeout = parent->http_timeout;
			vapidpub = parent->vapid.public_b64url;
			std::string origin = WebPush::OriginOf(job.endpoint);
			prepared = !origin.empty()
				&& WebPush::EncryptAes128Gcm(job.plaintext, job.p256dh, job.auth, body)
				&& WebPush::JwtEs256(parent->vapid.pkey, origin, contact,
					time(nullptr) + 12 * 3600, jwt);
		}

		WebPush::HttpResult result;
		if (!prepared)
		{
			result.kind = WebPush::HttpStatusKind::Error;
			result.error = "encrypt or vapid failed";
		}
		else
		{
			std::vector<std::pair<std::string, std::string>> hdrs;
			hdrs.emplace_back("Content-Type", "application/octet-stream");
			hdrs.emplace_back("Content-Encoding", "aes128gcm");
			hdrs.emplace_back("TTL", std::to_string(ttl));
			if (!job.urgency.empty())
				hdrs.emplace_back("Urgency", job.urgency);
			hdrs.emplace_back("Authorization", "vapid t=" + jwt + ", k=" + vapidpub);
			result = WebPush::HttpsPost(job.endpoint, body, hdrs, timeout);
		}

		{
			std::lock_guard<std::mutex> qlock(parent->queue_mutex);
			PushReply reply;
			reply.kind = job.kind;
			reply.uuid = job.uuid;
			reply.owner = job.owner;
			reply.endpoint = job.endpoint;
			reply.keys_param = job.keys_param;
			reply.p256dh = job.p256dh;
			reply.auth = job.auth;
			reply.result = std::move(result);
			parent->outbox.push_back(std::move(reply));
		}
		NotifyParent();
		LockQueue();
	}
	UnlockQueue();
}

void PushWorker::OnNotify()
{
	parent->DrainReplies();
}

MODULE_INIT(ModuleWebPush)

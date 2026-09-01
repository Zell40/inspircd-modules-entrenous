/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 * Provides IRCv3 draft/metadata-2 and draft/metadata-3 (METADATA GET/SET/…).
 * Compatible with Orbit (draft/metadata-2: METADATA * SUB, GET, METADATA/761 pushes).
 * Per-user buffer prefs (soju.im/muted, soju.im/pinned, soju.im/blocked) for Web Push.
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
/// $ModConfig: <ircv3metadata maxsubs="32" maxkeys="16" maxvaluebytes="500" requireaccount="yes" allowkeys="avatar bio pronouns timezone url" persistfile="ircv3-metadata.db" synclimit="200" beforeconnect="no">
/// $ModDesc: Provides IRCv3 draft/metadata-2 and draft/metadata-3 (METADATA).
/// $ModDepends: core 4

#include "inspircd.h"
#include "modules/account.h"
#include "modules/cap.h"
#include "modules/ircv3_replies.h"
#include "m_ircv3_webpush/ircv3_metadata.h"
#include "modules/monitor.h"
#include "modules/whois.h"

#include <cctype>
#include <fstream>
#include <set>

static constexpr const char* KEY_MUTED = "soju.im/muted";
static constexpr const char* KEY_PINNED = "soju.im/pinned";
static constexpr const char* KEY_BLOCKED = "soju.im/blocked";

enum MetaNumeric
{
	RPL_WHOISKEYVALUE = 760,
	RPL_KEYVALUE = 761,
	RPL_METADATAEND = 762,
	RPL_KEYNOTSET = 766,
	RPL_METADATASUBOK = 770,
	RPL_METADATAUNSUBOK = 771,
	RPL_METADATASUBS = 772,
	RPL_METADATASYNCLATER = 774
};

using MetaMap = std::map<std::string, std::string>;
using KeySet = std::set<std::string>;
using TargetPrefs = std::map<std::string, MetaMap, irc::insensitive_swo>;

struct UserSubs final
{
	KeySet keys;
};

static bool IsBufferPrefKey(const std::string& key)
{
	return irc::equals(key, KEY_MUTED)
		|| irc::equals(key, KEY_PINNED)
		|| irc::equals(key, KEY_BLOCKED);
}

static bool IsValidMetaKey(const std::string& key)
{
	if (key.empty() || key.size() > 64)
		return false;
	for (const unsigned char c : key)
	{
		if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '/' || c == '-')
			continue;
		return false;
	}
	return true;
}

static void ToLowerInPlace(std::string& s)
{
	for (auto& c : s)
		c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
}

class MetaCap final
	: public Cap::Capability
{
	std::string capvalue;

	bool OnList(LocalUser* user) override
	{
		return GetProtocol(user) != Cap::CAP_LEGACY;
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
	MetaCap(Module* mod, const std::string& capname)
		: Cap::Capability(mod, capname)
	{
	}

	void SetValueString(const std::string& v)
	{
		if (capvalue == v)
			return;
		capvalue = v;
		NotifyValueChange();
	}
};

class ModuleIRCv3Metadata;

class CommandMetadata final
	: public SplitCommand
{
public:
	ModuleIRCv3Metadata& mod;
	IRCv3::Replies::Fail& fail;

	CommandMetadata(Module* Creator, ModuleIRCv3Metadata& Mod, IRCv3::Replies::Fail& Fail);

	CmdResult HandleLocal(LocalUser* user, const Params& parameters) override;
};

class ModuleIRCv3Metadata final
	: public Module
	, public Account::EventListener
	, public Whois::EventListener
	, public Timer
{
public:
	Account::API accountapi;
	Monitor::API monitorapi;
	MetaCap cap2;
	MetaCap cap3;
	IRCv3::Replies::Fail fail;
	ClientProtocol::EventProvider metaev;
	CommandMetadata cmd;
	SimpleExtItem<UserSubs> subsext;
	SimpleExtItem<MetaMap> chanmetaext;

	std::map<std::string, MetaMap, irc::insensitive_swo> usermeta;
	std::map<std::string, TargetPrefs, irc::insensitive_swo> bufferprefs;
	bool dirty = false;

	size_t maxsubs = 32;
	size_t maxkeys = 16;
	size_t maxvaluebytes = 500;
	size_t synclimit = 200;
	bool requireaccount = true;
	bool beforeconnect = false;
	std::string persistfile;
	KeySet allowkeys;
	unsigned long saveperiod = 30;

	class MetadataAPIImpl final
		: public IRCv3Metadata::APIBase
	{
		ModuleIRCv3Metadata& mod;

	public:
		MetadataAPIImpl(ModuleIRCv3Metadata& parent);
		bool IsMuted(LocalUser* user, const std::string& target) const override;
		bool IsMutedOwner(const std::string& owner, const std::string& target) const override;
		bool IsBlocked(LocalUser* user, const std::string& target) const override;
	};

	MetadataAPIImpl apiimpl;

	ModuleIRCv3Metadata()
		: Module(VF_NONE, "Provides the IRCv3 draft/metadata-2 and draft/metadata-3 capabilities.")
		, Account::EventListener(this)
		, Whois::EventListener(this)
		, Timer(30, true)
		, accountapi(this)
		, monitorapi(this)
		, cap2(this, "draft/metadata-2")
		, cap3(this, "draft/metadata-3")
		, fail(this)
		, metaev(this, "METADATA")
		, cmd(this, *this, fail)
		, subsext(this, "ircv3-metadata-subs", ExtensionType::USER, false)
		, chanmetaext(this, "ircv3-metadata-chan", ExtensionType::CHANNEL, false)
		, apiimpl(*this)
	{
	}

	~ModuleIRCv3Metadata() override
	{
		SaveStore();
	}

	void init() override
	{
		if (!ServerInstance->Modules.Find("cap"))
		{
			ServerInstance->Logs.Normal(MODNAME, "WARNING: the cap module is not loaded! "
				"metadata will not be advertised until it is loaded.");
		}
		LoadStore();
	}

	void ReadConfig(ConfigStatus& status) override
	{
		const auto& tag = ServerInstance->Config->ConfValue("ircv3metadata");
		maxsubs = tag->getNum<size_t>("maxsubs", 32, 1, 200);
		maxkeys = tag->getNum<size_t>("maxkeys", 16, 1, 200);
		maxvaluebytes = tag->getNum<size_t>("maxvaluebytes", 500, 1, 4096);
		synclimit = tag->getNum<size_t>("synclimit", 200, 10, 5000);
		requireaccount = tag->getBool("requireaccount", true);
		beforeconnect = tag->getBool("beforeconnect", false);
		persistfile = ServerInstance->Config->Paths.PrependData(tag->getString("persistfile", "ircv3-metadata.db", 1));
		saveperiod = tag->getDuration("saveperiod", 30, 5, 3600);
		SetInterval(saveperiod, true);

		allowkeys.clear();
		irc::spacesepstream ks(tag->getString("allowkeys", "avatar bio pronouns timezone url"));
		for (std::string k; ks.GetToken(k); )
		{
			ToLowerInPlace(k);
			if (IsValidMetaKey(k))
				allowkeys.insert(k);
		}

		std::string value = "max-subs=" + ConvToStr(maxsubs)
			+ ",max-keys=" + ConvToStr(maxkeys)
			+ ",max-value-bytes=" + ConvToStr(maxvaluebytes)
			+ ",max-key-bytes=64";
		if (beforeconnect)
			value = "before-connect," + value;
		cap2.SetValueString(value);
		cap3.SetValueString(value);
	}

	bool Tick() override
	{
		if (dirty)
			SaveStore();
		return true;
	}

	bool HasMeta(LocalUser* user) const
	{
		return cap2.IsEnabled(user) || cap3.IsEnabled(user);
	}

	bool PreferMeta3(LocalUser* user) const
	{
		return cap3.IsEnabled(user);
	}

	bool KeyAllowed(const std::string& key) const
	{
		if (!IsValidMetaKey(key))
			return false;
		if (IsBufferPrefKey(key))
			return true;
		if (allowkeys.empty())
			return true;
		return allowkeys.find(key) != allowkeys.end();
	}

	std::string OwnerKey(User* user) const
	{
		if (accountapi)
		{
			const std::string* acct = accountapi->GetAccountName(user);
			if (acct && !acct->empty())
				return *acct;
		}
		return user->nick;
	}

	MetaMap* GetUserStore(const std::string& owner, bool create)
	{
		auto it = usermeta.find(owner);
		if (it != usermeta.end())
			return &it->second;
		if (!create)
			return nullptr;
		return &usermeta[owner];
	}

	MetaMap* GetUserStore(User* user, bool create)
	{
		return GetUserStore(OwnerKey(user), create);
	}

	MetaMap* GetBufferStore(const std::string& owner, const std::string& target, bool create)
	{
		auto oit = bufferprefs.find(owner);
		if (oit == bufferprefs.end())
		{
			if (!create)
				return nullptr;
			return &bufferprefs[owner][target];
		}
		auto tit = oit->second.find(target);
		if (tit != oit->second.end())
			return &tit->second;
		if (!create)
			return nullptr;
		return &oit->second[target];
	}

	MetaMap* GetBufferStore(User* user, const std::string& target, bool create)
	{
		return GetBufferStore(OwnerKey(user), target, create);
	}

	void TrimBufferOwner(const std::string& owner)
	{
		auto oit = bufferprefs.find(owner);
		if (oit == bufferprefs.end())
			return;
		for (auto tit = oit->second.begin(); tit != oit->second.end(); )
		{
			if (tit->second.empty())
				tit = oit->second.erase(tit);
			else
				++tit;
		}
		if (oit->second.empty())
			bufferprefs.erase(oit);
	}

	bool GetBufferFlag(LocalUser* user, const std::string& target, const char* key) const
	{
		if (!user || target.empty())
			return false;
		return GetBufferFlagOwner(OwnerKey(user), target, key);
	}

	bool GetBufferFlagOwner(const std::string& owner, const std::string& target, const char* key) const
	{
		if (owner.empty() || target.empty())
			return false;
		auto oit = bufferprefs.find(owner);
		if (oit == bufferprefs.end())
			return false;
		auto tit = oit->second.find(target);
		if (tit == oit->second.end())
			return false;
		auto kit = tit->second.find(key);
		if (kit == tit->second.end())
			return false;
		return kit->second == "1";
	}

	bool RequireAccountForWrite(LocalUser* user, const std::string& key)
	{
		if (!requireaccount)
			return true;
		if (accountapi && accountapi->GetAccountName(user))
			return true;
		fail.Send(user, &cmd, "KEY_NO_PERMISSION", "*", key,
			"You must be logged in to set metadata");
		return false;
	}

	static bool IsValidBufferBool(const std::string& value)
	{
		return value == "0" || value == "1";
	}

	CmdResult HandleBufferSet(LocalUser* user, const std::string& target, const std::string& key,
		const std::string* value_opt)
	{
		if (!RequireAccountForWrite(user, key))
			return CmdResult::FAILURE;

		std::string storekey = key;
		ToLowerInPlace(storekey);

		std::string display = target;
		if (ServerInstance->Channels.IsChannel(target))
		{
			Channel* chan = ServerInstance->Channels.Find(target);
			if (!chan || !chan->HasUser(user))
			{
				FailInvalidTarget(user, target);
				return CmdResult::FAILURE;
			}
			display = chan->name;
		}
		else if (target == "*")
		{
			FailInvalidTarget(user, target);
			return CmdResult::FAILURE;
		}
		else
		{
			User* peer = ServerInstance->Users.FindNick(target);
			if (peer)
				display = peer->nick;
		}

		const bool clearing = !value_opt || value_opt->empty() || *value_opt == "0";
		if (!clearing && !IsValidBufferBool(*value_opt))
		{
			fail.Send(user, &cmd, PreferMeta3(user) ? "INVALID_VALUE" : "VALUE_INVALID",
				key, "Value must be 0 or 1");
			return CmdResult::FAILURE;
		}

		const std::string owner = OwnerKey(user);
		if (clearing)
		{
			MetaMap* store = GetBufferStore(owner, display, false);
			if (store)
			{
				store->erase(storekey);
				TrimBufferOwner(owner);
			}
			dirty = true;
			SendKeyNotSet(user, display, storekey);
			NotifyWatcher(user, display, storekey, nullptr);
			return CmdResult::SUCCESS;
		}

		MetaMap* store = GetBufferStore(owner, display, true);
		if (store->find(storekey) == store->end() && store->size() >= maxkeys)
		{
			fail.Send(user, &cmd, "LIMIT_REACHED", key, "Metadata limit reached");
			return CmdResult::FAILURE;
		}
		(*store)[storekey] = "1";
		dirty = true;
		SendKeyValue(user, display, storekey, "1");
		NotifyWatcher(user, display, storekey, &(*store)[storekey]);
		return CmdResult::SUCCESS;
	}

	UserSubs* GetSubs(LocalUser* user, bool create)
	{
		UserSubs* s = subsext.Get(user);
		if (s || !create)
			return s;
		return &subsext.GetRef(user);
	}

	void FailInvalidTarget(LocalUser* user, const std::string& target)
	{
		fail.Send(user, &cmd, PreferMeta3(user) ? "INVALID_TARGET" : "TARGET_INVALID",
			target, "Invalid metadata target");
	}

	void FailInvalidKey(LocalUser* user, const std::string& key)
	{
		fail.Send(user, &cmd, PreferMeta3(user) ? "INVALID_KEY" : "KEY_INVALID",
			key, "Invalid key");
	}

	void SendKeyValue(LocalUser* user, const std::string& target, const std::string& key,
		const std::string& value)
	{
		user->WriteNumeric(RPL_KEYVALUE, target, key, "*", value);
	}

	void SendKeyNotSet(LocalUser* user, const std::string& target, const std::string& key)
	{
		user->WriteNumeric(RPL_KEYNOTSET, target, key, "key not set");
	}

	/** Live notification: METADATA verb for -2 (Orbit), 761/766 for -3. */
	void NotifyWatcher(LocalUser* watcher, const std::string& target, const std::string& key,
		const std::string* value)
	{
		if (!HasMeta(watcher))
			return;

		if (PreferMeta3(watcher))
		{
			if (value)
				SendKeyValue(watcher, target, key, *value);
			else
				SendKeyNotSet(watcher, target, key);
			return;
		}

		ClientProtocol::Message msg("METADATA", ServerInstance->Config->GetServerName());
		msg.PushParam(target);
		msg.PushParam(key);
		msg.PushParam("*");
		if (value)
			msg.PushParam(*value);
		ClientProtocol::Event ev(metaev, msg);
		watcher->Send(ev);
	}

	bool SharesVisibility(User* a, User* b) const
	{
		if (a == b)
			return true;
		for (const Membership* memb : a->chans)
		{
			if (memb->chan->HasUser(b))
				return true;
		}
		return false;
	}

	void NotifyUserKeyChange(User* subject, const std::string& key, const std::string* value)
	{
		const uint64_t sid = ServerInstance->Users.NextAlreadySentId();

		for (auto* u : ServerInstance->Users.GetLocalUsers())
		{
			if (u->already_sent == sid)
				continue;
			if (!HasMeta(u))
				continue;
			UserSubs* subs = GetSubs(u, false);
			if (!subs || subs->keys.find(key) == subs->keys.end())
				continue;
			if (!SharesVisibility(u, subject))
				continue;
			u->already_sent = sid;
			NotifyWatcher(u, subject->nick, key, value);
		}

		class WatcherNotify final
			: public Monitor::ForEachHandler
		{
			ModuleIRCv3Metadata& m;
			User* subject;
			const std::string& key;
			const std::string* value;
			uint64_t sid;

			void Execute(LocalUser* watcher) override
			{
				if (watcher->already_sent == sid)
					return;
				if (!m.HasMeta(watcher))
					return;
				UserSubs* subs = m.GetSubs(watcher, false);
				if (!subs || subs->keys.find(key) == subs->keys.end())
					return;
				watcher->already_sent = sid;
				m.NotifyWatcher(watcher, subject->nick, key, value);
			}

		public:
			WatcherNotify(ModuleIRCv3Metadata& Mod, User* Subject, const std::string& Key,
				const std::string* Value, uint64_t Sid)
				: m(Mod)
				, subject(Subject)
				, key(Key)
				, value(Value)
				, sid(Sid)
			{
			}
		};

		if (monitorapi)
		{
			WatcherNotify h(*this, subject, key, value, sid);
			monitorapi->ForEachWatcher(subject, h, false);
		}
	}

	void NotifyChannelKeyChange(Channel* chan, const std::string& key, const std::string* value)
	{
		for (const auto& [member, _] : chan->GetUsers())
		{
			LocalUser* lu = IS_LOCAL(member);
			if (!lu || !HasMeta(lu))
				continue;
			UserSubs* subs = GetSubs(lu, false);
			if (!subs || subs->keys.find(key) == subs->keys.end())
				continue;
			NotifyWatcher(lu, chan->name, key, value);
		}
	}

	void PushKeysToUser(LocalUser* watcher, const std::string& target, const MetaMap* store,
		const KeySet* filter)
	{
		if (!store || !filter)
			return;
		for (const auto& key : *filter)
		{
			auto it = store->find(key);
			if (it == store->end())
				continue;
			if (PreferMeta3(watcher))
				SendKeyValue(watcher, target, key, it->second);
			else
				NotifyWatcher(watcher, target, key, &it->second);
		}
	}

	void SyncChannelToUser(LocalUser* user, Channel* chan)
	{
		UserSubs* subs = GetSubs(user, false);
		if (!subs || subs->keys.empty())
			return;

		if (chan->GetUsers().size() > synclimit)
		{
			user->WriteNumeric(RPL_METADATASYNCLATER, chan->name, "5",
				"Metadata sync deferred; use METADATA SYNC");
			return;
		}

		MetaMap* cstore = chanmetaext.Get(chan);
		if (PreferMeta3(user))
			PushKeysToUser(user, chan->name, cstore, &subs->keys);
		else if (cstore)
		{
			for (const auto& key : subs->keys)
			{
				if (IsBufferPrefKey(key))
					continue;
				auto it = cstore->find(key);
				if (it != cstore->end())
					NotifyWatcher(user, chan->name, key, &it->second);
			}
		}

		MetaMap* bstore = GetBufferStore(user, chan->name, false);
		if (bstore)
		{
			for (const auto& key : subs->keys)
			{
				if (!IsBufferPrefKey(key))
					continue;
				auto it = bstore->find(key);
				if (it != bstore->end())
					NotifyWatcher(user, chan->name, key, &it->second);
			}
		}

		for (const auto& [member, _] : chan->GetUsers())
		{
			MetaMap* ustore = GetUserStore(member, false);
			if (PreferMeta3(user))
				PushKeysToUser(user, member->nick, ustore, &subs->keys);
			else if (ustore)
			{
				for (const auto& key : subs->keys)
				{
					if (IsBufferPrefKey(key))
						continue;
					auto it = ustore->find(key);
					if (it != ustore->end())
						NotifyWatcher(user, member->nick, key, &it->second);
				}
			}
		}
	}

	void HandleGet(LocalUser* user, const std::string& target, const std::vector<std::string>& keys)
	{
		MetaMap* profilestore = nullptr;
		MetaMap* bufferstore = nullptr;
		std::string display = target;
		bool channel_target = false;

		if (target == "*")
		{
			profilestore = GetUserStore(user, false);
			display = "*";
		}
		else if (ServerInstance->Channels.IsChannel(target))
		{
			Channel* chan = ServerInstance->Channels.Find(target);
			if (!chan)
			{
				FailInvalidTarget(user, target);
				return;
			}
			display = chan->name;
			channel_target = true;
			profilestore = chanmetaext.Get(chan);
			bufferstore = GetBufferStore(user, display, false);
		}
		else
		{
			User* dest = ServerInstance->Users.FindNick(target);
			if (dest)
			{
				display = dest->nick;
				profilestore = GetUserStore(dest, false);
			}
			else
				display = target;
			bufferstore = GetBufferStore(user, display, false);
		}

		for (const auto& key : keys)
		{
			if (!IsValidMetaKey(key))
			{
				FailInvalidKey(user, key);
				continue;
			}
			if (!KeyAllowed(key))
			{
				fail.Send(user, &cmd, "KEY_NO_PERMISSION", display, key, "Permission denied");
				continue;
			}

			if (IsBufferPrefKey(key))
			{
				if (target == "*")
				{
					SendKeyNotSet(user, display, key);
					continue;
				}
				if (channel_target)
				{
					Channel* chan = ServerInstance->Channels.Find(display);
					if (!chan || !chan->HasUser(user))
					{
						fail.Send(user, &cmd, "KEY_NO_PERMISSION", display, key, "Permission denied");
						continue;
					}
				}
				std::string look = key;
				ToLowerInPlace(look);
				if (!bufferstore)
				{
					SendKeyNotSet(user, display, look);
					continue;
				}
				auto it = bufferstore->find(look);
				if (it == bufferstore->end())
					SendKeyNotSet(user, display, look);
				else
					SendKeyValue(user, display, look, it->second);
				continue;
			}

			if (!profilestore)
			{
				SendKeyNotSet(user, display, key);
				continue;
			}
			auto it = profilestore->find(key);
			if (it == profilestore->end())
				SendKeyNotSet(user, display, key);
			else
				SendKeyValue(user, display, key, it->second);
		}

		user->WriteNumeric(RPL_METADATAEND, "end of metadata");
	}

	void HandleList(LocalUser* user, const std::string& target)
	{
		MetaMap* profilestore = nullptr;
		MetaMap* bufferstore = nullptr;
		std::string display = target;

		if (target == "*")
		{
			profilestore = GetUserStore(user, false);
			display = "*";
		}
		else if (ServerInstance->Channels.IsChannel(target))
		{
			Channel* chan = ServerInstance->Channels.Find(target);
			if (!chan)
			{
				FailInvalidTarget(user, target);
				return;
			}
			display = chan->name;
			profilestore = chanmetaext.Get(chan);
			if (chan->HasUser(user))
				bufferstore = GetBufferStore(user, display, false);
		}
		else
		{
			User* dest = ServerInstance->Users.FindNick(target);
			if (dest)
			{
				display = dest->nick;
				profilestore = GetUserStore(dest, false);
			}
			else
				display = target;
			bufferstore = GetBufferStore(user, display, false);
		}

		if (profilestore)
		{
			for (const auto& [key, value] : *profilestore)
			{
				if (KeyAllowed(key) && !IsBufferPrefKey(key))
					SendKeyValue(user, display, key, value);
			}
		}
		if (bufferstore)
		{
			for (const auto& [key, value] : *bufferstore)
			{
				if (IsBufferPrefKey(key))
					SendKeyValue(user, display, key, value);
			}
		}
	}

	CmdResult HandleSet(LocalUser* user, const std::string& target, const std::string& key,
		const std::string* value_opt)
	{
		if (!IsValidMetaKey(key) || !KeyAllowed(key))
		{
			FailInvalidKey(user, key);
			return CmdResult::FAILURE;
		}

		if (IsBufferPrefKey(key))
			return HandleBufferSet(user, target, key, value_opt);

		const bool clearing = !value_opt || value_opt->empty();
		if (!clearing && value_opt->size() > maxvaluebytes)
		{
			fail.Send(user, &cmd, PreferMeta3(user) ? "INVALID_VALUE" : "VALUE_INVALID",
				key, "Value is too long");
			return CmdResult::FAILURE;
		}

		if (ServerInstance->Channels.IsChannel(target))
		{
			Channel* chan = ServerInstance->Channels.Find(target);
			if (!chan)
			{
				FailInvalidTarget(user, target);
				return CmdResult::FAILURE;
			}
			if (chan->GetPrefixValue(user) < HALFOP_VALUE && !user->HasPrivPermission("channels/auspex"))
			{
				fail.Send(user, &cmd, "KEY_NO_PERMISSION", target, key, "Permission denied");
				return CmdResult::FAILURE;
			}

			MetaMap* store = chanmetaext.Get(chan);
			if (!store && !clearing)
				store = &chanmetaext.GetRef(chan);

			if (clearing)
			{
				if (store)
					store->erase(key);
				SendKeyNotSet(user, target, key);
				NotifyChannelKeyChange(chan, key, nullptr);
			}
			else
			{
				if (store->find(key) == store->end() && store->size() >= maxkeys)
				{
					fail.Send(user, &cmd, "LIMIT_REACHED", key, "Metadata limit reached");
					return CmdResult::FAILURE;
				}
				(*store)[key] = *value_opt;
				SendKeyValue(user, target, key, *value_opt);
				NotifyChannelKeyChange(chan, key, value_opt);
			}
			return CmdResult::SUCCESS;
		}

		const bool self = (target == "*" || irc::equals(target, user->nick));
		if (!self)
		{
			fail.Send(user, &cmd, "KEY_NO_PERMISSION", target, key, "Permission denied");
			return CmdResult::FAILURE;
		}

		if (!RequireAccountForWrite(user, key))
			return CmdResult::FAILURE;

		MetaMap* store = GetUserStore(user, true);
		if (clearing)
		{
			store->erase(key);
			if (store->empty())
				usermeta.erase(OwnerKey(user));
			dirty = true;
			SendKeyNotSet(user, "*", key);
			NotifyUserKeyChange(user, key, nullptr);
		}
		else
		{
			if (store->find(key) == store->end() && store->size() >= maxkeys)
			{
				fail.Send(user, &cmd, "LIMIT_REACHED", key, "Metadata limit reached");
				return CmdResult::FAILURE;
			}
			(*store)[key] = *value_opt;
			dirty = true;
			SendKeyValue(user, "*", key, *value_opt);
			NotifyUserKeyChange(user, key, value_opt);
		}
		return CmdResult::SUCCESS;
	}

	CmdResult HandleClear(LocalUser* user, const std::string& target)
	{
		if (ServerInstance->Channels.IsChannel(target))
		{
			Channel* chan = ServerInstance->Channels.Find(target);
			if (!chan)
			{
				FailInvalidTarget(user, target);
				return CmdResult::FAILURE;
			}
			if (chan->GetPrefixValue(user) < HALFOP_VALUE && !user->HasPrivPermission("channels/auspex"))
			{
				fail.Send(user, &cmd, "KEY_NO_PERMISSION", target, "*", "Permission denied");
				return CmdResult::FAILURE;
			}
			MetaMap* store = chanmetaext.Get(chan);
			if (store)
			{
				const KeySet keys = [&]() {
					KeySet k;
					for (const auto& [name, _] : *store)
						k.insert(name);
					return k;
				}();
				for (const auto& k : keys)
				{
					SendKeyNotSet(user, target, k);
					NotifyChannelKeyChange(chan, k, nullptr);
				}
				store->clear();
			}
			return CmdResult::SUCCESS;
		}

		if (target != "*" && !irc::equals(target, user->nick))
		{
			fail.Send(user, &cmd, "KEY_NO_PERMISSION", target, "*", "Permission denied");
			return CmdResult::FAILURE;
		}

		MetaMap* store = GetUserStore(user, false);
		if (store)
		{
			KeySet keys;
			for (const auto& [k, _] : *store)
				keys.insert(k);
			for (const auto& k : keys)
			{
				SendKeyNotSet(user, "*", k);
				NotifyUserKeyChange(user, k, nullptr);
			}
			usermeta.erase(OwnerKey(user));
			dirty = true;
		}
		return CmdResult::SUCCESS;
	}

	CmdResult HandleSub(LocalUser* user, const std::vector<std::string>& keys, bool unsub)
	{
		UserSubs* subs = GetSubs(user, true);
		std::vector<std::string> ok;

		for (const auto& key : keys)
		{
			if (!IsValidMetaKey(key))
			{
				FailInvalidKey(user, key);
				continue;
			}

			if (unsub)
			{
				subs->keys.erase(key);
				ok.push_back(key);
				continue;
			}

			if (subs->keys.find(key) == subs->keys.end() && subs->keys.size() >= maxsubs)
			{
				fail.Send(user, &cmd, PreferMeta3(user) ? "LIMIT_REACHED" : "TOO_MANY_SUBS",
					key, "Too many subscriptions");
				break;
			}
			subs->keys.insert(key);
			ok.push_back(key);
		}

		if (!ok.empty())
		{
			Numeric::Numeric n(unsub ? RPL_METADATAUNSUBOK : RPL_METADATASUBOK);
			for (const auto& k : ok)
				n.push(k);
			user->WriteNumeric(n);
		}

		if (!unsub && !ok.empty())
		{
			KeySet filter(ok.begin(), ok.end());
			MetaMap* self = GetUserStore(user, false);
			if (PreferMeta3(user))
				PushKeysToUser(user, user->nick, self, &filter);
			else if (self)
			{
				for (const auto& k : filter)
				{
					auto it = self->find(k);
					if (it != self->end())
						NotifyWatcher(user, user->nick, k, &it->second);
				}
			}
			for (const Membership* memb : user->chans)
				SyncChannelToUser(user, memb->chan);
		}

		return CmdResult::SUCCESS;
	}

	void HandleSubs(LocalUser* user)
	{
		UserSubs* subs = GetSubs(user, false);
		if (!subs || subs->keys.empty())
			return;

		Numeric::Numeric n(RPL_METADATASUBS);
		for (const auto& k : subs->keys)
			n.push(k);
		user->WriteNumeric(n);
	}

	CmdResult HandleSync(LocalUser* user, const std::string& target)
	{
		UserSubs* subs = GetSubs(user, false);
		if (!subs || subs->keys.empty())
			return CmdResult::SUCCESS;

		if (target == "*ALL")
		{
			for (const Membership* memb : user->chans)
				SyncChannelToUser(user, memb->chan);
			return CmdResult::SUCCESS;
		}

		if (ServerInstance->Channels.IsChannel(target))
		{
			Channel* chan = ServerInstance->Channels.Find(target);
			if (!chan || !chan->HasUser(user))
			{
				FailInvalidTarget(user, target);
				return CmdResult::FAILURE;
			}
			SyncChannelToUser(user, chan);
			return CmdResult::SUCCESS;
		}

		User* dest = (target == "*") ? static_cast<User*>(user) : ServerInstance->Users.FindNick(target);
		if (!dest || !SharesVisibility(user, dest))
		{
			FailInvalidTarget(user, target);
			return CmdResult::FAILURE;
		}

		MetaMap* store = GetUserStore(dest, false);
		if (PreferMeta3(user))
			PushKeysToUser(user, dest->nick, store, &subs->keys);
		else if (store)
		{
			for (const auto& k : subs->keys)
			{
				auto it = store->find(k);
				if (it != store->end())
					NotifyWatcher(user, dest->nick, k, &it->second);
			}
		}
		return CmdResult::SUCCESS;
	}

	void OnUserJoin(Membership* memb, bool sync, bool created, CUList& except) override
	{
		LocalUser* joiner = IS_LOCAL(memb->user);
		if (joiner && HasMeta(joiner) && !sync)
			SyncChannelToUser(joiner, memb->chan);

		MetaMap* store = GetUserStore(memb->user, false);
		if (!store || store->empty())
			return;

		for (const auto& [member, _] : memb->chan->GetUsers())
		{
			LocalUser* watcher = IS_LOCAL(member);
			if (!watcher || watcher == memb->user || !HasMeta(watcher))
				continue;
			UserSubs* subs = GetSubs(watcher, false);
			if (!subs)
				continue;
			for (const auto& [key, value] : *store)
			{
				if (subs->keys.find(key) != subs->keys.end())
					NotifyWatcher(watcher, memb->user->nick, key, &value);
			}
		}
	}

	void OnPostConnect(User* user) override
	{
		LocalUser* lu = IS_LOCAL(user);
		if (!lu || !HasMeta(lu))
			return;

		MetaMap* store = GetUserStore(lu, false);
		KeySet all;
		if (store)
		{
			for (const auto& [k, _] : *store)
				all.insert(k);
		}
		if (PreferMeta3(lu))
			PushKeysToUser(lu, lu->nick, store, &all);
		else if (store)
		{
			for (const auto& [k, v] : *store)
				NotifyWatcher(lu, lu->nick, k, &v);
		}
	}

	void OnAccountChange(User* user, const std::string& account) override
	{
		if (account.empty())
			return;
		auto nickit = usermeta.find(user->nick);
		if (nickit != usermeta.end())
		{
			auto& acctstore = usermeta[account];
			if (acctstore.empty())
			{
				acctstore = std::move(nickit->second);
				usermeta.erase(nickit);
				dirty = true;
			}
		}

		auto bufit = bufferprefs.find(user->nick);
		if (bufit != bufferprefs.end())
		{
			auto& dest = bufferprefs[account];
			if (dest.empty())
			{
				dest = std::move(bufit->second);
				bufferprefs.erase(bufit);
				dirty = true;
			}
		}
	}

	void OnWhois(Whois::Context& whois) override
	{
		LocalUser* source = whois.GetSource();
		if (!HasMeta(source))
			return;
		MetaMap* store = GetUserStore(whois.GetTarget(), false);
		if (!store)
			return;
		UserSubs* subs = GetSubs(source, false);
		for (const auto& [key, value] : *store)
		{
			if (!KeyAllowed(key) || IsBufferPrefKey(key))
				continue;
			if (subs && !subs->keys.empty() && subs->keys.find(key) == subs->keys.end())
				continue;
			whois.SendLine(RPL_WHOISKEYVALUE, key, "*", value);
		}
	}

	void LoadStore()
	{
		usermeta.clear();
		bufferprefs.clear();
		std::ifstream in(persistfile.c_str());
		if (!in)
			return;
		std::string line;
		std::string owner;
		while (std::getline(in, line))
		{
			if (line.empty() || line[0] == '#')
				continue;
			if (line.compare(0, 2, "b\t") == 0)
			{
				irc::sepstream stream(line.substr(2), '\t');
				std::string bowner;
				std::string btarget;
				std::string bkey;
				std::string bval;
				if (!stream.GetToken(bowner) || !stream.GetToken(btarget)
					|| !stream.GetToken(bkey) || !stream.GetToken(bval))
				{
					continue;
				}
				if (IsBufferPrefKey(bkey) && (bval == "0" || bval == "1"))
				{
					if (bval == "1")
						bufferprefs[bowner][btarget][bkey] = bval;
				}
				continue;
			}
			if (line[0] == '@')
			{
				owner = line.substr(1);
				continue;
			}
			if (owner.empty())
				continue;
			const auto sep = line.find('=');
			if (sep == std::string::npos)
				continue;
			std::string key = line.substr(0, sep);
			std::string val = line.substr(sep + 1);
			if (IsValidMetaKey(key) && !IsBufferPrefKey(key))
				usermeta[owner][key] = val;
		}
		ServerInstance->Logs.Normal(MODNAME, "Loaded metadata for {} owner(s), {} buffer-pref owner(s) from {}",
			usermeta.size(), bufferprefs.size(), persistfile);
	}

	void SaveStore()
	{
		std::ofstream out(persistfile.c_str(), std::ios::trunc);
		if (!out)
		{
			ServerInstance->Logs.Normal(MODNAME, "Failed to write {}", persistfile);
			return;
		}
		out << "# m_ircv3_metadata v2 (profile @owner + b\\towner\\ttarget\\tkey\\tvalue)\n";
		for (const auto& [ow, keys] : usermeta)
		{
			out << '@' << ow << '\n';
			for (const auto& [k, v] : keys)
				out << k << '=' << v << '\n';
		}
		for (const auto& [ow, targets] : bufferprefs)
		{
			for (const auto& [tgt, keys] : targets)
			{
				for (const auto& [k, v] : keys)
					out << "b\t" << ow << '\t' << tgt << '\t' << k << '\t' << v << '\n';
			}
		}
		dirty = false;
	}

	void Prioritize() override
	{
		ServerInstance->Modules.SetPriority(this, I_OnUserJoin, PRIORITY_LAST);
	}
};

CommandMetadata::CommandMetadata(Module* Creator, ModuleIRCv3Metadata& Mod, IRCv3::Replies::Fail& Fail)
	: SplitCommand(Creator, "METADATA", 2)
	, mod(Mod)
	, fail(Fail)
{
	works_before_reg = true;
}

ModuleIRCv3Metadata::MetadataAPIImpl::MetadataAPIImpl(ModuleIRCv3Metadata& parent)
	: IRCv3Metadata::APIBase(&parent)
	, mod(parent)
{
}

bool ModuleIRCv3Metadata::MetadataAPIImpl::IsMuted(LocalUser* user, const std::string& target) const
{
	return mod.GetBufferFlag(user, target, KEY_MUTED);
}

bool ModuleIRCv3Metadata::MetadataAPIImpl::IsMutedOwner(const std::string& owner, const std::string& target) const
{
	return mod.GetBufferFlagOwner(owner, target, KEY_MUTED);
}

bool ModuleIRCv3Metadata::MetadataAPIImpl::IsBlocked(LocalUser* user, const std::string& target) const
{
	return mod.GetBufferFlag(user, target, KEY_BLOCKED);
}

CmdResult CommandMetadata::HandleLocal(LocalUser* user, const Params& parameters)
{
	if (!mod.HasMeta(user))
	{
		fail.Send(user, this, "INVALID_CAP", "draft/metadata-2",
			"You must request draft/metadata-2 or draft/metadata-3 to use this command");
		return CmdResult::FAILURE;
	}

	if (!(user->connected & User::CONN_FULL) && !mod.beforeconnect)
	{
		fail.Send(user, this, "INVALID_PARAMS", "*", "METADATA is not available before connect");
		return CmdResult::FAILURE;
	}

	const std::string& target = parameters[0];
	std::string sub_upper = parameters[1];
	for (auto& c : sub_upper)
		c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));

	if (sub_upper == "GET")
	{
		if (parameters.size() < 3)
		{
			fail.Send(user, this, "INVALID_PARAMS", sub_upper, "METADATA GET requires keys");
			return CmdResult::FAILURE;
		}
		std::vector<std::string> keys(parameters.begin() + 2, parameters.end());
		mod.HandleGet(user, target, keys);
		return CmdResult::SUCCESS;
	}
	if (sub_upper == "LIST")
	{
		mod.HandleList(user, target);
		return CmdResult::SUCCESS;
	}
	if (sub_upper == "SET")
	{
		if (parameters.size() < 3)
		{
			fail.Send(user, this, "INVALID_PARAMS", sub_upper, "METADATA SET requires a key");
			return CmdResult::FAILURE;
		}
		const std::string& key = parameters[2];
		if (parameters.size() >= 4)
		{
			std::string value = parameters[3];
			return mod.HandleSet(user, target, key, &value);
		}
		return mod.HandleSet(user, target, key, nullptr);
	}
	if (sub_upper == "CLEAR")
		return mod.HandleClear(user, target);
	if (sub_upper == "SUB" || sub_upper == "UNSUB")
	{
		if (target != "*")
		{
			mod.FailInvalidTarget(user, target);
			return CmdResult::FAILURE;
		}
		if (parameters.size() < 3)
		{
			fail.Send(user, this, "INVALID_PARAMS", sub_upper, "METADATA SUB requires keys");
			return CmdResult::FAILURE;
		}
		std::vector<std::string> keys(parameters.begin() + 2, parameters.end());
		return mod.HandleSub(user, keys, sub_upper == "UNSUB");
	}
	if (sub_upper == "SUBS")
	{
		if (target != "*")
		{
			mod.FailInvalidTarget(user, target);
			return CmdResult::FAILURE;
		}
		mod.HandleSubs(user);
		return CmdResult::SUCCESS;
	}
	if (sub_upper == "SYNC")
		return mod.HandleSync(user, target);

	fail.Send(user, this, "INVALID_PARAMS", sub_upper, "Unknown METADATA subcommand");
	return CmdResult::FAILURE;
}

MODULE_INIT(ModuleIRCv3Metadata)

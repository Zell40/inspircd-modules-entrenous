/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 * Provides IRCv3 draft/metadata-2 and draft/metadata-3 (METADATA GET/SET/…).
 * Compatible with Orbit (draft/metadata-2: METADATA * SUB, GET, METADATA/761 pushes).
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
#include "clientprotocolmsg.h"
#include "modules/account.h"
#include "modules/cap.h"
#include "modules/ircv3_batch.h"
#include "modules/ircv3_replies.h"
#include "modules/monitor.h"
#include "modules/whois.h"

#include <cctype>
#include <fstream>
#include <set>

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

struct UserSubs final
{
	KeySet keys;
};

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
	IRCv3::Batch::API batchmanager;
	IRCv3::Batch::CapReference batchcap;
	ClientProtocol::EventProvider metaev;
	CommandMetadata cmd;
	SimpleExtItem<UserSubs> subsext;
	SimpleExtItem<MetaMap> chanmetaext;

	std::map<std::string, MetaMap, irc::insensitive_swo> usermeta;
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
		, batchmanager(this)
		, batchcap(this)
		, metaev(this, "METADATA")
		, cmd(this, *this, fail)
		, subsext(this, "ircv3-metadata-subs", ExtensionType::USER, false)
		, chanmetaext(this, "ircv3-metadata-chan", ExtensionType::CHANNEL, false)
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
		const std::string& value, IRCv3::Batch::Batch* batch)
	{
		Numeric::Numeric n(RPL_KEYVALUE);
		n.push(target).push(key).push("*").push(value);
		ClientProtocol::Messages::Numeric msg(n, user);
		if (batch && batch->IsRunning())
			batch->AddToBatch(msg);
		user->Send(ServerInstance->GetRFCEvents().numeric, msg);
	}

	void SendKeyNotSet(LocalUser* user, const std::string& target, const std::string& key,
		IRCv3::Batch::Batch* batch)
	{
		Numeric::Numeric n(RPL_KEYNOTSET);
		n.push(target).push(key).push("key not set");
		ClientProtocol::Messages::Numeric msg(n, user);
		if (batch && batch->IsRunning())
			batch->AddToBatch(msg);
		user->Send(ServerInstance->GetRFCEvents().numeric, msg);
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
				SendKeyValue(watcher, target, key, *value, nullptr);
			else
				SendKeyNotSet(watcher, target, key, nullptr);
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
		const KeySet* filter, IRCv3::Batch::Batch* batch)
	{
		if (!store || !filter)
			return;
		for (const auto& key : *filter)
		{
			auto it = store->find(key);
			if (it == store->end())
				continue;
			if (PreferMeta3(watcher) || batch)
				SendKeyValue(watcher, target, key, it->second, batch);
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

		IRCv3::Batch::Batch batch("metadata");
		const bool use_batch = PreferMeta3(user) && batchmanager && batchcap.IsEnabled(user);
		if (use_batch)
		{
			batchmanager->Start(batch);
			batch.GetBatchStartMessage().PushParamRef(chan->name);
		}
		IRCv3::Batch::Batch* bp = batch.IsRunning() ? &batch : nullptr;

		MetaMap* cstore = chanmetaext.Get(chan);
		if (PreferMeta3(user))
			PushKeysToUser(user, chan->name, cstore, &subs->keys, bp);
		else if (cstore)
		{
			for (const auto& key : subs->keys)
			{
				auto it = cstore->find(key);
				if (it != cstore->end())
					NotifyWatcher(user, chan->name, key, &it->second);
			}
		}

		for (const auto& [member, _] : chan->GetUsers())
		{
			MetaMap* ustore = GetUserStore(member, false);
			if (PreferMeta3(user))
				PushKeysToUser(user, member->nick, ustore, &subs->keys, bp);
			else if (ustore)
			{
				for (const auto& key : subs->keys)
				{
					auto it = ustore->find(key);
					if (it != ustore->end())
						NotifyWatcher(user, member->nick, key, &it->second);
				}
			}
		}

		if (batch.IsRunning())
			batchmanager->End(batch);
	}

	void HandleGet(LocalUser* user, const std::string& target, const std::vector<std::string>& keys)
	{
		IRCv3::Batch::Batch batch("metadata");
		if (batchmanager && batchcap.IsEnabled(user))
		{
			batchmanager->Start(batch);
			batch.GetBatchStartMessage().PushParam(target);
		}
		IRCv3::Batch::Batch* bp = batch.IsRunning() ? &batch : nullptr;

		MetaMap* store = nullptr;
		std::string display = target;

		if (target == "*")
		{
			store = GetUserStore(user, false);
			display = "*";
		}
		else if (ServerInstance->Channels.IsChannel(target))
		{
			Channel* chan = ServerInstance->Channels.Find(target);
			if (!chan)
			{
				FailInvalidTarget(user, target);
				if (batch.IsRunning())
					batchmanager->End(batch);
				return;
			}
			store = chanmetaext.Get(chan);
		}
		else
		{
			User* dest = ServerInstance->Users.FindNick(target);
			if (!dest)
			{
				FailInvalidTarget(user, target);
				if (batch.IsRunning())
					batchmanager->End(batch);
				return;
			}
			store = GetUserStore(dest, false);
			display = dest->nick;
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
			if (!store)
			{
				SendKeyNotSet(user, display, key, bp);
				continue;
			}
			auto it = store->find(key);
			if (it == store->end())
				SendKeyNotSet(user, display, key, bp);
			else
				SendKeyValue(user, display, key, it->second, bp);
		}

		if (batch.IsRunning())
			batchmanager->End(batch);
		else
			user->WriteNumeric(RPL_METADATAEND, "end of metadata");
	}

	void HandleList(LocalUser* user, const std::string& target)
	{
		IRCv3::Batch::Batch batch("metadata");
		if (batchmanager && batchcap.IsEnabled(user))
		{
			batchmanager->Start(batch);
			batch.GetBatchStartMessage().PushParam(target);
		}
		IRCv3::Batch::Batch* bp = batch.IsRunning() ? &batch : nullptr;

		MetaMap* store = nullptr;
		std::string display = target;
		if (target == "*")
		{
			store = GetUserStore(user, false);
			display = "*";
		}
		else if (ServerInstance->Channels.IsChannel(target))
		{
			Channel* chan = ServerInstance->Channels.Find(target);
			if (!chan)
			{
				FailInvalidTarget(user, target);
				if (batch.IsRunning())
					batchmanager->End(batch);
				return;
			}
			store = chanmetaext.Get(chan);
		}
		else
		{
			User* dest = ServerInstance->Users.FindNick(target);
			if (!dest)
			{
				FailInvalidTarget(user, target);
				if (batch.IsRunning())
					batchmanager->End(batch);
				return;
			}
			store = GetUserStore(dest, false);
			display = dest->nick;
		}

		if (store)
		{
			for (const auto& [key, value] : *store)
			{
				if (KeyAllowed(key))
					SendKeyValue(user, display, key, value, bp);
			}
		}

		if (batch.IsRunning())
			batchmanager->End(batch);
	}

	CmdResult HandleSet(LocalUser* user, const std::string& target, const std::string& key,
		const std::string* value_opt)
	{
		if (!IsValidMetaKey(key) || !KeyAllowed(key))
		{
			FailInvalidKey(user, key);
			return CmdResult::FAILURE;
		}

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
				SendKeyNotSet(user, target, key, nullptr);
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
				SendKeyValue(user, target, key, *value_opt, nullptr);
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

		if (requireaccount)
		{
			if (!accountapi || !accountapi->GetAccountName(user))
			{
				fail.Send(user, &cmd, "KEY_NO_PERMISSION", "*", key,
					"You must be logged in to set metadata");
				return CmdResult::FAILURE;
			}
		}

		MetaMap* store = GetUserStore(user, true);
		if (clearing)
		{
			store->erase(key);
			if (store->empty())
				usermeta.erase(OwnerKey(user));
			dirty = true;
			SendKeyNotSet(user, "*", key, nullptr);
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
			SendKeyValue(user, "*", key, *value_opt, nullptr);
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
					SendKeyNotSet(user, target, k, nullptr);
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
				SendKeyNotSet(user, "*", k, nullptr);
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
				PushKeysToUser(user, user->nick, self, &filter, nullptr);
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
		IRCv3::Batch::Batch batch("metadata-subs");
		if (batchmanager && batchcap.IsEnabled(user))
			batchmanager->Start(batch);

		if (subs && !subs->keys.empty())
		{
			Numeric::Numeric n(RPL_METADATASUBS);
			for (const auto& k : subs->keys)
				n.push(k);
			ClientProtocol::Messages::Numeric msg(n, user);
			if (batch.IsRunning())
				batch.AddToBatch(msg);
			user->Send(ServerInstance->GetRFCEvents().numeric, msg);
		}

		if (batch.IsRunning())
			batchmanager->End(batch);
	}

	CmdResult HandleSync(LocalUser* user, const std::string& target)
	{
		UserSubs* subs = GetSubs(user, false);
		if (!subs || subs->keys.empty())
		{
			IRCv3::Batch::Batch batch("metadata");
			if (batchmanager && batchcap.IsEnabled(user))
			{
				batchmanager->Start(batch);
				batch.GetBatchStartMessage().PushParam(target);
				batchmanager->End(batch);
			}
			return CmdResult::SUCCESS;
		}

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

		IRCv3::Batch::Batch batch("metadata");
		if (batchmanager && batchcap.IsEnabled(user))
		{
			batchmanager->Start(batch);
			batch.GetBatchStartMessage().PushParam(dest->nick);
		}
		MetaMap* store = GetUserStore(dest, false);
		if (PreferMeta3(user))
			PushKeysToUser(user, dest->nick, store, &subs->keys, batch.IsRunning() ? &batch : nullptr);
		else if (store)
		{
			for (const auto& k : subs->keys)
			{
				auto it = store->find(k);
				if (it != store->end())
					NotifyWatcher(user, dest->nick, k, &it->second);
			}
		}
		if (batch.IsRunning())
			batchmanager->End(batch);
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

		IRCv3::Batch::Batch batch("metadata");
		if (batchmanager && batchcap.IsEnabled(lu))
		{
			batchmanager->Start(batch);
			batch.GetBatchStartMessage().PushParamRef(lu->nick);
		}
		MetaMap* store = GetUserStore(lu, false);
		KeySet all;
		if (store)
		{
			for (const auto& [k, _] : *store)
				all.insert(k);
		}
		if (PreferMeta3(lu))
			PushKeysToUser(lu, lu->nick, store, &all, batch.IsRunning() ? &batch : nullptr);
		else if (store)
		{
			for (const auto& [k, v] : *store)
				NotifyWatcher(lu, lu->nick, k, &v);
		}
		if (batch.IsRunning())
			batchmanager->End(batch);
	}

	void OnAccountChange(User* user, const std::string& account) override
	{
		if (account.empty())
			return;
		auto nickit = usermeta.find(user->nick);
		if (nickit == usermeta.end())
			return;
		auto& acctstore = usermeta[account];
		if (acctstore.empty())
		{
			acctstore = std::move(nickit->second);
			usermeta.erase(nickit);
			dirty = true;
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
			if (!KeyAllowed(key))
				continue;
			if (subs && !subs->keys.empty() && subs->keys.find(key) == subs->keys.end())
				continue;
			whois.SendLine(RPL_WHOISKEYVALUE, key, "*", value);
		}
	}

	void LoadStore()
	{
		usermeta.clear();
		std::ifstream in(persistfile.c_str());
		if (!in)
			return;
		std::string line;
		std::string owner;
		while (std::getline(in, line))
		{
			if (line.empty() || line[0] == '#')
				continue;
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
			if (IsValidMetaKey(key))
				usermeta[owner][key] = val;
		}
		ServerInstance->Logs.Normal(MODNAME, "Loaded metadata for {} owner(s) from {}",
			usermeta.size(), persistfile);
	}

	void SaveStore()
	{
		std::ofstream out(persistfile.c_str(), std::ios::trunc);
		if (!out)
		{
			ServerInstance->Logs.Normal(MODNAME, "Failed to write {}", persistfile);
			return;
		}
		out << "# m_ircv3_metadata v1\n";
		for (const auto& [owner, keys] : usermeta)
		{
			out << '@' << owner << '\n';
			for (const auto& [k, v] : keys)
				out << k << '=' << v << '\n';
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

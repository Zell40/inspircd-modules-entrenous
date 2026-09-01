/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 * Provides IRCv3 draft/chathistory (CHATHISTORY LATEST/BEFORE/…).
 * Compatible with Orbit: LATEST * N and BEFORE timestamp=… N in a chathistory batch.
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
/// $ModConfig: <ircv3chathistory maxlines="500" maxduration="7d" maxquery="50" savepms="yes" savebots="yes" saveevents="yes" saveusermodes="yes" clearminrank="op" allowselfpmclear="yes">
/// $ModDesc: Provides IRCv3 draft/chathistory and draft/event-playback (CHATHISTORY).
/// $ModDepends: core 4

#include "inspircd.h"
#include "clientprotocolmsg.h"
#include "modules/cap.h"
#include "modules/ircv3_batch.h"
#include "modules/ircv3_replies.h"
#include "modules/ircv3_servertime.h"
#include "modules/isupport.h"

#include <algorithm>
#include <cctype>
#include <ctime>
#include <deque>

typedef insp::flat_map<std::string, std::string> HistoryTagMap;

struct HistoryItem final
{
	time_t ts = 0;
	long ms = 0;
	bool is_event = false;
	std::string text;
	MessageType type = MessageType::PRIVMSG;
	HistoryTagMap tags;
	std::string sourcemask;
	std::string msgid;
	std::string command; // event verb: JOIN, PART, …
	std::vector<std::string> eparams;

	HistoryItem() = default;

	HistoryItem(User* source, const MessageDetails& details)
		: ts(ServerInstance->Time())
		, text(details.text)
		, type(details.type)
		, sourcemask(source->GetMask())
	{
		tags.reserve(details.tags_out.size());
		for (const auto& [tagname, tagvalue] : details.tags_out)
		{
			tags[tagname] = tagvalue.value;
			if (irc::equals(tagname, "msgid"))
				msgid = tagvalue.value;
		}
	}

	static HistoryItem Event(User* source, const std::string& cmd, std::vector<std::string> params)
	{
		HistoryItem item;
		item.is_event = true;
		item.ts = ServerInstance->Time();
		item.sourcemask = source->GetMask();
		item.command = cmd;
		item.eparams = std::move(params);
		return item;
	}

	static HistoryItem EventMask(const std::string& mask, const std::string& cmd, std::vector<std::string> params)
	{
		HistoryItem item;
		item.is_event = true;
		item.ts = ServerInstance->Time();
		item.sourcemask = mask;
		item.command = cmd;
		item.eparams = std::move(params);
		return item;
	}

	bool EarlierThan(time_t ots, long oms) const
	{
		if (ts != ots)
			return ts < ots;
		return ms < oms;
	}

	bool LaterThan(time_t ots, long oms) const
	{
		if (ts != ots)
			return ts > ots;
		return ms > oms;
	}
};

struct HistoryList final
{
	std::deque<HistoryItem> lines;
};

class DraftCap final
	: public Cap::Capability
{
	bool OnList(LocalUser* user) override
	{
		return GetProtocol(user) != Cap::CAP_LEGACY;
	}

	bool OnRequest(LocalUser* user, bool adding) override
	{
		return OnList(user);
	}

public:
	DraftCap(Module* mod, const std::string& capname)
		: Cap::Capability(mod, capname)
	{
	}
};

static bool ParseISOTime(const std::string& in, time_t& out, long& millis)
{
	int year = 0;
	int mon = 0;
	int day = 0;
	int hour = 0;
	int min = 0;
	int sec = 0;
	int ms = 0;
	const int n = sscanf(in.c_str(), "%d-%d-%dT%d:%d:%d.%dZ",
		&year, &mon, &day, &hour, &min, &sec, &ms);
	if (n < 6)
		return false;

	std::tm tm{};
	tm.tm_year = year - 1900;
	tm.tm_mon = mon - 1;
	tm.tm_mday = day;
	tm.tm_hour = hour;
	tm.tm_min = min;
	tm.tm_sec = sec;
#if defined(_WIN32)
	out = _mkgmtime(&tm);
#else
	out = timegm(&tm);
#endif
	if (out == static_cast<time_t>(-1))
		return false;
	millis = (n >= 7) ? ms : 0;
	return true;
}

static bool ParseSelector(const std::string& sel, bool& is_star, bool& is_ts, bool& is_msgid,
	time_t& ts, long& ms, std::string& msgid)
{
	is_star = is_ts = is_msgid = false;
	if (sel == "*")
	{
		is_star = true;
		return true;
	}
	if (sel.compare(0, 10, "timestamp=") == 0)
	{
		is_ts = true;
		return ParseISOTime(sel.substr(10), ts, ms);
	}
	if (sel.compare(0, 6, "msgid=") == 0)
	{
		is_msgid = true;
		msgid = sel.substr(6);
		return !msgid.empty();
	}
	return false;
}

class ModuleIRCv3ChatHistory;

class CommandChatHistory final
	: public SplitCommand
{
public:
	ModuleIRCv3ChatHistory& mod;
	IRCv3::Replies::Fail& fail;

	CommandChatHistory(Module* Creator, ModuleIRCv3ChatHistory& Mod, IRCv3::Replies::Fail& Fail);

	CmdResult HandleLocal(LocalUser* user, const Params& parameters) override;
};

class ModuleIRCv3ChatHistory final
	: public Module
	, public ISupport::EventListener
{
public:
	DraftCap cap;
	DraftCap eventcap;
	IRCv3::Replies::Fail fail;
	IRCv3::Batch::API batchmanager;
	IRCv3::Batch::CapReference batchcap;
	IRCv3::ServerTime::API servertimemanager;
	ClientProtocol::MessageTagEvent tagevent;
	// Own provider: never use GetRFCEvents().join/part/… for replay — hooks
	// (m_ircv3, delayjoin, auditorium) static_cast to Events::Join and crash.
	ClientProtocol::EventProvider histprov;
	CommandChatHistory cmd;
	SimpleExtItem<HistoryList> chanhist;
	UserModeReference botmode;

	// PM history: key = lower(sorted nickA\0nickB)
	std::map<std::string, HistoryList> pmhist;

	size_t maxlines = 500;
	time_t maxduration = 7 * 24 * 3600;
	size_t maxquery = 50;
	bool savepms = true;
	bool savebots = true;
	bool saveevents = true;
	bool saveusermodes = true;
	bool allowselfpmclear = true;
	ModeHandler::Rank clearminrank = OP_VALUE;

	ModuleIRCv3ChatHistory()
		: Module(VF_NONE, "Provides the IRCv3 draft/chathistory and draft/event-playback capabilities.")
		, ISupport::EventListener(this)
		, cap(this, "draft/chathistory")
		, eventcap(this, "draft/event-playback")
		, fail(this)
		, batchmanager(this)
		, batchcap(this)
		, servertimemanager(this)
		, tagevent(this)
		, histprov(this, "chathistory")
		, cmd(this, *this, fail)
		, chanhist(this, "ircv3-chathistory", ExtensionType::CHANNEL, false)
		, botmode(this, "bot")
	{
	}

	static ModeHandler::Rank RankFromName(const std::string& name)
	{
		if (irc::equals(name, "voice") || name == "v")
			return VOICE_VALUE;
		if (irc::equals(name, "halfop") || name == "h")
			return HALFOP_VALUE;
		if (irc::equals(name, "op") || name == "o")
			return OP_VALUE;
		// Conventional customprefix ranks (docs/conf/modules.example.conf).
		if (irc::equals(name, "admin") || name == "a")
			return 40000;
		if (irc::equals(name, "founder") || irc::equals(name, "owner") || name == "q")
			return 50000;

		ModeHandler* mh = ServerInstance->Modes.FindMode(name, MODETYPE_CHANNEL);
		if (mh)
		{
			PrefixMode* pm = mh->IsPrefixMode();
			if (pm)
				return pm->GetPrefixRank();
		}
		return ConvToNum<ModeHandler::Rank>(name);
	}

	void ReadConfig(ConfigStatus& status) override
	{
		const auto& tag = ServerInstance->Config->ConfValue("ircv3chathistory");
		maxlines = tag->getNum<size_t>("maxlines", 500, 10, 10000);
		maxduration = static_cast<time_t>(tag->getDuration("maxduration", 7 * 24 * 3600, 60, 365 * 24 * 3600UL));
		maxquery = tag->getNum<size_t>("maxquery", 50, 1, 500);
		savepms = tag->getBool("savepms", true);
		savebots = tag->getBool("savebots", true);
		saveevents = tag->getBool("saveevents", true);
		saveusermodes = tag->getBool("saveusermodes", true);
		allowselfpmclear = tag->getBool("allowselfpmclear", true);
		clearminrank = RankFromName(tag->getString("clearminrank", "op"));
		if (clearminrank == 0)
			clearminrank = OP_VALUE;
	}

	void OnBuildISupport(ISupport::TokenMap& tokens) override
	{
		tokens["CHATHISTORY"] = ConvToStr(maxquery);
		tokens["MSGREFTYPES"] = "timestamp,msgid";
	}

	void init() override
	{
		if (!ServerInstance->Modules.Find("cap"))
		{
			ServerInstance->Logs.Normal(MODNAME, "WARNING: the cap module is not loaded! "
				"chathistory will not be advertised until it is loaded.");
		}
		if (!ServerInstance->Modules.Find("ircv3_batch"))
		{
			ServerInstance->Logs.Normal(MODNAME, "WARNING: ircv3_batch is not loaded! "
				"Orbit expects CHATHISTORY replies inside a chathistory batch.");
		}
	}

	void Prune(HistoryList& list)
	{
		const time_t mintime = maxduration ? (ServerInstance->Time() - maxduration) : 0;
		while (!list.lines.empty() && mintime && list.lines.front().ts < mintime)
			list.lines.pop_front();
		while (list.lines.size() > maxlines)
			list.lines.pop_front();
	}

	std::string PMKey(User* a, User* b) const
	{
		std::string na = a->nick;
		std::string nb = b->nick;
		for (auto& c : na)
			c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
		for (auto& c : nb)
			c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
		if (na > nb)
			std::swap(na, nb);
		return na + '\0' + nb;
	}

	HistoryList* GetChannelHistory(Channel* chan, bool create)
	{
		HistoryList* list = chanhist.Get(chan);
		if (list || !create)
			return list;
		return &chanhist.GetRef(chan);
	}

	void AddTag(ClientProtocol::Message& msg, const std::string& tagkey, std::string& tagval)
	{
		for (auto* subscriber : tagevent.GetSubscribers())
		{
			auto* const tagprov = static_cast<ClientProtocol::MessageTagProvider*>(subscriber);
			const ModResult res = tagprov->OnProcessTag(ServerInstance->FakeClient, tagkey, tagval);
			if (res == MOD_RES_ALLOW)
				msg.AddTag(tagkey, tagprov, tagval);
			else if (res == MOD_RES_DENY)
				break;
		}
	}

	void StoreEvent(Channel* chan, HistoryItem item)
	{
		if (!saveevents || !chan)
			return;
		HistoryList* list = GetChannelHistory(chan, true);
		list->lines.push_back(std::move(item));
		Prune(*list);
	}

	void SendBatch(LocalUser* user, const std::string& targetname,
		const std::vector<const HistoryItem*>& items)
	{
		IRCv3::Batch::Batch batch("chathistory");
		if (batchmanager && batchcap.IsEnabled(user))
		{
			batchmanager->Start(batch);
			batch.GetBatchStartMessage().PushParam(targetname);
		}

		for (const HistoryItem* item : items)
		{
			if (item->is_event)
			{
				ClientProtocol::Message out(item->command.c_str(), item->sourcemask);
				for (const auto& p : item->eparams)
					out.PushParam(p);
				if (servertimemanager)
					servertimemanager->Set(out, item->ts, item->ms);
				if (batch.IsRunning())
					batch.AddToBatch(out);
				user->Send(histprov, out);
				continue;
			}

			ClientProtocol::Messages::Privmsg out(
				ClientProtocol::Messages::Privmsg::nocopy,
				item->sourcemask,
				targetname,
				item->text,
				item->type);

			for (auto tagpair : item->tags)
			{
				std::string val = tagpair.second;
				AddTag(out, tagpair.first, val);
			}
			if (servertimemanager)
				servertimemanager->Set(out, item->ts, item->ms);

			if (batch.IsRunning())
				batch.AddToBatch(out);
			// Same histprov as events — avoid RFC PRIVMSG hooks mutating replay.
			user->Send(histprov, out);
		}

		if (batch.IsRunning())
			batchmanager->End(batch);
	}

	bool FindByMsgid(const HistoryList& list, const std::string& msgid, size_t& idx) const
	{
		for (size_t i = 0; i < list.lines.size(); ++i)
		{
			if (list.lines[i].msgid == msgid)
			{
				idx = i;
				return true;
			}
		}
		return false;
	}

	static bool ChangeListIsPrefixModesOnly(const Modes::ChangeList& changelist)
	{
		bool any = false;
		for (const auto& change : changelist.getlist())
		{
			any = true;
			if (!change.mh->IsPrefixMode())
				return false;
		}
		return any;
	}

	bool IsStoredPrefixModeOnly(const HistoryItem& item) const
	{
		if (!item.is_event || !irc::equals(item.command, "MODE") || item.eparams.size() < 2)
			return false;
		const std::string& modestr = item.eparams[1];
		bool any = false;
		for (unsigned char c : modestr)
		{
			if (c == '+' || c == '-')
				continue;
			any = true;
			ModeHandler* mh = ServerInstance->Modes.FindMode(static_cast<char>(c), MODETYPE_CHANNEL);
			if (!mh || !mh->IsPrefixMode())
				return false;
		}
		return any;
	}

	bool IncludeHistoryItem(const HistoryItem& item, bool want_events) const
	{
		if (!item.is_event)
			return true;
		if (!want_events)
			return false;
		if (!saveusermodes && IsStoredPrefixModeOnly(item))
			return false;
		return true;
	}

	void CollectLatest(const HistoryList& list, size_t limit, time_t after_ts, long after_ms,
		bool have_after, bool want_events, std::vector<const HistoryItem*>& out)
	{
		for (auto it = list.lines.rbegin(); it != list.lines.rend() && out.size() < limit; ++it)
		{
			if (!IncludeHistoryItem(*it, want_events))
				continue;
			if (have_after && !it->LaterThan(after_ts, after_ms))
				continue;
			out.push_back(&(*it));
		}
		std::reverse(out.begin(), out.end());
	}

	void CollectBefore(const HistoryList& list, size_t limit, time_t before_ts, long before_ms,
		bool want_events, std::vector<const HistoryItem*>& out)
	{
		for (auto it = list.lines.rbegin(); it != list.lines.rend() && out.size() < limit; ++it)
		{
			if (!IncludeHistoryItem(*it, want_events))
				continue;
			if (!it->EarlierThan(before_ts, before_ms))
				continue;
			out.push_back(&(*it));
		}
		std::reverse(out.begin(), out.end());
	}

	void CollectAfter(const HistoryList& list, size_t limit, time_t after_ts, long after_ms,
		bool want_events, std::vector<const HistoryItem*>& out)
	{
		for (const auto& item : list.lines)
		{
			if (!IncludeHistoryItem(item, want_events))
				continue;
			if (!item.LaterThan(after_ts, after_ms))
				continue;
			out.push_back(&item);
			if (out.size() >= limit)
				break;
		}
	}

	CmdResult Query(LocalUser* user, const std::string& sub, const std::string& target,
		const std::string& sel1, const std::string& sel2, size_t limit)
	{
		HistoryList* list = nullptr;
		std::string display = target;

		if (ServerInstance->Channels.IsChannel(target))
		{
			Channel* chan = ServerInstance->Channels.Find(target);
			if (!chan || !chan->HasUser(user))
			{
				fail.Send(user, &cmd, "INVALID_TARGET", sub, target, "Messages could not be retrieved");
				return CmdResult::FAILURE;
			}
			list = GetChannelHistory(chan, false);
			display = chan->name;
		}
		else
		{
			if (!savepms)
			{
				fail.Send(user, &cmd, "INVALID_TARGET", sub, target, "Messages could not be retrieved");
				return CmdResult::FAILURE;
			}
			User* peer = ServerInstance->Users.FindNick(target);
			if (!peer)
			{
				fail.Send(user, &cmd, "INVALID_TARGET", sub, target, "Messages could not be retrieved");
				return CmdResult::FAILURE;
			}
			auto it = pmhist.find(PMKey(user, peer));
			if (it != pmhist.end())
				list = &it->second;
			display = peer->nick;
		}

		HistoryList empty;
		if (!list)
			list = &empty;
		else
			Prune(*list);

		bool star1 = false;
		bool ts1 = false;
		bool mid1 = false;
		time_t t1 = 0;
		long m1 = 0;
		std::string id1;
		if (!ParseSelector(sel1, star1, ts1, mid1, t1, m1, id1))
		{
			fail.Send(user, &cmd, "INVALID_PARAMS", sub, sel1, "Invalid timestamp or msgid");
			return CmdResult::FAILURE;
		}

		std::vector<const HistoryItem*> items;
		const bool want_events = eventcap.IsEnabled(user);

		if (sub == "LATEST")
		{
			if (star1)
				CollectLatest(*list, limit, 0, 0, false, want_events, items);
			else if (ts1)
				CollectLatest(*list, limit, t1, m1, true, want_events, items);
			else
			{
				size_t idx = 0;
				if (!FindByMsgid(*list, id1, idx))
				{
					SendBatch(user, display, items);
					return CmdResult::SUCCESS;
				}
				CollectLatest(*list, limit, list->lines[idx].ts, list->lines[idx].ms, true, want_events, items);
			}
		}
		else if (sub == "BEFORE")
		{
			if (star1)
			{
				fail.Send(user, &cmd, "INVALID_PARAMS", sub, sel1, "BEFORE requires timestamp or msgid");
				return CmdResult::FAILURE;
			}
			if (ts1)
				CollectBefore(*list, limit, t1, m1, want_events, items);
			else
			{
				size_t idx = 0;
				if (!FindByMsgid(*list, id1, idx))
				{
					SendBatch(user, display, items);
					return CmdResult::SUCCESS;
				}
				CollectBefore(*list, limit, list->lines[idx].ts, list->lines[idx].ms, want_events, items);
			}
		}
		else if (sub == "AFTER")
		{
			if (star1)
			{
				fail.Send(user, &cmd, "INVALID_PARAMS", sub, sel1, "AFTER requires timestamp or msgid");
				return CmdResult::FAILURE;
			}
			if (ts1)
				CollectAfter(*list, limit, t1, m1, want_events, items);
			else
			{
				size_t idx = 0;
				if (!FindByMsgid(*list, id1, idx))
				{
					SendBatch(user, display, items);
					return CmdResult::SUCCESS;
				}
				CollectAfter(*list, limit, list->lines[idx].ts, list->lines[idx].ms, want_events, items);
			}
		}
		else if (sub == "AROUND")
		{
			if (star1)
			{
				fail.Send(user, &cmd, "INVALID_PARAMS", sub, sel1, "AROUND requires timestamp or msgid");
				return CmdResult::FAILURE;
			}
			time_t cts = t1;
			long cms = m1;
			if (mid1)
			{
				size_t idx = 0;
				if (!FindByMsgid(*list, id1, idx))
				{
					SendBatch(user, display, items);
					return CmdResult::SUCCESS;
				}
				cts = list->lines[idx].ts;
				cms = list->lines[idx].ms;
			}
			const size_t before_n = limit / 2;
			const size_t after_n = limit - before_n;
			std::vector<const HistoryItem*> before;
			std::vector<const HistoryItem*> after;
			CollectBefore(*list, before_n, cts, cms, want_events, before);
			CollectAfter(*list, after_n, cts, cms, want_events, after);
			items = before;
			for (const auto& item : list->lines)
			{
				if (!IncludeHistoryItem(item, want_events))
					continue;
				if (item.ts == cts && item.ms == cms)
				{
					items.push_back(&item);
					break;
				}
			}
			items.insert(items.end(), after.begin(), after.end());
		}
		else if (sub == "BETWEEN")
		{
			bool star2 = false;
			bool ts2 = false;
			bool mid2 = false;
			time_t t2 = 0;
			long m2 = 0;
			std::string id2;
			if (!ParseSelector(sel2, star2, ts2, mid2, t2, m2, id2) || star2)
			{
				fail.Send(user, &cmd, "INVALID_PARAMS", sub, sel2, "Invalid second selector");
				return CmdResult::FAILURE;
			}
			if (mid1)
			{
				size_t idx = 0;
				if (!FindByMsgid(*list, id1, idx))
				{
					SendBatch(user, display, items);
					return CmdResult::SUCCESS;
				}
				t1 = list->lines[idx].ts;
				m1 = list->lines[idx].ms;
			}
			if (mid2)
			{
				size_t idx = 0;
				if (!FindByMsgid(*list, id2, idx))
				{
					SendBatch(user, display, items);
					return CmdResult::SUCCESS;
				}
				t2 = list->lines[idx].ts;
				m2 = list->lines[idx].ms;
			}
			const bool forward = (t1 < t2) || (t1 == t2 && m1 <= m2);
			if (forward)
			{
				for (const auto& item : list->lines)
				{
					if (!IncludeHistoryItem(item, want_events))
						continue;
					if (!item.LaterThan(t1, m1))
						continue;
					if (!item.EarlierThan(t2, m2))
						break;
					items.push_back(&item);
					if (items.size() >= limit)
						break;
				}
			}
			else
			{
				for (auto it = list->lines.rbegin(); it != list->lines.rend() && items.size() < limit; ++it)
				{
					if (!IncludeHistoryItem(*it, want_events))
						continue;
					if (!it->EarlierThan(t1, m1))
						continue;
					if (!it->LaterThan(t2, m2))
						break;
					items.push_back(&(*it));
				}
				std::reverse(items.begin(), items.end());
			}
		}
		else
		{
			fail.Send(user, &cmd, "INVALID_PARAMS", sub, "Unknown command");
			return CmdResult::FAILURE;
		}

		SendBatch(user, display, items);
		return CmdResult::SUCCESS;
	}

	bool CanClearChannel(LocalUser* user, Channel* chan) const
	{
		if (user->HasPrivPermission("channels/clear-chathistory"))
			return true;
		if (!chan->HasUser(user))
			return false;
		return chan->GetPrefixValue(user) >= clearminrank;
	}

	bool CanClearPM(LocalUser* user, User* peer) const
	{
		if (user->HasPrivPermission("users/clear-chathistory"))
			return true;
		if (!allowselfpmclear)
			return false;
		return peer != nullptr;
	}

	size_t ClearAllPMForNick(const std::string& nick)
	{
		std::string needle = nick;
		for (auto& c : needle)
			c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
		size_t n = 0;
		for (auto it = pmhist.begin(); it != pmhist.end(); )
		{
			const size_t nul = it->first.find('\0');
			const std::string a = it->first.substr(0, nul);
			const std::string b = (nul == std::string::npos) ? std::string() : it->first.substr(nul + 1);
			if (a == needle || b == needle)
			{
				n += it->second.lines.size();
				it = pmhist.erase(it);
			}
			else
				++it;
		}
		return n;
	}

	CmdResult HandleClear(LocalUser* user, const std::string& target)
	{
		if (ServerInstance->Channels.IsChannel(target))
		{
			Channel* chan = ServerInstance->Channels.Find(target);
			if (!chan)
			{
				fail.Send(user, &cmd, "INVALID_TARGET", "CLEAR", target, "No such channel");
				return CmdResult::FAILURE;
			}
			if (!CanClearChannel(user, chan))
			{
				if (user->IsOper())
					user->WriteNumeric(ERR_NOPRIVILEGES, "Permission Denied - You need channels/clear-chathistory or sufficient channel rank");
				else
					user->WriteNumeric(ERR_CHANOPRIVSNEEDED, chan->name, "You're not channel operator");
				return CmdResult::FAILURE;
			}
			HistoryList* list = GetChannelHistory(chan, false);
			const size_t n = list ? list->lines.size() : 0;
			if (list)
				list->lines.clear();
			user->WriteNotice("*** Cleared {} history entr{} for {}", n, n == 1 ? "y" : "ies", chan->name);
			ServerInstance->SNO.WriteGlobalSno('a', "{} cleared chathistory for {} ({} entries)",
				user->nick, chan->name, n);
			return CmdResult::SUCCESS;
		}

		if (!savepms)
		{
			fail.Send(user, &cmd, "INVALID_TARGET", "CLEAR", target, "Private message history is disabled");
			return CmdResult::FAILURE;
		}

		User* peer = ServerInstance->Users.FindNick(target);
		if (!peer)
		{
			if (!user->HasPrivPermission("users/clear-chathistory"))
			{
				fail.Send(user, &cmd, "INVALID_TARGET", "CLEAR", target, "No such nick");
				return CmdResult::FAILURE;
			}
			const size_t n = ClearAllPMForNick(target);
			user->WriteNotice("*** Cleared {} PM history entr{} involving {}", n, n == 1 ? "y" : "ies", target);
			ServerInstance->SNO.WriteGlobalSno('a', "{} cleared all PM chathistory involving {} ({} entries)",
				user->nick, target, n);
			return CmdResult::SUCCESS;
		}

		if (user->HasPrivPermission("users/clear-chathistory") && !irc::equals(user->nick, peer->nick))
		{
			const size_t n = ClearAllPMForNick(peer->nick);
			user->WriteNotice("*** Cleared {} PM history entr{} involving {}", n, n == 1 ? "y" : "ies", peer->nick);
			ServerInstance->SNO.WriteGlobalSno('a', "{} cleared all PM chathistory involving {} ({} entries)",
				user->nick, peer->nick, n);
			return CmdResult::SUCCESS;
		}

		if (!CanClearPM(user, peer))
		{
			user->WriteNumeric(ERR_NOPRIVILEGES, "Permission Denied - You cannot clear this private history");
			return CmdResult::FAILURE;
		}

		const std::string key = PMKey(user, peer);
		auto it = pmhist.find(key);
		const size_t n = (it != pmhist.end()) ? it->second.lines.size() : 0;
		if (it != pmhist.end())
			pmhist.erase(it);
		user->WriteNotice("*** Cleared {} PM history entr{} with {}", n, n == 1 ? "y" : "ies", peer->nick);
		ServerInstance->SNO.WriteGlobalSno('a', "{} cleared PM chathistory with {} ({} entries)",
			user->nick, peer->nick, n);
		return CmdResult::SUCCESS;
	}

	void OnUserPostMessage(User* user, const MessageTarget& target, const MessageDetails& details) override
	{
		if (user->IsModeSet(botmode) && !savebots)
			return;

		std::string_view ctcpname;
		if (details.IsCTCP(ctcpname) && !irc::equals(ctcpname, "ACTION"))
			return;

		if (target.type == MessageTarget::TYPE_CHANNEL)
		{
			if (target.status)
				return;
			Channel* chan = target.Get<Channel>();
			HistoryList* list = GetChannelHistory(chan, true);
			list->lines.emplace_back(user, details);
			Prune(*list);
			return;
		}

		if (target.type == MessageTarget::TYPE_USER && savepms)
		{
			User* dest = target.Get<User>();
			LocalUser* local_src = IS_LOCAL(user);
			LocalUser* local_dst = IS_LOCAL(dest);
			if (!local_src && !local_dst)
				return;
			HistoryList& list = pmhist[PMKey(user, dest)];
			list.lines.emplace_back(user, details);
			Prune(list);
		}
	}

	void OnPostJoin(Membership* memb) override
	{
		StoreEvent(memb->chan, HistoryItem::Event(memb->user, "JOIN", { memb->chan->name }));
	}

	void OnUserPart(Membership* memb, std::string& partmessage, CUList& except_list) override
	{
		std::vector<std::string> params = { memb->chan->name };
		if (!partmessage.empty())
			params.push_back(partmessage);
		StoreEvent(memb->chan, HistoryItem::Event(memb->user, "PART", std::move(params)));
	}

	void OnUserKick(User* source, Membership* memb, const std::string& reason, CUList& except_list) override
	{
		std::vector<std::string> params = { memb->chan->name, memb->user->nick };
		if (!reason.empty())
			params.push_back(reason);
		StoreEvent(memb->chan, HistoryItem::Event(source, "KICK", std::move(params)));
	}

	void OnUserQuit(User* user, const std::string& message, const std::string& oper_message) override
	{
		std::vector<std::string> params;
		if (!message.empty())
			params.push_back(message);
		for (const Membership* memb : user->chans)
			StoreEvent(memb->chan, HistoryItem::Event(user, "QUIT", params));
	}

	void OnUserPostNick(User* user, const std::string& oldnick) override
	{
		const std::string oldmask = oldnick + "!" + user->GetRealUser() + "@" + user->GetDisplayedHost();
		for (const Membership* memb : user->chans)
			StoreEvent(memb->chan, HistoryItem::EventMask(oldmask, "NICK", { user->nick }));
	}

	void OnPostTopicChange(User* user, Channel* chan, const std::string& topic) override
	{
		StoreEvent(chan, HistoryItem::Event(user, "TOPIC", { chan->name, topic }));
	}

	void OnMode(User* user, User* usertarget, Channel* chantarget, const Modes::ChangeList& changelist,
		ModeParser::ModeProcessFlag processflags) override
	{
		(void)usertarget;
		(void)processflags;
		if (!chantarget || !saveevents)
			return;
		if (!saveusermodes && ChangeListIsPrefixModesOnly(changelist))
			return;

		std::string modes;
		std::vector<std::string> params = { chantarget->name };
		char output_pm = '\0';
		for (const auto& change : changelist.getlist())
		{
			const char needed_pm = change.adding ? '+' : '-';
			if (needed_pm != output_pm)
			{
				output_pm = needed_pm;
				modes.push_back(output_pm);
			}
			modes.push_back(change.mh->GetModeChar());
		}
		if (modes.empty())
			return;
		params.push_back(modes);
		for (const auto& change : changelist.getlist())
		{
			if (!change.param.empty())
				params.push_back(change.param);
		}
		StoreEvent(chantarget, HistoryItem::Event(user, "MODE", std::move(params)));
	}
};

CommandChatHistory::CommandChatHistory(Module* Creator, ModuleIRCv3ChatHistory& Mod, IRCv3::Replies::Fail& Fail)
	: SplitCommand(Creator, "CHATHISTORY", 2)
	, mod(Mod)
	, fail(Fail)
{
}

CmdResult CommandChatHistory::HandleLocal(LocalUser* user, const Params& parameters)
{
	std::string sub = parameters[0];
	for (auto& c : sub)
		c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));

	// CLEAR does not require the client capability (channel ops / opers).
	if (sub == "CLEAR")
	{
		if (parameters.size() < 2)
		{
			fail.Send(user, this, "INVALID_PARAMS", sub, "Insufficient parameters");
			return CmdResult::FAILURE;
		}
		return mod.HandleClear(user, parameters[1]);
	}

	if (!mod.cap.IsEnabled(user))
	{
		fail.Send(user, this, "INVALID_CAP", "draft/chathistory",
			"You must request draft/chathistory to use this command");
		return CmdResult::FAILURE;
	}

	if (sub == "TARGETS")
	{
		fail.Send(user, this, "INVALID_PARAMS", sub, "TARGETS is not supported yet");
		return CmdResult::FAILURE;
	}

	if (parameters.size() < 4)
	{
		fail.Send(user, this, "INVALID_PARAMS", sub, "Insufficient parameters");
		return CmdResult::FAILURE;
	}

	const std::string& target = parameters[1];
	size_t limit = 0;
	std::string sel1;
	std::string sel2;

	if (sub == "BETWEEN")
	{
		if (parameters.size() < 5)
		{
			fail.Send(user, this, "INVALID_PARAMS", sub, "Insufficient parameters");
			return CmdResult::FAILURE;
		}
		sel1 = parameters[2];
		sel2 = parameters[3];
		limit = ConvToNum<size_t>(parameters[4]);
	}
	else
	{
		sel1 = parameters[2];
		limit = ConvToNum<size_t>(parameters[3]);
	}

	if (limit == 0)
	{
		fail.Send(user, this, "INVALID_PARAMS", sub, "Invalid limit");
		return CmdResult::FAILURE;
	}
	if (limit > mod.maxquery)
		limit = mod.maxquery;

	return mod.Query(user, sub, target, sel1, sel2, limit);
}

MODULE_INIT(ModuleIRCv3ChatHistory)

/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 * Provides IRCv3 draft/read-marker (MARKREAD). Compatible with Orbit.
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
/// $ModConfig: <ircv3readmarker persistfile="ircv3-readmarker.db" requireaccount="yes" saveperiod="30s">
/// $ModDesc: Provides the IRCv3 draft/read-marker capability (MARKREAD).
/// $ModDepends: core 4

#include "inspircd.h"
#include "modules/account.h"
#include "modules/cap.h"
#include "modules/ircv3_replies.h"
#include "modules/ircv3_servertime.h"

#include <cctype>
#include <ctime>
#include <fstream>
#include <map>

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

struct ReadStamp final
{
	time_t ts = 0;
	long ms = 0;
	bool set = false;

	bool EarlierOrEqual(time_t ots, long oms) const
	{
		if (!set)
			return true;
		if (ts != ots)
			return ts < ots;
		return ms <= oms;
	}

	bool LaterThan(time_t ots, long oms) const
	{
		if (!set)
			return false;
		if (ts != ots)
			return ts > ots;
		return ms > oms;
	}
};

class ModuleIRCv3ReadMarker;

class CommandMarkRead final
	: public SplitCommand
{
public:
	ModuleIRCv3ReadMarker& mod;
	IRCv3::Replies::Fail& fail;

	CommandMarkRead(Module* Creator, ModuleIRCv3ReadMarker& Mod, IRCv3::Replies::Fail& Fail);

	CmdResult HandleLocal(LocalUser* user, const Params& parameters) override;
};

class ModuleIRCv3ReadMarker final
	: public Module
	, public Account::EventListener
	, public Timer
{
public:
	Account::API accountapi;
	DraftCap cap;
	IRCv3::Replies::Fail fail;
	ClientProtocol::EventProvider markev;
	CommandMarkRead cmd;

	// owner -> (target -> stamp); owner is account or nick
	std::map<std::string, std::map<std::string, ReadStamp, irc::insensitive_swo>, irc::insensitive_swo> store;
	bool dirty = false;

	bool requireaccount = true;
	std::string persistfile;
	unsigned long saveperiod = 30;

	ModuleIRCv3ReadMarker()
		: Module(VF_NONE, "Provides the IRCv3 draft/read-marker capability.")
		, Account::EventListener(this)
		, Timer(30, true)
		, accountapi(this)
		, cap(this, "draft/read-marker")
		, fail(this)
		, markev(this, "MARKREAD")
		, cmd(this, *this, fail)
	{
	}

	~ModuleIRCv3ReadMarker() override
	{
		SaveStore();
	}

	void init() override
	{
		LoadStore();
	}

	void ReadConfig(ConfigStatus& status) override
	{
		const auto& tag = ServerInstance->Config->ConfValue("ircv3readmarker");
		requireaccount = tag->getBool("requireaccount", true);
		persistfile = ServerInstance->Config->Paths.PrependData(tag->getString("persistfile", "ircv3-readmarker.db", 1));
		saveperiod = tag->getDuration("saveperiod", 30, 5, 3600);
		SetInterval(saveperiod, true);
	}

	bool Tick() override
	{
		if (dirty)
			SaveStore();
		return true;
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

	void SendMark(LocalUser* user, const std::string& target, const ReadStamp& stamp)
	{
		ClientProtocol::Message msg("MARKREAD", ServerInstance->Config->GetServerName());
		msg.PushParam(target);
		if (!stamp.set)
			msg.PushParam("*");
		else
			msg.PushParam("timestamp=" + IRCv3::ServerTime::FormatTime(stamp.ts, stamp.ms));
		ClientProtocol::Event ev(markev, msg);
		user->Send(ev);
	}

	void BroadcastMark(const std::string& owner, const std::string& target, const ReadStamp& stamp)
	{
		for (auto* u : ServerInstance->Users.GetLocalUsers())
		{
			if (!cap.IsEnabled(u))
				continue;
			if (!irc::equals(OwnerKey(u), owner))
				continue;
			SendMark(u, target, stamp);
		}
	}

	CmdResult HandleGet(LocalUser* user, const std::string& target)
	{
		const std::string owner = OwnerKey(user);
		ReadStamp stamp;
		auto oit = store.find(owner);
		if (oit != store.end())
		{
			auto tit = oit->second.find(target);
			if (tit != oit->second.end())
				stamp = tit->second;
		}
		SendMark(user, target, stamp);
		return CmdResult::SUCCESS;
	}

	CmdResult HandleSet(LocalUser* user, const std::string& target, time_t ts, long ms)
	{
		if (requireaccount && (!accountapi || !accountapi->GetAccountName(user)))
		{
			fail.Send(user, &cmd, "INTERNAL_ERROR", target, "You must be logged in to set read markers");
			return CmdResult::FAILURE;
		}

		const std::string owner = OwnerKey(user);
		ReadStamp& cur = store[owner][target];
		if (cur.set && (cur.ts > ts || (cur.ts == ts && cur.ms >= ms)))
		{
			// Client sent older or equal — reply with stored value.
			SendMark(user, target, cur);
			return CmdResult::SUCCESS;
		}

		// Clamp to now
		const time_t now = ServerInstance->Time();
		if (ts > now)
		{
			ts = now;
			ms = 0;
		}

		cur.ts = ts;
		cur.ms = ms;
		cur.set = true;
		dirty = true;
		BroadcastMark(owner, target, cur);
		return CmdResult::SUCCESS;
	}

	void OnPostJoin(Membership* memb) override
	{
		LocalUser* user = IS_LOCAL(memb->user);
		if (!user || !cap.IsEnabled(user))
			return;

		const std::string owner = OwnerKey(user);
		ReadStamp stamp;
		auto oit = store.find(owner);
		if (oit != store.end())
		{
			auto tit = oit->second.find(memb->chan->name);
			if (tit != oit->second.end())
				stamp = tit->second;
		}
		SendMark(user, memb->chan->name, stamp);
	}

	void OnAccountChange(User* user, const std::string& account) override
	{
		if (account.empty())
			return;
		auto nickit = store.find(user->nick);
		if (nickit == store.end())
			return;
		auto& acctmap = store[account];
		if (acctmap.empty())
		{
			acctmap = std::move(nickit->second);
			store.erase(nickit);
			dirty = true;
		}
	}

	void LoadStore()
	{
		store.clear();
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
			// target\tts\tms
			const auto p1 = line.find('\t');
			if (p1 == std::string::npos)
				continue;
			const auto p2 = line.find('\t', p1 + 1);
			if (p2 == std::string::npos)
				continue;
			ReadStamp st;
			st.ts = ConvToNum<time_t>(line.substr(p1 + 1, p2 - p1 - 1));
			st.ms = ConvToNum<long>(line.substr(p2 + 1));
			st.set = true;
			store[owner][line.substr(0, p1)] = st;
		}
	}

	void SaveStore()
	{
		std::ofstream out(persistfile.c_str(), std::ios::trunc);
		if (!out)
			return;
		out << "# m_ircv3_read_marker v1\n";
		for (const auto& [owner, targets] : store)
		{
			out << '@' << owner << '\n';
			for (const auto& [target, st] : targets)
			{
				if (!st.set)
					continue;
				out << target << '\t' << st.ts << '\t' << st.ms << '\n';
			}
		}
		dirty = false;
	}

	void Prioritize() override
	{
		// After JOIN / before ENDOFNAMES as far as module hooks allow.
		ServerInstance->Modules.SetPriority(this, I_OnPostJoin, PRIORITY_LAST);
	}
};

CommandMarkRead::CommandMarkRead(Module* Creator, ModuleIRCv3ReadMarker& Mod, IRCv3::Replies::Fail& Fail)
	: SplitCommand(Creator, "MARKREAD", 1)
	, mod(Mod)
	, fail(Fail)
{
}

CmdResult CommandMarkRead::HandleLocal(LocalUser* user, const Params& parameters)
{
	if (!mod.cap.IsEnabled(user))
	{
		fail.Send(user, this, "INVALID_CAP", "draft/read-marker",
			"You must request draft/read-marker to use this command");
		return CmdResult::FAILURE;
	}

	if (parameters.empty())
	{
		fail.Send(user, this, "NEED_MORE_PARAMS", "Missing parameters");
		return CmdResult::FAILURE;
	}

	const std::string& target = parameters[0];
	if (parameters.size() == 1)
		return mod.HandleGet(user, target);

	const std::string& arg = parameters[1];
	if (arg == "*")
	{
		// Get-style unset reply only from server; clients must not set *.
		fail.Send(user, this, "INVALID_PARAMS", arg, "Invalid parameters");
		return CmdResult::FAILURE;
	}
	if (arg.compare(0, 10, "timestamp=") != 0)
	{
		fail.Send(user, this, "INVALID_PARAMS", arg, "Invalid parameters");
		return CmdResult::FAILURE;
	}

	time_t ts = 0;
	long ms = 0;
	if (!ParseISOTime(arg.substr(10), ts, ms))
	{
		fail.Send(user, this, "INVALID_PARAMS", arg, "Invalid parameters");
		return CmdResult::FAILURE;
	}
	return mod.HandleSet(user, target, ts, ms);
}

MODULE_INIT(ModuleIRCv3ReadMarker)

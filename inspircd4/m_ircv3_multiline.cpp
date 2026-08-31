/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 * Provides IRCv3 draft/multiline (client BATCH + PRIVMSG/NOTICE lines).
 * Compatible with Orbit: BATCH draft/multiline, draft/multiline-concat.
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
/// $ModConfig: <ircv3multiline maxlines="20" maxbytes="40000" batchtimeout="30s" maxbatchesperminute="10">
/// $ModDesc: Provides the IRCv3 draft/multiline capability (client batches).
/// $ModDepends: core 4

#include "inspircd.h"
#include "clientprotocolmsg.h"
#include "numerichelper.h"
#include "modules/account.h"
#include "modules/cap.h"
#include "modules/ircv3_batch.h"
#include "modules/ircv3_replies.h"
#include "modules/ircv3_servertime.h"

#include <cctype>
#include <deque>

static constexpr const char* BATCH_TYPE = "draft/multiline";
static constexpr const char* CONCAT_TAG = "draft/multiline-concat";

struct MultilineLine final
{
	std::string text;
	bool concat = false;
	ClientProtocol::TagMap tags;
};

struct MultilineBatchState final
{
	bool active = false;
	std::string ref;
	std::string target;
	MessageType cmd = MessageType::PRIVMSG;
	bool cmd_set = false;
	std::vector<MultilineLine> lines;
	size_t content_bytes = 0;
	ClientProtocol::TagMap batch_tags;
	std::string label;

	void Reset()
	{
		active = false;
		ref.clear();
		target.clear();
		cmd = MessageType::PRIVMSG;
		cmd_set = false;
		lines.clear();
		content_bytes = 0;
		batch_tags.clear();
		label.clear();
	}
};

struct MultilineUserExt final
{
	MultilineBatchState batch;
	time_t batch_opened = 0;
	std::deque<time_t> completions;

	void ResetBatch()
	{
		batch.Reset();
		batch_opened = 0;
	}
};

class MultilineMessageDetails final
	: public MessageDetails
{
public:
	MultilineMessageDetails(MessageType mt, const std::string& msg, const ClientProtocol::TagMap& tags)
		: MessageDetails(mt, msg, tags)
	{
	}

	bool IsCTCP(std::string_view& name, std::string_view& body) const override
	{
		name = body = std::string_view();
		return false;
	}

	bool IsCTCP(std::string_view& name) const override
	{
		name = std::string_view();
		return false;
	}

	bool IsCTCP() const override
	{
		return false;
	}
};

class MultilineCap final
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
	MultilineCap(Module* mod)
		: Cap::Capability(mod, "draft/multiline")
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

class ConcatTag final
	: public ClientProtocol::MessageTagProvider
{
public:
	ConcatTag(Module* mod)
		: ClientProtocol::MessageTagProvider(mod)
	{
	}

	ModResult OnProcessTag(User* user, const std::string& tagname, std::string& tagvalue) override
	{
		if (irc::equals(tagname, CONCAT_TAG))
			return MOD_RES_ALLOW;
		return MOD_RES_PASSTHRU;
	}

	bool ShouldSendTag(LocalUser* user, const ClientProtocol::MessageTagData& tagdata) override
	{
		return irc::equals(tagdata.key, CONCAT_TAG);
	}
};

class EchoTagRef final
	: public ClientProtocol::MessageTagProvider
{
public:
	Cap::Capability echocap;

	EchoTagRef(Module* mod)
		: ClientProtocol::MessageTagProvider(mod)
		, echocap(mod, "echo-message")
	{
	}

	bool ShouldSendTag(LocalUser* user, const ClientProtocol::MessageTagData& tagdata) override
	{
		return echocap.IsEnabled(user) && irc::equals(tagdata.key, "inspircd.org/echo");
	}
};

class ModuleIRCv3Multiline;

class CommandBatch final
	: public SplitCommand
{
public:
	ModuleIRCv3Multiline& mod;

	CommandBatch(Module* Creator, ModuleIRCv3Multiline& Mod);

	CmdResult HandleLocal(LocalUser* user, const Params& parameters) override;
};

class ModuleIRCv3Multiline final
	: public Module
	, public Timer
{
public:
	MultilineCap cap;
	ConcatTag concat_tag;
	EchoTagRef echo_tag;
	IRCv3::Replies::Fail fail;
	IRCv3::Batch::API batchmanager;
	IRCv3::Batch::CapReference batchcap;
	IRCv3::ServerTime::API servertimemanager;
	Account::API accountapi;
	Cap::Capability echomsgcap;
	CommandBatch batchcmd;
	SimpleExtItem<MultilineUserExt> userext;
	ChanModeReference moderatedmode;
	ChanModeReference noextmsgmode;

	ClientProtocol::EventProvider batchev;
	ClientProtocol::EventProvider msgprov;

	size_t maxlines = 20;
	size_t maxbytes = 40000;
	unsigned long batchtimeout = 30;
	size_t maxbatchesperminute = 10;
	uint64_t msgid_counter = 0;

	ModuleIRCv3Multiline()
		: Module(VF_NONE, "Provides the IRCv3 draft/multiline capability.")
		, Timer(5, true)
		, cap(this)
		, concat_tag(this)
		, echo_tag(this)
		, fail(this)
		, batchmanager(this)
		, batchcap(this)
		, servertimemanager(this)
		, accountapi(this)
		, echomsgcap(this, "echo-message")
		, batchcmd(this, *this)
		, userext(this, "ircv3-multiline", ExtensionType::USER, false)
		, moderatedmode(this, "moderated")
		, noextmsgmode(this, "noextmsg")
		, batchev(this, "BATCH")
		, msgprov(this, "MULTILINE")
	{
	}

	void ReadConfig(ConfigStatus& status) override
	{
		const auto& tag = ServerInstance->Config->ConfValue("ircv3multiline");
		maxlines = tag->getNum<size_t>("maxlines", 20, 1, 500);
		maxbytes = tag->getNum<size_t>("maxbytes", 40000, 256, 1000000);
		batchtimeout = tag->getDuration("batchtimeout", 30, 5, 300);
		maxbatchesperminute = tag->getNum<size_t>("maxbatchesperminute", 10, 0, 120);
		cap.SetValueString(INSP_FORMAT("max-bytes={},max-lines={}", maxbytes, maxlines));
	}

	bool Tick() override
	{
		if (!batchtimeout)
			return true;

		const time_t now = ServerInstance->Time();
		for (auto* user : ServerInstance->Users.GetLocalUsers())
		{
			MultilineUserExt& data = userext.GetRef(user);
			if (!data.batch.active || !data.batch_opened)
				continue;
			if (static_cast<unsigned long>(now - data.batch_opened) > batchtimeout)
				AbortBatch(user, data, "MULTILINE_INVALID", data.batch.target, "Multiline batch timed out");
		}
		return true;
	}

	void PruneCompletions(MultilineUserExt& data) const
	{
		const time_t cutoff = ServerInstance->Time() - 60;
		while (!data.completions.empty() && data.completions.front() < cutoff)
			data.completions.pop_front();
	}

	bool RateLimitExceeded(MultilineUserExt& data) const
	{
		if (!maxbatchesperminute)
			return false;
		PruneCompletions(data);
		return data.completions.size() >= maxbatchesperminute;
	}

	void RecordCompletion(MultilineUserExt& data)
	{
		if (!maxbatchesperminute)
			return;
		data.completions.push_back(ServerInstance->Time());
		PruneCompletions(data);
	}

	bool BatchTimedOut(const MultilineUserExt& data) const
	{
		if (!batchtimeout || !data.batch.active || !data.batch_opened)
			return false;
		return static_cast<unsigned long>(ServerInstance->Time() - data.batch_opened) > batchtimeout;
	}

	void init() override
	{
		if (!ServerInstance->Modules.Find("ircv3_batch"))
		{
			ServerInstance->Logs.Normal(MODNAME, "WARNING: ircv3_batch is not loaded! "
				"Orbit requires batch + draft/multiline.");
		}
	}

	static bool ValidRef(const std::string& ref)
	{
		if (ref.empty())
			return false;
		for (char c : ref)
		{
			if (std::isalnum(static_cast<unsigned char>(c)) || c == '-')
				continue;
			return false;
		}
		return true;
	}

	static std::string MergeLines(const std::vector<MultilineLine>& lines)
	{
		std::string out;
		for (const MultilineLine& line : lines)
		{
			if (!out.empty() && !line.concat)
				out.push_back('\n');
			out.append(line.text);
		}
		return out;
	}

	std::string NextMsgId()
	{
		return INSP_FORMAT("{}~{}~{}", ServerInstance->Config->ServerId, ServerInstance->startup_time, msgid_counter++);
	}

	void FailBatch(LocalUser* user, const std::string& code, const std::string& context, const std::string& desc)
	{
		fail.Send(user, &batchcmd, code, context, desc);
	}

	void AbortBatch(LocalUser* user, MultilineUserExt& data, const std::string& code,
		const std::string& context, const std::string& desc)
	{
		FailBatch(user, code, context, desc);
		data.ResetBatch();
	}

	bool ChannelMaySend(User* user, Channel* chan, std::string& err) const
	{
		if (chan->IsModeSet(noextmsgmode) && !chan->HasUser(user))
		{
			err = "external messages";
			return false;
		}
		const bool no_chan_priv = chan->GetPrefixValue(user) < VOICE_VALUE;
		if (no_chan_priv && chan->IsModeSet(moderatedmode))
		{
			err = "messages";
			return false;
		}
		if (no_chan_priv && ServerInstance->Config->RestrictBannedUsers != ServerConfig::BUT_NORMAL && chan->IsBanned(user))
			return false;
		return true;
	}

	bool AllowedLineTag(const std::string& key) const
	{
		if (irc::equals(key, "batch") || irc::equals(key, CONCAT_TAG))
			return true;
		if (key == "+draft/channel-context" || key == "+channel-context")
			return true;
		if (key == "+draft/reply" || key == "+reply")
			return true;
		return false;
	}

	bool CollectLine(LocalUser* user, User* source, MessageTarget& target, MessageDetails& details,
		MultilineUserExt& data)
	{
		MultilineBatchState& state = data.batch;
		if (BatchTimedOut(data))
		{
			AbortBatch(user, data, "MULTILINE_INVALID", state.target, "Multiline batch timed out");
			return false;
		}

		std::string_view ctcp;
		if (details.IsCTCP(ctcp))
		{
			AbortBatch(user, data, "MULTILINE_INVALID", state.target, "Invalid multiline batch");
			return false;
		}

		if (!state.cmd_set)
		{
			state.cmd = details.type;
			state.cmd_set = true;
		}
		else if (state.cmd != details.type)
		{
			AbortBatch(user, data, "MULTILINE_INVALID", state.target, "Invalid multiline batch");
			return false;
		}

		if (!irc::equals(target.GetName(), state.target))
		{
			AbortBatch(user, data, "MULTILINE_INVALID_TARGET", state.target, "Invalid multiline target");
			return false;
		}

		for (const auto& [key, _] : details.tags_in)
		{
			if (!AllowedLineTag(key))
			{
				AbortBatch(user, data, "MULTILINE_INVALID", state.target, "Invalid multiline batch");
				return false;
			}
		}

		const bool concat = details.tags_in.find(CONCAT_TAG) != details.tags_in.end();
		if (concat && details.text.empty())
		{
			AbortBatch(user, data, "MULTILINE_INVALID", state.target, "Invalid multiline batch with concatenated blank line");
			return false;
		}

		if (target.type == MessageTarget::TYPE_CHANNEL)
		{
			std::string err;
			if (!ChannelMaySend(source, target.Get<Channel>(), err))
			{
				if (!err.empty())
					source->WriteNumeric(Numerics::CannotSendTo(target.Get<Channel>(), err, *moderatedmode));
				data.ResetBatch();
				return false;
			}
		}

		size_t add_bytes = details.text.size();
		if (!state.lines.empty() && !concat)
			++add_bytes;
		if (state.lines.size() >= maxlines || state.content_bytes + add_bytes > maxbytes)
		{
			if (state.lines.size() >= maxlines)
				AbortBatch(user, data, "MULTILINE_MAX_LINES", ConvToStr(maxlines), "Multiline batch max-lines exceeded");
			else
				AbortBatch(user, data, "MULTILINE_MAX_BYTES", ConvToStr(maxbytes), "Multiline batch max-bytes exceeded");
			return false;
		}

		MultilineLine line;
		line.text = details.text;
		line.concat = concat;
		line.tags = details.tags_in;
		state.lines.push_back(std::move(line));
		state.content_bytes += add_bytes;
		return true;
	}

	void AddCommonTags(ClientProtocol::Message& msg, const std::string& msgid, User* source) const
	{
		if (!msgid.empty())
			msg.AddTag("msgid", &concat_tag, msgid);
		if (accountapi)
		{
			const std::string* acct = accountapi->GetAccountName(source);
			if (acct && !acct->empty())
				msg.AddTag("account", &concat_tag, *acct);
		}
		if (servertimemanager)
			servertimemanager->Set(msg, ServerInstance->Time(), 0);
	}

	static std::string PMContext(const MultilineBatchState& state)
	{
		for (const MultilineLine& line : state.lines)
		{
			auto it = line.tags.find("+draft/channel-context");
			if (it == line.tags.end())
				it = line.tags.find("+channel-context");
			if (it != line.tags.end() && !it->second.value.empty())
				return it->second.value;
		}
		return {};
	}

	void SendFallback(LocalUser* dest, User* source, const std::string& targetname, MessageType type,
		char status, const MultilineBatchState& state, const std::string& msgid, bool echo) const
	{
		bool msgid_sent = false;
		for (const MultilineLine& line : state.lines)
		{
			if (line.text.empty())
				continue;

			ClientProtocol::Messages::Privmsg msg(ClientProtocol::Messages::Privmsg::nocopy,
				source, targetname, line.text, type, status);
			if (!msgid_sent)
			{
				if (!msgid.empty())
					msg.AddTag("msgid", &concat_tag, msgid);
				msgid_sent = true;
			}
			if (echo)
				msg.AddTag("inspircd.org/echo", &echo_tag, "");
			dest->Send(ServerInstance->GetRFCEvents().privmsg, msg);
		}
	}

	void SendBatch(LocalUser* dest, User* source, const std::string& targetname, MessageType type,
		char status, const MultilineBatchState& state, const std::string& msgid, bool echo)
	{
		IRCv3::Batch::Batch batch(BATCH_TYPE);
		if (!batchmanager || !batchcap.IsEnabled(dest))
		{
			SendFallback(dest, source, targetname, type, status, state, msgid, echo);
			return;
		}

		batchmanager->Start(batch);
		ClientProtocol::Message& start = batch.GetBatchStartMessage();
		start.PushParam(state.target);
		AddCommonTags(start, msgid, source);
		if (!state.label.empty())
			start.AddTag("label", &concat_tag, state.label);

		for (const MultilineLine& line : state.lines)
		{
			ClientProtocol::Messages::Privmsg msg(ClientProtocol::Messages::Privmsg::nocopy,
				source, targetname, line.text, type, status);
			if (line.concat)
				msg.AddTag(CONCAT_TAG, &concat_tag, "");
			if (echo)
				msg.AddTag("inspircd.org/echo", &echo_tag, "");
			batch.AddToBatch(msg);
			dest->Send(msgprov, msg);
		}

		batchmanager->End(batch);
	}

	void Deliver(User* source, const MultilineBatchState& state)
	{
		const std::string merged = MergeLines(state.lines);
		const std::string msgid = NextMsgId();
		ClientProtocol::TagMap tags_out;
		tags_out.emplace("msgid", ClientProtocol::MessageTagData(&concat_tag, msgid));

		LocalUser* lsource = IS_LOCAL(source);
		const bool echo = lsource && echomsgcap.IsEnabled(lsource);
		const std::string pmctx = PMContext(state);

		if (ServerInstance->Channels.IsPrefix(state.target[0]) || ServerInstance->Channels.IsChannel(state.target))
		{
			Channel* chan = ServerInstance->Channels.Find(state.target);
			if (!chan)
				return;

			CUList except;
			except.insert(source);
			for (const auto& [member, _] : chan->GetUsers())
			{
				LocalUser* dest = IS_LOCAL(member);
				if (!dest || except.count(member))
					continue;
				SendBatch(dest, source, chan->name, state.cmd, 0, state, msgid, false);
			}

			if (echo)
				SendBatch(lsource, source, chan->name, state.cmd, 0, state, msgid, true);

			MessageTarget msgtarget(chan, 0);
			MultilineMessageDetails postdetails(state.cmd, merged, tags_out);
			if (lsource)
				lsource->idle_lastmsg = ServerInstance->Time();
			FOREACH_MOD(OnUserPostMessage, (source, msgtarget, postdetails));
			return;
		}

		User* destuser = ServerInstance->Users.FindNick(state.target, true);
		if (!destuser)
			return;

		const std::string display = pmctx.empty() ? destuser->nick : pmctx;
		LocalUser* ldest = IS_LOCAL(destuser);
		if (ldest)
			SendBatch(ldest, source, display, state.cmd, 0, state, msgid, false);

		if (echo)
			SendBatch(lsource, source, display, state.cmd, 0, state, msgid, true);

		MessageTarget msgtarget(destuser);
		MultilineMessageDetails postdetails(state.cmd, merged, tags_out);
		if (lsource)
			lsource->idle_lastmsg = ServerInstance->Time();
		FOREACH_MOD(OnUserPostMessage, (source, msgtarget, postdetails));
	}

	bool ValidBatch(const MultilineBatchState& state) const
	{
		if (state.lines.empty())
			return false;

		bool any_nonblank = false;
		for (const MultilineLine& line : state.lines)
		{
			if (!line.text.empty())
				any_nonblank = true;
		}
		return any_nonblank;
	}

	CmdResult EndBatch(LocalUser* user, MultilineUserExt& data, const std::string& ref)
	{
		MultilineBatchState& state = data.batch;
		if (!state.active || state.ref != ref)
		{
			FailBatch(user, "MULTILINE_INVALID", ref, "Invalid multiline batch");
			data.ResetBatch();
			return CmdResult::FAILURE;
		}

		if (BatchTimedOut(data))
		{
			AbortBatch(user, data, "MULTILINE_INVALID", state.target, "Multiline batch timed out");
			return CmdResult::FAILURE;
		}

		if (!ValidBatch(state))
		{
			AbortBatch(user, data, "MULTILINE_INVALID", state.target, "Invalid multiline batch with blank lines only");
			return CmdResult::FAILURE;
		}

		Deliver(user, state);
		RecordCompletion(data);
		data.ResetBatch();
		return CmdResult::SUCCESS;
	}

	CmdResult StartBatch(LocalUser* user, const std::string& ref, const std::string& type,
		const std::string& target, const ClientProtocol::TagMap& tags)
	{
		if (!cap.IsEnabled(user))
		{
			FailBatch(user, "MULTILINE_INVALID", ref, "Invalid multiline batch");
			return CmdResult::FAILURE;
		}

		if (!batchcap.IsEnabled(user))
		{
			FailBatch(user, "MULTILINE_INVALID", ref, "batch capability required");
			return CmdResult::FAILURE;
		}

		if (!irc::equals(type, BATCH_TYPE))
		{
			FailBatch(user, "MULTILINE_INVALID", ref, "Invalid multiline batch");
			return CmdResult::FAILURE;
		}

		MultilineUserExt& data = userext.GetRef(user);
		if (data.batch.active)
		{
			FailBatch(user, "MULTILINE_INVALID", ref, "Invalid multiline batch");
			return CmdResult::FAILURE;
		}

		if (RateLimitExceeded(data))
		{
			FailBatch(user, "MULTILINE_INVALID", ref,
				INSP_FORMAT("Multiline rate limit exceeded (max {} batches per minute)", maxbatchesperminute));
			return CmdResult::FAILURE;
		}

		if (!ValidRef(ref) || target.empty())
		{
			FailBatch(user, "MULTILINE_INVALID", ref, "Invalid multiline batch");
			return CmdResult::FAILURE;
		}

		if (ServerInstance->Channels.IsPrefix(target[0]) || ServerInstance->Channels.IsChannel(target))
		{
			Channel* chan = ServerInstance->Channels.Find(target);
			if (!chan)
			{
				user->WriteNumeric(Numerics::NoSuchChannel(target));
				return CmdResult::FAILURE;
			}
			std::string err;
			if (!ChannelMaySend(user, chan, err))
			{
				if (!err.empty())
					user->WriteNumeric(Numerics::CannotSendTo(chan, err, *moderatedmode));
				return CmdResult::FAILURE;
			}
		}
		else if (!ServerInstance->Users.FindNick(target))
		{
			user->WriteNumeric(Numerics::NoSuchNick(target));
			return CmdResult::FAILURE;
		}

		data.ResetBatch();
		data.batch.active = true;
		data.batch.ref = ref;
		data.batch.target = target;
		data.batch.batch_tags = tags;
		data.batch_opened = ServerInstance->Time();
		auto labelit = tags.find("label");
		if (labelit != tags.end())
			data.batch.label = labelit->second.value;
		return CmdResult::SUCCESS;
	}

	ModResult OnUserPreMessage(User* user, MessageTarget& target, MessageDetails& details) override
	{
		LocalUser* luser = IS_LOCAL(user);
		if (!luser)
			return MOD_RES_PASSTHRU;

		MultilineUserExt& data = userext.GetRef(luser);
		if (!data.batch.active)
			return MOD_RES_PASSTHRU;

		auto bit = details.tags_in.find("batch");
		if (bit == details.tags_in.end() || bit->second.value != data.batch.ref)
			return MOD_RES_PASSTHRU;

		if (!CollectLine(luser, user, target, details, data))
			return MOD_RES_DENY;

		details.echo = false;
		return MOD_RES_DENY;
	}

	void OnUserDisconnect(LocalUser* user) override
	{
		userext.GetRef(user).ResetBatch();
	}
};

CommandBatch::CommandBatch(Module* Creator, ModuleIRCv3Multiline& Mod)
	: SplitCommand(Creator, "BATCH", 1)
	, mod(Mod)
{
}

CmdResult CommandBatch::HandleLocal(LocalUser* user, const Params& parameters)
{
	if (parameters.empty())
		return CmdResult::FAILURE;

	const std::string& token = parameters[0];
	if (token.empty())
		return CmdResult::FAILURE;

	const bool start = (token[0] == '+');
	const bool end = (token[0] == '-');
	if (!start && !end)
		return CmdResult::FAILURE;

	const std::string ref = token.substr(1);
	MultilineUserExt& data = mod.userext.GetRef(user);

	if (end)
		return mod.EndBatch(user, data, ref);

	if (parameters.size() < 3)
	{
		mod.FailBatch(user, "MULTILINE_INVALID", ref, "Invalid multiline batch");
		return CmdResult::FAILURE;
	}

	return mod.StartBatch(user, ref, parameters[1], parameters[2], parameters.GetTags());
}

MODULE_INIT(ModuleIRCv3Multiline)

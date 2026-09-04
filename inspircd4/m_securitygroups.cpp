/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   (C) 2026 reverse - mike.chevronnet@gmail.com
 *
 * Implements UnrealIRCd 6-style security-groups for InspIRCd 4.
 *
 * Configuration example:
 *
 *   <securitygroups whoispubliconly="yes">
 *
 *   <securitygroup name="webirc-users"
 *     mask="*@webirc.example.com"
 *     webirc="yes"
 *     scoremin="0"
 *     scoremax="100"
 *     public="yes">
 *
 * Matching options. All criteria in a group are AND-ed. Most have a positive
 * form (require) and a negative form. The two views of TLS and account are
 * opposites of the same fact; setting contradictory criteria is a config error.
 *
 * Positive (require) / negative (exclude):
 * - mask                 / exclude (exclude-mask): hostmask globs or CIDR.
 * - tls (tls-users)      / insecure (insecure-users), exclude-tls, exclude-insecure
 * - account (registered) / unregistered, exclude-account (exclude-registered)
 * - websocket="yes"      / websocket="no", exclude-websocket
 * - webirc (webirc-users)/ exclude-webirc
 * - bmode (bot)          / exclude-bmode (exclude-bot)
 * - oper="yes"           / oper="no", exclude-oper
 * - country=<codes>      / exclude-country=<codes>   (needs a geolocation provider)
 * - connectclass=<names> / exclude-connectclass=<names>
 * - scoremin / scoremax: reputation score range (needs the reputation module).
 *
 * Module options (<securitygroups>):
 * - whoispubliconly: when yes, /WHOIS (including self-whois and users/auspex)
 *   only lists groups with public="yes". The full list remains available via
 *   /SECURITYGROUPS for self-lookup and users/auspex.
 *
 * Exposes:
 * - user extension "securitygroups" (comma-separated list, synced across the network)
 * - /SECURITYGROUPS [nick] command
 */

/// $ModAuthor: reverse - mike.chevronnet@gmail.com
/// $ModDepends: core 4
/// $ModDesc: Implements UnrealIRCd-style security-groups for InspIRCd 4.
/// $ModConfig: <securitygroups whoispubliconly="no"> <securitygroup name="example" mask="*@example.com" account="no" unregistered="no" tls="no" insecure="no" websocket="no" webirc="no" bmode="no" public="yes">

#include "inspircd.h"
#include "extension.h"
#include "numerichelper.h"
#include "modules/account.h"
#include "modules/extban.h"
#include "modules/geolocation.h"
#include "modules/ssl.h"
#include "modules/webirc.h"
#include "modules/whois.h"

#include <deque>

// One or more hostmask globs or CIDR ranges.
typedef std::vector<std::string> MaskList;

// A set of security group names.
typedef insp::flat_set<std::string, irc::insensitive_swo> SecurityGroupList;

static std::string FormatSecurityGroupList(const SecurityGroupList* list)
{
	return (list && !list->empty()) ? insp::join(*list, ',') : "none";
}

// Tri-state for criteria that can be "don't care", "must be", or "must not be".
enum class TriState
{
	IGNORE,
	YES,
	NO,
};

// A set of names matched case-insensitively (country codes, connect classes).
typedef insp::flat_set<std::string, irc::insensitive_swo> NameSet;

// The boolean facts about a user that group criteria are checked against.
// Computed once per Matches() call so require/exclude share the same values.
struct UserFacts final
{
	bool tls = false;
	bool websocket = false;
	bool webirc = false;
	bool bot = false;
	bool oper = false;
	bool account = false;
};

struct SecurityGroup final
{
	std::string name;
	MaskList masks;          // positive: match = any one of these
	MaskList exclude_masks;  // negative: matching any one vetoes membership

	// Each boolean criterion is a TriState: IGNORE / YES (must have) / NO (must
	// not have). "require" keys set YES; "exclude-" keys set NO. tls/insecure are
	// two views of the same fact (insecure == not tls).
	TriState want_tls = TriState::IGNORE;
	TriState want_websocket = TriState::IGNORE;
	TriState want_webirc = TriState::IGNORE;
	TriState want_bot = TriState::IGNORE;
	TriState want_oper = TriState::IGNORE;
	TriState want_account = TriState::IGNORE;

	NameSet countries;              // positive: country must be in this set
	NameSet exclude_countries;      // negative: country must NOT be in this set
	NameSet connectclasses;         // positive: class must be in this set
	NameSet exclude_connectclasses; // negative: class must NOT be in this set

	int score_min = -1;
	int score_max = -1;
	bool publicgroup = false;
};

class CommandSecurityGroups final
	: public Command
{
private:
	ListExtItem<SecurityGroupList>& allgroups;
	ListExtItem<SecurityGroupList>& publicgroups;

public:
	CommandSecurityGroups(Module* Creator, ListExtItem<SecurityGroupList>& all, ListExtItem<SecurityGroupList>& pub)
		: Command(Creator, "SECURITYGROUPS", 0, 1)
		, allgroups(all)
		, publicgroups(pub)
	{
		syntax = { "[<nick>]" };
	}

	CmdResult Handle(User* user, const Params& parameters) override
	{
		User* target = user;
		bool self = true;

		if (!parameters.empty())
		{
			target = ServerInstance->Users.FindNick(parameters[0]);
			if (!target)
			{
				user->WriteNumeric(Numerics::NoSuchNick(parameters[0]));
				return CmdResult::FAILURE;
			}
			self = (target == user);
		}

		const bool canseeall = self || user->HasPrivPermission("users/auspex");
		const SecurityGroupList* list = canseeall ? allgroups.Get(target) : publicgroups.Get(target);
		user->WriteNotice(INSP_FORMAT("Security groups for {}: {}",
			target->nick, FormatSecurityGroupList(list)));
		return CmdResult::SUCCESS;
	}
};

class ModuleSecurityGroups final
	: public Module
	, public Account::EventListener
	, public WebIRC::EventListener
	, public Whois::EventListener
{
private:
	class SecurityGroupExtBan final
		: public ExtBan::MatchingBase
	{
	private:
		ListExtItem<SecurityGroupList>& sgext;

	public:
		SecurityGroupExtBan(Module* Creator, ListExtItem<SecurityGroupList>& ext)
			: ExtBan::MatchingBase(Creator, "securitygroup", 'g')
			, sgext(ext)
		{
		}

		bool IsMatch(User* user, Channel* channel, const std::string& text) override
		{
			const SecurityGroupList* list = sgext.Get(user);
			if (!list || list->empty() || text.empty())
				return false;

			for (const auto& group : *list)
			{
				if (InspIRCd::Match(group, text, ascii_case_insensitive_map))
					return true;
			}

			return false;
		}
	};

	std::vector<SecurityGroup> groups;
	bool usesreputation = false;
	bool whoispubliconly = false;

	// On rehash / reputation-unload we re-evaluate every local user. On a large
	// server doing that synchronously is a burst of CPU + extension-sync traffic
	// inside the rehash. Instead we queue the users (by UUID, so disconnected
	// users are skipped safely) and drain a bounded batch per background tick.
	std::deque<std::string> rebuildqueue;
	// Small batch so each background tick stays trivially cheap and never
	// blocks the single main thread (no user-visible lag, even with many
	// groups/masks). Convergence after a rehash is gradual by design.
	static constexpr size_t REBUILD_BATCH = 64;

	// Reputation scores climb over time, so score-based group membership must be
	// periodically re-evaluated even without a connect/mode/account event. We
	// re-queue all local users this often (seconds) when any group uses scores.
	static constexpr time_t SCORE_REFRESH_INTERVAL = 30;
	time_t nextscorerefresh = 0;

	void QueueRebuildAll()
	{
		rebuildqueue.clear();
		for (auto* user : ServerInstance->Users.GetLocalUsers())
			rebuildqueue.push_back(user->uuid);
	}

	Account::API accountapi;
	UserCertificateAPI sslapi;
	Geolocation::API geoapi;
	UserModeReference botmode;
	BoolExtItem webircext;
	ListExtItem<SecurityGroupList> sgext;
	ListExtItem<SecurityGroupList> sgpublicext;
	SecurityGroupExtBan extban;
	CommandSecurityGroups cmd;

	static bool HasExt(const Extensible* ext, const std::string& extname)
	{
		ExtensionItem* item = ServerInstance->Extensions.GetItem(extname);
		if (!item)
			return false;

		const auto& extlist = ext->GetExtList();
		return extlist.find(item) != extlist.end();
	}

	static bool IsWebSocketUser(LocalUser* user)
	{
		// Prefer checking the websocket module's extension items as this is
		// stable even when hook ordering differs (testing).
		if (HasExt(user, "websocket-origin") || HasExt(user, "websocket-realhost") || HasExt(user, "websocket-realip"))
			return true;

		// Fallback: check if the user's socket has a websocket I/O hook.
		for (IOHook* hook = user->eh.GetIOHook(); hook; )
		{
			if (hook->prov && insp::equalsci(hook->prov->name, "websocket"))
				return true;

			IOHookMiddle* middle = IOHookMiddle::ToMiddleHook(hook);
			hook = middle ? middle->GetNextHook() : nullptr;
		}
		return false;
	}

	// Parse a tri-state config key: absent = IGNORE, true = YES, false = NO.
	static TriState ParseTriState(const std::shared_ptr<ConfigTag>& tag, const std::string& key)
	{
		const std::string raw = tag->getString(key);
		if (raw.empty())
			return TriState::IGNORE;
		return tag->getBool(key) ? TriState::YES : TriState::NO;
	}

	// Parse a comma- or space-separated list of names into a case-insensitive set.
	static void ParseNameSet(const std::string& input, NameSet& out)
	{
		irc::spacesepstream stream(input);
		for (std::string token; stream.GetToken(token); )
		{
			// Allow comma separators too (e.g. country="FR,DE,BE").
			irc::commasepstream inner(token);
			for (std::string item; inner.GetToken(item); )
			{
				if (!item.empty())
					out.insert(item);
			}
		}
	}

	static bool MatchesMask(LocalUser* user, const std::string& mask)
	{
		if (mask.empty())
			return true;

		// Check common user masks.
		if (InspIRCd::Match(user->GetRealMask(), mask))
			return true;
		if (InspIRCd::Match(user->GetRealUserHost(), mask))
			return true;
		if (InspIRCd::Match(user->GetUserHost(), mask))
			return true;
		if (InspIRCd::Match(user->GetRealHost(), mask))
			return true;

		// Check IP/CIDR.
		if (InspIRCd::MatchCIDR(user->GetAddress(), mask))
			return true;

		return false;
	}

	static IntExtItem* GetReputationExt()
	{
		auto* extitem = ServerInstance->Extensions.GetItem("reputation");
		if (!extitem || extitem->extype != ExtensionType::USER)
			return nullptr;

		return static_cast<IntExtItem*>(extitem);
	}

	// Apply a tri-state criterion: IGNORE passes; YES requires fact==true;
	// NO requires fact==false. Returns false if the user fails the criterion.
	static bool CheckTri(TriState want, bool fact)
	{
		switch (want)
		{
			case TriState::YES: return fact;
			case TriState::NO:  return !fact;
			default:            return true;
		}
	}

	bool Matches(LocalUser* user, const SecurityGroup& group)
	{
		// ── Mask criteria ──
		// exclude masks veto; positive masks require a match (if any are set).
		for (const auto& mask : group.exclude_masks)
		{
			if (MatchesMask(user, mask))
				return false;
		}
		if (!group.masks.empty())
		{
			bool anymask = false;
			for (const auto& mask : group.masks)
			{
				if (MatchesMask(user, mask))
				{
					anymask = true;
					break;
				}
			}
			if (!anymask)
				return false;
		}

		// ── Boolean criteria ── compute each fact once, then apply require/exclude.
		UserFacts facts;
		facts.tls       = sslapi ? sslapi->IsSecure(user) : (SSLIOHook::IsSSL(&user->eh) != nullptr);
		facts.websocket = IsWebSocketUser(user);
		facts.webirc    = webircext.Get(user);
		facts.bot       = botmode && user->IsModeSet(botmode);
		facts.oper      = user->IsOper();
		facts.account   = accountapi && accountapi->GetAccountName(user);

		if (!CheckTri(group.want_tls, facts.tls))             return false;
		if (!CheckTri(group.want_websocket, facts.websocket)) return false;
		if (!CheckTri(group.want_webirc, facts.webirc))       return false;
		if (!CheckTri(group.want_bot, facts.bot))             return false;
		if (!CheckTri(group.want_oper, facts.oper))           return false;
		if (!CheckTri(group.want_account, facts.account))     return false;

		// ── Connect class ──
		const std::string klassname = user->GetClass() ? user->GetClass()->GetName() : "";
		if (!group.connectclasses.empty() && group.connectclasses.find(klassname) == group.connectclasses.end())
			return false;
		if (!group.exclude_connectclasses.empty() && group.exclude_connectclasses.find(klassname) != group.exclude_connectclasses.end())
			return false;

		// ── Country (needs a geolocation provider) ──
		if (!group.countries.empty() || !group.exclude_countries.empty())
		{
			Geolocation::Location* loc = geoapi ? geoapi->GetLocation(user) : nullptr;
			const std::string code = loc ? loc->GetCode() : "";
			if (!group.countries.empty() && group.countries.find(code) == group.countries.end())
				return false;
			if (!group.exclude_countries.empty() && group.exclude_countries.find(code) != group.exclude_countries.end())
				return false;
		}

		// ── Reputation score ──
		if (group.score_min != -1 || group.score_max != -1)
		{
			IntExtItem* repouserext = GetReputationExt();
			if (!repouserext)
				return false;

			const intptr_t raw = repouserext->Get(user);
			const int score = static_cast<int>(std::max<intptr_t>(0, raw));
			if (group.score_min != -1 && score < group.score_min)
				return false;
			if (group.score_max != -1 && score > group.score_max)
				return false;
		}

		return true;
	}

	void Rebuild(LocalUser* user)
	{
		SecurityGroupList matched;
		SecurityGroupList matchedpublic;

		for (const auto& group : groups)
		{
			if (!Matches(user, group))
				continue;

			matched.insert(group.name);
			if (group.publicgroup)
				matchedpublic.insert(group.name);
		}

		if (matched.empty())
			sgext.Unset(user);
		else
			sgext.Set(user, matched);

		if (matchedpublic.empty())
			sgpublicext.Unset(user);
		else
			sgpublicext.Set(user, matchedpublic);
	}

public:
	ModuleSecurityGroups()
		: Module(VF_VENDOR, "Implements security-groups for InspIRCd 4")
		, Account::EventListener(this)
		, WebIRC::EventListener(this)
		, Whois::EventListener(this)
		, accountapi(this)
		, sslapi(this)
		, geoapi(this)
		, botmode(this, "bot")
		, webircext(this, "securitygroups-webirc", ExtensionType::USER)
		, sgext(this, "securitygroups", ExtensionType::USER, true)
		, sgpublicext(this, "securitygroups-public", ExtensionType::USER, true)
		, extban(this, sgext)
		, cmd(this, sgext, sgpublicext)
	{
	}

	void ReadConfig(ConfigStatus& status) override
	{
		const auto& modtag = ServerInstance->Config->ConfValue("securitygroups");
		whoispubliconly = modtag->getBool("whoispubliconly", false);

		std::vector<SecurityGroup> newgroups;
		usesreputation = false;
		bool usesgeo = false;

		for (const auto& [_, tag] : ServerInstance->Config->ConfTags("securitygroup"))
		{
			SecurityGroup group;
			group.name = tag->getString("name", "", 1);
			if (group.name.empty())
				throw ModuleException(this, "<securitygroup:name> is empty at " + tag->source.str());

			irc::spacesepstream maskstream(tag->getString("mask"));
			for (std::string mask; maskstream.GetToken(mask); )
				group.masks.push_back(mask);

			// exclude / exclude-mask: masks that, if matched, veto membership.
			irc::spacesepstream exclstream(tag->getString("exclude", tag->getString("exclude-mask")));
			for (std::string mask; exclstream.GetToken(mask); )
				group.exclude_masks.push_back(mask);

			group.publicgroup = tag->getBool("public", false);

			// Sets a want_X tri-state, throwing if two keys demand opposite values.
			auto setwant = [&](TriState& target, bool condition, TriState value, const char* what)
			{
				if (!condition)
					return;
				if (target != TriState::IGNORE && target != value)
					throw ModuleException(this, INSP_FORMAT("<securitygroup> has contradictory '{}' criteria at {}", what, tag->source.str()));
				target = value;
			};

			// ── TLS / insecure: two views of one fact (insecure == not tls). ──
			setwant(group.want_tls, tag->getBool("tls", tag->getBool("tls-users", false)), TriState::YES, "tls");
			setwant(group.want_tls, tag->getBool("insecure", tag->getBool("insecure-users", false)), TriState::NO, "tls");
			setwant(group.want_tls, tag->getBool("exclude-tls"), TriState::NO, "tls");
			setwant(group.want_tls, tag->getBool("exclude-insecure"), TriState::YES, "tls");

			// ── Account: account/registered == has account; unregistered == not. ──
			setwant(group.want_account, tag->getBool("account", tag->getBool("registered", false)), TriState::YES, "account");
			setwant(group.want_account, tag->getBool("unregistered", tag->getBool("unregistered-users", false)), TriState::NO, "account");
			setwant(group.want_account, tag->getBool("exclude-account", tag->getBool("exclude-registered")), TriState::NO, "account");

			// ── WebSocket: tri-state yes/no, plus exclude-websocket. ──
			TriState ws = ParseTriState(tag, "websocket");
			if (ws == TriState::IGNORE)
				ws = ParseTriState(tag, "websocket-users");
			setwant(group.want_websocket, ws != TriState::IGNORE, ws, "websocket");
			setwant(group.want_websocket, tag->getBool("exclude-websocket"), TriState::NO, "websocket");

			// ── WebIRC. ──
			setwant(group.want_webirc, tag->getBool("webirc", tag->getBool("webirc-users", false)), TriState::YES, "webirc");
			setwant(group.want_webirc, tag->getBool("exclude-webirc"), TriState::NO, "webirc");

			// ── Bot (+B mode). ──
			setwant(group.want_bot, tag->getBool("bmode", tag->getBool("bot", false)), TriState::YES, "bmode");
			setwant(group.want_bot, tag->getBool("exclude-bmode", tag->getBool("exclude-bot")), TriState::NO, "bmode");

			// ── Oper: tri-state yes/no, plus exclude-oper. ──
			TriState op = ParseTriState(tag, "oper");
			setwant(group.want_oper, op != TriState::IGNORE, op, "oper");
			setwant(group.want_oper, tag->getBool("exclude-oper"), TriState::NO, "oper");

			// ── Country / connectclass: positive + exclude name lists. ──
			ParseNameSet(tag->getString("country"), group.countries);
			ParseNameSet(tag->getString("exclude-country"), group.exclude_countries);
			ParseNameSet(tag->getString("connectclass"), group.connectclasses);
			ParseNameSet(tag->getString("exclude-connectclass"), group.exclude_connectclasses);

			group.score_min = tag->getNum<int>("scoremin", -1);
			group.score_max = tag->getNum<int>("scoremax", -1);
			if ((group.score_min != -1 && group.score_min < 0) || (group.score_max != -1 && group.score_max < 0))
				throw ModuleException(this, "<securitygroup> scoremin/scoremax must be >= 0 (or omitted) at " + tag->source.str());
			if (group.score_min != -1 && group.score_max != -1 && group.score_min > group.score_max)
				throw ModuleException(this, "<securitygroup> scoremin must be <= scoremax at " + tag->source.str());
			if (group.score_min != -1 || group.score_max != -1)
				usesreputation = true;

			if (!group.countries.empty() || !group.exclude_countries.empty())
				usesgeo = true;

			newgroups.push_back(group);
		}

		if (usesreputation && !GetReputationExt())
			throw ModuleException(this, "<securitygroup> uses scoremin/scoremax but the reputation user extension (from the reputation module) is not loaded");

		// Geolocation can be loaded after us, so warn rather than refuse to load.
		if (usesgeo && !geoapi)
			ServerInstance->Logs.Warning(MODNAME, "A <securitygroup> uses country= but no geolocation provider (m_geo_maxmind/m_geoclass) is loaded; those groups will match nobody until one is.");

		groups.swap(newgroups);

		// Re-evaluate everyone, but spread the work across background ticks.
		QueueRebuildAll();
	}

	void OnUnloadModule(Module* mod) override
	{
		// If reputation is unloaded then re-evaluate score-based memberships.
		if (!usesreputation)
			return;
		QueueRebuildAll();
	}

	void OnBackgroundTimer(time_t curtime) override
	{
		// Periodically re-evaluate score-based memberships, since reputation
		// scores climb over time with no connect/mode/account event to trigger a
		// rebuild. Only when score groups exist and the queue is already drained
		// (so we never pile up faster than we process).
		if (usesreputation && rebuildqueue.empty() && curtime >= nextscorerefresh)
		{
			QueueRebuildAll();
			nextscorerefresh = curtime + SCORE_REFRESH_INTERVAL;
		}

		// Drain a bounded batch of queued rebuilds. UUID lookup means any user
		// who disconnected since being queued is simply skipped.
		for (size_t processed = 0; processed < REBUILD_BATCH && !rebuildqueue.empty(); ++processed)
		{
			const std::string uuid = rebuildqueue.front();
			rebuildqueue.pop_front();

			auto* user = ServerInstance->Users.FindUUID<LocalUser>(uuid);
			if (user && !user->quitting)
				Rebuild(user);
		}
	}

	void OnUserPostInit(LocalUser* user) override
	{
		// Called after I/O hooks have been checked and the user has a connect class.
		Rebuild(user);
	}

	void OnUserConnect(LocalUser* user) override
	{
		Rebuild(user);
	}

	void OnAccountChange(User* user, const std::string& newaccount) override
	{
		LocalUser* luser = IS_LOCAL(user);
		if (luser)
			Rebuild(luser);
	}

	void OnWebIRCAuth(LocalUser* user, const WebIRC::FlagMap* flags) override
	{
		// m_gateway calls this before it changes the user's remote address; we
		// just mark the user and let OnChangeRemoteAddress recalculate.
		webircext.Set(user);
	}

	void OnChangeRemoteAddress(LocalUser* user) override
	{
		Rebuild(user);
	}

	void OnMode(User* user, User* usertarget, Channel* chantarget, const Modes::ChangeList& changelist, ModeParser::ModeProcessFlag processflags) override
	{
		// A change to the +B bot mode may affect group membership. Only react to
		// local user-mode changes, and only when the bot mode is actually in the
		// changelist (so unrelated mode changes don't trigger needless rebuilds).
		if (!usertarget || !botmode)
			return;

		LocalUser* luser = IS_LOCAL(usertarget);
		if (!luser)
			return;

		for (const auto& change : changelist.getlist())
		{
			if (change.mh == *botmode)
			{
				Rebuild(luser);
				return;
			}
		}
	}

	void OnWhois(Whois::Context& whois) override
	{
		// whoispubliconly: Orbit / WHOIS never leaks private groups, even on
		// self-whois or for users/auspex. Full membership stays on /SECURITYGROUPS.
		const bool canseeall = !whoispubliconly
			&& (whois.IsSelfWhois() || whois.GetSource()->HasPrivPermission("users/auspex"));
		const SecurityGroupList* list = canseeall ? sgext.Get(whois.GetTarget()) : sgpublicext.Get(whois.GetTarget());
		if (!list || list->empty())
			return;

		whois.SendLine(RPL_WHOISSPECIAL, "is in security groups: " + insp::join(*list, ','));
	}
};

MODULE_INIT(ModuleSecurityGroups)

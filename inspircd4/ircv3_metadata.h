/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 * API for m_ircv3_metadata (per-user buffer prefs: soju.im/muted, …).
 * Copy this file into include/modules/ when installing the module.
 *
 * Copyright (C) 2026
 *
 * This file is part of InspIRCd. InspIRCd is free software: you can
 * redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 */

#pragma once

#include "event.h"

namespace IRCv3Metadata
{
	class API;
	class APIBase;
}

/** Defines the interface for the IRCv3 metadata buffer-preference API. */
class IRCv3Metadata::APIBase
	: public DataProvider
{
public:
	APIBase(Module* parent)
		: DataProvider(parent, "ircv3metadataapi")
	{
	}

	/** True if the user has soju.im/muted=1 for the given channel or nick target. */
	virtual bool IsMuted(LocalUser* user, const std::string& target) const = 0;

	/** True if the given metadata owner key (account name or nick) has muted the target. */
	virtual bool IsMutedOwner(const std::string& owner, const std::string& target) const = 0;

	/** True if the user has soju.im/blocked=1 for the given nick (or channel) target. */
	virtual bool IsBlocked(LocalUser* user, const std::string& target) const = 0;
};

/** Allows modules to query per-user buffer metadata preferences. */
class IRCv3Metadata::API final
	: public dynamic_reference<IRCv3Metadata::APIBase>
{
public:
	API(Module* parent)
		: dynamic_reference<IRCv3Metadata::APIBase>(parent, "ircv3metadataapi")
	{
	}
};

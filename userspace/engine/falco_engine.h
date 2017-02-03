/*
Copyright (C) 2016 Draios inc.

This file is part of falco.

falco is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

falco is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with falco.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <string>
#include <memory>
#include <set>

#include "sinsp.h"
#include "filter.h"

#include "rules.h"

#include "falco_common.h"

//
// This class acts as the primary interface between a program and the
// falco rules engine. Falco outputs (writing to files/syslog/etc) are
// handled in a separate class falco_outputs.
//

class falco_engine : public falco_common
{
public:
	falco_engine(bool seed_rng=true);
	virtual ~falco_engine();

	//
	// Load rules either directly or from a filename.
	//
	void load_rules_file(const std::string &rules_filename, bool verbose, bool all_events);
	void load_rules(const std::string &rules_content, bool verbose, bool all_events);

	//
	// Enable/Disable any rules matching the provided pattern (regex).
	//
	void enable_rule(std::string &pattern, bool enabled);

	//
	// Enable/Disable any rules with any of the provided tags (set, exact matches only)
	//
	void enable_rule_by_tag(std::set<string> &tags, bool enabled);

	//
	// Given a set of rules as strings, return an object
	// that can be passed to process_event(), which will in turn
	// limit the set of (loaded) rules that runs.
	//
	// Throws an exception if one of the tag strings provided does
	// not map to any tag in any rule.
	//
	// This is slightly different than using enable_rule_by_tag,
	// as it allows having a single loaded rule set be used by
	// multiple executors, each of whom wants to run a slightly
	// different subset of the loaded rules.
	//

	typedef std::set<sinsp_evttype_filter::tag_t> tag_match_t;

	tag_match_t gen_tag_match(std::set<string> &tags);

	struct rule_result {
		sinsp_evt *evt;
		std::string rule;
		std::string priority;
		std::string format;
	};

	//
	// Given an event, check it against the set of rules in the
	// engine and if a matching rule is found, return details on
	// the rule that matched. If no rule matched, returns NULL.
	//
	// If tag_match_t is non-NULL, only those rules matching the
	// tags in match will be run.
	//
	// the reutrned rule_result is allocated and must be delete()d.
	std::unique_ptr<rule_result> process_event(sinsp_evt *ev, tag_match_t *match = NULL);

	//
	// Print details on the given rule. If rule is NULL, print
	// details on all rules.
	//
	void describe_rule(std::string *rule);

	//
	// Print statistics on how many events matched each rule.
	//
	void print_stats();

	//
	// Add a filter, which is related to the specified set of
	// event types, to the engine.
	//
	void add_evttype_filter(std::string &rule,
				set<uint32_t> &evttypes,
				set<string> &tags,
				sinsp_filter* filter);

	// Clear all existing filters.
	void clear_filters();

	//
	// Set the sampling ratio, which can affect which events are
	// matched against the set of rules.
	//
	void set_sampling_ratio(uint32_t sampling_ratio);

	//
	// Set the sampling ratio multiplier, which can affect which
	// events are matched against the set of rules.
	//
	void set_sampling_multiplier(double sampling_multiplier);

	//
	// You can optionally add "extra" formatting fields to the end
	// of all output expressions. You can also choose to replace
	// %container.info with the extra information or add it to the
	// end of the expression. This is used in open source falco to
	// add k8s/mesos/container information to outputs when
	// available.
	//
	void set_extra(string &extra, bool replace_container_info);

private:

	//
	// Determine whether the given event should be matched at all
	// against the set of rules, given the current sampling
	// ratio/multiplier.
	//
	inline bool should_drop_evt();

	falco_rules *m_rules;
	std::unique_ptr<sinsp_evttype_filter> m_evttype_filter;

	//
	// Maps from tag name to tag id. Allows for more efficient tag
	// comparisons than doing a bunch of string matches.
	//
	std::map<std::string, sinsp_evttype_filter::tag_t> m_known_tags;
	sinsp_evttype_filter::tag_t m_next_tag;

	//
	// Here's how the sampling ratio and multiplier influence
	// whether or not an event is dropped in
	// should_drop_evt(). The intent is that m_sampling_ratio is
	// generally changing external to the engine e.g. in the main
	// inspector class based on how busy the inspector is. A
	// sampling ratio implies no dropping. Values > 1 imply
	// increasing levels of dropping. External to the engine, the
	// sampling ratio results in events being dropped at the
	// kernel/inspector interface.
	//
	// The sampling multiplier is an amplification to the sampling
	// factor in m_sampling_ratio. If 0, no additional events are
	// dropped other than those that might be dropped by the
	// kernel/inspector interface. If 1, events that make it past
	// the kernel module are subject to an additional level of
	// dropping at the falco engine, scaling with the sampling
	// ratio in m_sampling_ratio.
	//

	uint32_t m_sampling_ratio;
	double m_sampling_multiplier;

	std::string m_lua_main_filename = "rule_loader.lua";

	std::string m_extra;
	bool m_replace_container_info;
};


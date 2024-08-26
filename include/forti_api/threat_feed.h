//
// Created by Cooper Larson on 8/26/24.
//

#ifndef FORTI_API_THREAT_FEED_H
#define FORTI_API_THREAT_FEED_H

#include <string>
#include <format>
#include <nlohmann/json.hpp>
#include <vector>
#include <regex>
#include "api.h"

struct ThreatFeedSchema {
    std::string name;
    std::string status;
    std::string type;
    std::string update_method;
    std::string server_identity_check;
    unsigned int category;
    std::string comments;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(ThreatFeedSchema, name, status, type, update_method,
                                   server_identity_check, category, comments)
};

struct CommandEntry {
    std::string name;
    std::string command{};
    std::vector<std::string> entries;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(CommandEntry, name, command, entries)
};

struct CommandsRequest {
    std::vector<CommandEntry> commands;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(CommandsRequest, commands)
};

class ThreatFeed {
    inline static std::string command = "snapshot";
    inline static std::string external_resource =
            std::format("{}/cmdb/system/external-resource", API::base_api_endpoint);
    inline static std::string external_resource_monitor =
            std::format("{}/monitor/system/external-resource/dynamic", API::base_api_endpoint);
    inline static std::string external_resource_entry_list =
            std::format("{}/entry-list?include_notes=true&vdom=root&mkey=", external_resource);

public:

    static void update(const std::string& name, const nlohmann::json& data) {
        API::post(std::format("{}/{}", external_resource_monitor, name), data);
    }

    static void updateMonitor(const nlohmann::json& data) { API::post(external_resource_monitor, data); }

    static std::vector<ThreatFeedSchema> get() { return API::get(external_resource); }

    static ThreatFeedSchema get(const std::string& query) {
        return API::get(std::format("{}/{}", external_resource, query));
    }

    static nlohmann::json getEntryList(const std::string& feed) {
        return API::get(std::format("{}/{}", external_resource_entry_list, feed));
    }

    static unsigned int count(const std::string& match) {
        auto results = get();
        unsigned int count = 0;
        for (const auto& doc : results) if (doc["name"] == match) ++count;
        return count;
    }

    static void enable(const std::string& name) { set(name, true); }

    static void disable(const std::string& name) { set(name, false); }

    static void set(const std::string& name, bool enable = true) {
        nlohmann::json j;
        j["status"] = enable ? "enable" : "disable";
        API::post(std::format("{}/{}", external_resource, name), j);
    }

    static void add(const std::string& name, const std::string& category) {
        nlohmann::json j;
        j["name"] = name;
        j["category"] = category;
        API::post(external_resource, j);
    }

    static void del(const std::regex& regex) {
        auto feeds = get();
        std::reverse(feeds.begin(), feeds.end());
        for (const auto& feed : feeds)
            if (std::regex_match(feed.name, regex)) API::del(feed.name);
    }

    static void del(const std::string& name) { API::del(std::format("{}/{}", external_resource, name)); }
};

#endif //FORTI_API_THREAT_FEED_H

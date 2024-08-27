//
// Created by Cooper Larson on 8/26/24.
//

#ifndef FORTI_API_THREAT_FEED_HPP
#define FORTI_API_THREAT_FEED_HPP

#include <cstring>
#include <format>
#include <nlohmann/json.hpp>
#include <vector>
#include "api.hpp"

struct ThreatFeedType {
    std::string name, status, type, update_method, server_identity_check, comments;
    unsigned int category{};

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(ThreatFeedType, name, status, type, update_method,
                                   server_identity_check, category, comments)
};

struct ExternalResourcesResponse : public Response {
    std::vector<ThreatFeedType> results;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(ExternalResourcesResponse, http_method, size, matched_count, next_idx,
                                   revision, vdom, path, name, status, http_status, serial, version,
                                   build, results)
};

struct ExternalResourceResponse : public Response {
    ThreatFeedType results;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(ExternalResourceResponse, http_method, size, matched_count, next_idx,
                                   revision, vdom, path, name, status, http_status, serial, version,
                                   build, results)
};

struct Entry {
    std::string entry, valid;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(Entry, entry, valid);
};

struct ExternalResourceEntryList {
    std::string status, resource_file_status;
    unsigned long last_content_update_time{};
    std::vector<Entry> entries;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(ExternalResourceEntryList, status, resource_file_status,
                                   last_content_update_time, entries);
};

struct ExternalResourceEntryListResponse : public Response {
    ExternalResourceEntryList results;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(ExternalResourceEntryListResponse, http_method, size, matched_count, next_idx,
                                   revision, vdom, path, name, status, http_status, serial, version,
                                   build, results)
};

struct CommandEntry {
    std::string name, command;
    std::vector<std::string> entries;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(CommandEntry, name, entries, command)
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

    static void update_info(const std::string& name, const nlohmann::json& data) {
        API::post(std::format("{}/{}", external_resource_monitor, name), data);
    }

    static void update_feed(const nlohmann::json& data) { API::post(external_resource_monitor, data); }

    static std::vector<ThreatFeedType> get() {
        return API::get<ExternalResourcesResponse>(external_resource).results;
    }

    static ThreatFeedType get(const std::string& query) {
        return API::get<ExternalResourceResponse>(std::format("{}/{}", external_resource, query)).results;
    }

    static std::vector<Entry> get_entry_list(const std::string& feed) {
        return API::get<ExternalResourceEntryListResponse>
                (std::format("{}/{}", external_resource_entry_list, feed)).results.entries;
    }

    static bool contains(const std::string& name) {
        auto results = get();
        return std::ranges::any_of(results, [&name](const ThreatFeedType& threatFeed) {
            return threatFeed.name == name;
        });
    }

    static void enable(const std::string& name) { set(name, true); }

    static void disable(const std::string& name) { set(name, false); }

    static void set(const std::string& name, bool enable = true) {
        nlohmann::json j;
        j["status"] = enable ? "enable" : "disable";
        API::post(std::format("{}/{}", external_resource, name), j);
    }

    static void add(const std::string& name, unsigned int category) {
        nlohmann::json j;
        j["name"] = name;
        j["category"] = category;
        API::post(external_resource, j);
    }

    static void del(const std::string& name) { API::del(std::format("{}/{}", external_resource, name)); }
};

#endif //FORTI_API_THREAT_FEED_HPP

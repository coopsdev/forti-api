//
// Created by Cooper Larson on 8/26/24.
//

#ifndef FORTI_API_THREAT_FEED_HPP
#define FORTI_API_THREAT_FEED_HPP

#include "dns_filter.hpp"
#include <cstring>
#include <format>
#include <nlohmann/json.hpp>
#include <vector>
#include "api.hpp"


struct PushThreatFeed {
    std::string name, status, type, update_method, server_identity_check, comments;
    unsigned int category{};

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(PushThreatFeed, name, status, type, update_method,
                                                server_identity_check, category, comments)
};

struct FeedThreatFeed : public PushThreatFeed {
    std::string resource;
    unsigned int refresh_rate{};

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(FeedThreatFeed, name, status, type, update_method,
                                                server_identity_check, category, comments, resource, refresh_rate)
};

struct ExternalResourcesResponse : public Response {
    std::vector<PushThreatFeed> results;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(ExternalResourcesResponse, http_method, size, matched_count, next_idx,
                                   revision, vdom, path, name, status, http_status, serial, version,
                                   build, results)
};

struct Entry {
    std::string entry, valid;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(Entry, entry, valid);
};

struct ExternalResourceEntryList {
    std::string status, resource_file_status;
    unsigned long last_content_update_time{};
    std::vector<Entry> entries;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(ExternalResourceEntryList, status, resource_file_status,
                                   last_content_update_time, entries);
};

struct ExternalResourceEntryListResponse : public Response {
    ExternalResourceEntryList results;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(ExternalResourceEntryListResponse, http_method, size, matched_count, next_idx,
                                   revision, vdom, path, name, status, http_status, serial, version,
                                   build, results)
};

struct CommandEntry {
    std::string name, command;
    std::vector<std::string> entries;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(CommandEntry, name, entries, command)
};

struct CommandsRequest {
    std::vector<CommandEntry> commands;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(CommandsRequest, commands)
};

class ThreatFeed {
    inline static std::string command = "snapshot";
    inline static std::string comment = "This threat feed is automatically managed by forti-api";
    inline static std::string external_resource = "/cmdb/system/external-resource";
    inline static std::string external_resource_monitor = "/monitor/system/external-resource/dynamic";
    inline static std::string external_resource_entry_list =
            std::format("{}/entry-list?include_notes=true&vdom=root&mkey=", external_resource);

    static void set(const std::string& name, bool enable = true) {
        nlohmann::json j;
        j["status"] = enable ? "enable" : "disable";
        API::post(std::format("{}/{}", external_resource, name), j);
    }

public:
    static void update_info(const std::string& name, const nlohmann::json& data) {
        API::post(std::format("{}/{}", external_resource_monitor, name), data);
    }

    static void update_feed(const nlohmann::json& data) { API::post(external_resource_monitor, data); }

    static std::vector<PushThreatFeed> get() {
        return API::get<ExternalResourcesResponse>(external_resource).results;
    }

    static PushThreatFeed get(const std::string& query) {
        return API::get<ExternalResourcesResponse>(std::format("{}/{}", external_resource, query)).results[0];
    }

    static std::vector<Entry> get_entry_list(const std::string& feed) {
        return API::get<ExternalResourceEntryListResponse>
                (std::format("{}/{}", external_resource_entry_list, feed)).results.entries;
    }

    static bool contains(const std::string& name) {
        return API::get<ExternalResourcesResponse>(std::format("{}/{}", external_resource, name)).http_status == 200;
    }

    static void enable(const std::string& name) { set(name, true); }

    static void disable(const std::string& name) { set(name, false); }

    static void add(const std::string& name, unsigned int category) {
        PushThreatFeed threat_feed(name, "enable", "domain", "push", "none", comment, category);
        API::post(external_resource, threat_feed);
    }

    static void del(const std::string& name) {
        if (contains(name)) API::del(std::format("{}/{}", external_resource, name));
        else std::cerr << "Couldn't locate threat feed for deletion: " << name << std::endl;
    }

    static void delete_auto_generated_feeds() {
        auto feeds = get();
        std::reverse(feeds.begin(), feeds.end());
        for (const auto& feed : feeds) {
            if (feed.comments == comment) {
                del(feed.name);
            }
        }
    }
};

#endif //FORTI_API_THREAT_FEED_HPP

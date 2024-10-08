//
// Created by Cooper Larson on 8/26/24.
//

#ifndef FORTI_API_DNS_FILTER_HPP
#define FORTI_API_DNS_FILTER_HPP

#include <utility>
#include "api.hpp"


struct Filter {
    unsigned int id = 0, q_origin_key = 0, category{};
    std::string action, log = "enable";

    Filter() = default;
    explicit Filter(unsigned int category, std::string  action = "allow") :
            category(category), action(std::move(action)) {}

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(Filter, id, q_origin_key, category, action, log)
};

struct CompareFilters {
    bool operator()(const Filter& a, const Filter& b) const { return a.category < b.category; }
    bool operator()(const Filter& a, unsigned int category) const { return a.category < category; }
    bool operator()(unsigned int category, const Filter& b) const { return category < b.category; }
};

struct DNSFilterOptions {
    std::string options;
    std::vector<Filter> filters;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(DNSFilterOptions, options, filters)

    std::pair<bool, unsigned int> find_category(unsigned int category) {
        auto it = std::lower_bound(filters.begin(), filters.end(), category, CompareFilters());
        if (it != filters.end() && it->category == category) {
            return std::make_pair(true, std::distance(filters.begin(), it));
        }
        return std::make_pair(false, std::distance(filters.begin(), it));
    }

    bool contains(unsigned int category) { return find_category(category).first; }

    void block(unsigned int category) {
        const auto& [match_found, index] = find_category(category);
        if (match_found) filters[index].action = "block";
        else filters.emplace(filters.begin() + index, category, "block");
    }

    void allow(unsigned int category) {
        const auto& [match_found, index] = find_category(category);
        if (match_found) filters.erase(filters.begin() + index);
    }

    void monitor(unsigned int category) {
        const auto& [match_found, index] = find_category(category);
        if (match_found) filters[index].action = "monitor";
        else filters.emplace(filters.begin() + index, category, "monitor");
    }

    void sort_filters() { std::sort(filters.begin(), filters.end(), CompareFilters()); }
};

struct DomainFilter {
    unsigned int domain_filter_table = 2;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(DomainFilter, domain_filter_table)
};

struct DNSProfile {
    std::string name, q_origin_key,
                comment = "Automatically managed with forti_api",
                log_all_domain = "disable",
                sdns_ftgd_err_log = "enable",
                sdns_domain_log = "enable",
                block_action = "redirect",
                redirect_portal = "0.0.0.0",
                redirect_portal6 = "::",
                block_botnet = "disable",
                safe_search = "disable",
                youtube_restrict = "strict";
    DomainFilter domain_filter{};
    std::vector<std::string> external_ip_blocklist{}, dns_translation{};
    DNSFilterOptions ftgd_dns{};

    DNSProfile() = default;
    explicit DNSProfile(const std::string& name) : name(name), q_origin_key(name) {}

    void block_category(unsigned int category) { ftgd_dns.block(category); }
    void allow_category(unsigned int category) { ftgd_dns.allow(category); }
    void monitor_category(unsigned int category) { ftgd_dns.monitor(category); }
    bool contains_category(unsigned int category) { return ftgd_dns.contains(category); }

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(DNSProfile, name, q_origin_key, comment, sdns_ftgd_err_log,
                                                sdns_domain_log, block_action, redirect_portal, redirect_portal6,
                                                block_botnet, safe_search, youtube_restrict, log_all_domain,
                                                domain_filter, external_ip_blocklist, dns_translation, ftgd_dns)
};


struct DNSFiltersResponse : public Response {
    std::vector<DNSFilterOptions> results;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(DNSFiltersResponse, http_method, size, matched_count, next_idx,
                                                revision, vdom, path, name, status, http_status, serial, version,
                                                build, results)
};

struct DNSProfilesResponse : public Response {
    std::vector<DNSProfile> results;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(DNSProfilesResponse, http_method, size, matched_count, next_idx,
                                                revision, vdom, path, name, status, http_status, serial, version,
                                                build, results)
};


class DNSFilter {
    inline static std::string api_endpoint = "/cmdb/dnsfilter/profile";

public:
    static void update(const DNSProfile& profile) {
        if (!contains(profile.name)) throw std::runtime_error("Can't update non-existent DNS Profile");
        FortiAPI::put(std::format("{}/{}", api_endpoint, profile.name), profile);
    }

    static void add(const std::string& name) { FortiAPI::post(api_endpoint, DNSProfile(name)); }

    static void del(const std::string& name) {
        if (!contains(name)) throw std::runtime_error("Can't delete non-existent item: " + name);
        else FortiAPI::del(std::format("{}/{}", api_endpoint, name));
    }

    static bool contains(const std::string& name) {
        return FortiAPI::get<DNSProfilesResponse>(std::format("{}/{}", api_endpoint, name)).http_status == 200;
    }

    static std::vector<DNSProfile> get() {
        auto results = FortiAPI::get<DNSProfilesResponse>(api_endpoint).results;
        for (auto& profile : results) profile.ftgd_dns.sort_filters();
        return results;
    }

    static DNSProfile get(const std::string& feed) {
        auto result = FortiAPI::get<DNSProfilesResponse>(std::format("{}/{}", api_endpoint, feed)).results[0];
        result.ftgd_dns.sort_filters();
        return result;
    }

    static void global_allow_category(unsigned int category) {
        for (auto& profile : get()) {
            profile.allow_category(category);
            update(profile);
        }
    }

    static void block_category_in_profile(const std::string& profile_name, unsigned int category) {
        auto profile = get(profile_name);
        profile.block_category(category);
        update(profile);
    }

    static void block_category_in_profiles(const std::vector<std::string>& profiles, unsigned int category) {
        for (const auto& name : profiles) block_category_in_profile(name, category);
    }
};

#endif //FORTI_API_DNS_FILTER_HPP

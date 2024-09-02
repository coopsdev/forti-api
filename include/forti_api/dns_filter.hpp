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

struct CompareFilters { bool operator()(const Filter& a, const Filter& b) { return a.category < b.category; } };

struct DNSFilterOptions {
    std::string options;
    std::vector<Filter> filters;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(DNSFilterOptions, options, filters)

    std::pair<bool, unsigned int> binary_search(unsigned int category) {
        unsigned int start = 0, end = filters.size();
        while (start != end) {
            unsigned int mid = start + (end - start) / 2;
            auto cat = filters[mid].category;
            if (cat == category) return std::make_pair(true, mid);
            else if (cat < category) start = mid + 1;
            else end = mid;
        }
        return std::make_pair(false, start);
    }

    bool contains(unsigned int category) { return binary_search(category).first; }

    void block(unsigned int category) {
        const auto& [match_found, index] = binary_search(category);
        if (match_found) filters[index].action = "block";
        else filters.emplace_back(category, "block");
    }

    void allow(unsigned int category) {
        const auto& [match_found, index] = binary_search(category);
        if (match_found) {
            if (index == filters.size() - 1) filters.resize(filters.size() - 1);
            else {
                std::vector<Filter> new_filters(filters.size() - 1);
                if (index == 0) std::move(filters.begin() + 1, filters.end(), new_filters.begin());
                else {
                    std::move(filters.begin(), filters.begin() + index, new_filters.begin());
                    std::move(filters.begin() + index + 1, filters.end(), new_filters.begin() + index);
                }
                filters = new_filters;
            }
        }
    }

    void monitor(unsigned int category) {
        const auto& [match_found, index] = binary_search(category);
        if (match_found) filters[index].action = "monitor";
        else filters.emplace_back(category, "monitor");
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
    static void update(DNSProfile& profile) {
        if (!contains(profile.name)) throw std::runtime_error("Can't update non-existent DNS Profile");
        profile.ftgd_dns.sort_filters();
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
        return FortiAPI::get<DNSProfilesResponse>(api_endpoint).results;
    }

    static DNSProfile get(const std::string& feed) {
        return FortiAPI::get<DNSProfilesResponse>(std::format("{}/{}", api_endpoint, feed)).results[0];
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

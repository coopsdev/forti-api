//
// Created by Cooper Larson on 8/26/24.
//

#ifndef FORTI_API_DNS_FILTER_H
#define FORTI_API_DNS_FILTER_H

#include <string>
#include <format>
#include <nlohmann/json.hpp>
#include "api.h"


struct Filter {
    unsigned int id, q_origin_key, category;
    std::string action, log;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(Filter, id, category, action, log)
};

struct DnsProfile {
    std::string options;
    std::vector<Filter> filters;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(DnsProfile, options, filters)
};

struct DnsFilter {
    std::string name, q_origin_key, comment;
    std::vector<std::string> domain_filter;
    DnsProfile ftgd_dns;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(DnsFilter, name, q_origin_key, comment, domain_filter, ftgd_dns)
};

struct DnsProfileResponse : public Response {
    DnsProfile results;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(DnsProfileResponse, http_method, size, matched_count, next_idx,
                                   revision, vdom, path, name, status, http_status, serial, version,
                                   build, results)
};

struct DnsFiltersResponse : public Response {
    std::vector<DnsFilter> results;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(DnsFiltersResponse, http_method, size, matched_count, next_idx,
                                   revision, vdom, path, name, status, http_status, serial, version,
                                   build, results)
};

struct DnsFilterResponse : public Response {
    DnsFilter results;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(DnsFilterResponse, http_method, size, matched_count, next_idx,
                                   revision, vdom, path, name, status, http_status, serial, version,
                                   build, results)
};

class DNSFilter {
    inline static std::string api_endpoint = std::format("{}/cmdb/dnsfilter/profile", API::base_api_endpoint);

public:
    static void set_filter(const std::string& feed,
                           unsigned int category,
                           bool active = true) {
        std::string action = active ? "block" : "allow";
        auto query = std::format("{}/{}/ftgd-dns/", api_endpoint, feed);
        auto response = API::get<DnsProfileResponse>(query);

        if (response.http_status == 200) {
            auto filters = response.results.filters;

            std::pair<bool, unsigned int> pair = std::make_pair(false, 0);
            for (unsigned int i = 0; i < filters.size(); ++i) {
                if (filters[i].category == category) {
                    pair = std::make_pair(true, i);
                    break;
                }
            }

            const auto& [matchFound, index] = pair;

            if (matchFound) {
                filters[index].action = action;
                set_filters(feed, filters);
            }
        }
    }

    static void set_threat_feeds(const std::string& feed, bool active = true) {
        std::string action = active ? "block" : "allow";
        auto query = std::format("{}/{}/ftgd-dns/", api_endpoint, feed);
        auto response = API::get<DnsProfileResponse>(query);

        if (response.http_status == 200) {
            auto& filters = response.results.filters;

            for (auto& filter : filters) {
                if (filter.category >= 192 && filter.category <= 221) filter.action = action;
            }

            set_filters(feed, response.results);
        }
    }

    static void set_filters(
            const std::string& feed,
            const nlohmann::json& filters = nlohmann::json()) {
        auto query = std::format("{}/{}/ftgd-dns/", api_endpoint, feed);
        auto profile = API::get<DnsProfileResponse>(query).results;
        profile.filters = filters;
        API::put(query, profile);
    }

    static std::vector<DnsFilter> get() {
        return API::get<DnsFiltersResponse>(api_endpoint).results;
    }

    static DnsFilter get(const std::string& feed) {
        return API::get<DnsFilterResponse>(std::format("{}/{}", api_endpoint, feed)).results;
    }
};

#endif //FORTI_API_DNS_FILTER_H

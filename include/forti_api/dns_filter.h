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
    int id;
    int category;
    std::string action;
    std::string log;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(Filter, id, category, action, log)
};

struct DnsProfile {
    std::string options;
    std::vector<Filter> filters;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(DnsProfile, options, filters)
};

struct DnsFilter {
    std::string name;
    std::string q_origin_key;
    std::string comment;
    std::vector<std::string> domain_filter;
    DnsProfile ftgd_dns;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(DnsFilter, name, q_origin_key, comment, domain_filter, ftgd_dns)
};

struct DnsResponse {
    std::vector<DnsFilter> results;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(DnsResponse, results)
};

class DNSFilter {
    inline static std::string api_endpoint = std::format("{}/cmdb/dnsfilter/profile", API::base_api_endpoint);

public:
    static void set(const std::string& feed,
                    const std::string& category,
                    const std::string& name,
                    bool active = true) {
        std::string action = active ? "allow" : "block";
        auto filters = getFilters(feed);

        std::pair<bool, unsigned int> searchPair = std::make_pair(false, 0);
        for (unsigned int i = 0; i < filters.size(); ++i) {
            if (filters[i]["name"] == name) {
                searchPair = std::make_pair(true, i);
                break;
            }
        }

        auto [matchFound, index] = searchPair;

        if (matchFound) {
            if (active) {
                if (index == 0 || index == filters.size() - 1) {
                    if (index == 0) std::swap(filters[0], filters[filters.size() - 1]);
                    filters.resize(filters.size() - 1);
                } else {
                    std::vector<nlohmann::json> newFilters(filters.size() - 1);
                    std::move(filters.begin(), filters.begin() + index, newFilters.begin());
                    std::move(filters.begin() + index + 1, filters.end(), newFilters.begin() + index);
                    filters = std::move(newFilters);
                }
            } else { filters[index]["action"] = action; }
        } else if (!active) {
            nlohmann::json j;
            j["category"] = category;
            j["action"] = action;
            filters.push_back(j);
        }

        setFilters(feed, filters);
    }

    static void setFilters(
            const std::string& feed,
            const nlohmann::json& filters = nlohmann::json()) {
        nlohmann::json j;
        j["ftgd-dns"]["filters"] = filters;
        API::put(std::format("{}/{}", api_endpoint, feed), j);
    }

    static std::vector<nlohmann::json> getFilters(const std::string& feed) {
        Response response = API::get(std::format("{}/{}", api_endpoint, feed));
        auto results = response.results;
        for (const auto& entry : results) {
            if (entry["name"] == feed) return entry["ftgd_dns"]["filters"];
        }
        return {};
    }
};

#endif //FORTI_API_DNS_FILTER_H

//
// Created by Cooper Larson on 8/25/24.
//

#ifndef FORTI_API_H
#define FORTI_API_H

#include "schemas.hpp"

#include <cstring>
#include <format>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <nlohmann/json-schema.hpp>
#include <curl/curl.h>
#include <iostream>
#include <cstdlib>
#include <utility>

class Auth {
    std::string ip, cert_path, api_key;
    unsigned int port;

    Auth() :
            ip(std::getenv("FORTIGATE_GATEWAY_IP")),
            cert_path(std::getenv("PATH_TO_CA_CERT")),
            api_key(std::getenv("FORTIGATE_API_KEY")),
            port(std::stoi(std::getenv("ADMIN_SSH_PORT"))),
            url(std::format("https://{}:{}/api/v2", ip, port)) {
        headers["Authorization"] = std::format("Bearer {}", api_key);
    }

public:
    std::string url;
    nlohmann::json headers;

    // Singleton pattern
    static Auth& getInstance() {
        static Auth instance;
        return instance;
    }

    // Deleted methods to enforce singleton
    Auth(const Auth&) = delete;
    void operator=(const Auth&) = delete;

    [[nodiscard]] const std::string &getCertPath() const {
        return cert_path;
    }

    [[nodiscard]] const nlohmann::json &getHeaders() const {
        return headers;
    }
};

class API {
    static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
        ((std::string*)userp)->append((char*)contents, size * nmemb);
        return size * nmemb;
    }

    static nlohmann::json request(const std::string &method, const std::string &path, const nlohmann::json &data = {}) {
        CURL *curl;
        CURLcode res;
        std::string readBuffer;

        curl = curl_easy_init();
        if(curl) {
            std::string url = auth.url + path;

            struct curl_slist *headers = nullptr;
            for (auto& [key, value] : auth.getHeaders().items()) {
                headers = curl_slist_append(headers, std::format("{}: {}", key, nlohmann::to_string(value)).c_str());
            }
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
            curl_easy_setopt(curl, CURLOPT_CAINFO, auth.getCertPath().c_str());

            if (method == "POST") {
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.dump().c_str());
            } else if (method == "PUT") {
                curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.dump().c_str());
            } else if (method == "DELETE") {
                curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
            }

            res = curl_easy_perform(curl);
            if(res != CURLE_OK) {
                std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
            }
            curl_easy_cleanup(curl);
        }

        return nlohmann::json::parse(readBuffer);
    }

public:
    inline static Auth& auth = Auth::getInstance();

    static nlohmann::json get(const std::string &path) { return request("GET", path); }

    static void post(const std::string &path, const nlohmann::json &data) { request("POST", path, data); }

    static void put(const std::string &path, const nlohmann::json &data) { request("PUT", path, data); }

    static void del(const std::string &path) { request("DELETE", path); }
};

namespace Forti {

    inline bool isValid(const nlohmann::json& document, std::basic_string<char> schema) {
        nlohmann::json_schema::json_validator validator;
        validator.set_root_schema(nlohmann::json::parse(schema));

        try {
            validator.validate(document);
            return true;
        } catch (const std::exception& e) {
            return false;
        }
    }

    class DNSFilter {
        inline static std::string api_endpoint = std::format("{}/cmdb/dnsfilter/profile", API::auth.url);

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
                        filters = newFilters;
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
            auto response = API::get(std::format("{}/{}", api_endpoint, feed));
            nlohmann::json_schema::json_validator validator;
            validator.set_root_schema(nlohmann::json::parse(schemas::dns::response_schema_json));
            if (isValid(response, schemas::response_schema_json)) {
                auto results = response["results"];
                for (const auto& entry : results) {
                    if (entry["name"] == feed) return entry["ftgd_dns"]["filters"];
                }
            }
            return {};
        }
    };

} // namespace Forti

#endif //FORTI_API_H

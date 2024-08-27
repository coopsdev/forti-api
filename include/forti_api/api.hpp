//
// Created by Cooper Larson on 8/26/24.
//

#ifndef FORTI_API_API_HPP
#define FORTI_API_API_HPP

#include <cstring>
#include <nlohmann/json.hpp>
#include <iostream>
#include <format>
#include <curl/curl.h>

struct Response {
    unsigned int size{}, matched_count{}, next_idx{}, http_status{}, build{};
    std::string http_method, revision, vdom, path, name, status, serial, version;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(Response, http_method, size, matched_count, next_idx, revision,
                                   vdom, path, name, status, http_status, serial, version, build)
};

class Auth {
    std::string cert_path, api_key;
    nlohmann::json headers;

    friend class API;

    Auth() : cert_path(std::getenv("PATH_TO_FORTIGATE_CA_CERT")),
             api_key(std::getenv("FORTIGATE_API_KEY")) {
        headers["Authorization"] = std::format("Bearer {}", api_key);
    }

public:
    static Auth& getInstance() {
        static Auth instance;
        return instance;
    }

    Auth(const Auth&) = delete;
    void operator=(const Auth&) = delete;

    [[nodiscard]] const std::string& getCertPath() const { return cert_path; }
    [[nodiscard]] const nlohmann::json& getHeaders() const { return headers; }
};

class API {
    static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
        ((std::string*)userp)->append((char*)contents, size * nmemb);
        return size * nmemb;
    }

    template<typename T>
    static T request(const std::string &method, const std::string &path, const nlohmann::json &data = {}) {
        CURL *curl;
        CURLcode res;
        std::string readBuffer;

        curl = curl_easy_init();
        if(curl) {
            std::string url = base_api_endpoint + path;

            struct curl_slist *headers = nullptr;
            for (auto& [key, value] : auth.getHeaders().items()) {
                headers = curl_slist_append(headers, std::format("{}: {}", key, nlohmann::to_string(value)).c_str());
            }

            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
            curl_easy_setopt(curl, CURLOPT_CAINFO, auth.getCertPath().c_str());

            if (method == "POST") curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.dump().c_str());
            else if (method == "PUT") {
                curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.dump().c_str());
            } else if (method == "DELETE") curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");

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
    inline static std::string base_api_endpoint = std::format("https://{}:{}/api/v2",
                                                              std::getenv("FORTIGATE_GATEWAY_IP"),
                                                              std::stoi(std::getenv("FORTIGATE_ADMIN_SSH_PORT")));

    template<typename T>
    static T get(const std::string &path) { return request<T>("GET", path); }

    static void post(const std::string &path, const nlohmann::json &data) { request<Response>("POST", path, data); }
    static void put(const std::string &path, const nlohmann::json &data) { request<Response>("PUT", path, data); }
    static void del(const std::string &path) { request<Response>("DELETE", path); }
};

#endif //FORTI_API_API_HPP

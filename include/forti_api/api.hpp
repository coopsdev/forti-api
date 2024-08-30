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
#include <algorithm>
#include <cctype>

struct Response {
    unsigned int size{}, matched_count{}, next_idx{}, http_status{}, build{};
    std::string http_method, revision, vdom, path, name, status, serial, version;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(Response, http_method, size, matched_count, next_idx, revision,
                                                vdom, path, name, status, http_status, serial, version, build)
};

inline static nlohmann::json convert_keys_to_hyphens(const nlohmann::json& j) {
    nlohmann::json result;

    for (auto it = j.begin(); it != j.end(); ++it) {
        std::string key = it.key();
        std::replace(key.begin(), key.end(), '_', '-');

        if (it->is_object()) result[key] = convert_keys_to_hyphens(*it);
        else if (it->is_array()) {
            nlohmann::json array_result = nlohmann::json::array();
            for (const auto& elem : it.value()) {
                if (elem.is_object()) array_result.push_back(convert_keys_to_hyphens(elem));
                else array_result.push_back(elem);
            }
            result[key] = array_result;
        } else result[key] = *it;
    }

    return result;
}

inline static nlohmann::json convert_keys_to_underscores(const nlohmann::json& j) {
    nlohmann::json result;

    for (auto it = j.begin(); it != j.end(); ++it) {
        std::string key = it.key();
        std::replace(key.begin(), key.end(), '-', '_');

        if (it->is_object()) result[key] = convert_keys_to_underscores(*it);
        else if (it->is_array()) {
            nlohmann::json array_result = nlohmann::json::array();
            for (const auto& elem : it.value()) {
                if (elem.is_object()) array_result.push_back(convert_keys_to_underscores(elem));
                else array_result.push_back(elem);
            }
            result[key] = array_result;
        } else {
            result[key] = *it;
        }
    }

    return result;
}


class Auth {
    std::string ca_cert_path, ssl_cert_path, cert_password, api_key, auth_header;

    friend class API;

    Auth() : ca_cert_path(std::getenv("PATH_TO_FORTIGATE_CA_CERT")),
             ssl_cert_path(std::getenv("PATH_TO_FORTIGATE_SSL_CERT")),
             cert_password(std::getenv("FORTIGATE_SSL_CERT_PASS")),
             api_key(std::getenv("FORTIGATE_API_KEY")) {
        auth_header = std::format("Authorization: Bearer {}", api_key);
        assert_necessary_fields_exist();
    }

    void assert_necessary_fields_exist() {
        assert(!ca_cert_path.empty());
        assert(!ssl_cert_path.empty());
        assert(!cert_password.empty());
        assert(!api_key.empty());
        assert(!auth_header.empty());
    }

public:
    static Auth& getInstance() {
        static Auth instance;
        return instance;
    }

    Auth(const Auth&) = delete;
    void operator=(const Auth&) = delete;
};

class API {
    inline static Auth& auth = Auth::getInstance();
    inline static std::string base_api_endpoint = std::format("https://{}:{}/api/v2",
                                                              std::getenv("FORTIGATE_GATEWAY_IP"),
                                                              std::getenv("FORTIGATE_ADMIN_SSH_PORT"));

    static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
        ((std::string*)userp)->append((char*)contents, size * nmemb);
        return size * nmemb;
    }

    static int curl_debug_callback(CURL *handle, curl_infotype type, char *data, size_t size, void *userptr) {
        switch (type) {
            case CURLINFO_TEXT:
                std::cerr << "== Info: " << std::string(data, size);
                break;
            case CURLINFO_HEADER_OUT:
                std::cerr << "=> Send header: " << std::string(data, size);
                break;
            case CURLINFO_DATA_OUT:
                std::cerr << "=> Send data: " << std::string(data, size);
                break;
            case CURLINFO_SSL_DATA_OUT:
                std::cerr << "=> Send SSL data: " << std::string(data, size);
                break;
            case CURLINFO_HEADER_IN:
                std::cerr << "<= Recv header: " << std::string(data, size);
                break;
            case CURLINFO_DATA_IN:
                std::cerr << "<= Recv data: " << std::string(data, size);
                break;
            case CURLINFO_SSL_DATA_IN:
                std::cerr << "<= Recv SSL data: " << std::string(data, size);
                break;
            default:
                break;
        }
        return 0;
    }

    template<typename T>
    static T request(const std::string &method, const std::string &path, const nlohmann::json &data = {}) {
        CURL *curl;
        CURLcode res;
        std::string readBuffer;

        curl = curl_easy_init();
        if (curl) {
            std::string url = base_api_endpoint + path;

            struct curl_slist *headers = nullptr;
            headers = curl_slist_append(headers, "Content-Type: application/json");
            headers = curl_slist_append(headers, auth.auth_header.c_str());

            curl_easy_setopt(curl, CURLOPT_SSL_SESSIONID_CACHE, 1L);
            curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 0L);
            curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 0L);
            curl_easy_setopt(curl, CURLOPT_DNS_CACHE_TIMEOUT, -1);
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
            curl_easy_setopt(curl, CURLOPT_CAINFO, auth.ca_cert_path.c_str());
            curl_easy_setopt(curl, CURLOPT_SSLCERT, auth.ssl_cert_path.c_str());
            curl_easy_setopt(curl, CURLOPT_KEYPASSWD, auth.cert_password.c_str());

            std::string json_payload = convert_keys_to_hyphens(data).dump();  // do not simplify by deleting this
            if (method == "POST" || method == "PUT")
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload.c_str());

            if (method != "POST" && method != "GET")
                curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method.c_str());

#ifdef ENABLE_DEBUG
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
            curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, curl_debug_callback);
            curl_easy_setopt(curl, CURLOPT_DEBUGDATA, nullptr);
#endif

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
            curl_easy_cleanup(curl);
        }

        return convert_keys_to_underscores(nlohmann::json::parse(readBuffer));
    }

public:
    template<typename T>
    static T get(const std::string &path) { return request<T>("GET", path); }

    static void post(const std::string &path, const nlohmann::json &data) { request<Response>("POST", path, data); }
    static void put(const std::string &path, const nlohmann::json &data) { request<Response>("PUT", path, data); }
    static void del(const std::string &path) { request<Response>("DELETE", path); }
};

#endif //FORTI_API_API_HPP

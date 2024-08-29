//
// Created by Cooper Larson on 8/29/24.
//

#ifndef FORTI_API_DEFINE_TYPE_H
#define FORTI_API_DEFINE_TYPE_H

#include <nlohmann/json.hpp>
#include <string>
#include <algorithm>


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


#endif //FORTI_API_DEFINE_TYPE_H

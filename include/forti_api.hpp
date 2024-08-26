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

namespace Forti {

    inline bool isValid(const nlohmann::json& document, std::basic_string<char> schema) {
        nlohmann::json_schema::json_validator validator;
        validator.set_root_schema(nlohmann::json::parse(schema));

        try {
            validator.validate(document);
            return true;
        } catch (const std::exception& e) { return false; }
    }

} // namespace Forti

#endif //FORTI_API_H

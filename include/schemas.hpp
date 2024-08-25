// dns_schemas.hpp
#pragma once

#include <string>

namespace schemas {

const std::string response_schema_json = R"({
    "type": "object",
    "properties": {
        "http_method": {"type": "string"},
        "size": {"type": "integer"},
        "matched_count": {"type": "integer"},
        "next_idx": {"type": "integer"},
        "revision": {"type": "string"},
        "results": {"type": "array"},
        "vdom": {"type": "string"},
        "path": {"type": "string"},
        "name": {"type": "string"},
        "status": {"type": "string"},
        "http_status": {"type": "integer"},
        "serial": {"type": "string"},
        "version": {"type": "string"},
        "build": {"type": "integer"}
    },
    "required": [
        "http_method", "size", "matched_count", "next_idx", "revision",
        "results", "vdom", "path", "name", "status", "http_status",
        "serial", "version", "build"
    ]
})";

}

namespace schemas::dns {

const std::string filter_schema_json = R"({
    "type": "object",
    "properties": {
        "id": {"type": "integer"},
        "category": {"type": "integer"},
        "action": {"type": "string"},
        "log": {"type": "string"}
    },
    "required": ["id", "category", "action", "log"]
})";

const std::string dns_profile_schema_json = R"({
    "type": "object",
    "properties": {
        "options": {"type": "string"},
        "filters": {
            "type": "array",
            "items": )" + filter_schema_json + R"(
        }
    },
    "required": ["options", "filters"]
})";

const std::string dns_filter_schema_json = R"({
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "q_origin_key": {"type": "string"},
        "comment": {"type": "string"},
        "domain_filter": {
            "type": "array",
            "items": {"type": "string"}
        },
        "ftgd_dns": )" + dns_profile_schema_json + R"(
    },
    "required": ["name", "q_origin_key", "comment", "domain_filter", "ftgd_dns"]
})";

const std::string response_schema_json = R"({
    "type": "object",
    "properties": {
        "results": {
            "type": "array",
            "items": )" + dns_filter_schema_json + R"(
        }
    },
    "required": ["results"]
})";

} // namespace schemas::dns


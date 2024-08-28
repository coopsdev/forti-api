//
// Created by Cooper Larson on 8/28/24.
//

#include <gtest/gtest.h>
#include "include/forti_api/system.hpp"
#include <regex>

bool validate_ip_addr(const std::string& ip) {
    std::regex ipv4_regex(R"(^(\d{1,3}\.){3}\d{1,3}$)");
    return std::regex_match(ip, ipv4_regex);
}

TEST(TestSystem, TestGetWan1IP) {
    auto ip = System::get_wan_ip();
    ASSERT_TRUE(validate_ip_addr(ip)) << "Invalid IP: " << ip;
}

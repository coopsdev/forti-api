//
// Created by Cooper Larson on 8/28/24.
//

#include <gtest/gtest.h>
#include "include/forti_api/dns_filter.hpp"

TEST(TestDNSFilter, TestAddRemove) {
    std::string name = "test-123";
    ASSERT_TRUE(!DNSFilter::contains(name));

    DNSFilter::add(name);
    ASSERT_TRUE(DNSFilter::contains(name));

    DNSFilter::del(name);
    ASSERT_TRUE(!DNSFilter::contains(name));
}

TEST(TestDNSFilter, TestToggleFilters) {
    std::string name = "test-456";
    DNSFilter::add(name);
    ASSERT_TRUE(DNSFilter::contains(name));

    auto filter = DNSFilter::get(name);
    filter.allow_category(1);
    filter.block_category(2);
    filter.monitor_category(3);
    DNSFilter::update(filter);

    const auto& [match_found, index] = filter.ftgd_dns.binary_search(1);
    ASSERT_TRUE(!match_found);

    const auto& [match_found1, index1] = filter.ftgd_dns.binary_search(2);
    ASSERT_TRUE(match_found1);
    ASSERT_TRUE(filter.ftgd_dns.filters[index1].action == "block");

    const auto& [match_found2, index2] = filter.ftgd_dns.binary_search(3);
    ASSERT_TRUE(match_found2);
    ASSERT_TRUE(filter.ftgd_dns.filters[index2].action == "monitor");

    DNSFilter::del(filter.name);
    ASSERT_TRUE(!DNSFilter::contains(filter.name));
}

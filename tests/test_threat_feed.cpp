//
// Created by Cooper Larson on 8/28/24.
//

#include <gtest/gtest.h>
#include "include/forti_api/threat_feed.hpp"

TEST(TestThreatFeed, TestGetAllFeeds) {
    auto feeds = ThreatFeed::get();
    ASSERT_TRUE(!feeds.empty());
}

//
// Created by Cooper Larson on 8/31/24.
//

#ifndef FORTI_API_FIREWALL_HPP
#define FORTI_API_FIREWALL_HPP

#include "api.hpp"
#include "include/forti_api/types/policy.hpp"

namespace FortiGate {

    class Policy {
        inline static std::string endpoint = "/cmdb/firewall/policy";

    public:
        static std::vector<FirewallPolicy> get() { return FortiAPI::get<FirewallPoliciesResponse>(endpoint).results; }

        static FirewallPolicy get(const std::string& name) {
            auto policies = get();
            for (const auto& policy : policies) if (policy.name == name) return policy;
            throw std::runtime_error("Unable to locate firewall policy: " + name);
        }

        static void update(const FirewallPolicy& policy) {
            FortiAPI::put(std::format("{}/{}", endpoint, policy.policyid), policy);
        }
    };

}


#endif //FORTI_API_FIREWALL_HPP

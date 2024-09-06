//
// Created by Cooper Larson on 8/28/24.
//

#ifndef FORTI_API_SYSTEM_H
#define FORTI_API_SYSTEM_H

#include "api.hpp"
#include <string>
#include <utility>
#include <algorithm>


// SYSTEM INTERFACE TYPES

struct SystemResponse {
    unsigned int build{};
    std::string http_method, revision, vdom, path, name, action, status, serial, version;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(SystemResponse, build, http_method, revision, vdom, path, name, action,
                                   status, serial, version);
};

struct GeneralInterface {
    std::string name;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(GeneralInterface, name);
};

struct GeneralResponse : public Response {
    std::vector<GeneralInterface> results;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(GeneralResponse, http_method, size, matched_count, next_idx,
                                   revision, vdom, path, name, status, http_status, serial, version,
                                   build, results)
};

struct IPV4Address {
    std::string ip, netmask;
    unsigned int cidr_netmask{};

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(IPV4Address, ip, netmask, cidr_netmask);
};

struct SystemInterface {
    std::string name, type, real_interface_name, vdom, status, alias, vlan_protocol, role,
            mac_address, port_speed, media, physical_switch, link, duplex, icon;
    bool is_used{}, is_physical{}, dynamic_addressing{}, dhcp_interface{}, valid_in_policy{},
            is_ipsecable{}, is_routable{}, supports_fortilink{}, supports_dhcp{}, is_explicit_proxyable{},
            supports_device_id{}, supports_fortitelemetry{}, is_system_interface{}, monitor_bandwidth{};
    unsigned int in_bandwidth_limit{}, out_bandwidth_limit{}, dhcp4_client_count{}, dhcp6_client_count{},
            estimated_upstream_bandwidth{}, estimated_downstream_bandwidth{}, chip_id{}, speed{};
    std::vector<IPV4Address> ipv4_addresses{};
    std::vector<std::string> members{};

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(SystemInterface,
                                   name, type, real_interface_name, vdom, status, alias, vlan_protocol, role,
                                   mac_address, port_speed, media, physical_switch, link, duplex, icon,
                                   is_used, is_physical, dynamic_addressing, dhcp_interface, valid_in_policy,
                                   is_ipsecable, is_routable, supports_fortilink, supports_dhcp, is_explicit_proxyable,
                                   supports_device_id, supports_fortitelemetry, is_system_interface, monitor_bandwidth,
                                   in_bandwidth_limit, out_bandwidth_limit, dhcp4_client_count, dhcp6_client_count,
                                   estimated_upstream_bandwidth, estimated_downstream_bandwidth, chip_id, speed,
                                   ipv4_addresses
    )
};

struct VirtualWANLink {
    std::string name, vdom, status, type, link, icon;
    bool is_sdwan_zone{}, valid_in_policy{};
    std::vector<std::string> members{};

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(VirtualWANLink, name, vdom, status, type, link, icon, is_sdwan_zone,
                                                valid_in_policy, members);
};

struct InterfacesGeneralResponse : public SystemResponse {
    std::vector<nlohmann::json> results;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(InterfacesGeneralResponse, build, http_method, revision, vdom, path,
                                                name, action, status, serial, version, results);
};


// SYSTEM ADMIN TYPES

struct VDomEntry {
    std::string name, q_origin_key;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(VDomEntry, name, q_origin_key)
};

enum class TrustHostType {
    IPV4,
    IPV6,
};

struct TrustHostEntry {
    unsigned int id{}, q_origin_key{};
    std::string type;

    TrustHostEntry() = default;
    explicit TrustHostEntry(std::string type) : type(std::move(type)) {}

    [[nodiscard]] virtual TrustHostType get_type() const = 0;
    [[nodiscard]] virtual std::string get_subnet() const = 0;
    virtual ~TrustHostEntry() = default;

    [[nodiscard]] bool is_ipv4() const { return get_type() == TrustHostType::IPV4; }
    [[nodiscard]] bool is_ipv6() const { return get_type() == TrustHostType::IPV6; }

    friend void to_json(nlohmann::json& j, const TrustHostEntry& host) {
        j = nlohmann::json{
                {"id", host.id},
                {"q_origin_key", host.q_origin_key},
                {"type", host.type},
                {host.is_ipv4() ? "ipv4-trusthost" : "ipv6-trusthost", host.get_subnet()}
        };
    }
};

// Derived class for IPv4 TrustHost
struct IPV4TrustHost : public TrustHostEntry {
    std::string ipv4_trusthost;

    [[nodiscard]] TrustHostType get_type() const override { return TrustHostType::IPV4; }
    [[nodiscard]] std::string get_subnet() const override { return ipv4_trusthost; }

    IPV4TrustHost() = default;
    explicit IPV4TrustHost(std::string ip_addr) : TrustHostEntry("ipv4-trusthost"), ipv4_trusthost(std::move(ip_addr)) {}

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(IPV4TrustHost, id, q_origin_key, type, ipv4_trusthost)
};

// Derived class for IPv6 TrustHost
struct IPV6TrustHost : public TrustHostEntry {
    std::string ipv6_trusthost;

    [[nodiscard]] TrustHostType get_type() const override { return TrustHostType::IPV6; }
    [[nodiscard]] std::string get_subnet() const override { return ipv6_trusthost; }

    IPV6TrustHost() = default;
    explicit IPV6TrustHost(std::string ip_addr) : TrustHostEntry("ipv4-trusthost"), ipv6_trusthost(std::move(ip_addr)) {}

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(IPV6TrustHost, id, q_origin_key, type, ipv6_trusthost)
};

struct TrustHost : public std::vector<std::shared_ptr<TrustHostEntry>> {
    friend void from_json(const nlohmann::json& j, TrustHost& th) {
        for (const auto& item : j) {
            auto type = item.at("type").get<std::string>();
            if (type == "ipv4-trusthost") th.push_back(std::make_shared<IPV4TrustHost>(item));
            else th.push_back(std::make_shared<IPV6TrustHost>(item));
        }
    }

    friend void to_json(nlohmann::json& j, const TrustHost& th) {
        for (const auto& host : th) j.push_back(*host);
    }
};

struct APIUser {
    inline static std::string api_user_endpoint = "/cmdb/system/api-user";
    std::string name, q_origin_key, comments, api_key, accprofile, schedule, cors_allow_origin,
            peer_auth, peer_group;
    TrustHost trusthost;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(APIUser, name, q_origin_key, comments, api_key, accprofile,
                                                schedule, cors_allow_origin, peer_auth, peer_group, trusthost)

    bool is_trusted(const std::string& subnet) {
        return std::any_of(trusthost.begin(), trusthost.end(),
                           [&subnet](const std::shared_ptr<TrustHostEntry>& host) {
                               return host->get_subnet() == subnet;
                           });
    }

    void trust(const std::string& subnet) {
        if (is_trusted(subnet)) return;
        if (std::regex_match(subnet, ipv4)) trusthost.push_back(std::make_shared<IPV4TrustHost>(subnet));
        else if (std::regex_match(subnet, ipv6)) trusthost.push_back(std::make_shared<IPV6TrustHost>(subnet));
    }

    void distrust(const std::string& subnet) {
        if (!is_trusted(subnet)) return;
        trusthost.erase(std::remove_if(trusthost.begin(), trusthost.end(),
                                       [&subnet](const std::shared_ptr<TrustHostEntry>& entry) {
                                           return entry->get_subnet() == subnet;
                                       }), trusthost.end());
    }

    void update() {
        FortiAPI::put(std::format("{}/{}", api_user_endpoint, name), *this);
    }
};

struct AllAPIUsersResponse : public Response {
    std::vector<APIUser> results;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(AllAPIUsersResponse, http_method, size, matched_count, next_idx,
                                                revision, vdom, path, name, status, http_status, serial, version,
                                                build, results)
};

namespace System {

    class Interface {
        inline static std::string available_interfaces_endpoint = "/monitor/system/available-interfaces";

        inline static std::vector<SystemInterface> physical_interfaces{},
                tunnel_interfaces{},
                hard_switch_vlan_interfaces{},
                aggregate_interfaces{};

        static void update_local_interface_data() {
            physical_interfaces.clear();
            tunnel_interfaces.clear();
            hard_switch_vlan_interfaces.clear();
            aggregate_interfaces.clear();

            auto interfaces = FortiAPI::get<InterfacesGeneralResponse>(available_interfaces_endpoint);
            for (const auto& interface : interfaces.results) {
                if (!interface.contains("type")) continue;
                auto type = interface["type"].get<std::string>();

                if (type == "physical") physical_interfaces.emplace_back(interface);
                else if (type == "tunnel") tunnel_interfaces.emplace_back(interface);
                else if (type == "hard-switch-vlan") hard_switch_vlan_interfaces.emplace_back(interface);
                else if (type == "aggregate") aggregate_interfaces.emplace_back(interface);
            }
        }

        static unsigned int count_interfaces() {
            return FortiAPI::get<GeneralResponse>(available_interfaces_endpoint).results.size();
        }

        static nlohmann::json get(const std::string& name, const std::string& vdom = "root") {
            std::string endpoint =
                    std::format("{}?vdom={}&mkey={}", available_interfaces_endpoint, vdom, name);

            return FortiAPI::get<std::vector<nlohmann::json>>(endpoint)[0];
        }

        static SystemInterface get(const std::vector<SystemInterface>& interfaces,
                                   const std::string& name, const std::string& vdom = "root") {
            if (interfaces.empty()) update_local_interface_data();
            for (const auto& interface : interfaces)
                if (interface.name == name && interface.vdom == vdom) return interface;
            throw std::runtime_error(std::format("No system interface found for: {}", name));
        }

    public:
        static SystemInterface get_physical_interface(const std::string& name, const std::string& vdom = "root") {
            return get(physical_interfaces, name, vdom);
        }

        static SystemInterface get_tunnel_interface(const std::string& name, const std::string& vdom = "root") {
            return get(tunnel_interfaces, name, vdom);
        }

        static SystemInterface get_hard_vlan_switch_interface(const std::string& name, const std::string& vdom = "root") {
            return get(hard_switch_vlan_interfaces, name, vdom);
        }

        static SystemInterface get_aggregate_interface(const std::string& name, const std::string& vdom = "root") {
            return get(aggregate_interfaces, name, vdom);
        }

        static VirtualWANLink get_virtual_wan_link(const std::string& name = "virtual-wan-link", const std::string& vdom = "root") {
            return get(name, vdom);
        }

        static std::string get_wan_ip(unsigned int wan_port = 1, const std::string& vdom = "root") {
            return get_physical_interface(std::format("wan{}", wan_port), vdom).ipv4_addresses[0].ip;
        }
    }; // System::Interface

    class Admin {
        inline static std::string admin_endpoint = "/cmdb/system/admin";
        inline static std::string admin_profiles_endpoint = "cmdb/system/accprofile";

    public:

        class API {
            inline static std::string api_user_endpoint = "/cmdb/system/api-user";

            static std::string get_trusthost_endpoint(const std::string& admin) {
                return std::format("{}/{}/trusthost", api_user_endpoint, admin);
            }

        public:
            static std::vector<APIUser> get() {
                return FortiAPI::get<AllAPIUsersResponse>(api_user_endpoint).results;
            }

            static APIUser get(const std::string& api_admin_name) {
                auto endpoint = std::format("{}/{}", api_user_endpoint, api_admin_name);
                auto response = FortiAPI::get<AllAPIUsersResponse>(endpoint);
                if (response.status == "success") return response.results[0];
                else throw std::runtime_error("API Admin user " + api_admin_name + " not found...");
            }
        };
    };

}  // namespace System



#endif //FORTI_API_SYSTEM_H

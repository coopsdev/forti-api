//
// Created by Cooper Larson on 8/28/24.
//

#ifndef FORTI_API_SYSTEM_H
#define FORTI_API_SYSTEM_H

#include "api.hpp"
#include <string>
#include <nlohmann/json.hpp>


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

struct PhysicalInterface {

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

class System {
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
};

#endif //FORTI_API_SYSTEM_H

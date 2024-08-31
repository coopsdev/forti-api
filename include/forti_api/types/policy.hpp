//
// Created by Cooper Larson on 8/31/24.
//

#ifndef FORTI_API_POLICY_HPP
#define FORTI_API_POLICY_HPP

#include "api.hpp"
#include <vector>

template<typename T>
void to_json_vector(nlohmann::json& j, const std::string& key, const std::vector<T>& vec) {
    j[key] = vec;
}

template<typename T>
void from_json_vector(const nlohmann::json& j, const std::string& key, std::vector<T>& vec) {
    if (j.contains(key)) {
        j.at(key).get_to(vec);
    }
}

struct Module { std::string name, q_origin_key; };

struct Interface : public Module {
    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(Interface, name, q_origin_key)
};

struct Address : public Module {
    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(Address, name, q_origin_key)
};

struct Service : public Module {
    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(Service, name, q_origin_key)
};

struct FirewallPolicy {
    unsigned int policyid{}, q_origin_key{}, uuid_idx{};
    std::string status = "disable", name, uuid, action = "deny";

    std::vector<Interface> srcintf, dstintf;
    std::vector<Address> srcaddr, dstaddr;
    std::vector<Service> service;

    std::vector<std::string> srcaddr6, dstaddr6, ztna_ems_tag, ztna_geo_tag, internet_service_name, internet_service_group,
            internet_service_custom, network_service_dynamic, internet_service_custom_group, internet_service_src_name,
            internet_service_src_group, internet_service_src_custom, network_service_src_dynamic, internet_service_src_custom_group,
            src_vendor_mac, internet_service6_name, internet_service6_group, internet_service6_custom, internet_service6_custom_group,
            internet_service6_src_name, internet_service6_src_group, internet_service6_src_custom, internet_service6_src_custom_group,
            rtp_addr, ntlm_enabled_browsers, groups, users, fsso_groups, poolname, poolname6, custom_log_fields, sgt;

    std::string nat64 = "disable", nat46 = "disable", ztna_status = "disable", ztna_device_ownership = "disable",
            ztna_tags_match_logic = "or", internet_service = "disable", internet_service_src = "disable",
            reputation_direction = "destination", internet_service6 = "disable", reputation_direction6 = "destination",
            rtp_nat = "disable", send_deny_packet = "disable", firewall_session_dirty = "check-all",
            schedule = "always", schedule_timeout = "disable", policy_expiry = "disable", policy_behaviour_type = "standard",
            ip_version_type = "ipv4", tos = "0x00", tos_mask = "0x00", tos_negate = "disable",
            anti_replay = "enable", tcp_session_without_syn = "disable", geoip_anycast = "disable", geoip_match = "physical-location",
            dynamic_shaping = "disable", passive_wan_health_measurement = "disable", utm_status = "disable", inspection_mode = "flow",
            http_policy_redirect = "disable", ssh_policy_redirect = "disable", ztna_policy_redirect = "disable",
            profile_type = "single", profile_protocol_options = "default", ssl_ssh_profile = "no-inspection",
            logtraffic = "utm", logtraffic_start = "disable", capture_packet = "disable",
            auto_asic_offload = "enable", np_acceleration = "enable", nat = "enable", permit_any_host = "disable", permit_stun_host = "disable",
            fixedport = "disable", ippool = "disable", session_ttl = "0", inbound = "disable", outbound = "enable",
            natinbound = "disable", natoutbound = "disable", fec = "disable", wccp = "disable", ntlm = "disable",
            ntlm_guest = "disable", auth_path = "disable", disclaimer = "disable",
            email_collect = "disable", vpntunnel, natip = "0.0.0.0 0.0.0.0", match_vip = "enable", match_vip_only = "disable",
            diffserv_copy = "disable", diffserv_forward = "disable", diffserv_reverse = "disable", diffservcode_forward = "000000",
            diffservcode_rev = "000000", block_notification = "disable", replacemsg_override_group,
            srcaddr_negate = "disable", srcaddr6_negate = "disable", dstaddr_negate = "disable", dstaddr6_negate = "disable",
            service_negate = "disable", internet_service_negate = "disable", internet_service_src_negate = "disable",
            internet_service6_negate = "disable", internet_service6_src_negate = "disable", timeout_send_rst = "disable",
            captive_portal_exempt = "disable", decrypted_traffic_mirror, dsri = "disable", radius_mac_auth_bypass = "disable",
            delay_tcp_npu_session = "disable", vlan_filter, sgt_check = "disable", internet_service6_src = "disable",
            dnsfilter_profile, webfilter_profile;

    unsigned int reputation_minimum{}, reputation_minimum6{}, vlan_cos_fwd{255}, vlan_cos_rev{255}, tcp_mss_sender{}, tcp_mss_receiver{};

    void enable() { status = "enable"; }
    void disable() { status = "disable"; }
    void set_dns_filter(const std::string& profile_name) { dnsfilter_profile = profile_name; }
};

void to_json(nlohmann::json& j, const FirewallPolicy& p) {
    j = nlohmann::json{
            {"policyid", p.policyid},
            {"q_origin_key", p.q_origin_key},
            {"uuid_idx", p.uuid_idx},
            {"status", p.status},
            {"name", p.name},
            {"uuid", p.uuid},
            {"action", p.action},
            {"srcintf", p.srcintf},
            {"dstintf", p.dstintf},
            {"srcaddr", p.srcaddr},
            {"dstaddr", p.dstaddr},
            {"service", p.service},
            {"srcaddr6", p.srcaddr6},
            {"dstaddr6", p.dstaddr6},
            {"ztna_ems_tag", p.ztna_ems_tag},
            {"ztna_geo_tag", p.ztna_geo_tag},
            {"internet_service_name", p.internet_service_name},
            {"internet_service_group", p.internet_service_group},
            {"internet_service_custom", p.internet_service_custom},
            {"network_service_dynamic", p.network_service_dynamic},
            {"network_service_custom_group", p.internet_service_custom_group},
            {"internet_service_src_name", p.internet_service_src_name},
            {"internet_service_src_group", p.internet_service_src_group},
            {"internet_service_src_custom", p.internet_service_src_custom},
            {"network_service_src_dynamic", p.network_service_src_dynamic},
            {"internet_service_src_custom_group", p.internet_service_src_custom_group},
            {"src_vendor_mac", p.src_vendor_mac},
            {"internet_service6_name", p.internet_service6_name},
            {"internet_service6_group", p.internet_service6_group},
            {"internet_service6_custom", p.internet_service6_custom},
            {"internet_service6_custom_group", p.internet_service6_custom_group},
            {"internet_service6_src_name", p.internet_service6_src_name},
            {"internet_service6_src_group", p.internet_service6_src_group},
            {"internet_service6_src_custom", p.internet_service6_src_custom},
            {"internet_service6_src_custom_group", p.internet_service6_src_custom_group},
            {"rtp_addr", p.rtp_addr},
            {"ntlm_enabled_browsers", p.ntlm_enabled_browsers},
            {"groups", p.groups},
            {"users", p.users},
            {"fsso_groups", p.fsso_groups},
            {"poolname", p.poolname},
            {"poolname6", p.poolname6},
            {"custom_log_fields", p.custom_log_fields},
            {"sgt", p.sgt},
            {"nat64", p.nat64},
            {"nat46", p.nat46},
            {"ztna_status", p.ztna_status},
            {"ztna_device_ownership", p.ztna_device_ownership},
            {"ztna_tags_match_logic", p.ztna_tags_match_logic},
            {"internet_service", p.internet_service},
            {"internet_service_src", p.internet_service_src},
            {"reputation_direction", p.reputation_direction},
            {"internet_service6", p.internet_service6},
            {"reputation_direction6", p.reputation_direction6},
            {"rtp_nat", p.rtp_nat},
            {"send_deny_packet", p.send_deny_packet},
            {"firewall_session_dirty", p.firewall_session_dirty},
            {"schedule", p.schedule},
            {"schedule_timeout", p.schedule_timeout},
            {"policy_expiry", p.policy_expiry},
            {"policy_behaviour_type", p.policy_behaviour_type},
            {"ip_version_type", p.ip_version_type},
            {"tos", p.tos},
            {"tos_mask", p.tos_mask},
            {"tos_negate", p.tos_negate},
            {"anti_replay", p.anti_replay},
            {"tcp_session_without_syn", p.tcp_session_without_syn},
            {"geoip_anycast", p.geoip_anycast},
            {"geoip_match", p.geoip_match},
            {"dynamic_shaping", p.dynamic_shaping},
            {"passive_wan_health_measurement", p.passive_wan_health_measurement},
            {"utm_status", p.utm_status},
            {"inspection_mode", p.inspection_mode},
            {"http_policy_redirect", p.http_policy_redirect},
            {"ssh_policy_redirect", p.ssh_policy_redirect},
            {"ztna_policy_redirect", p.ztna_policy_redirect},
            {"profile_type", p.profile_type},
            {"profile_protocol_options", p.profile_protocol_options},
            {"ssl_ssh_profile", p.ssl_ssh_profile},
            {"logtraffic", p.logtraffic},
            {"logtraffic_start", p.logtraffic_start},
            {"capture_packet", p.capture_packet},
            {"auto_asic_offload", p.auto_asic_offload},
            {"np_acceleration", p.np_acceleration},
            {"nat", p.nat},
            {"permit_any_host", p.permit_any_host},
            {"permit_stun_host", p.permit_stun_host},
            {"fixedport", p.fixedport},
            {"ippool", p.ippool},
            {"session_ttl", p.session_ttl},
            {"vlan_cos_fwd", p.vlan_cos_fwd},
            {"vlan_cos_rev", p.vlan_cos_rev},
            {"inbound", p.inbound},
            {"outbound", p.outbound},
            {"natinbound", p.natinbound},
            {"natoutbound", p.natoutbound},
            {"fec", p.fec},
            {"wccp", p.wccp},
            {"ntlm", p.ntlm},
            {"ntlm_guest", p.ntlm_guest},
            {"auth_path", p.auth_path},
            {"disclaimer", p.disclaimer},
            {"email_collect", p.email_collect},
            {"vpntunnel", p.vpntunnel},
            {"natip", p.natip},
            {"match_vip", p.match_vip},
            {"match_vip_only", p.match_vip_only},
            {"diffserv_copy", p.diffserv_copy},
            {"diffserv_forward", p.diffserv_forward},
            {"diffserv_reverse", p.diffserv_reverse},
            {"diffservcode_forward", p.diffservcode_forward},
            {"diffservcode_rev", p.diffservcode_rev},
            {"block_notification", p.block_notification},
            {"replacemsg_override_group", p.replacemsg_override_group},
            {"srcaddr_negate", p.srcaddr_negate},
            {"srcaddr6_negate", p.srcaddr6_negate},
            {"dstaddr_negate", p.dstaddr_negate},
            {"dstaddr6_negate", p.dstaddr6_negate},
            {"service_negate", p.service_negate},
            {"internet_service_negate", p.internet_service_negate},
            {"internet_service_src_negate", p.internet_service_src_negate},
            {"internet_service6_negate", p.internet_service6_negate},
            {"internet_service6_src_negate", p.internet_service6_src_negate},
            {"timeout_send_rst", p.timeout_send_rst},
            {"captive_portal_exempt", p.captive_portal_exempt},
            {"decrypted_traffic_mirror", p.decrypted_traffic_mirror},
            {"dsri", p.dsri},
            {"radius_mac_auth_bypass", p.radius_mac_auth_bypass},
            {"delay_tcp_npu_session", p.delay_tcp_npu_session},
            {"vlan_filter", p.vlan_filter},
            {"sgt_check", p.sgt_check},
            {"sgt", p.sgt},
            {"reputation_minimum", p.reputation_minimum},
            {"reputation_minimum6", p.reputation_minimum6},
            {"tcp_mss_sender", p.tcp_mss_sender},
            {"tcp_mss_receiver", p.tcp_mss_receiver},
            {"dnsfilter_profile", p.dnsfilter_profile},
            {"webfilter_profile", p.webfilter_profile}
    };
}

void from_json(const nlohmann::json& j, FirewallPolicy& p) {
    j.at("policyid").get_to(p.policyid);
    j.at("q_origin_key").get_to(p.q_origin_key);
    j.at("uuid_idx").get_to(p.uuid_idx);
    j.at("status").get_to(p.status);
    j.at("name").get_to(p.name);
    j.at("uuid").get_to(p.uuid);
    j.at("action").get_to(p.action);
    j.at("srcintf").get_to(p.srcintf);
    j.at("dstintf").get_to(p.dstintf);
    j.at("srcaddr").get_to(p.srcaddr);
    j.at("dstaddr").get_to(p.dstaddr);
    j.at("service").get_to(p.service);
    j.at("srcaddr6").get_to(p.srcaddr6);
    j.at("dstaddr6").get_to(p.dstaddr6);
    j.at("ztna_ems_tag").get_to(p.ztna_ems_tag);
    j.at("ztna_geo_tag").get_to(p.ztna_geo_tag);
    j.at("internet_service_name").get_to(p.internet_service_name);
    j.at("internet_service_group").get_to(p.internet_service_group);
    j.at("internet_service_custom").get_to(p.internet_service_custom);
    j.at("network_service_dynamic").get_to(p.network_service_dynamic);
    j.at("network_service_custom_group").get_to(p.internet_service_custom_group);
    j.at("internet_service_src_name").get_to(p.internet_service_src_name);
    j.at("internet_service_src_group").get_to(p.internet_service_src_group);
    j.at("internet_service_src_custom").get_to(p.internet_service_src_custom);
    j.at("network_service_src_dynamic").get_to(p.network_service_src_dynamic);
    j.at("internet_service_src_custom_group").get_to(p.internet_service_src_custom_group);
    j.at("src_vendor_mac").get_to(p.src_vendor_mac);
    j.at("internet_service6_name").get_to(p.internet_service6_name);
    j.at("internet_service6_group").get_to(p.internet_service6_group);
    j.at("internet_service6_custom").get_to(p.internet_service6_custom);
    j.at("internet_service6_custom_group").get_to(p.internet_service6_custom_group);
    j.at("internet_service6_src_name").get_to(p.internet_service6_src_name);
    j.at("internet_service6_src_group").get_to(p.internet_service6_src_group);
    j.at("internet_service6_src_custom").get_to(p.internet_service6_src_custom);
    j.at("internet_service6_src_custom_group").get_to(p.internet_service6_src_custom_group);
    j.at("rtp_addr").get_to(p.rtp_addr);
    j.at("ntlm_enabled_browsers").get_to(p.ntlm_enabled_browsers);
    j.at("groups").get_to(p.groups);
    j.at("users").get_to(p.users);
    j.at("fsso_groups").get_to(p.fsso_groups);
    j.at("poolname").get_to(p.poolname);
    j.at("poolname6").get_to(p.poolname6);
    j.at("custom_log_fields").get_to(p.custom_log_fields);
    j.at("sgt").get_to(p.sgt);
    j.at("nat64").get_to(p.nat64);
    j.at("nat46").get_to(p.nat46);
    j.at("ztna_status").get_to(p.ztna_status);
    j.at("ztna_device_ownership").get_to(p.ztna_device_ownership);
    j.at("ztna_tags_match_logic").get_to(p.ztna_tags_match_logic);
    j.at("internet_service").get_to(p.internet_service);
    j.at("internet_service_src").get_to(p.internet_service_src);
    j.at("reputation_direction").get_to(p.reputation_direction);
    j.at("internet_service6").get_to(p.internet_service6);
    j.at("reputation_direction6").get_to(p.reputation_direction6);
    j.at("rtp_nat").get_to(p.rtp_nat);
    j.at("send_deny_packet").get_to(p.send_deny_packet);
    j.at("firewall_session_dirty").get_to(p.firewall_session_dirty);
    j.at("schedule").get_to(p.schedule);
    j.at("schedule_timeout").get_to(p.schedule_timeout);
    j.at("policy_expiry").get_to(p.policy_expiry);
    j.at("policy_behaviour_type").get_to(p.policy_behaviour_type);
    j.at("ip_version_type").get_to(p.ip_version_type);
    j.at("tos").get_to(p.tos);
    j.at("tos_mask").get_to(p.tos_mask);
    j.at("tos_negate").get_to(p.tos_negate);
    j.at("anti_replay").get_to(p.anti_replay);
    j.at("tcp_session_without_syn").get_to(p.tcp_session_without_syn);
    j.at("geoip_anycast").get_to(p.geoip_anycast);
    j.at("geoip_match").get_to(p.geoip_match);
    j.at("dynamic_shaping").get_to(p.dynamic_shaping);
    j.at("passive_wan_health_measurement").get_to(p.passive_wan_health_measurement);
    j.at("utm_status").get_to(p.utm_status);
    j.at("inspection_mode").get_to(p.inspection_mode);
    j.at("http_policy_redirect").get_to(p.http_policy_redirect);
    j.at("ssh_policy_redirect").get_to(p.ssh_policy_redirect);
    j.at("ztna_policy_redirect").get_to(p.ztna_policy_redirect);
    j.at("profile_type").get_to(p.profile_type);
    j.at("profile_protocol_options").get_to(p.profile_protocol_options);
    j.at("ssl_ssh_profile").get_to(p.ssl_ssh_profile);
    j.at("logtraffic").get_to(p.logtraffic);
    j.at("logtraffic_start").get_to(p.logtraffic_start);
    j.at("capture_packet").get_to(p.capture_packet);
    j.at("auto_asic_offload").get_to(p.auto_asic_offload);
    j.at("np_acceleration").get_to(p.np_acceleration);
    j.at("nat").get_to(p.nat);
    j.at("permit_any_host").get_to(p.permit_any_host);
    j.at("permit_stun_host").get_to(p.permit_stun_host);
    j.at("fixedport").get_to(p.fixedport);
    j.at("ippool").get_to(p.ippool);
    j.at("session_ttl").get_to(p.session_ttl);
    j.at("vlan_cos_fwd").get_to(p.vlan_cos_fwd);
    j.at("vlan_cos_rev").get_to(p.vlan_cos_rev);
    j.at("inbound").get_to(p.inbound);
    j.at("outbound").get_to(p.outbound);
    j.at("natinbound").get_to(p.natinbound);
    j.at("natoutbound").get_to(p.natoutbound);
    j.at("fec").get_to(p.fec);
    j.at("wccp").get_to(p.wccp);
    j.at("ntlm").get_to(p.ntlm);
    j.at("ntlm_guest").get_to(p.ntlm_guest);
    j.at("auth_path").get_to(p.auth_path);
    j.at("disclaimer").get_to(p.disclaimer);
    j.at("email_collect").get_to(p.email_collect);
    j.at("vpntunnel").get_to(p.vpntunnel);
    j.at("natip").get_to(p.natip);
    j.at("match_vip").get_to(p.match_vip);
    j.at("match_vip_only").get_to(p.match_vip_only);
    j.at("diffserv_copy").get_to(p.diffserv_copy);
    j.at("diffserv_forward").get_to(p.diffserv_forward);
    j.at("diffserv_reverse").get_to(p.diffserv_reverse);
    j.at("diffservcode_forward").get_to(p.diffservcode_forward);
    j.at("diffservcode_rev").get_to(p.diffservcode_rev);
    j.at("block_notification").get_to(p.block_notification);
    j.at("replacemsg_override_group").get_to(p.replacemsg_override_group);
    j.at("srcaddr_negate").get_to(p.srcaddr_negate);
    j.at("srcaddr6_negate").get_to(p.srcaddr6_negate);
    j.at("dstaddr_negate").get_to(p.dstaddr_negate);
    j.at("dstaddr6_negate").get_to(p.dstaddr6_negate);
    j.at("service_negate").get_to(p.service_negate);
    j.at("internet_service_negate").get_to(p.internet_service_negate);
    j.at("internet_service_src_negate").get_to(p.internet_service_src_negate);
    j.at("internet_service6_negate").get_to(p.internet_service6_negate);
    j.at("internet_service6_src_negate").get_to(p.internet_service6_src_negate);
    j.at("timeout_send_rst").get_to(p.timeout_send_rst);
    j.at("captive_portal_exempt").get_to(p.captive_portal_exempt);
    j.at("decrypted_traffic_mirror").get_to(p.decrypted_traffic_mirror);
    j.at("dsri").get_to(p.dsri);
    j.at("radius_mac_auth_bypass").get_to(p.radius_mac_auth_bypass);
    j.at("delay_tcp_npu_session").get_to(p.delay_tcp_npu_session);
    j.at("vlan_filter").get_to(p.vlan_filter);
    j.at("sgt_check").get_to(p.sgt_check);
    j.at("sgt").get_to(p.sgt);
    j.at("reputation_minimum").get_to(p.reputation_minimum);
    j.at("reputation_minimum6").get_to(p.reputation_minimum6);
    j.at("tcp_mss_sender").get_to(p.tcp_mss_sender);
    j.at("tcp_mss_receiver").get_to(p.tcp_mss_receiver);
    j.at("dnsfilter_profile").get_to(p.dnsfilter_profile);
    j.at("webfilter_profile").get_to(p.webfilter_profile);
}

struct FirewallPoliciesResponse : public Response {
    std::vector<FirewallPolicy> results;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(FirewallPoliciesResponse, http_method, size, matched_count, next_idx,
            revision, vdom, path, name, status, http_status, serial, version,
            build, results)
};

#endif //FORTI_API_POLICY_HPP

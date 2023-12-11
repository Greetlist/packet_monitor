#include "prom_client.h"

PromeClient::PromeClient(const std::string& server_addr, const std::string& record_vlan_vec) : server_addr_(server_addr), record_vlan_vec_str_(record_vlan_vec), exposer_(server_addr) {
}

void PromeClient::Init() {
  size_t start_index = 0, end_index = 0;
  while (1) {
    end_index = record_vlan_vec_str_.find(",", start_index);
    if (end_index == std::string::npos) {
      record_vlan_vec_.push_back(std::stoi(std::string{record_vlan_vec_str_, start_index}));
      break;
    } else {
      record_vlan_vec_.push_back(std::stoi(std::string{record_vlan_vec_str_, start_index, end_index}));
      start_index = end_index + 1;
    }
  }
  registry_ = std::make_shared<Registry>();
  auto& counter_family = BuildCounter()
      .Name("packet_counter")
      .Help("Network Packet Counter")
      .Register(*registry_);

  for (auto& vlan : record_vlan_vec_) {
    if (auto iter = counter_map_.find(vlan); iter == counter_map_.end()) {
      counter_map_[vlan] = std::unordered_map<std::string, FC>();
    }
    for (auto& [t, ts] : TYPE_MAP) {
      FC fc{"packet_conter", "Network Packet Couneter", {{"protocol_type", std::to_string(t)}, {"protocol_name", ts}, {"vlan", std::to_string(vlan)}}};
      //counter_map_[vlan].insert(std::make_pair(ts, fc));
    }
  }
  exposer_.RegisterCollectable(registry_);
}

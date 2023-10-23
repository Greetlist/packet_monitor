#include "prom_client.h"

PromeClient::PromeClient(const std::string& server_addr, const std::vector<int>& record_vlan_vec) : server_addr_(server_addr), record_vlan_vec_(record_vlan_vec), exposer_(server_addr) {
}

void PromeClient::Init() {
  registry_ = std::make_shared<Registry>();
  auto counter_family = BuildCounter()
      .Name("packet_counter")
      .Help("Network Packet Counter")
      .Register(*registry_);

  for (auto& vlan : record_vlan_vec_) {
    for (auto& [t, ts] : TYPE_MAP) {
      counter_map_[vlan] = counter_family.Add({{"protocol_type", t}, {"protocol_name", ts}, {"vlan", vlan}});
    }
  }
  exposer_.RegisterCollectable(registry_);
}

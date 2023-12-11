#ifndef __PROM_CLIENT_H_
#define __PROM_CLIENT_H_

#include <prometheus/counter.h>
#include <prometheus/exposer.h>
#include <prometheus/registry.h>

#include <string>
#include <vector>
#include <memory>

#include "record_struct.h"

using namespace prometheus;
typedef Family<Counter> FC;

class PromeClient {
public:
  PromeClient(const std::string& server_addr, const std::string& record_vlan_vec);
  ~PromeClient() = default;
  void Init();
  std::unordered_map<int, std::unordered_map<std::string, FC>> counter_map_;
private:
  std::string server_addr_;
  std::string record_vlan_vec_str_;
  std::vector<int> record_vlan_vec_;
  Exposer exposer_;
  std::shared_ptr<Registry> registry_;
  Counter packet_counter_;
};

#endif

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

class PromeClient {
public:
  PromeClient(const std::string& server_addr, const std::vector<int>& record_vlan_vec);
  ~PromeClient() = default;
  void Init();
private:
  std::string server_addr_;
  std::vector<int> record_vlan_vec_;
  std::vector<Counter> counter_vec_;
  std::unordered_map<int, Counter> counter_map_;
  Exposer exposer_;
  std::shared_ptr<Registry> registry_;
  Counter packet_counter_;
};

#endif

#ifndef __RECORD_STRUCT_H_
#define __RECORD_STRUCT_H_

#include <unordered_map>

struct PacketNum {
  PacketNum() : ICMP_packet_num_(0), TCP_packet_num_(0), UDP_packet_num_(0) {}
  ~PacketNum() = default;
  int ICMP_packet_num_;
  int TCP_packet_num_;
  int UDP_packet_num_;
};

class VlanRecord {
public:
  VlanRecord() = default;
  ~VlanRecord() = default;
  int total_packet_num = 0;
  std::unordered_map<int, PacketNum*> record_map;
};

#endif

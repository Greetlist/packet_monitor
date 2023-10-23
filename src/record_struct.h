#ifndef __RECORD_STRUCT_H_
#define __RECORD_STRUCT_H_

#include <unordered_map>
#include <string>

struct PacketNum {
  PacketNum() : ICMP_packet_num_(0), IGMP_packet_num_(0), TCP_packet_num_(0), UDP_packet_num_(0), Unknown_packet_num_(0) {}
  ~PacketNum() = default;
  int ICMP_packet_num_;
  int IGMP_packet_num_;
  int TCP_packet_num_;
  int UDP_packet_num_;
  int Unknown_packet_num_;
};

struct VlanRecord {
  VlanRecord() = default;
  ~VlanRecord() = default;
  int total_packet_num = 0;
  std::unordered_map<int, PacketNum*> record_map;
};

static std::unordered_map<int, std::string> TYPE_MAP = {
  {1, "icmp"},
  {2, "igmp"},
  {6, "tcp"},
  {17, "udp"},
  {252, "unknown"},
};

#endif

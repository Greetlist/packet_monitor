#ifndef __PACKET_DUMPER_H_
#define __PACKET_DUMPER_H_

#include <string>
#include <atomic>
#include <pcap/pcap.h>
#include <glog/logging.h>

#include "record_struct.h"

class PacketDumper {
public:
  explicit PacketDumper(const std::string& device, const std::string& filter_phrase, const int max_capture_num, bool record_vlan, bool record_mac);
  ~PacketDumper() = default;
  void OnPacketReceive(u_char* args, const struct pcap_phkhdr* header, const u_char* packet);
  void StartCapture();
  void Stop();
  void GenerateReport();
private:
  bool Init();
  std::string device_;
  std::string filter_phrase_;
  int max_capture_num_;
  bool record_vlan_;
  std::atomic<bool> stop_ = false;

  pcap_t* pcap_handler_;
  VlanRecord vlan_record_;
};

#endif

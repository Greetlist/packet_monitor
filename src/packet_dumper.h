#ifndef __PACKET_DUMPER_H_
#define __PACKET_DUMPER_H_

#include <string>
#include <atomic>
#include <pcap.h>
#include <glog/logging.h>
#include <unistd.h>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "record_struct.h"
#include "net_device.h"

class PacketDumper {
public:
  explicit PacketDumper(const std::string& device, const std::string& filter_phrase, const int max_capture_num, bool record_vlan);
  ~PacketDumper();
  void Init();
  void StartCapture();
  void Stop();
  void GenerateReport();
private:
  void ExtractThreeLayerHeader(unsigned char*);
  void ExtractFourLayerHeader(unsigned char*);
  std::string TransportProtocol(unsigned char);
  std::string device_name_;
  std::string filter_phrase_;
  NetDevice* net_device_ = nullptr;
  pcap_t* pcap_handler_ = nullptr;
  struct bpf_program fp_;

  int max_capture_num_ = 0;
  int invalid_packet_num_ = 0;
  int vlan_packet_num_ = 0;
  std::atomic<bool> stop_{false};
  bool record_vlan_;
  VlanRecord vlan_record_;

  static constexpr int ETH_MAX_LEN = 1500;
};

#endif

#include "packet_dumper.h"

PacketDumper::PacketDumper(const std::string& device, const std::string& filter_phrase, const int max_capture_num, bool record_vlan, bool record_mac) : device_(device), filter_phrase_(filter_phrase), max_capture_num(max_capture_num), record_vlan_(record_vlan) {}

void PacketDumper::OnPacketReceive(u_char* args, const struct pcap_phkhdr* header, const u_char* packet) {
  struct ethhdr* ethernet_header = static_cast<struct ethhdr* ethernet_header>(packet);
}

void PacketDumper::StartCapture() {
  while (!stop_) {
    struct pcap_pkthdr h;
    memset(&h, 0, sizeof(struct pcap_pkthdr));
    const u_char* packet = pcap_next(pcap_handler_, &h);
    if (packet == nullptr) {
      LOG(ERROR) << "pcan_next error, continue";
      continue;
    }

    if (record_vlan_) {
      struct vlan_ethhdr* vlan_eth_header = static_cast<struct vlan_ethhdr*>(packet);
      short vlan_tci = static_cast<short>(vlan_eth_header->h_vlan_TCI);
      int vlan_id = static_cast<int>(vlan_tci & 0x0fff);
      if (auto it = vlan_record_.record_map.find(vlan_id); it == vlan_record_.record_map.end()) {
        vlan_record_.record_map_[vlan_id] = new PacketNum();
      }

      vlan_record_.total_packet_num++;
      LOG(INFO) << vlan_id;
      continue;
    }

  }
}

void PacketDumper::Stop() {
  stop_ = true;
}

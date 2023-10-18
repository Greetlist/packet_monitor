#include "packet_dumper.h"

PacketDumper::PacketDumper(const std::string& device_name, const std::string& filter_phrase, const int max_capture_num, bool record_vlan) : device_name_(device_name), filter_phrase_(filter_phrase), record_vlan_(record_vlan) {}

PacketDumper::~PacketDumper() {
  if (net_device_) {
    delete net_device_;
    net_device_ = nullptr;
  }
  if (pcap_handler_) {
    pcap_close(pcap_handler_);
    pcap_handler_ = nullptr;
  }
  for (auto [vlan_id, record] : vlan_record_.record_map) {
    delete record;
  }
}

void PacketDumper::Init() {
  net_device_ = new NetDevice();
  char err_msg[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;

  pcap_if_t* dev_list;
  if (pcap_findalldevs(&dev_list, err_msg)) {
    LOG(ERROR) << "pcap_findalldevs Error is: " << err_msg;
    exit(1);
  }

  while (dev_list != nullptr) {
    dev_list = dev_list->next;
    if (std::string(dev_list->name) == device_name_) {
      LOG(INFO) << "Match Dev: " << dev_list->name;
      net_device_->dev = dev_list->name;
      break;
    }
  }
  if (net_device_->dev == nullptr) {
    LOG(ERROR) << "pcap_lookupdev Error is: " << err_msg;
    exit(1);
  }

  if (pcap_lookupnet(net_device_->dev, &net_device_->net, &net_device_->mask, err_msg) == -1) {
    LOG(ERROR) << "pcap_lookupnet Error is: " << err_msg;
    exit(1);
  }

  pcap_handler_ = pcap_open_live(net_device_->dev, ETH_MAX_LEN, 1, 1000, err_msg);
  if (pcap_handler_ == nullptr) {
    LOG(ERROR) << "pcap_open_live Error is: " << err_msg;
    exit(1);
  }

  if (pcap_compile(pcap_handler_, &fp_, filter_phrase_.c_str(), 0, net_device_->net) == -1) {
    LOG(ERROR) << "pcap_compile Error is: " << err_msg;
    exit(1);
  }

  if (pcap_setfilter(pcap_handler_, &fp_) == -1) {
    LOG(ERROR) << "pcap_setfilter Error is: " << err_msg;
    exit(1);
  }
  LOG(INFO)
    << "Final Capture Packet On Device: ["
    << net_device_->dev
    << "], Filter Phrase is: ["
    << filter_phrase_.c_str()
    << "]";
}

void PacketDumper::StartCapture() {
  LOG(INFO) << "Start Capture";
  while (!stop_) {
    struct pcap_pkthdr h;
    u_char raw_data[ETH_MAX_LEN];
    memset(&h, 0, sizeof(struct pcap_pkthdr));
    const u_char* packet = pcap_next(pcap_handler_, &h);
    if (packet == nullptr) {
      LOG(ERROR) << "pcan_next error, continue";
      continue;
    }

    memset(raw_data, 0, ETH_MAX_LEN);
    if (h.len > ETH_MAX_LEN) {
      LOG(WARNING) << "Capture Packet Len is over 1500!";
      memcpy(raw_data, packet, 1500);
    } else {
      memcpy(raw_data, packet, h.len);
    }

    short tpid = (raw_data[12] << 8) | raw_data[13];
    bool is_vlan_frame = false;
    int vlan_id;

    if (tpid == (short)0x8100) { //IEEE 802.1Q VLAN frame
      LOG(INFO) << "Capture VLAN frame, Length: " << h.len;
      vlan_packet_num_++;
      is_vlan_frame = true;
      short tci = (raw_data[14] << 8) | raw_data[15];
      vlan_id = tci & (short)0x0FFF;
    } else if (tpid <= 1500) { //Normal Ethernet frame [Length]
    } else if (tpid >= 1536) { //Normal Ethernet frame [Type]
    } else if (tpid >= 1501 && tpid <= 1535) { //Undefined/Invalid frame
      invalid_packet_num_++;
    }

    if (record_vlan_ && is_vlan_frame) {
      if (auto it = vlan_record_.record_map.find(vlan_id); it == vlan_record_.record_map.end()) {
        vlan_record_.record_map[vlan_id] = new PacketNum();
      }
      vlan_record_.total_packet_num++;
      LOG(INFO) << vlan_id;
    }
  }
  LOG(INFO) << "Finish Capture";
}

void PacketDumper::Stop() {
  LOG(INFO) << "Stop Capture";
  stop_ = true;
}

void PacketDumper::GenerateReport() {
  for (auto [vlan_id, record] : vlan_record_.record_map) {
    LOG(INFO)
      << "Vlan: " << vlan_id << " has " 
      << record->ICMP_packet_num_ << " ICMP Packets, "
      << record->TCP_packet_num_ << " TCP Packets, "
      << record->UDP_packet_num_ << " UDP Packets";
  }
}

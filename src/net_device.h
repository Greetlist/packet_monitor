#ifndef __NET_DEVICE_H_
#define __NET_DEVICE_H_

struct NetDevice {
  NetDevice() : dev(nullptr), net(0), mask(0) {}
  ~NetDevice() = default;
  char* dev;
  bpf_u_int32 net;
  bpf_u_int32 mask;
};

#endif

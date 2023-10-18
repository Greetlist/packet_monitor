#include <iostream>
#include <glog/logging.h>
#include <gflags/gflags.h>
#include "packet_dumper.h"
#include <csignal>
#include <functional>

DEFINE_string(dev_name, "", "net device name");
DEFINE_string(filter_phrase, "", "tcpdump filter phrase");
DEFINE_int32(max_capture_num, 10000000, "max capture number");
DEFINE_bool(record_vlan, false, "record vlan tag frame");

std::function<void(int)> stop_capture;
void signal_handler(int signal) {
  stop_capture(signal);
}

int main(int argc, char** argv)
{
  gflags::ParseCommandLineFlags(&argc, &argv, true);
  PacketDumper dumper(FLAGS_dev_name, FLAGS_filter_phrase, FLAGS_max_capture_num, FLAGS_record_vlan);
  stop_capture = [&] (int signal) {
    dumper.Stop();
  };
  dumper.Init();
  dumper.StartCapture();
  std::signal(45, signal_handler);
  return 0;
}

#include <iostream>
#include <glog/logging.h>
#include <gflags/gflags.h>
#include "packet_dumper.h"


DEFINE_string(dev_name, "", "net device name");
DEFINE_string(filter_phrase, "", "tcpdump filter phrase");
DEFINE_int32(max_capture_num, 10000000, "max capture number");
DEFINE_bool(record_vlan, false, "record vlan tag frame");

int main(int argc, char** argv)
{
  PacketDumper dumper(FLAGS_dev_name, FLAGS_filter_phrase, FLAGS_max_capture_num, FLAGS_record_vlan);
  dumper.Init();
  dumper.StartCapture();
  return 0;
}

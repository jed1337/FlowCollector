import utils as utils

from Attributes import feature as feat
from meta_data import MetaData
from arff_writer import ArffWriter

from scapy.all import *

from importlib import reload
import sys

import itertools as it
import glob


def print_summary(pkt):
   """
   src   = source ip (string)

   dst   = destination ip (string)

   sport = source port (int)

   dport = destination port (int)

   proto = protocol (int). E.g. 6 = tcp

   :param pkt:
   :return:
   """

   ip = scapy.layers.inet.IP
   tcp = scapy.layers.inet.TCP

   if ip in pkt and tcp in pkt:
      ip_src = pkt[ip].src
      ip_dst = pkt[ip].dst
      tcp_sport = pkt[tcp].sport
      tcp_dport = pkt[tcp].dport

      print(" IP src " + str(ip_src) + " TCP sport " + str(tcp_sport))
      print(" IP dst " + str(ip_dst) + " TCP dport " + str(tcp_dport))


def get_flows(pcap_path, flow_type):
   """
   Aggregates the packets based on the source IP, destination IP, source port, destination port, and protocol.

   Whether or not to aggregate the packets in both the forward and backward direction in a single flow
   depends on the function passed as the flow_type

   Doesn't check for the of flow (FIN), or time limit

   :param pcap_path:
   :param flow_type: Either uni_flow or bi_flow
   :return: a dictionary. Key = identifier, Value = flow packets
   """
   flows = {}

   packets = rdpcap(pcap_path)
   for index, packet in enumerate(packets, start=0):
      # print("Current packet index = %s" % index)
      if scapy.layers.inet.IP not in packet:
         print("IP layer not in packet #%s" % index)
         continue
         # print("IP inside")

      orig_packet_time = packet.time
      packet_ip = packet['IP']
      packet_ip.time = orig_packet_time

      src = packet_ip.src
      dst = packet_ip.dst
      sport = packet_ip.sport
      dport = packet_ip.dport
      proto = packet_ip.proto

      flow_type(flows, packet_ip, src, dst, sport, dport, proto)

   return flows


def bi_flow(flows, packet_ip, src, dst, sport, dport, proto):
   """
   Aggregates packets in both directions in a flow.

   A gets data from B.

   Flow count: 1. A -> B
   """

   key = "%s; %s; -> %s; %s; %s" % (src, sport, dst, dport, proto)
   inv_key = "%s; %s; -> %s; %s; %s" % (dst, dport, src, sport, proto)  # inverted key

   if inv_key in flows:
      flows[inv_key].append(packet_ip)
   else:
      flows[key] = flows.get(key, [])  # Returns [] if flows[key] doesn't exist
      flows[key].append(packet_ip)


def uni_flow(flows, packet_ip, src, dst, sport, dport, proto):
   """
   Aggregates packets in both directions in a flow

   A gets data from B.

   Flow count: 2. A -> B, B -> A
   """
   # flows
   key = "%s; %s; -> %s; %s; %s" % (src, sport, dst, dport, proto)
   flows[key] = flows.get(key, [])
   flows[key].append(packet_ip)


def all_pcap_paths(dir, pcap_extensions = [".pcapng", ".pcap"]):
   """
   Recursively gets all the paths of the pcap files from the dir.
   This includes the current dir and all its sub folders

   :param dir: The directory form where to recursively look for pcap files.
   :param pcap_extensions: the extensions to look for. Defaults at ".pcapng" and ".pcap"
   :return: an itertools.chain looping through all the file extensions found
   """

   return it.chain.from_iterable(
      glob.iglob(dir + "/**/*" + pcap_extension, recursive=True) for pcap_extension in pcap_extensions
   )


def features_arr():
   return [
      feat.SrcIP,
      feat.SrcPort,
      feat.DstIP,
      feat.DstPort,
      feat.ProtoNumber,
      feat.Duration,
      feat.CumulativeOrOfFlags,
      feat.PacketCountInForwardDirection,
      feat.PacketCountInBackwardDirection,
      feat.BytesInForwardDirection,
      feat.BytesInBackwardDirection,
      feat.PacketsPerSecondInForwardDirection,
      feat.PacketsPerSecondInBackwardDirection,
      feat.BytesPerSecondInForwardDirection,
      feat.BytesPerSecondInBackwardDirection,
      feat.RatioOfForwardAndBackwardPackets,
      feat.RatioOfForwardAndBackwardBytes,
      feat.MinPacketSizeInForwardDirection,
      feat.MeanPacketSizeInForwardDirection,
      feat.MaxPacketSizeInForwardDirection,
      feat.StdPacketSizeInForwardDirection,
      feat.MinPacketSizeInBackwardDirection,
      feat.MeanPacketSizeInBackwardDirection,
      feat.MaxPacketSizeInBackwardDirection,
      feat.StdPacketSizeInBackwardDirection,
      feat.MinInterarrivalTimeInForwardDirection,
      feat.MeanInterarrivalTimeInForwardDirection,
      feat.MaxInterarrivalTimeInForwardDirection,
      feat.StdInterarrivalTimeInForwardDirection,
      feat.MinInterarrivalTimeInBackwardDirection,
      feat.MeanInterarrivalTimeInBackwardDirection,
      feat.MaxInterarrivalTimeInBackwardDirection,
      feat.StdInterarrivalTimeInBackwardDirection,
      feat.PshFlagCountInForwardDirection,
      feat.UrgFlagCountInForwardDirection,
      feat.PshFlagCountInBackwardDirection,
      feat.UrgFlagCountInBackwardDirection
   ]

#Execute this if the script is being ran directly. Directly = python main.py
if __name__ == "__main__":
   if len(sys.argv) > 1:
       pcap_dir = sys.argv[1]
   else:
       pcap_dir = "../SamplePcap/noise/N"
       # pcap_dir = "C:/Users/dell/OneDrive - De La Salle University - Manila/Thesis/Datasets/testbed/finalDataset/Feb26"

   for pcap_path in all_pcap_paths(pcap_dir):
      md = MetaData(pcap_path)

      aw = ArffWriter(md.output_file_name, md.class_attribute, features_arr())
      aw.write_headers()
      aw.write_pcap_path(pcap_path)
      aw.write_data(get_flows(pcap_path, bi_flow))
   else:
   #    Only executed if the loop never iterated
      print("No pcap files were found in %s"%pcap_dir)

   # packets = rdpcap(file_name)
   # bi_flows = get_flows(packets, bi_flow)
   #
   # # ps = bi_flows['172.16.15.3; 49622; -> 152.14.13.11; 80; 6']
   #
   # aw = ArffWriter("../TextFiles/output.arff", "normal", features_arr())
   # aw.write_headers()
   # aw.write_data(bi_flows)

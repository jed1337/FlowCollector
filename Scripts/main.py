import attribute as att
import utils as utils

from scapy.all import *
from importlib import reload


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


def get_flows(packets, flow_type):
   """
   Aggregates the packets based on the source IP, destination IP, source port, destination port, and protocol.

   Whether or not to aggregate the packets in both the forward and backward direction in a single flow
   depends on the function passed as the flow_type

   Doesn't check for the of flow (FIN), or time limit

   :param packets:
   :param flow_type: Either uni_flow or bi_flow
   :return: a dictionary. Key = identifier, Value = flow packets
   """

   flows = {}

   for index, packet in enumerate(packets, start=0):
      print("Current packet index = %s" % index)
      if scapy.layers.inet.IP not in packet:
         print("IP layer not in packet #%s" % index)
         continue
      else:
         print("IP inside")

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


# def main():
packets = rdpcap("../SamplePcap/NormalWithTeardown.pcapng")
# packets = rdpcap("../SamplePcap/SYN.pcapng")
uni_flows = get_flows(packets, uni_flow)
bi_flows = get_flows(packets, bi_flow)

ps = bi_flows['172.16.15.3; 49622; -> 152.14.13.11; 80; 6']
# main()
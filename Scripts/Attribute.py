from scapy.all import *

IP = scapy.layers.inet.IP
TCP = scapy.layers.inet.TCP


# class SrcIP(Attribute):
#    def name(self):
#        return "SrcIP"

#    def extract_from_packets(self, packets):
#        for packet in packets:
#           if IP in packet:
#              print(packet['IP'].src)


def src_ip(packets):
   return packets[0].src


def src_port(packets):
   return packets[0].sport


def dst_ip(packets):
   return packets[0].dst


def dst_port(packets):
   return packets[0].dport


def proto_number(packets):
   return packets[0].proto


def packet_count(packets):
   return len(packets)


def total_bytes(packets):
   total = 0
   for packet in packets:
      total += packet.len

   return total


def average_bytes_per_packet(packets):
   return float(total_bytes(packets)) / float(packet_count(packets))

def _bytes_in_direction(packets, direc_func):
   src = 0
   sport = 0
   dst = 0
   dport = 0

   for packet in packets:
      if IP not in packet:
         continue
      src = packet.src
      sport = packet.sport
      dst = packet.dst
      dport = packet.dport
      break

   direc_bytes = 0
   for packet in packets:
      if IP not in packet:
         continue

      # if all([packet.src == src, packet.sport == sport, packet.dst == dst, packet.dport == dport]):
      if direc_func(packet, src, sport, dst, dport):
         direc_bytes += packet.len

   return direc_bytes


def _bytes_in_forward_direction(packet, src, sport, dst, dport):
   return all([packet.src == src, packet.sport == sport, packet.dst == dst, packet.dport == dport])


def bytes_in_forward_direction(packets):
   return _bytes_in_direction(packets, _bytes_in_forward_direction)


def _bytes_in_backward_direction(packet, src, sport, dst, dport):
   return all([packet.src == dst, packet.sport == dport, packet.dst == src, packet.dport == sport])


def bytes_in_backward_direction(packets):
   return _bytes_in_direction(packets, _bytes_in_backward_direction)


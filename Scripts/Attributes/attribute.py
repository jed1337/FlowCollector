import utils
import Attributes.directions as dir
from Attributes.direction_holder import DirectionHolder

from operator import or_
from scapy.all import *

IP = scapy.layers.inet.IP
TCP = scapy.layers.inet.TCP
TCP_NUMBER = utils.protocol_number("TCP")


def src_ip(packets):
   """Returns the source IP of the first packet"""
   return packets[0].src


def src_port(packets):
   """Returns the source port of the first packet"""
   return packets[0].sport


def dst_ip(packets):
   """Returns the destination IP of the first packet"""
   return packets[0].dst


def dst_port(packets):
   """Returns the destination port of the first packet"""
   return packets[0].dport


def proto_number(packets):
   """
   Returns the protocol number of the first packet. E.g. 6 = TCP, 17 = UDP

   Only considers the first packet since it assumes that since packets is a flow,
   it's already aggregated by protocol. Thus there's no point in checking the
   other packets in the flow

   :param: packets, the flow of packets
   """
   return packets[0].proto


def _packets_in_direction(packets, direc_func):
   dh = DirectionHolder(packets)

   direc_packets = []
   for packet in packets:
      if direc_func(packet, dh):
         direc_packets.append(packet)

   return direc_packets


def packet_count_in_direction(packets, direc_func):
   direc_packets = _packets_in_direction(packets, direc_func)

   return len(direc_packets)


def bytes_in_direction(packets, direc_func):
   """
   This function assumes that all unnecessary layers from the packets have been removed.

   Returns the number of bytes in packets. Note that all layers present in the packet
   are taken in account for when counting the size
   :param packets:
   :return:
   """
   direc_packets = _packets_in_direction(packets, direc_func)

   return sum(map((lambda direc_packet: len(direc_packet)), direc_packets))


def _start_time(packets):
   return min(list(map((lambda packet: packet.time), packets)))


def _end_time(packets):
   return max(list(map((lambda packet: packet.time), packets)))


def duration(packets):
   """:return: max_time(packets) - min_time(packets"""
   return _end_time(packets) - _start_time(packets)


def packets_per_second_in_direction(packets, direc_func):
   direc_packets = _packets_in_direction(packets, direc_func)
   dur = duration(direc_packets)

   return float(len(direc_packets))/float(dur)


def bytes_per_second_in_direction(packets, direc_func):
   direc_bytes = bytes_in_direction(packets, direc_func)

   direc_packets = _packets_in_direction(packets, direc_func)
   dur = duration(direc_packets)

   return float(direc_bytes)/float(dur)


def ratio_of_forward_and_backward_packets(packets):
   forward_packets = packet_count_in_direction(packets, dir.forward)
   backward_packets = packet_count_in_direction(packets, dir.backward)

   return float(forward_packets)/float(backward_packets)


def ratio_of_forward_and_backward_bytes(packets):
   forward_bytes  = bytes_in_direction(packets, dir.forward)
   backward_bytes = bytes_in_direction(packets, dir.backward)

   return float(forward_bytes)/float(backward_bytes)


def cumulative_or_of_flags(packets):
   if proto_number(packets) != TCP_NUMBER:
      return "N/A"

   return str(reduce(or_, map((lambda packet: packet[TCP].flags), packets)))


def flag_count_in_direction(packets, flag_bit, direc_func):
   direc_packets = _packets_in_direction(packets, direc_func)
   if proto_number(direc_packets) != TCP_NUMBER:
      return -1

   #We use the & to perform a byte-wise and operation
   return sum(map((lambda direc_packet: (direc_packet[TCP].flags & flag_bit) > 0), direc_packets))


def meta_packet_size_in_direction(packets, reduce_func, direc_func):
   """ :return: packet size (in bytes) given the parameters """
   direc_packets = _packets_in_direction(packets, direc_func)
   direc_packet_byte_array = list(map((lambda direc_packet: len(direc_packet)), direc_packets))

   return reduce_func(direc_packet_byte_array)


def meta_interarrival_times(packets, reduce_func, direc_func):
   direc_packets = _packets_in_direction(packets, direc_func)

   # packet index, we start at index 1 (i.e. the second item)
   # since the time[i] = packets[i] - packets[i-1]
   dp_index = 1

   interarrival_times = []
   while dp_index < len(direc_packets):
      interarrival_time = direc_packets[dp_index].time - direc_packets[dp_index-1].time
      interarrival_times.append(interarrival_time)

      dp_index+=1

   return reduce_func(interarrival_times)
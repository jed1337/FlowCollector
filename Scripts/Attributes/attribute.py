import utils
import directions
import numpy as np

from direction_holder import DirectionHolder
from scapy.all import *

IP = scapy.layers.inet.IP
TCP = scapy.layers.inet.TCP


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
   """Returns the protocol number of the first packet. E.g. 6 = TCP, 17 = UDP"""
   return packets[0].proto


def packet_count(packets):
   """Returns len(packets)"""
   return len(packets)


def _packets_in_direction(packets, direc_func):
   dh = DirectionHolder(packets)

   direc_packets = []
   for packet in packets:
      if direc_func(packet, dh):
         direc_packets.append(packet)

   return direc_packets


def _packet_count_in_direction(packets, direc_func):
   dh = DirectionHolder(packets)

   direc_packet_count = 0
   for packet in packets:
      if direc_func(packet, dh):
         direc_packet_count += 1

   return direc_packet_count


def packet_count_in_backward_direction(packets):
   return _packet_count_in_direction(packets, directions.backward)


def packet_count_in_forward_direction(packets):
   return _packet_count_in_direction(packets, directions.forward)


def total_bytes(packets):
   """
   This function assumes that all unnecessary layers from the packets have been removed.

   Returns the number of bytes in packets. Note that all layers present in the packet
   are taken in account for when counting the size
   :param packets:
   :return:
   """
   total = 0
   for packet in packets:
      total += packet.len

   return total


def average_bytes_per_packet(packets):
   return float(total_bytes(packets)) / float(packet_count(packets))


def _bytes_in_direction(packets, direc_func):
   dh = DirectionHolder(packets)

   direc_bytes = 0
   for packet in packets:
      if IP not in packet:
         continue

      # if all([packet.src == src, packet.sport == sport, packet.dst == dst, packet.dport == dport]):
      if direc_func(packet, dh):
         direc_bytes += packet.len

   return direc_bytes


def bytes_in_forward_direction(packets):
   return _bytes_in_direction(packets, directions.forward)


def bytes_in_backward_direction(packets):
   return _bytes_in_direction(packets, directions.backward)


def start_time(packets):
   return min(list(map((lambda packet: packet.time), packets)))


def end_time(packets):
   return max(list(map((lambda packet: packet.time), packets)))


def duration(packets):
   """:return: max_time(packets) - min_time(packets"""
   return end_time(packets) - start_time(packets)


def _interarrival_times(packets):
   """ Interarrival time = time between 2 packets """

   # packet index, we start at index 1 (i.e. the second item)
   # since the time[i] = packets[i] - packets[i-1]
   p_index = 1

   interarrival_times = []
   while p_index < len(packets):
      interarrival_time = packets[p_index].time - packets[p_index-1].time
      interarrival_times.append(interarrival_time)

      p_index+=1

   return interarrival_times


def _meta_interarrival_times(packets, reduce_func, direc_func):
   """TODO Test"""
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


def max_interarrival_time(packets):
   return max(_interarrival_times(packets))


def min_interarrival_time(packets):
   return min(_interarrival_times(packets))


def std_interarrival_time(packets):
   return np.std(_interarrival_times(packets))

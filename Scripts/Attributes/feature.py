import general_utils
import Attributes.directions as directions
import Attributes.aggregate_functions as agg

from flags import Flags
from Attributes.direction_holder import DirectionHolder
from Attributes.data_type_holder import DataTypeHolder as DH

from functools import reduce
from operator import or_
from scapy.all import *

IP = scapy.layers.inet.IP
TCP = scapy.layers.inet.TCP
TCP_NUMBER = general_utils.protocol_number("TCP")

NUMERIC = "numeric"
STRING = "string"


def _start_time(packets):
   """returns the min time of the packets. If there are no packets, return 0"""
   return min(list(map((lambda packet: packet.time), packets)), default=0)


def _end_time(packets):
   """returns the max time of the packets. If there are no packets, return 0"""
   return max(list(map((lambda packet: packet.time), packets)), default=0)


def _packets_in_direction(packets, direc_func):
   dh = DirectionHolder(packets)

   direc_packets = []
   for packet in packets:
      if direc_func(packet, dh):
         direc_packets.append(packet)

   return direc_packets


def _packet_count_in_direction(packets, direc_func):
   direc_packets = _packets_in_direction(packets, direc_func)

   return len(direc_packets)


def _bytes_in_direction(packets, direc_func):
   """
   This assumes that all unnecessary layers from the packets have been removed.

   Returns the number of bytes in packets. Note that all layers present in the packet
   are taken in account for when counting the size
   :param packets:
   :return:
   """
   direc_packets = _packets_in_direction(packets, direc_func)

   return sum(map((lambda direc_packet: len(direc_packet)), direc_packets))


def _safe_division(numerator, denominator):
   """
   Assumes that all parameters have already been formatted.
   :return: float(numerator/denominator). If denominator == 0, return 0
   """
   return float(numerator / denominator if denominator else 0)


def _packets_per_second_in_direction(packets, direc_func):
   """ :return: The packets per second given a direction. 0, if there're no packets in the direction """

   direc_packets = _packets_in_direction(packets, direc_func)
   dur = float(Duration.action(direc_packets))

   return _safe_division(len(direc_packets), dur)

   # return float(len(direc_packets))/dur if dur else 0


def _bytes_per_second_in_direction(packets, direc_func):
   direc_bytes = _bytes_in_direction(packets, direc_func)

   direc_packets = _packets_in_direction(packets, direc_func)
   dur = Duration.action(direc_packets)

   return _safe_division(direc_bytes, dur)

   # return float(direc_bytes)/float(dur)


def _meta_packet_size_in_direction(packets, reduce_func, direc_func):
   """ :return: packet size (in bytes) given the parameters """
   direc_packets = _packets_in_direction(packets, direc_func)
   direc_packet_byte_array = list(map((lambda direc_packet: len(direc_packet)), direc_packets))

   return reduce_func(direc_packet_byte_array)


def _meta_interarrival_times(packets, reduce_func, direc_func):
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


def _flag_count_in_direction(packets, flag_bit, direc_func):
   direc_packets = _packets_in_direction(packets, direc_func)
   if ProtoNumber.action(direc_packets) != TCP_NUMBER:
      return -1

   #We use the & to perform a byte-wise and operation
   return sum(map((lambda direc_packet: (direc_packet[TCP].flags & flag_bit) > 0), direc_packets))


class SrcIP:
   @staticmethod
   def data_type_holder():
      return DH("src_ip", STRING)

   @staticmethod
   def action(packets):
      """Returns the source IP of the first packet"""
      return packets[0].src


class SrcPort:
   @staticmethod
   def data_type_holder():
      return DH("src_port", NUMERIC)

   @staticmethod
   def action(packets):
      """Returns the source port of the first packet"""
      return packets[0].sport


class DstIP:
   @staticmethod
   def data_type_holder():
      return DH("dst_ip", STRING)

   @staticmethod
   def action(packets):
      """Returns the destination IP of the first packet"""
      return packets[0].dst


class DstPort:
   @staticmethod
   def data_type_holder():
      return DH("dst_port", NUMERIC)

   @staticmethod
   def action(packets):
      """Returns the destination port of the first packet"""
      return packets[0].dport


class ProtoNumber:
   @staticmethod
   def data_type_holder():
      return DH("proto_number", NUMERIC)

   @staticmethod
   def action(packets):
      """
      Returns the protocol number of the first packet. E.g. 6 = TCP, 17 = UDP

      Only considers the first packet since it assumes that since packets is a flow,
      it's already aggregated by protocol. Thus there's no point in checking the
      other packets in the flow

      :param: packets, the flow of packets
      """
      if not packets:
         return -1
      return packets[0].proto


class Duration:
   @staticmethod
   def data_type_holder():
      return DH("duration", NUMERIC)

   @staticmethod
   def action(packets):
      """:return: max_time(packets) - min_time(packets"""
      return _end_time(packets) - _start_time(packets)


class CumulativeOrOfFlags:
   @staticmethod
   def data_type_holder():
      return DH("cof", STRING)

   @staticmethod
   def action(packets):
      """
      Since the TCP flags have specific positions, an 'or' operation
      can be used to aggregate them together.
      :return: N/A if the protocol of the packets passed is not TCP.
      Else, return a String representing all the flags
      """
      if ProtoNumber.action(packets) != TCP_NUMBER:
         return "N/A"

      return reduce(or_, map(lambda packet: packet[TCP].flags, packets))


class PacketCountInForwardDirection:
   @staticmethod
   def data_type_holder():
      return DH("total_f_packets", NUMERIC)

   @staticmethod
   def action(packets):
      return _packet_count_in_direction(packets, directions.forward)


class PacketCountInBackwardDirection:
   @staticmethod
   def data_type_holder():
      return DH("total_b_packets", NUMERIC)

   @staticmethod
   def action(packets):
      return _packet_count_in_direction(packets, directions.backward)


class BytesInForwardDirection:
   @staticmethod
   def data_type_holder():
      return DH("total_f_bytes", NUMERIC)

   @staticmethod
   def action(packets):
      return _bytes_in_direction(packets, directions.forward)


class BytesInBackwardDirection:
   @staticmethod
   def data_type_holder():
      return DH("total_b_bytes", NUMERIC)

   @staticmethod
   def action(packets):
      return _bytes_in_direction(packets, directions.backward)


class PacketsPerSecondInForwardDirection:
   @staticmethod
   def data_type_holder():
      return DH("pps_f", NUMERIC)

   @staticmethod
   def action(packets):
      return _packets_per_second_in_direction(packets, directions.forward)


class PacketsPerSecondInBackwardDirection:
   @staticmethod
   def data_type_holder():
      return DH("pps_b", NUMERIC)

   @staticmethod
   def action(packets):
      return _packets_per_second_in_direction(packets, directions.backward)


class BytesPerSecondInForwardDirection:
   @staticmethod
   def data_type_holder():
      return DH("bps_f", NUMERIC)

   @staticmethod
   def action(packets):
      return _bytes_per_second_in_direction(packets, directions.forward)


class BytesPerSecondInBackwardDirection:
   @staticmethod
   def data_type_holder():
      return DH("bps_b", NUMERIC)

   @staticmethod
   def action(packets):
      return _bytes_per_second_in_direction(packets, directions.backward)


class RatioOfForwardAndBackwardPackets:
   @staticmethod
   def data_type_holder():
      return DH("rfb_packets", NUMERIC)

   @staticmethod
   def action(packets):
      forward_packets = _packet_count_in_direction(packets, directions.forward)
      backward_packets = _packet_count_in_direction(packets, directions.backward)

      return _safe_division(forward_packets, backward_packets)

      # return float(forward_packets)/float(backward_packets)


class RatioOfForwardAndBackwardBytes:
   @staticmethod
   def data_type_holder():
      return DH("rfb_bytes", NUMERIC)

   @staticmethod
   def action(packets):
      forward_bytes  = _bytes_in_direction(packets, directions.forward)
      backward_bytes = _bytes_in_direction(packets, directions.backward)

      return _safe_division(forward_bytes, backward_bytes)
      # return float(forward_bytes)/float(backward_bytes)


class MinPacketSizeInForwardDirection:
   @staticmethod
   def data_type_holder():
      return DH("min_f_pkt", NUMERIC)

   @staticmethod
   def action(packets):
      return _meta_packet_size_in_direction(packets, agg.min_agg, directions.forward)


class MeanPacketSizeInForwardDirection:
   @staticmethod
   def data_type_holder():
      return DH("mean_f_pkt", NUMERIC)

   @staticmethod
   def action(packets):
      return _meta_packet_size_in_direction(packets, agg.mean_agg, directions.forward)


class MaxPacketSizeInForwardDirection:
   @staticmethod
   def data_type_holder():
      return DH("max_f_pkt", NUMERIC)

   @staticmethod
   def action(packets):
      return _meta_packet_size_in_direction(packets, agg.max_agg, directions.forward)


class StdPacketSizeInForwardDirection:
   @staticmethod
   def data_type_holder():
      return DH("std_f_pkt", NUMERIC)

   @staticmethod
   def action(packets):
      return _meta_packet_size_in_direction(packets, agg.std_agg, directions.forward)


class MinPacketSizeInBackwardDirection:
   @staticmethod
   def data_type_holder():
      return DH("min_b_pkt", NUMERIC)

   @staticmethod
   def action(packets):
      return _meta_packet_size_in_direction(packets, agg.min_agg, directions.backward)


class MeanPacketSizeInBackwardDirection:
   @staticmethod
   def data_type_holder():
      return DH("mean_b_pkt", NUMERIC)

   @staticmethod
   def action(packets):
      return _meta_packet_size_in_direction(packets, agg.mean_agg, directions.backward)


class MaxPacketSizeInBackwardDirection:
   @staticmethod
   def data_type_holder():
      return DH("max_b_pkt", NUMERIC)

   @staticmethod
   def action(packets):
      return _meta_packet_size_in_direction(packets, agg.max_agg, directions.backward)


class StdPacketSizeInBackwardDirection:
   @staticmethod
   def data_type_holder():
      return DH("std_b_pkt", NUMERIC)

   @staticmethod
   def action(packets):
      return _meta_packet_size_in_direction(packets, agg.std_agg, directions.backward)


class MinInterarrivalTimeInForwardDirection:
   @staticmethod
   def data_type_holder():
      return DH("min_f_time", NUMERIC)

   @staticmethod
   def action(packets):
      return _meta_interarrival_times(packets, agg.min_agg, directions.forward)


class MeanInterarrivalTimeInForwardDirection:
   @staticmethod
   def data_type_holder():
      return DH("mean_f_time", NUMERIC)

   @staticmethod
   def action(packets):
      return _meta_interarrival_times(packets, agg.mean_agg, directions.forward)


class MaxInterarrivalTimeInForwardDirection:
   @staticmethod
   def data_type_holder():
      return DH("max_f_time", NUMERIC)

   @staticmethod
   def action(packets):
      return _meta_interarrival_times(packets, agg.max_agg, directions.forward)


class StdInterarrivalTimeInForwardDirection:
   @staticmethod
   def data_type_holder():
      return DH("std_f_time", NUMERIC)

   @staticmethod
   def action(packets):
      return _meta_interarrival_times(packets, agg.std_agg, directions.forward)


class MinInterarrivalTimeInBackwardDirection:
   @staticmethod
   def data_type_holder():
      return DH("min_b_time", NUMERIC)

   @staticmethod
   def action(packets):
      return _meta_interarrival_times(packets, agg.min_agg, directions.backward)


class MeanInterarrivalTimeInBackwardDirection:
   @staticmethod
   def data_type_holder():
      return DH("mean_b_time", NUMERIC)

   @staticmethod
   def action(packets):
      return _meta_interarrival_times(packets, agg.mean_agg, directions.backward)


class MaxInterarrivalTimeInBackwardDirection:
   @staticmethod
   def data_type_holder():
      return DH("max_b_time", NUMERIC)

   @staticmethod
   def action(packets):
      return _meta_interarrival_times(packets, agg.max_agg, directions.backward)


class StdInterarrivalTimeInBackwardDirection:
   @staticmethod
   def data_type_holder():
      return DH("std_b_time", NUMERIC)

   @staticmethod
   def action(packets):
      return _meta_interarrival_times(packets, agg.std_agg, directions.backward)


class PshFlagCountInForwardDirection:
   @staticmethod
   def data_type_holder():
      return DH("psh_f_cnt", NUMERIC)

   @staticmethod
   def action(packets):
      return _flag_count_in_direction(packets, Flags.PSH, directions.forward)


class UrgFlagCountInForwardDirection:
   @staticmethod
   def data_type_holder():
      return DH("urg_f_cnt", NUMERIC)

   @staticmethod
   def action(packets):
      return _flag_count_in_direction(packets, Flags.URG, directions.forward)


class PshFlagCountInBackwardDirection:
   @staticmethod
   def data_type_holder():
      return DH("psh_b_cnt", NUMERIC)

   @staticmethod
   def action(packets):
      return _flag_count_in_direction(packets, Flags.PSH, directions.backward)


class UrgFlagCountInBackwardDirection:
   @staticmethod
   def data_type_holder():
      return DH("urg_b_cnt", NUMERIC)

   @staticmethod
   def action(packets):
      return _flag_count_in_direction(packets, Flags.URG, directions.backward)

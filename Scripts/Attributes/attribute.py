import utils
import Attributes.directions as dir
import Attributes.aggregate_functions as agg

from flags import Flags
from Attributes.direction_holder import DirectionHolder
from Attributes.data_type_holder import DataTypeHolder as DH

from operator import or_
from scapy.all import *

IP = scapy.layers.inet.IP
TCP = scapy.layers.inet.TCP
TCP_NUMBER = utils.protocol_number("TCP")

NUMERIC = "numeric"
STRING = "string"


def src_ip(packets):
   """Returns the source IP of the first packet"""
   return packets[0].src, DH("src_ip", STRING)


def src_port(packets):
   """Returns the source port of the first packet"""

   return packets[0].sport, DH("src_port", NUMERIC)


def dst_ip(packets):
   """Returns the destination IP of the first packet"""
   return packets[0].dst, DH("dst_ip", STRING)


def dst_port(packets):
   """Returns the destination port of the first packet"""
   return packets[0].dport, DH("dst_port", NUMERIC)


def proto_number(packets):
   """
   Returns the protocol number of the first packet. E.g. 6 = TCP, 17 = UDP

   Only considers the first packet since it assumes that since packets is a flow,
   it's already aggregated by protocol. Thus there's no point in checking the
   other packets in the flow

   :param: packets, the flow of packets
   """
   return (packets[0].proto, DH("proto_number", NUMERIC))


def _start_time(packets):
   return min(list(map((lambda packet: packet.time), packets)))


def _end_time(packets):
   return max(list(map((lambda packet: packet.time), packets)))


def duration(packets):
   """:return: max_time(packets) - min_time(packets"""
   return ((_end_time(packets) - _start_time(packets)), DH("duration", NUMERIC))


def cumulative_or_of_flags(packets):
   """
   Since the TCP flags have specific positions, an 'or' operation
   can be used to aggregate them together.
   :return: N/A if the protocol of the packets passed is not TCP.
   Else, return a String representing all the flags
   """
   if proto_number(packets) != TCP_NUMBER:
      return "N/A"

   return (str(reduce(or_, map((lambda packet: packet[TCP].flags), packets))), DH("cof", STRING))


def _packets_in_direction(packets, direc_func):
   dh = DirectionHolder(packets)

   direc_packets = []
   for packet in packets:
      if direc_func(packet, dh):
         direc_packets.append(packet)

   return direc_packets


def packet_count_in_forward_direction(packets):
   return (_packet_count_in_direction(packets, dir.forward), DH("total_f_packets", NUMERIC))


def packet_count_in_backward_direction(packets):
   return (_packet_count_in_direction(packets, dir.backward), DH("total_b_packets", NUMERIC))


def _packet_count_in_direction(packets, direc_func):
   direc_packets = _packets_in_direction(packets, direc_func)

   return len(direc_packets)


def _bytes_in_forward_direction(packets):
   return (_bytes_in_direction(packets, dir.forward), DH("total_f_bytes", NUMERIC))


def _bytes_in_backward_direction(packets):
   return (_bytes_in_direction(packets, dir.backward), DH("total_b_bytes", NUMERIC))


def _bytes_in_direction(packets, direc_func):
   """
   This function assumes that all unnecessary layers from the packets have been removed.

   Returns the number of bytes in packets. Note that all layers present in the packet
   are taken in account for when counting the size
   :param packets:
   :return:
   """
   direc_packets = _packets_in_direction(packets, direc_func)

   return sum(map((lambda direc_packet: len(direc_packet)), direc_packets))


def _packets_per_second_in_forward_direction(packets):
   return (_packets_per_second_in_direction(packets, dir.forward), DH("pps_f", NUMERIC))


def _packets_per_second_in_backward_direction(packets):
   return (_packets_per_second_in_direction(packets, dir.backward), DH("pps_b", NUMERIC))


def _packets_per_second_in_direction(packets, direc_func):
   direc_packets = _packets_in_direction(packets, direc_func)
   dur = duration(direc_packets)

   return float(len(direc_packets))/float(dur)


def _bytes_per_second_in_forward_direction(packets):
   return (_bytes_per_second_in_direction(packets, dir.forward), DH("bps_f"))


def _bytes_per_second_in_backward_direction(packets):
   return (_bytes_per_second_in_direction(packets, dir.backward), DH("bps_b"))


def _bytes_per_second_in_direction(packets, direc_func):
   direc_bytes = _bytes_in_direction(packets, direc_func)

   direc_packets = _packets_in_direction(packets, direc_func)
   dur = duration(direc_packets)

   return float(direc_bytes)/float(dur)


def ratio_of_forward_and_backward_packets(packets):
   forward_packets = _packet_count_in_direction(packets, dir.forward)
   backward_packets = _packet_count_in_direction(packets, dir.backward)

   return float(forward_packets)/float(backward_packets)


def ratio_of_forward_and_backward_bytes(packets):
   forward_bytes  = _bytes_in_direction(packets, dir.forward)
   backward_bytes = _bytes_in_direction(packets, dir.backward)

   return float(forward_bytes)/float(backward_bytes)


def min_packet_size_in_forward_direction(packets):
   return (_meta_packet_size_in_direction(packets, agg.min_agg, dir.forward), DH("min_f_pkt", NUMERIC))
def mean_packet_size_in_forward_direction(packets):
   return (_meta_packet_size_in_direction(packets, agg.mean_agg, dir.forward), DH("mean_f_pkt", NUMERIC))
def max_packet_size_in_forward_direction(packets):
   return (_meta_packet_size_in_direction(packets, agg.max_agg, dir.forward), DH("max_f_pkt", NUMERIC))
def std_packet_size_in_forward_direction(packets):
   return (_meta_packet_size_in_direction(packets, agg.std_agg, dir.forward), DH("std_f_pkt", NUMERIC))
def min_packet_size_in_backward_direction(packets):
   return (_meta_packet_size_in_direction(packets, agg.min_agg, dir.backward), DH("min_b_pkt", NUMERIC))
def mean_packet_size_in_backward_direction(packets):
   return (_meta_packet_size_in_direction(packets, agg.mean_agg, dir.backward), DH("mean_b_pkt", NUMERIC))
def max_packet_size_in_backward_direction(packets):
   return (_meta_packet_size_in_direction(packets, agg.max_agg, dir.backward), DH("max_b_pkt", NUMERIC))
def std_packet_size_in_backward_direction(packets):
   return (_meta_packet_size_in_direction(packets, agg.std_agg, dir.backward), DH("std_b_pkt", NUMERIC))
def _meta_packet_size_in_direction(packets, reduce_func, direc_func):
   """ :return: packet size (in bytes) given the parameters """
   direc_packets = _packets_in_direction(packets, direc_func)
   direc_packet_byte_array = list(map((lambda direc_packet: len(direc_packet)), direc_packets))

   return reduce_func(direc_packet_byte_array)

def min_interarrival_time_in_forward_direction(packets):
   return (_meta_interarrival_times(packets, agg.min_agg, dir.forward), DH("min_f_time", NUMERIC))
def mean_interarrival_time_in_forward_direction(packets):
   return (_meta_interarrival_times(packets, agg.mean_agg, dir.forward), DH("mean_f_time", NUMERIC))
def max_interarrival_time_in_forward_direction(packets):
   return (_meta_interarrival_times(packets, agg.max_agg, dir.forward), DH("max_f_time", NUMERIC))
def std_interarrival_time_in_forward_direction(packets):
   return (_meta_interarrival_times(packets, agg.std_agg, dir.forward), DH("std_f_time", NUMERIC))
def min_interarrival_time_in_backward_direction(packets):
   return (_meta_interarrival_times(packets, agg.min_agg, dir.backward), DH("min_b_time", NUMERIC))
def mean_interarrival_time_in_backward_direction(packets):
   return (_meta_interarrival_times(packets, agg.mean_agg, dir.backward), DH("mean_b_time", NUMERIC))
def max_interarrival_time_in_backward_direction(packets):
   return (_meta_interarrival_times(packets, agg.max_agg, dir.backward), DH("max_b_time", NUMERIC))
def std_interarrival_time_in_backward_direction(packets):
   return (_meta_interarrival_times(packets, agg.std_agg, dir.backward), DH("std_b_time", NUMERIC))
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



def psh_flag_count_in_forward_direction(packets):
   return (_flag_count_in_direction(packets, Flags.PSH, dir.forward), DH("psh_f_cnt", NUMERIC))
def urg_flag_count_in_forward_direction(packets):
   return (_flag_count_in_direction(packets, Flags.URG, dir.forward), DH("urg_f_cnt", NUMERIC))
def psh_flag_count_in_backward_direction(packets):
   return (_flag_count_in_direction(packets, Flags.PSH, dir.backward), DH("psh_b_cnt", NUMERIC))
def urg_flag_count_in_backward_direction(packets):
   return (_flag_count_in_direction(packets, Flags.URG, dir.backward), DH("urg_b_cnt", NUMERIC))
def _flag_count_in_direction(packets, flag_bit, direc_func):
   direc_packets = _packets_in_direction(packets, direc_func)
   if proto_number(direc_packets) != TCP_NUMBER:
      return -1

   #We use the & to perform a byte-wise and operation
   return sum(map((lambda direc_packet: (direc_packet[TCP].flags & flag_bit) > 0), direc_packets))
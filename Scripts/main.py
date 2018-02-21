from scapy.all import *
from collections import defaultdict
from FlowMarker import FlowMarker


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

    IP = scapy.layers.inet.IP
    TCP = scapy.layers.inet.TCP
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
    if TCP in pkt:
        tcp_sport = pkt[TCP].sport
        tcp_dport = pkt[TCP].dport

        print(" IP src " + str(ip_src) + " TCP sport " + str(tcp_sport))
        print(" IP dst " + str(ip_dst) + " TCP dport " + str(tcp_dport))

        # print_summary()


def print_abstime(packet):
    """
    Source: http://strftime.org/

    :param packet: To get the absolute time from
    :return: nothing
    """
    print(datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S %f'))


def get_unidirectional_flows(packets):
    """
    Aggregates the packets based on the source IP, destination IP, source port, destination port, and protocol.

    Doesn't check end of flow, or time limit

    Default dict source: https://codefisher.org/catch/blog/2015/04/22/python-how-group-and-count-dictionaries/

    :param packets:
    :return: a list containing the flows
    """
    flows = defaultdict(list)

    for index, packet in enumerate(packets, start=0):
        print("Current packet count = %s" % (index))
        if scapy.layers.inet.IP not in packet:
            print("IP layer not in packet #%s" % index)
            continue
        else:
            print("IP inside")

        packet_ip = packet['IP']

        src = packet_ip.src
        dst = packet_ip.dst
        sport = packet_ip.sport
        dport = packet_ip.dport
        proto = packet_ip.proto

        key = "%s; %s; -> %s; %s; %s" % (src, sport, dst, dport, proto)
        print("key = %s" % (key))
        flows[key].append(packet_ip)

    return flows


def get_bidirectional_flows(packets):
    flows = {}

    for index, packet in enumerate(packets, start=0):
        print("Current packet count = %s" % (index))
        if scapy.layers.inet.IP not in packet:
            print("IP layer not in packet #%s" % index)
            continue
        else:
            print("IP inside")

        packet_ip = packet['IP']

        src = packet_ip.src
        dst = packet_ip.dst
        sport = packet_ip.sport
        dport = packet_ip.dport
        proto = packet_ip.proto

        key = "%s; %s; -> %s; %s; %s" % (src, sport, dst, dport, proto)
        inv_key = "%s; %s; -> %s; %s; %s" % (dst, dport, src, sport, proto)  # inverted key

        if inv_key in flows:
            flows[inv_key].append(packet)
        else:
            flows[key] = flows.get(key, [])  # Returns [] if flows[key] doesn't exist
            flows[key].append(packet)

    return flows


# def get_bidirectional_flows_old(initIndex, flow_markers):
# 	for other_flow_marker in range(initIndex+1, len(flow_markers)):
#
# 		if(other_flow_marker is not None):
# 			break #Since this packet's already been assigned a flow, move on to the next
#
# 		pSameFlow = packets[other_flow_marker] #Check if this will cause the other parts to assign values
#
# 		#Checks for same flow
# 		if(pSameFlow.proto == proto and
# 			any([
# 				all([pSameFlow.src == src, pSameFlow.sport == sport, pSameFlow.dst == dst, pSameFlow.dport == dport]),
# 				all([pSameFlow.dst == src, pSameFlow.dport == sport, pSameFlow.src == dst, pSameFlow.sport == dport])
# 			])):
#
# 			pSameFlow.setFlow(flowName)
#
# 			isEndOfFlow = isEndOfFlow(pSameFlow)
# 			if isEndOfFlow == "End":
# 				break outer

def main():
    # packets = rdpcap("../SamplePcap/NormalWithTeardown.pcapng")
    packets = rdpcap("../SamplePcap/SYN.pcapng")
    uni_flows = get_unidirectional_flows(packets)
    bi_flows = get_bidirectional_flows(packets)
    print("Flow count is: %d" % len(bi_flows))
    print()

main()
# flows = get_unidirectional_flows(packets)
# print(flows.keys())
from abc import ABC, abstractmethod
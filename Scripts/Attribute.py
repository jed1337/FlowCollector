from abc import ABC, abstractmethod
from scapy.all import *
from FlowMarker import FlowMarker

IP  = scapy.layers.inet.IP
TCP = scapy.layers.inet.TCP


# class SrcIP(Attribute):
#     def name(self):
#         return "SrcIP"

#     def extract_from_packets(self, packets):
#         for packet in packets:
#             if IP in packet:
#                 print(packet['IP'].src)



def SrcPort(self, packets):
    for packet in packets:
        packet.


def attribue(self, packets):
    print("Attribute):")


def DstPort(self, packets):
    print("DstPort(Attribute):")


def PacketCount(self, packets):
    print("PacketCount(Attribute):")

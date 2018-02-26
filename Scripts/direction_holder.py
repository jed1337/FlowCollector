from scapy.all import *

class DirectionHolder():
   def __init__(self, packets):
      self.src = None
      self.sport = None
      self.dst = None
      self.dport = None

      for packet in packets:
         if IP not in packet:
            continue
         self.src = packet.src
         self.sport = packet.sport
         self.dst = packet.dst
         self.dport = packet.dport
         break
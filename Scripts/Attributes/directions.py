def forward(packet, dh):
   """
   :param packet: The packet to compare to dh
   :param dh: Direction Holder
   :return: True if the packet belongs in the forward direction
   """
   return all([packet.src == dh.src, packet.sport == dh.sport, packet.dst == dh.dst, packet.dport == dh.dport])


def backward(packet, dh):
   """
   :param packet: The packet to compare to dh
   :param dh: Direction Holder
   :return: True if the packet belongs in the backward direction
   """
   return all([packet.src == dh.dst, packet.sport == dh.dport, packet.dst == dh.src, packet.dport == dh.sport])

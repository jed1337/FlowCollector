import socket
import os
import ntpath
from datetime import datetime

PROTOCOL_TABLE = {num: name[8:] for name, num in vars(socket).items() if name.startswith("IPPROTO")}


def protocol_name(protocol_number):
   """
   Uses the lookup table PROTOCOL_TABLE to give the protocol number

   Source: https://stackoverflow.com/questions/37004965/how-to-turn-protocol-number-to-name-with-python
   :param protocol_number:
   :return: The protocol name
   """

   return PROTOCOL_TABLE[protocol_number]


def protocol_number(protocol_name):
   return socket.getprotobyname(protocol_name)


def abs_time(time):
   dt = datetime.fromtimestamp(time).strftime('%Y-%m-%d %H:%M:%S %f')
   return dt


def seconds(time):
   dt = datetime.fromtimestamp(time).strftime('%S %f seconds')
   return dt


def packet_abs_time(packet, time_func=abs_time):
   """
   Source: http://strftime.org/

   :param packet: To get the absolute time from
   :param time_func: What fucntion to use to gete the time
   :return: the date time object
   """
   return time_func(packet.time)

def path_leaf(path):
   """
   Source: https://stackoverflow.com/a/8384788
   :param path: A file name
   """
   head, tail = ntpath.split(path)
   return os.path.splitext(tail)[0] or ntpath.basename(head)
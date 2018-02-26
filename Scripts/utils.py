import socket
from datetime import datetime

PROTOCOL_TABLE = {num: name[8:] for name, num in vars(socket).items() if name.startswith("IPPROTO")}


def get_protocol_name(protocol_number):
    return PROTOCOL_TABLE[protocol_number]


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

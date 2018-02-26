import socket
from datetime import datetime

PROTOCOL_TABLE = {num: name[8:] for name, num in vars(socket).items() if name.startswith("IPPROTO")}


def get_protocol_name(protocol_number):
    return PROTOCOL_TABLE[protocol_number]


def packet_abs_time(packet):
    """
    Source: http://strftime.org/

    :param packet: To get the absolute time from
    :return: the date time object
    """
    return abs_time(packet.time)


def abs_time(time):
    dt = datetime.fromtimestamp(time).strftime('%Y-%m-%d %H:%M:%S %f')
    return dt


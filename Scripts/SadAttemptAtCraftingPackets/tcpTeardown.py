from scapy.all import *

# conf.L3socket=L3RawSocket

sport=1338
dport=80
ip_packet=IP(dst="192.168.254.107")

SYN= ip_packet / TCP(sport=sport, dport=dport, flags="S")
SYNACK=sr1(SYN)
ACK= ip_packet / TCP(sport=sport, dport=dport, flags="A", seq=SYNACK.ack, ack=SYNACK.seq + 1)
send(ACK)

# ...
payload_packet = TCP(sport=sport, dport=dport, flags='A', seq=next_seq, ack=my_ack)
payload = "GET / HTTP/1.0\r\nHOST: 192.168.254.107\r\n\r\n"

FIN= ip_packet / TCP(sport=sport, dport=dport, flags="FA", seq=SYNACK.ack, ack=SYNACK.seq + 1)
FINACK=sr1(FIN)
LASTACK= ip_packet / TCP(sport=sport, dport=dport, flags="A", seq=FINACK.ack, ack=FINACK.seq + 1)
send(LASTACK)
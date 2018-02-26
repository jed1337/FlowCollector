from scapy.all import *

seq = 170000
sport = 1040
dport = 80

ip_packet = IP(dst='192.168.254.107')

SYN = ip_packet / TCP(sport=sport, dport=dport, flags='S', seq=seq)
SYNACK = sr1(SYN)

next_seq = seq + 1
my_ack = SYNACK.seq + 1

ACK = TCP(sport=sport, dport=dport, flags='A', seq=next_seq, ack=my_ack)

send(ip_packet / ACK)

payload_packet = TCP(sport=sport, dport=dport, flags='A', seq=next_seq, ack=my_ack)
payload = "GET / HTTP/1.0\r\nHOST: 192.168.254.107\r\n\r\n"

reply, error = sr(ip_packet/payload_packet/payload, multi=1, timeout=1)
for r in reply:
    r[0].show2()
    r[1].show2()

FIN= ip_packet / TCP(sport=sport, dport=dport, flags="FA", seq=SYNACK.ack, ack=SYNACK.seq + 1)
FINACK=sr1(FIN)
LASTACK= ip_packet / TCP(sport=sport, dport=dport, flags="A", seq=FINACK.ack, ack=FINACK.seq + 1)
send(LASTACK)
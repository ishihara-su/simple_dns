# simple_dns.py - Simple DNS client
#
import socket
import struct
import sys

# Note:
#  According to RFC1035...
#   - Label length <= 63 octets
#   - Name length <= 255 octes
#   - TTL < 0x7FFFFFFF
#   - UDP Message Length <= 512

DNS_QTYPE_A = 1
DNS_QCLASS_IN = 1
DNS_PORT = 53

def make_dns_request(domain_str):
    query_id = 0 # 16 bits
    qr = 0 << 15 # 1 bit
    opcode = 0 << 11 # 4 bit
    aa = 0 << 10 # 1 bit
    tc = 0 << 9 # 1 bit
    rd = 1 << 8 # 1 bit # 再帰要求（通常）
    ra = 0 << 7 # 1 bit
    z = 0 << 4 # 3 bits
    rcode = 0 # 4 bits
    qd_count = 1 # 16 bits
    ancount = 0 # 16 bits
    nscount = 0 # 16 bits
    arcount = 0 # 16 bits
    second_hw = qr & opcode & aa & tc & rd & ra & ra & z & rcode
    header = struct.pack('!hhhhhh', query_id, second_hw, qd_count, ancount, nscount, arcount)
    labels = domain_str.split('.')
    qname = b''
    for s in labels:
        qname += struct.pack('!B', len(s))
        qname += s.encode()
    qname += b'\0'
    return header + qname + struct.pack('!hh', DNS_QTYPE_A, DNS_QCLASS_IN)

def show_dns_reply(reply_bytes):
    i = 0
    for b in reply_bytes:
        i += 1
        print(f'{b:02x} ', end='')
        if i % 8 == 0:
            print('  ', end='')
        if i % 16 == 0:
            print()

if len(sys.argv) < 3:
    print(f'Usage python3 {sys.argv[0]} server domain_in_question', file=sys.stderr)
    sys.exit(1)

destination_host = sys.argv[1]
domain_in_question = sys.argv[2]
RCV_BUF_SIZE = 512

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    req = make_dns_request(domain_in_question)
    s.sendto(req, (destination_host, DNS_PORT))
    # TODO: handle timeout
    (rep, addr) = s.recvfrom(RCV_BUF_SIZE)

show_dns_reply(rep)

# simple_dns.py - Simple DNS client
#
import random
import socket
import struct
import sys

DNS_QTYPE_A = 1
DNS_QCLASS_IN = 1
DNS_PORT = 53
DNS_MAX_MSG_LEN = 512

def make_dns_request(domain_str):
    """Makes a DNS query request message

    :param domain_str: string of domain
    :return: bytes of DNS query message
    """
    query_id = random.getrandbits(16) # 16 bits
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
    second_hw = qr | opcode | aa | tc | rd | ra | ra | z | rcode
    header = struct.pack('!HHHHHH', query_id, second_hw, qd_count, ancount, nscount, arcount)
    labels = domain_str.split('.')
    qname = b''
    for s in labels:
        qname += struct.pack('!B', len(s))
        qname += s.encode()
    qname += b'\0'
    print(f'Query ID: {query_id:5d}')
    return header + qname + struct.pack('!hh', DNS_QTYPE_A, DNS_QCLASS_IN)

def show_dns_reply(reply_bytes):
    """Shows DNS reply

    :param reply_bytes: Replied DNS message
    """
    # TODO: decode the reply message
    print("------------------")
    i = 0
    for b in reply_bytes:
        i += 1
        print(f'{b:02x} ', end='')
        if i % 8 == 0:
            print('  ', end='')
        if i % 16 == 0:
            print()
    # decode header
    print()
    print("------------------")
    header = reply_bytes[:12]
    body = reply_bytes[12:]
    (query_id, field_byte1, field_byte2, qdcount, ancount, nscount, arcount) = struct.unpack('!HBBHHHH', header)
    qr = (0x80 & field_byte1) >> 7
    opcode = (0x78 & field_byte1) >> 3
    aa = (0x04 & field_byte1) >> 2
    tc = (0x02 & field_byte1) >> 1
    rd = 0x01 & field_byte1
    ra = (0x80 & field_byte2) >> 7
    z =  (0x70 & field_byte2) >> 4
    rcode = 0x0f & field_byte2
    print(f'ID       {query_id:5d}')
    print(f'QR      {qr:2d}')
    print(f'Opcode  {opcode:2d}')
    print(f'AA      {aa:2d}')
    print(f'TC      {tc:2d}')
    print(f'RD      {rd:2d}')
    print(f'RA      {ra:2d}')
    print(f'Z       {z:2d}')
    print(f'RCODE   {rcode:2d}')
    print(f'QDCOUNT {qdcount:2d}')
    print(f'ANCOUNT {ancount:2d}')
    print(f'NSCOUNT {nscount:2d}')
    print(f'ARCOUNT {arcount:2d}')

if len(sys.argv) < 3:
    print(f'Usage python3 {sys.argv[0]} server domain_in_question', file=sys.stderr)
    sys.exit(1)

destination_host = sys.argv[1]
domain_in_question = sys.argv[2]

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    req = make_dns_request(domain_in_question)
    s.sendto(req, (destination_host, DNS_PORT))
    # TODO: handle timeout
    (rep, addr) = s.recvfrom(DNS_MAX_MSG_LEN)

show_dns_reply(rep)

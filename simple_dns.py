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

class DNSHeader:
    def __init__(self, header_bytes=None, query_id=0, qr=0, opcode=0, aa=0, tc=0,
                 rd=1, ra=0, z=0, rcode=0, qdcount=1, ancount=0, nscount=0, arcount=0):
        if header_bytes:
            self.init_from_bytes(header_bytes)
            return
        self.query_id = query_id
        self.qr = qr
        self.opcode = opcode
        self.aa = aa
        self.tc = tc
        self.ra = ra
        self.rd = rd
        self.z = z
        self.rcode = rcode
        self.qdcount = qdcount
        self.ancount = ancount
        self.nscount = nscount
        self.arcount = arcount

    def init_from_bytes(self, header_bytes):
        (query_id, field_byte1, field_byte2, qdcount, ancount, nscount, arcount) = struct.unpack('!HBBHHHH', header_bytes)
        self.qr = (0x80 & field_byte1) >> 7
        self.opcode = (0x78 & field_byte1) >> 3
        self.aa = (0x04 & field_byte1) >> 2
        self.tc = (0x02 & field_byte1) >> 1
        self.rd = 0x01 & field_byte1
        self.ra = (0x80 & field_byte2) >> 7
        self.z =  (0x70 & field_byte2) >> 4
        self.rcode = 0x0f & field_byte2
        self.query_id = query_id
        self.qdcount = qdcount
        self.ancount = ancount
        self.nscount = nscount
        self.arcount = arcount

    def get_bytes(self):
        second_hw = (self.qr << 15 | self.opcode << 11 | self.aa << 10 | self.tc << 9 |
                     self.rd << 8 | self.ra << 7 | self.z << 4)
        header_bytes = struct.pack('!HHHHHH', self.query_id, second_hw,
                                   self.qdcount, self.ancount, self.nscount, self.arcount)
        return header_bytes


class DNSRecord:
    def __init__(self):
        pass

class DNSMessage:
    def __init__(self):
        pass

    def __init__(self, reply_bytes):
        pass

class DNSRecordReader:
    pass

class DNSClient:
    DNS_UDP_MAX_MESSAGE_LENGTH = 512

    def __init__(self):
        pass

    def do_query(self, nameserver, domain_str):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            req = self.make_dns_request(domain_str)
            s.sendto(req, (nameserver, DNS_PORT))
            # TODO: handle timeout
            (rep, addr) = s.recvfrom(DNSClient.DNS_UDP_MAX_MESSAGE_LENGTH)
        self.show_dns_reply(rep)

    def make_dns_request(self, domain_str):
        """Makes a DNS query request message

        :param domain_str: string of domain
        :return: bytes of DNS query message
        """
        header_bytes = DNSHeader(query_id=random.getrandbits(16)).get_bytes()
        labels = domain_str.split('.')
        qname = b''
        for s in labels:
            qname += struct.pack('!B', len(s))
            qname += s.encode()
        qname += b'\0'
        return header_bytes + qname + struct.pack('!hh', DNS_QTYPE_A, DNS_QCLASS_IN)

    def show_dns_reply(self, reply_bytes):
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
        header_bytes = reply_bytes[:12]
        body_bytes = reply_bytes[12:]
        header = DNSHeader(header_bytes)
        print(f'ID       {header.query_id:5d}')
        print(f'QR      {header.qr:2d}')
        print(f'Opcode  {header.opcode:2d}')
        print(f'AA      {header.aa:2d}')
        print(f'TC      {header.tc:2d}')
        print(f'RD      {header.rd:2d}')
        print(f'RA      {header.ra:2d}')
        print(f'Z       {header.z:2d}')
        print(f'RCODE   {header.rcode:2d}')
        print(f'QDCOUNT {header.qdcount:2d}')
        print(f'ANCOUNT {header.ancount:2d}')
        print(f'NSCOUNT {header.nscount:2d}')
        print(f'ARCOUNT {header.arcount:2d}')


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f'Usage python3 {sys.argv[0]} server domain_in_question', file=sys.stderr)
        sys.exit(1)

    nameserver = sys.argv[1]
    domain_str = sys.argv[2]
    dns_client = DNSClient()
    dns_client.do_query(nameserver, domain_str)

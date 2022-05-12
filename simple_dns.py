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

def dump_bytes(byte_data):
    i = 0
    dump_str = ""
    for b in byte_data:
        i += 1
        if (b == 45 or 48 <= b <= 57 or 65 <= b <= 90 or
            97 <= b <= 122):
            dump_str += f'{b:c}'
        else:
            dump_str += '_'
        print(f'{b:02x} ', end='')
        if i % 8 == 0:
            print('  ', end='')
        if i % 16 == 0:
            print('' + dump_str)
            dump_str = ""
    char_offset = 50 - (i % 16) * 3
    if char_offset > 26:
        char_offset += 2
    if char_offset < 50:
        print(' ' * char_offset + dump_str)
    print()

class DNSHeader:
    qr_str = ["Query", "Response"]
    opcode_str = ["QUERY", "IQUERY", "STATUS"] + ["RESERVED"] * 13
    aa_str = ["", "Authoritative Answer"]
    tc_str = ["", "Truncated"]
    rd_str = ["", "Recursion Desired"]
    ra_str = ["", "Recursion Available"]
    rcode_str = ["No error", "Format error", "Server failure",
                 "Name Error", "Not Implementd", "Refused"] + ["Reserved"] * 10
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

    def show(self):
        print(f'ID       {self.query_id:5d}')
        print(f'QR      {self.qr:2d} {DNSHeader.qr_str[self.qr]}')
        print(f'Opcode  {self.opcode:2d} {DNSHeader.opcode_str[self.opcode]}')
        print(f'AA      {self.aa:2d} {DNSHeader.aa_str[self.aa]}')
        print(f'TC      {self.tc:2d} {DNSHeader.tc_str[self.tc]}')
        print(f'RD      {self.rd:2d} {DNSHeader.rd_str[self.rd]}')
        print(f'RA      {self.ra:2d} {DNSHeader.ra_str[self.ra]}')
        print(f'Z       {self.z:2d}')
        print(f'RCODE   {self.rcode:2d} {DNSHeader.rcode_str[self.rcode]}')
        print(f'QDCOUNT {self.qdcount:2d}')
        print(f'ANCOUNT {self.ancount:2d}')
        print(f'NSCOUNT {self.nscount:2d}')
        print(f'ARCOUNT {self.arcount:2d}')


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
        print("* Hex dump")
        dump_bytes(reply_bytes)
        print()
        print("# Header ")
        header_bytes = reply_bytes[:12]
        body_bytes = reply_bytes[12:]
        header = DNSHeader(header_bytes)
        header.show()


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f'Usage python3 {sys.argv[0]} server domain_in_question', file=sys.stderr)
        sys.exit(1)

    nameserver = sys.argv[1]
    domain_str = sys.argv[2]
    dns_client = DNSClient()
    dns_client.do_query(nameserver, domain_str)

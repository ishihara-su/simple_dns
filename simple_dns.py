
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

class DNSNameManager:
    def __init__(self):
        self._dict = {}

    def read_domain_str(self, offset, domain_bytes):
        domain_str = ''
        i = 0
        while True:
            b = domain_bytes[i]
            if b >> 6 == 3: # Top 2 bits are 11
                return domain_str + self.get_label(b & 0x3f)
            elif b == 0:
                return domain_str
            elif b > 0x3f:
                # TODO: raise Error in DNSQuestion
                break
            label = domain_bytes[i+1:i+b+1]
            next_pos = i + b + 1 if domain_bytes[i+b+1] > 0 else 0
            self.register(offset + i, label, offset + next_pos)
            domain_str += '.' if i > 0 else ''
            domain_str += label

    def get_label(self, offset):
        label = ''
        while offset > 0:
            (new_label, offset) = self._dict[offset]
            if label == '':
                label = new_label
            else:
                label += '.' + new_label
        return label

    def register(self, offset, label, next_offset):
        self._dict[offset] = (label, next_offset)

class DNSQuestion:
    QTYPE_A = 1
    QTYPE_NS = 2
    QTYPE_MD = 3
    QTYPE_MF = 4
    QTYPE_CNAME = 5
    QTYPE_SOA = 6
    QTYPE_MB = 7
    QTYPE_MG = 8
    QTYPE_MR = 9
    QTYPE_NULL = 10
    QTYPE_WKS = 11
    QTYPE_PTR = 12
    QTYPE_HINFO = 13
    QTYPE_MINFO = 14
    QTYPE_MX = 15
    QTYPE_TXT = 16
    QTYPE_AXFR = 252
    QTYPE_MAILB = 253
    QTYPE_MAILA = 254
    QTYPE_ALL = 255
    qtype_str = {1:"A", 2:"NS", 3:"MD", 4:"MF", 5:"CNAME", 6:"SOA", 7:"MB", 8:"MG",
                 9:"MR", 10:"NULL", 11:"WKS", 12:"PTR", 13:"HINFO", 14:"MINFO",
                 15:"MX", 16:"TXT", 252:"AXFR", 253:"MAILB", 254:"MAILA", 255:"*"}
    CLASS_IN = 1
    CLASS_CS = 2
    CLASS_CH = 3
    CLASS_HS = 4
    class_str = {1:"IN", 2:"CS", 3:"CH", 4:"HS"}

    def __init__(self, name_manager, offset, question_bytes=None,
                 domain='', qtype=QTYPE_A, qclass=CLASS_IN):
        if question_bytes:
            self.init_from_bytes(name_manager, offset, question_bytes)
            return
        self.domain = domain
        self.qtype = qtype
        self.qclass = qclass
        self._byte_data = self._make_bytes(name_manager, offset)

    def init_from_bytes(self, name_manager: DNSNameManager, offset, question_bytes):
        self.domain = name_manager.read_domain_str(offset, question_bytes)
        qtype_pos = question_bytes.find(b'\0') + 1
        self.qtype = question_bytes[qtype_pos]
        self.qclass = question_bytes[qtype_pos+1]
        self._byte_data = question_bytes


    def _make_bytes(self, name_manager: DNSNameManager, offset):
        labels = self.domain.split('.')
        qname = b''
        pos = 0
        positions = []
        for s in labels:
            qname += struct.pack('!B', len(s))
            qname += s.encode()
            positions.append(pos)
            pos += len(s)
        qname += b'\0'
        positions.append(0)
        for i in len(labels):
            name_manager.register(offset+positions[i], labels[i], offset+positions[i+1])
        return qname +struct.pack('!HH', self.qtype, self.qclass)

    def get_bytes(self):
        return self._byte_data

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
        self.name_manager = DNSNameManager()
        pass

    def do_query(self, nameserver, domain_str):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            req = self.make_dns_request_new(domain_str)
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

    def make_dns_request_new(self, domain_str):
        header_bytes = DNSHeader(query_id=random.getrandbits(16)).get_bytes()
        question_bytes = DNSQuestion(self.name_manager, len(header_bytes),
                                     domain=domain_str).get_bytes()
        return header_bytes + question_bytes

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

# simple_dns.py - Simple DNS client
#   Susumu Ishihara <ishihara.susumu@shizuoka.ac.jp>
#
#   Usage: python3 simple_dns.py name_server domain
#

from __future__ import annotations
import random
import socket
import struct
import sys

DNS_QTYPE_A = 1
DNS_QCLASS_IN = 1
DNS_PORT = 53
DNS_MAX_MSG_LEN = 512


def debug_msg(message_str):
    print("DEBUG: ", end='', file=sys.stderr)
    print(message_str, file=sys.stderr)


def error_exit(message_str):
    print(f"Error: {message_str}", file=sys.stderr)
    sys.exit(1)


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

    def __init__(self, header_bytes: bytes = None, query_id: int = 0, qr: int = 0,
                 opcode: int = 0, aa: int = 0, tc: int = 0,
                 rd: int = 1, ra: int = 0, z: int = 0, rcode: int = 0,
                 qdcount: int = 1, ancount: int = 0, nscount: int = 0, arcount: int = 0):
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

    def init_from_bytes(self, header_bytes: bytes):
        (query_id, field_byte1, field_byte2, qdcount, ancount,
         nscount, arcount) = struct.unpack('!HBBHHHH', header_bytes)
        self.qr = (0x80 & field_byte1) >> 7
        self.opcode = (0x78 & field_byte1) >> 3
        self.aa = (0x04 & field_byte1) >> 2
        self.tc = (0x02 & field_byte1) >> 1
        self.rd = 0x01 & field_byte1
        self.ra = (0x80 & field_byte2) >> 7
        self.z = (0x70 & field_byte2) >> 4
        self.rcode = 0x0f & field_byte2
        self.query_id = query_id
        self.qdcount = qdcount
        self.ancount = ancount
        self.nscount = nscount
        self.arcount = arcount

    def get_bytes(self) -> bytes:
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

    def read_domain_str(self, offset: int, message_bytes: bytes) -> tuple[str, int]:
        """Read domain strings from the message

        :parameter offset: Position of the first byte of the string in the message
        :parameter message_bytes: Bytes of the message
        :returns: Tuple of the domain string and the offset of the byte after the string
        """
        domain_str = ''
        i = offset
        while True:
            if i >= len(message_bytes):
                error_exit("Label format error")
            b = message_bytes[i]
            debug_msg(f'read_domain_str(): i={i} {b:02x}')
            if b >> 6 == 3:  # Top 2 bits are 11
                return (domain_str + self.get_label(b & 0x3f), i+1)
            elif b == 0:
                return (domain_str, i+1)
            elif b > 0x3f:
                # TODO: raise Error in DNSQuestion
                error_exit("DNS Undefined label prefix.")
            label = message_bytes[i+1:i+b+1].decode()
            next_pos = i + b + 1 if message_bytes[i+b+1] > 0 else 0
            self.register(i, label, next_pos)
            domain_str += '.' if i > offset else ''
            domain_str += label
            debug_msg(f'read_domain_str(): domain_str {domain_str}')
            i += b + 1

    def get_label(self, offset: int) -> str:
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
    (Q_A, Q_NS, Q_MD, Q_MF, Q_CNAME,
     Q_SOA, Q_MB, Q_MG, Q_MR, Q_NULL,
     Q_WKS, Q_PTR, Q_HINFO, Q_MINFO, Q_MX, Q_TXT,
     Q_AXFR, Q_MAILB, Q_MAILA, Q_ALL) = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                                         252, 253, 254, 255)
    qtype_str = {1: "A", 2: "NS", 3: "MD", 4: "MF", 5: "CNAME", 6: "SOA", 7: "MB", 8: "MG",
                 9: "MR", 10: "NULL", 11: "WKS", 12: "PTR", 13: "HINFO", 14: "MINFO",
                 15: "MX", 16: "TXT", 252: "AXFR", 253: "MAILB", 254: "MAILA", 255: "*"}
    (C_IN, C_CS, C_CH, C_HS) = (1, 2, 3, 4)
    class_str = {1: "IN", 2: "CS", 3: "CH", 4: "HS"}

    def retrieve_question(name_manager: DNSNameManager,
                          message_bytes: bytes, offset: int) -> tuple[DNSQuestion, int]:
        """Retrieves a Question from a full message

        :parameter message: Full DNS message bytes
        :parameter offset: Position of the question in the message
        :returns: (retrieved DNSQuestion
        """
        (domain, qtype_pos) = name_manager.read_domain_str(offset, message_bytes)
        next_offset = qtype_pos + 4
        debug_msg(f"qtype_pos: {qtype_pos}")
        (qtype, qclass) = struct.unpack(
            '!HH', message_bytes[qtype_pos:next_offset])
        return (DNSQuestion(name_manager, offset, domain, qtype, qclass,
                            message_bytes[offset:next_offset]), next_offset)

    def __init__(self, name_manager: DNSNameManager, offset: int,
                 domain: str = '', qtype: int = Q_A, qclass: int = C_IN, byte_data: bytes = None):
        self.domain = domain
        self.qtype = qtype
        self.qclass = qclass
        self._byte_data = None
        if not byte_data:
            self._byte_data = self._make_bytes(name_manager, offset)
        else:
            self._byte_data = byte_data

    def _make_bytes(self, name_manager: DNSNameManager, offset: int) -> bytes:
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
        for i in range(len(labels)):
            name_manager.register(
                offset+positions[i], labels[i], offset+positions[i+1])
        return qname + struct.pack('!HH', self.qtype, self.qclass)

    def get_bytes(self) -> bytes:
        return self._byte_data

    def show(self):
        print(f"Question: {self.domain} "
              f"{self.qtype_str[self.qtype]}({self.qtype}) "
              f"{self.class_str[self.qclass]}({self.qclass})")


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
            req = self.make_dns_request(domain_str)
            s.sendto(req, (nameserver, DNS_PORT))
            # TODO: handle timeout
            (rep, addr) = s.recvfrom(DNSClient.DNS_UDP_MAX_MESSAGE_LENGTH)
        self.show_dns_reply(rep)

    def make_dns_request(self, domain_str):
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
        # TODO: change to DNSHeader.retrieve_from_message
        header = DNSHeader(header_bytes)
        header.show()
        offset = 12
        questions = []
        for i in range(header.qdcount):
            (q, offset) = DNSQuestion.retrieve_question(
                self.name_manager, reply_bytes, offset)
            q.show()
            questions.append(q)


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(
            f'Usage python3 {sys.argv[0]} server domain_in_question', file=sys.stderr)
        sys.exit(1)

    nameserver = sys.argv[1]
    domain_str = sys.argv[2]
    dns_client = DNSClient()
    dns_client.do_query(nameserver, domain_str)

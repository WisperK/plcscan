"""
File: s7.py
Desc: Partial implementation of s7comm protocol
Version: 0.1

Copyright (c) 2012 Dmitry Efanov (Positive Research)
"""

__author__ = 'defanov'

from struct import pack, unpack
from random import randint
from optparse import OptionGroup

import struct
import socket
import string


__FILTER = ''.join(
    [' '] + [
        ' ' if chr(x) not in string.printable or chr(x) in string.whitespace else chr(x)
        for x in range(1, 256)
    ]
)


def _to_bytes(value):
    if isinstance(value, bytes):
        return value
    if hasattr(value, 'pack'):
        return value.pack()
    return str(value).encode('latin-1', errors='replace')


def _to_text(value):
    if isinstance(value, bytes):
        return value.decode('latin-1', errors='replace')
    return value


def StripUnprintable(msg):
    return _to_text(msg).translate(str.maketrans(__FILTER))


class TPKTPacket:
    def __init__(self, data=b''):
        self.data = _to_bytes(data)

    def pack(self):
        return pack('!BBH', 3, 0, len(self.data) + 4) + self.data

    def unpack(self, packet):
        try:
            _version, _reserved, packet_len = unpack('!BBH', packet[:4])
        except struct.error:
            raise S7ProtocolError('Unknown TPKT format')

        self.data = packet[4:packet_len]
        return self


class COTPConnectionPacket:
    def __init__(self, dst_ref=0, src_ref=0, dst_tsap=0, src_tsap=0, tpdu_size=0):
        self.dst_ref = dst_ref
        self.src_ref = src_ref
        self.dst_tsap = dst_tsap
        self.src_tsap = src_tsap
        self.tpdu_size = tpdu_size

    def pack(self):
        return pack(
            '!BBHHBBBHBBHBBB',
            17,
            0xE0,
            self.dst_ref,
            self.src_ref,
            0,
            0xC1,
            2,
            self.src_tsap,
            0xC2,
            2,
            self.dst_tsap,
            0xC0,
            1,
            self.tpdu_size,
        )

    def __bytes__(self):
        return self.pack()

    def unpack(self, packet):
        try:
            size, pdu_type, self.dst_ref, self.src_ref, _flags = unpack('!BBHHB', packet[:7])
        except struct.error:
            raise S7ProtocolError('Wrong CC packet format')
        if len(packet) != size + 1:
            raise S7ProtocolError('Wrong CC packet size')
        if pdu_type != 0xD0:
            raise S7ProtocolError('Not a CC packet')
        return self


class COTPDataPacket:
    def __init__(self, data=b''):
        self.data = _to_bytes(data)

    def pack(self):
        return pack('!BBB', 2, 0xF0, 0x80) + self.data

    def unpack(self, packet):
        self.data = packet[packet[0] + 1:]
        return self

    def __bytes__(self):
        return self.pack()


class S7Packet:
    def __init__(self, type=1, req_id=0, parameters=b'', data=b''):
        self.type = type
        self.req_id = req_id
        self.parameters = _to_bytes(parameters)
        self.data = _to_bytes(data)
        self.error = 0

    def pack(self):
        if self.type not in [1, 7]:
            raise S7ProtocolError('Unknown pdu type')
        return (
            pack('!BBHHHH', 0x32, self.type, 0, self.req_id, len(self.parameters), len(self.data))
            + self.parameters
            + self.data
        )

    def unpack(self, packet):
        try:
            pdu_type = packet[1]
            if pdu_type in [3, 2]:
                header_size = 12
                _magic, self.type, _reserved, self.req_id, parameters_length, data_length, self.error = unpack(
                    '!BBHHHHH', packet[:header_size]
                )
                if self.error:
                    raise S7Error(self.error)
            elif pdu_type in [1, 7]:
                header_size = 10
                _magic, self.type, _reserved, self.req_id, parameters_length, data_length = unpack(
                    '!BBHHHH', packet[:header_size]
                )
            else:
                raise S7ProtocolError('Unknown pdu type (%d)' % pdu_type)
        except struct.error:
            raise S7ProtocolError('Wrong S7 packet format')

        self.parameters = packet[header_size:header_size + parameters_length]
        self.data = packet[header_size + parameters_length:header_size + parameters_length + data_length]
        return self

    def __bytes__(self):
        return self.pack()


class S7ProtocolError(Exception):
    def __init__(self, message, packet=b''):
        self.message = message
        self.packet = packet

    def __str__(self):
        return '[ERROR][S7Protocol] %s' % self.message


class S7Error(Exception):
    _errors = {
        0x05: 'Address Error',
        0x0A: 'Item not available',
        0x8104: 'Context not supported',
        0x8500: 'Wrong PDU size',
    }

    def __init__(self, code):
        self.code = code

    def __str__(self):
        message = S7Error._errors[self.code] if self.code in S7Error._errors else 'Unknown error'
        return '[ERROR][S7][0x%x] %s' % (self.code, message)


def Split(ar, size):
    return [ar[i:i + size] for i in range(0, len(ar), size)]


class s7:
    def __init__(self, ip, port, src_tsap=0x200, dst_tsap=0x201, timeout=8):
        self.ip = ip
        self.port = port
        self.req_id = 0
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.dst_ref = 0
        self.src_ref = 0x04
        self.dst_tsap = dst_tsap
        self.src_tsap = src_tsap
        self.timeout = timeout

    def Connect(self):
        self.src_ref = randint(1, 20)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.settimeout(self.timeout)
        self.s.connect((self.ip, self.port))
        self.s.sendall(TPKTPacket(COTPConnectionPacket(self.dst_ref, self.src_ref, self.dst_tsap, self.src_tsap, 0x0A)).pack())
        reply = self.s.recv(1024)
        COTPConnectionPacket().unpack(TPKTPacket().unpack(reply).data)
        self.NegotiatePDU()

    def Request(self, type, parameters=b'', data=b''):
        packet = TPKTPacket(COTPDataPacket(S7Packet(type, self.req_id, parameters, data))).pack()
        self.s.sendall(packet)
        reply = self.s.recv(1024)
        response = S7Packet().unpack(COTPDataPacket().unpack(TPKTPacket().unpack(reply).data).data)
        if self.req_id != response.req_id:
            raise S7ProtocolError('Sequence ID not correct')
        return response

    def NegotiatePDU(self, pdu=480):
        response = self.Request(0x01, pack('!BBHHH', 0xF0, 0x00, 0x01, 0x01, pdu))
        _func, _unknown, _pj1, _pj2, pdu = unpack('!BBHHH', response.parameters)
        return pdu

    def Function(self, type, group, function, data=b''):
        parameters = pack('!LBBBB', 0x00011200 + 0x04, 0x11, type * 0x10 + group, function, 0x00)
        data = pack('!BBH', 0xFF, 0x09, len(data)) + data
        response = self.Request(0x07, parameters, data)

        code, _transport_size, _data_len = unpack('!BBH', response.data[:4])
        if code != 0xFF:
            raise S7Error(code)
        return response.data[4:]

    def ReadSZL(self, szl_id):
        szl_data = self.Function(0x04, 0x04, 0x01, pack('!HH', szl_id, 1))
        _szl_id, _szl_index, element_size, _element_count = unpack('!HHHH', szl_data[:8])
        return Split(szl_data[8:], element_size)


def BruteTsap(ip, port, src_tsaps=(0x100, 0x200), dst_tsaps=(0x102, 0x200, 0x201)):
    for src_tsap in src_tsaps:
        for dst_tsap in dst_tsaps:
            try:
                con = s7(ip, port)
                con.src_tsap = src_tsap
                con.dst_tsap = dst_tsap
                con.Connect()
                return src_tsap, dst_tsap
            except S7ProtocolError:
                pass
    return None


def GetIdentity(ip, port, src_tsap, dst_tsap):
    res = []

    szl_dict = {
        0x11: {
            'title': 'Module Identification',
            'indexes': {1: 'Module', 6: 'Basic Hardware', 7: 'Basic Firmware'},
            'packer': {
                (1, 6): lambda packet: '{0:s} v.{2:d}.{3:d}'.format(_to_text(unpack('!20sHBBH', packet)[0]).rstrip('\x00'), *unpack('!20sHBBH', packet)[1:]),
                (7,): lambda packet: '{0:s} v.{3:d}.{4:d}.{5:d}'.format(_to_text(unpack('!20sHBBBB', packet)[0]).rstrip('\x00'), *unpack('!20sHBBBB', packet)[1:]),
            },
        },
        0x1C: {
            'title': 'Component Identification',
            'indexes': {
                1: 'Name of the PLC',
                2: 'Name of the module',
                3: 'Plant identification',
                4: 'Copyright',
                5: 'Serial number of module',
                6: 'Reserved for operating system',
                7: 'Module type name',
                8: 'Serial number of memory card',
                9: 'Manufacturer and profile of a CPU module',
                10: 'OEM ID of a module',
                11: 'Location designation of a module',
            },
            'packer': {
                (1, 2, 5): lambda packet: _to_text(packet[:24]),
                (3, 7, 8): lambda packet: _to_text(packet[:32]),
                (4,): lambda packet: _to_text(packet[:26]),
            },
        },
    }

    con = s7(ip, port, src_tsap, dst_tsap)
    con.Connect()

    for szl_id in szl_dict.keys():
        try:
            entities = con.ReadSZL(szl_id)
        except S7Error:
            continue

        indexes = szl_dict[szl_id]['indexes']
        packers = szl_dict[szl_id]['packer']
        for item in entities:
            if len(item) > 2:
                n, = unpack('!H', item[:2])
                item = item[2:]
                title = indexes[n] if n in indexes else 'Unknown (%d)' % n

                try:
                    packers_keys = [i for i in packers.keys() if n in i]
                    formated_item = packers[packers_keys[0]](item).strip('\x00')
                except (struct.error, IndexError):
                    formated_item = StripUnprintable(item).strip('\x00')

                res.append('%s: %s\t(%s)' % (title.ljust(25), formated_item.ljust(30), item.hex()))

    return res


def Scan(ip, port, options):
    src_tsaps = [int(n.strip(), 0) for n in options.src_tsap.split(',')] if options.src_tsap else [0x100, 0x200]
    dst_tsaps = [int(n.strip(), 0) for n in options.dst_tsap.split(',')] if options.dst_tsap else [0x102, 0x200, 0x201]

    res = ()
    try:
        res = BruteTsap(ip, port, src_tsaps, dst_tsaps)
    except socket.error as e:
        print('%s:%d %s' % (ip, port, e))

    if not res:
        return False

    print('%s:%d S7comm (src_tsap=0x%x, dst_tsap=0x%x)' % (ip, port, res[0], res[1]))

    identities = []
    for _attempt in [0, 1]:
        try:
            identities = GetIdentity(ip, port, res[0], res[1])
            break
        except (S7ProtocolError, socket.error) as e:
            print('  %s' % e)

    for line in identities:
        print('  %s' % line)

    return True


def AddOptions(parser):
    group = OptionGroup(parser, 'S7 scanner options')
    group.add_option('--src-tsap', help='Try this src-tsap (list) (default: 0x100,0x200)', type='string', metavar='LIST')
    group.add_option('--dst-tsap', help='Try this dst-tsap (list) (default: 0x102,0x200,0x201)', type='string', metavar='LIST')
    parser.add_option_group(group)

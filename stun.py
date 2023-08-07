#!/usr/bin/python3
import binascii
import logging
import random
import socket
import argparse
import sys
import struct
import codecs


# This should be replaced with lookups of
# _stun._udp.divmod.com and _stun._udp.wirlab.net
DefaultServers = [
    ("stun.qq.com", 3478)
    ("stun.miwifi.com", 3478),
    ('stun.xten.net', 3478),
    ('sip.iptel.org', 3478),
    ('stun2.wirlab.net', 3478),
    ('stun.wirlab.net', 3478),
    ('stun1.vovida.org', 3478),
    ('tesla.divmod.net', 3478),
    ('erlang.divmod.net', 3478),
]


class MessageType:
    BindingRequest = 0x0001
    BindingResponse = 0x0101
    BindingErrorResponse = 0x0111
    SharedSecretRequest = 0x0002
    SharedSecretResponse = 0x0102
    SharedSecretErrorResponse = 0x0112

    __types_string = {
        BindingRequest: "Binding Request",
        BindingResponse: "Binding Response",
        BindingErrorResponse: "Binding Error Response",
        SharedSecretRequest: "Shared Secret Request",
        SharedSecretResponse: "Shared Secret Response",
        SharedSecretErrorResponse: "Shared Secret Error Response"
    }

    @classmethod
    def as_string(cls, typ: int):
        cls.__types_string.setdefault(typ, "Unknown Message Type")


def get_transaction_id() -> bytes:
    # 96 bits Transaction ID
    MagicCookieBytes +
    return random.randbytes(12)


class AttributeType:
    MappedAddress = 0x0001
    ResponseAddress = 0x0002
    ChangeRequest = 0x0003
    SourceAddress = 0x0004
    ChangedRequest = 0x0005
    Username = 0x0006
    Password = 0x0007
    MessageIntegrity = 0x0008
    ErrorCode = 0x0009
    UnknownAttributes = 0x000a
    ReflectedFrom = 0x000b
    XORMappedAddress = 0x0020

    __types_string = {
        0x0001: 'MAPPED-ADDRESS',
        0x0002: 'RESPONSE-ADDRESS',
        0x0003: 'CHANGE-REQUEST',
        0x0004: 'SOURCE-ADDRESS',
        0x0005: 'CHANGED-ADDRESS',
        0x0006: 'USERNAME',
        0x0007: 'PASSWORD',
        0x0008: 'MESSAGE-INTEGRITY',
        0x0009: 'ERROR-CODE',
        0x000a: 'UNKNOWN-ATTRIBUTES',
        0x000b: 'REFLECTED-FROM',
        0x0020: 'XOR-MAPPED-ADDRESS'
    }

    @classmethod
    def as_string(cls, typ):
        return cls.__types_string.setdefault(typ, "Unknown Attribute Type")


# The Error Code
responseCodes = {
    400: 'Bad Request',
    420: 'Unknown attribute',
    431: 'Integrity Check Failure',
    500: 'Server Error',
    600: 'Global Failure'
}


MagicCookie = 0x2112A442
MagicCookieBytes = MagicCookie.to_bytes(byteorder="big")

# big endian, 2byte message type, 2 byte message length,
# 4 byte magic cookie, 12 byte transaction id
header_description = "!hh16b"
header_length = 20


def pack_header(typ:int, length:int, transaction_id:bytes) -> bytes:
    return struct.pack(header_description, typ, length, MagicCookie, transaction_id)


def unpack_header(data: bytes) -> (int, int, bytes):
    typ, length, transaction_id = struct.unpack(header_description, data)
    return typ, length, transaction_id


attribute_header_description = "!hh"
attribute_header_length = 4


def pack_attribute_header(typ: int, data: bytes) -> bytes:
    length = 0
    if data:
        length = len(data)
    return struct.pack(attribute_header_description, typ, length)

def unpack_attribute_header(data: bytes) -> (int, int):
    typ, length = struct.unpack(attribute_header_description, data)
    return typ, length

class StunError(Exception):
    pass

class StunResult:
    def __init__(self) -> None:
        self.ExternalIP: str = ""
        self.ExternalPort: int = 0
        self.SourceIP: str = ""
        self.SourcePort: int = 0
        self.ChangedIP: str = ""
        self.ChangedPort: int = 0

def connect_stun_server(stun_host: str, stun_port: int, 
                        source_ip: str, source_port: int, retry=3) -> AttributesType:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((source_ip, source_port))

    with sock:
        for _ in range(retry):
            stunresp = _connect_stun_server(sock, stun_host, stun_port):
            if stunresp is not None:
                return stunresp
    return 


def _connect_stun_server(sock: socket.socket, stun_host: str, stun_port: int) -> list:
    send_transaction_id = get_transaction_id()
    sendata = pack_header(MessageType.BindingRequest, 0, send_transaction_id)
    sock.sendto(sendata, (stun_host, stun_port))
    logging.debug("sendto %s %d data",(stun_host, stun_port), len(sendata))
    data, addr = sock.recvfrom(508)  # largest safe udp package size
    logging.debug("recvfrom %s %d data", addr, len(data))
    if len(data) < header_length:
        logging.debug("recvfrom incomplete header, want %d, got %d",
                      header_length, len(data))
        return
    msgtype, length, transaction_id = unpack_header(data[:header_length])
    logging.debug("recvfrom %s, %d, %d, %b", 
                  MessageType.as_string(msgtype), length, magic_cookie, transaction_id)
    if msgtype != MessageType.BindingResponse:
        return
    if transaction_id != send_transaction_id:
        return
    if len(data) < header_length+length:
        logging.debug("recvfrom incomplete body, want %d got %d",
                      header_length+length, len(data))
        return
    data = data[header_length:header_length+length]
    attributes = []
    while data:
        typ, length = unpack_attribute_header(data[:attribute_header_length])
        data = data[attribute_header_length:]
        if len(data) < length:
            logging.debug("recvfrom incomplete attribute: want %d, got %d",
                        length, len(data))
            return
        value = data[:length]
        data = data[length:]
        attributes.append((typ, value))
    return attributes


def xor(lhs, rhs):
    return bytes(a ^ b for a, b in zip(lhs, rhs))

def parse_address(typ: int, data: bytes) -> (str, int):
    magic, family, port = struct.unpack('bb2b')
    if typ == AttributeType.XORMappedAddress:
        port = xor(port, MagicCookieBytes[:2])

    port = int.from_bytes(port, byteorder='big')
    if family == 0x01: # IPv4
        return socket.inet_ntop(socket.AF_INET, data[4:8]), struct.unpack()
    elif family == 0x02:
        return socket.inet_ntop(socket.AF_INET, data[4:20]), port
    else:
        return ("", 0)

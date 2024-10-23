from itertools import batched
import socket
from dataclasses import dataclass

TIMEOUT = 0.01
MAX_PACKET_SIZE = 1514
HEADER_SIZE = 16
MAX_DATA_SIZE = MAX_PACKET_SIZE - HEADER_SIZE


@dataclass
class Header:
    syn: int
    ack: int

    def to_bytes(self) -> bytes:
        return self.syn.to_bytes(HEADER_SIZE // 2) + self.ack.to_bytes(HEADER_SIZE // 2)

    @classmethod
    def from_bytes(cls, data: bytes) -> "Header":
        return cls(
            int.from_bytes(data[: HEADER_SIZE // 2]),
            int.from_bytes(data[HEADER_SIZE // 2 :]),
        )


class Packet:
    def __init__(
        self,
        data: bytes,
        header: Header | None = None,
        syn: int | None = None,
        ack: int | None = None,
    ):
        self.header = header or Header(syn, ack)
        self.data = data

    def to_bytes(self) -> bytes:
        return self.header.to_bytes() + self.data

    @classmethod
    def from_bytes(cls, data: bytes) -> "Packet":
        return cls(data[HEADER_SIZE:], header=Header.from_bytes(data[:HEADER_SIZE]))


class UDPBasedProtocol:
    def __init__(self, *, local_addr, remote_addr):
        self.udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.remote_addr = remote_addr
        self.udp_socket.bind(local_addr)

    def sendto(self, data):
        return self.udp_socket.sendto(data, self.remote_addr)

    def recvfrom(self, n):
        msg, addr = self.udp_socket.recvfrom(n)
        return msg

    def close(self):
        self.udp_socket.close()


class MyTCPProtocol(UDPBasedProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.udp_socket.settimeout(TIMEOUT)

    def send(self, data: bytes) -> None:
        syn = 0

        for batch in batched(data, MAX_DATA_SIZE):
            packet = Packet(batch, ack=0, syn=syn)
            self._reliable_send(packet)
            self._wait_ack(syn)
            syn += 1

    def _wait_ack(self, syn: int) -> None:
        while True:
            try:
                data = self.recvfrom(MAX_DATA_SIZE)
            except Exception:
                continue

            packet = Packet.from_bytes(data)
            if packet.header.ack and packet.header.syn == syn:
                return

    def _reliable_send(self, packet: Packet) -> None:
        while True:
            try:
                self.udp_socket.sendto(packet.to_bytes())
            except Exception:
                continue

    def recv(self, n: int) -> bytes:
        message = b""

        while len(message) < n:
            try:
                data = self.recvfrom(MAX_PACKET_SIZE)
            except Exception:
                continue

            packet = Packet.from_bytes(data)
            self._send_ack(packet.header.syn)
            message += packet.data

        return message

    def _send_ack(self, syn: int) -> None:
        ack = Packet(b"", syn=syn, ack=1)

        while True:
            try:
                self.sendto(ack.to_bytes())
                return
            except Exception:
                continue

    def close(self):
        super().close()

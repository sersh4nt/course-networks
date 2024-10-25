import heapq
import socket
from dataclasses import dataclass
from typing import Generator

TIMEOUT = 0.001
MAX_PACKET_SIZE = 1500
HEADER_SIZE = 16
MAX_DATA_SIZE = MAX_PACKET_SIZE - HEADER_SIZE
MAX_RETRIES = 32


@dataclass
class Header:
    syn: int
    ack: int

    def to_bytes(self) -> bytes:
        return self.syn.to_bytes(HEADER_SIZE // 2, "big") + self.ack.to_bytes(
            HEADER_SIZE // 2, "big"
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "Header":
        return cls(
            int.from_bytes(data[: HEADER_SIZE // 2], "big"),
            int.from_bytes(data[HEADER_SIZE // 2 :], "big"),
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

    def __lt__(self, other: "Packet") -> bool:
        return self.header.syn < other.header.syn

    def __eq__(self, other: "Packet") -> bool:
        return self.header.syn == other.header.syn

    @property
    def is_ack(self) -> bool:
        return self.header.syn == 0


class UDPBasedProtocol:
    def __init__(self, *, local_addr: str, remote_addr: str) -> None:
        self.udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.remote_addr = remote_addr
        self.udp_socket.bind(local_addr)

    def sendto(self, data: bytes) -> int:
        return self.udp_socket.sendto(data, self.remote_addr)

    def recvfrom(self, n: int) -> bytes:
        msg, _ = self.udp_socket.recvfrom(n)
        return msg

    def close(self) -> None:
        self.udp_socket.close()


def batched(
    it: bytes, n: int, offset: int = 0
) -> Generator[tuple[bytes, int], None, None]:
    accumulator = 0

    for start in range(0, len(it), n):
        yield it[offset + start : offset + start + n], accumulator
        accumulator += n


class MyTCPProtocol(UDPBasedProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.udp_socket.settimeout(TIMEOUT)

        self.syn = 1
        self.ack = 1

        self.buffer: list[Packet] = []
        self.buffered_data = b""

    def send(self, data: bytes) -> int:
        sent_already = self.syn
        offset = self.syn - sent_already

        for chunk, accumulator in batched(data, MAX_PACKET_SIZE, offset):
            packet = Packet(chunk, syn=self.syn + accumulator, ack=self.ack)
            self.sendto(packet.to_bytes())

        tries = 0
        while self.syn < sent_already + len(data):
            try:
                response = self.recvfrom(MAX_PACKET_SIZE)
                packet = Packet.from_bytes(response)
                tries = 0

                if not packet.is_ack:
                    if packet.header.syn == self.ack:
                        # packet is in order
                        self.buffered_data += packet.data
                        self.ack += len(packet.data)
                        self.buffered_data += self._process_buffer()
                    else:
                        # packet was reordered
                        heapq.heappush(self.buffer, packet)

                    self._acknowledge()
                    continue

                if packet.header.ack <= self.syn:
                    continue

                self.syn = packet.header.ack

            except Exception:
                tries += 1
                if tries > MAX_RETRIES:
                    break

            if self.syn < sent_already + len(data):
                offset = self.syn - sent_already
                chunk = data[offset : offset + MAX_DATA_SIZE]
                packet = Packet(chunk, syn=self.syn, ack=self.ack)
                self.sendto(packet.to_bytes())

        self.syn = sent_already + len(data)
        return len(data)

    def _process_buffer(self) -> bytes:
        data = b""

        while self.buffer and self.buffer[0].header.syn <= self.ack:
            packet = heapq.heappop(self.buffer)
            if packet.header.syn < self.ack:
                continue

            data += packet.data
            self.ack += len(packet.data)

        return data

    def _acknowledge(self) -> None:
        packet = Packet(data=b"", syn=0, ack=self.ack)
        self.sendto(packet.to_bytes())

    def recv(self, n: int) -> bytes:
        received_already = self.ack
        data = self.buffered_data[:n]
        self.buffered_data = self.buffered_data[n:]
        n -= len(data)

        while self.ack < received_already + n:
            data += self._process_buffer()

            try:
                response = self.recvfrom(MAX_PACKET_SIZE)
                packet = Packet.from_bytes(response)

                if packet.header.syn < self.ack:
                    continue

                if packet.header.syn == self.ack:
                    data += packet.data
                    self.ack += len(packet.data)
                    data += self._process_buffer()
                else:
                    heapq.heappush(self.buffer, packet)

            except Exception:
                self._acknowledge()

        self._acknowledge()

        return data

    def close(self):
        super().close()

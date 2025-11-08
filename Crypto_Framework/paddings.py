from abc import ABC, abstractmethod

class Padding(ABC):
    @abstractmethod
    def pad(self, data: bytes, block_size: int) -> bytes:
        pass

    @abstractmethod
    def unpad(self, data: bytes) -> bytes:
        pass

class ZeroPadding(Padding):
    def pad(self, data, block_size):
        pad_len = (-len(data)) % block_size
        return data + (b'\x00' * pad_len)

    def unpad(self, data):
        return data.rstrip(b'\x00')

class DESBitPadding(Padding):
    def pad(self, data, block_size):
        pad_len = (-len(data)) % block_size
        if pad_len == 0:
            pad_len = block_size
        return data + b'\x80' + (b'\x00' * (pad_len - 1))

    def unpad(self, data):
        # find last 0x80
        idx = data.rfind(b'\x80')
        if idx == -1:
            return data  # or raise
        return data[:idx]

class SchneierFergusonPadding(Padding):
    def pad(self, data, block_size):
        pad_len = (-len(data)) % block_size
        if pad_len == 0:
            pad_len = block_size
        return data + bytes([pad_len]) * pad_len

    def unpad(self, data):
        if not data:
            return data
        n = data[-1]
        if n <= 0 or n > len(data):
            raise ValueError("Invalid padding")
        if data[-n:] != bytes([n])*n:
            raise ValueError("Invalid padding bytes")
        return data[:-n]

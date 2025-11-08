from abc import ABC, abstractmethod
from Crypto.Cipher import AES

class CipherAlgorithm(ABC):
    @abstractmethod
    def encrypt_block(self, block: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt_block(self, block: bytes) -> bytes:
        pass

class CustomVigenere(CipherAlgorithm):
    def __init__(self, key_bytes: bytes, block_size: int):
        self.key = key_bytes
        self.block_size = block_size

    def encrypt_block(self, block):
        out = bytearray(len(block))
        k = self.key
        for i, b in enumerate(block):
            kb = k[i % len(k)]
            out[i] = (b ^ kb) & 0xFF
        return bytes(out)

    def decrypt_block(self, block):
        return self.encrypt_block(block)


class AESAdapter(CipherAlgorithm):
    def __init__(self, key_bytes: bytes, block_size: int):
        self.key = key_bytes
        self.block_size = block_size
        self.aes = AES.new(key=self.key, mode=AES.MODE_ECB)

    def encrypt_block(self, block):
        result = self.aes.encrypt(block)
        return result

    def decrypt_block(self, block):
        result = self.aes.decrypt(block)
        return result

from abc import ABC, abstractmethod
from typing import Optional
from .algorithms import CipherAlgorithm

class Mode(ABC):
    def __init__(self, alg: CipherAlgorithm, block_size: int, iv: Optional[bytes]=None):
        self.alg = alg
        self.bs = block_size
        self.iv = iv

    @abstractmethod
    def encrypt(self, plaintext: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, ciphertext: bytes) -> bytes:
        pass

class ECBMode(Mode):
    def encrypt(self, plaintext):
        out = bytearray()
        for i in range(0, len(plaintext), self.bs):
            block = plaintext[i:i+self.bs]
            out += self.alg.encrypt_block(block)
        return bytes(out)

    def decrypt(self, ciphertext):
        out = bytearray()
        for i in range(0, len(ciphertext), self.bs):
            block = ciphertext[i:i+self.bs]
            out += self.alg.decrypt_block(block)
        return bytes(out)

class CBCMode(Mode):
    def encrypt(self, plaintext):
        iv = bytearray(self.iv)
        out = bytearray()
        for i in range(0, len(plaintext), self.bs):
            block = bytearray(plaintext[i:i+self.bs])
            # XOR with IV
            for j in range(len(block)):
                block[j] ^= iv[j]
            ct = self.alg.encrypt_block(bytes(block))
            out += ct
            iv = bytearray(ct)
        return bytes(out)

    def decrypt(self, ciphertext):
        iv = bytearray(self.iv)
        out = bytearray()
        for i in range(0, len(ciphertext), self.bs):
            block = ciphertext[i:i+self.bs]
            pt_block = bytearray(self.alg.decrypt_block(block))
            for j in range(len(pt_block)):
                pt_block[j] ^= iv[j]
            out += pt_block
            iv = bytearray(block)
        return bytes(out)

class CTRMode(Mode):
    def __init__(self, alg, block_size, iv):
        super().__init__(alg, block_size, iv)
        # counter initialized from iv
        self.counter = int.from_bytes(iv, byteorder='big')

    def _keystream_block(self):
        ctr_bytes = (self.counter).to_bytes(self.bs, byteorder='big')
        self.counter += 1
        return self.alg.encrypt_block(ctr_bytes)

    def encrypt(self, plaintext):
        out = bytearray()
        for i in range(0, len(plaintext), self.bs):
            block = plaintext[i:i+self.bs]
            ks = self._keystream_block()
            # XOR
            out += bytes([b ^ ks[j] for j,b in enumerate(block)])
        return bytes(out)

    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext)

class CFBMode(Mode):
    def encrypt(self, plaintext):
        iv = bytearray(self.iv)
        out = bytearray()
        for i in range(0, len(plaintext), self.bs):
            block = plaintext[i:i+self.bs]
            ks = self.alg.encrypt_block(bytes(iv))
            ct_block = bytearray()
            for j in range(len(block)):
                ct_byte = block[j] ^ ks[j]
                ct_block.append(ct_byte)
            out += ct_block
            iv = bytearray(ct_block)
        return bytes(out)
    def decrypt(self, ciphertext):
        iv = bytearray(self.iv)
        out = bytearray()
        for i in range(0, len(ciphertext), self.bs):
            block = ciphertext[i:i+self.bs]
            ks = self.alg.encrypt_block(bytes(iv))
            pt_block = bytearray()
            for j in range(len(block)):
                pt_byte = block[j] ^ ks[j]
                pt_block.append(pt_byte)
            out += pt_block
            iv = bytearray(block)
        return bytes(out)

class OFBMode(Mode):
    def encrypt(self, plaintext):
        iv = bytearray(self.iv)
        out = bytearray()
        for i in range(0, len(plaintext), self.bs):
            ks = self.alg.encrypt_block(bytes(iv))
            block = plaintext[i:i+self.bs]
            out += bytes([b ^ ks[j] for j,b in enumerate(block)])
            iv = bytearray(ks)
        return bytes(out)

    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext)

# file: block_framework.py
import json
import os
from .paddings import ZeroPadding, DESBitPadding, SchneierFergusonPadding
from .algorithms import CustomVigenere, AESAdapter
from .c_modes import ECBMode, CBCMode, CTRMode, OFBMode, CFBMode


def load_config(path):
    with open(path,'r') as f:
        return json.load(f)

def get_padding(cfg):
    if cfg['padding'].lower().startswith("zero"):
        return ZeroPadding()
    if cfg['padding'].lower().startswith("des"):
        return DESBitPadding()
    return SchneierFergusonPadding()

def get_algorithm(cfg, block_size_bytes):
    t = cfg['crypto_algorithm'].lower()
    key_hex = cfg['key']
    if key_hex.startswith("0x"):
        key = bytes.fromhex(key_hex[2:])
    else:
        key = key_hex.encode()
    if t == 'custom_vigenere':
        return CustomVigenere(key, block_size_bytes)
    if t == 'aes':
        return AESAdapter(key, block_size_bytes)
    raise ValueError("Unknown algorithm")

def get_mode(cfg, alg, bs, iv):
    m = cfg['mode'].upper()
    if m == 'ECB':
        return ECBMode(alg, bs, iv)
    if m == 'CBC':
        return CBCMode(alg, bs, iv)
    if m == 'CTR':
        return CTRMode(alg, bs, iv)
    if m == 'OFB':
        return OFBMode(alg, bs, iv)
    if m == 'CFB':
        return CFBMode(alg, bs, iv)
    raise NotImplementedError(f"Mode {cfg['mode']} not implemented in sketch")

def run_test_case(cfg_file):
    # Load config
    f = open(cfg_file,'r')
    cfg = json.load(f)
    f.close()

    #Get bytes
    block_size_bits = cfg['block_size']
    block_size_bytes = block_size_bits // 8

    padding = get_padding(cfg)

    algorithm = get_algorithm(cfg, block_size_bytes)

    iv_hex = cfg.get('iv','00'*block_size_bytes)
    iv = bytes.fromhex(iv_hex[2:] if iv_hex.startswith("0x") else iv_hex)

    mode = get_mode(cfg, algorithm, block_size_bytes, iv)

    f = open(cfg['input_file'],'rb')
    input_bytes=f.read()
    f.close()

    out_dir = cfg.get('output_dir','output/')
    os.makedirs(out_dir, exist_ok=True)

    padded_bytes=padding.pad(input_bytes,block_size_bytes)
    out=mode.encrypt(padded_bytes)

    g = open(os.path.join(out_dir, 'ctext.bin'),'wb')
    g.write(out)
    g.close()

    # Decrypt and unpad
    mode=get_mode(cfg, algorithm, block_size_bytes, iv)
    decrypted=mode.decrypt(out)
    unpadded=padding.unpad(decrypted)
    g = open(os.path.join(out_dir, 'dtext.bin'),'wb')
    g.write(unpadded)
    g.close()
    return unpadded == input_bytes


if __name__ == '__main__':
    assert(run_test_case('test1.json'))
    assert(run_test_case('test2.json'))
    assert(run_test_case('test3.json'))
    assert(run_test_case('test4.json'))
    assert(run_test_case('test5.json'))
    assert(run_test_case('test6.json'))
    assert(run_test_case('test7.json'))
    print("All tests passed.")

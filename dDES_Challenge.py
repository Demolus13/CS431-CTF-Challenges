#!/usr/bin/python3 -u
from pwn import *
from Crypto.Cipher import DES
import itertools
import string

import warnings
warnings.simplefilter("ignore", BytesWarning)

KEY_LEN = 6

def pad(msg):
    block_len = 8
    over = len(msg) % block_len
    pad = block_len - over
    return (msg + " " * pad).encode()

def double_decrypt(m, key1, key2):
    cipher2 = DES.new(key2, DES.MODE_ECB)
    dec_msg = cipher2.decrypt(m)

    cipher1 = DES.new(key1, DES.MODE_ECB)
    return cipher1.decrypt(dec_msg)

def all_possible_keys():
    for key in itertools.product(string.digits, repeat=KEY_LEN):
        yield ''.join(key) + '  '

# Connect to the remote service using netcat
r = remote("10.0.118.104", 4000)

# Send the roll number
roll_no = "22110201"
r.sendlineafter("Enter your 8 digit Roll no :", roll_no)

# Read until "Here is the flag:" and then the actual flag line
r.recvline()
r.recvline()
r.recvline()
r.recvline()
r.recvline()
flag = r.recvline().strip()

log.info("Encrypted flag: {}".format(flag.decode()))

# Known plaintext to perform meet-in-the-middle attack
to_encrypt = b'hello'
log.info("Trying to encrypt '{}'".format(to_encrypt.decode()))
r.sendlineafter("What would you like to encrypt?", to_encrypt.hex())
a_enc = r.recvline().strip()
log.info("Encrypted form: {}".format(a_enc.decode()))
a_enc = bytes.fromhex(a_enc.decode())

# Pad the plaintext
a_padded = pad(to_encrypt.decode())

# Dictionary to store intermediate encryption results
d = {}

with log.progress('Encrypting plaintext with all possible keys') as p:
    for k1 in all_possible_keys():
        p.status("Key: {}".format(k1))
        cipher1 = DES.new(k1.encode(), DES.MODE_ECB)
        enc = cipher1.encrypt(a_padded)
        d[enc] = k1

with log.progress('Decrypting ciphertext with all possible keys') as p:
    for k2 in all_possible_keys():
        p.status("Key: {}".format(k2))
        cipher2 = DES.new(k2.encode(), DES.MODE_ECB)
        dec = cipher2.decrypt(a_enc)
        if dec in d:
            k1 = d[dec]
            log.info("Found match, key1 = '{}', key2 = '{}'".format(k1, k2))
            decrypted_flag = double_decrypt(bytes.fromhex(flag.decode()), k1.encode(), k2.encode())
            log.success("Decrypted flag: {}".format(decrypted_flag.decode().strip()))
            break

r.close()

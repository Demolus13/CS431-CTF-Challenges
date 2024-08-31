#!/usr/bin/python3 -u
from pwn import *
from binascii import unhexlify, hexlify

# Function to perform bit-flipping attack
def bit_flip_attack(ciphertext, original_char, target_char, pos):
    modified_block = bytearray(ciphertext)
    modified_block[pos] ^= original_char ^ target_char
    return modified_block

# Connect to the remote service using netcat
r = remote("10.0.118.104", 3000)

# Provided ciphertexts (after IV)
r.recvline()
r.recvline()
r.recvline()
r.recvline()
ciphertext1 = unhexlify(r.recvline().strip())
ciphertext2 = unhexlify(r.recvline().strip())

# Print the provided ciphertexts in hexadecimal
log.info('Username Ciphertext: {}'.format(hexlify(ciphertext1).decode()))
log.info('Password Ciphertext: {}'.format(hexlify(ciphertext2).decode()))

# Flip for user:c?s to user:cns (1st ciphertext)
original_char1 = ord('?')
target_char1 = ord('n')
pos1 = 6
modified_ciphertext1 = bit_flip_attack(ciphertext1, original_char1, target_char1, pos1)

# Flip for pass:c?f to pass:ctf (2nd ciphertext)
original_char2 = ord('?')
target_char2 = ord('t')
pos2 = 6
modified_ciphertext2 = bit_flip_attack(ciphertext2, original_char2, target_char2, pos2)

# Print the modified ciphertexts in hexadecimal
log.info('Modified Username Ciphertext: {}'.format(hexlify(modified_ciphertext1).decode()))
log.info('Modified Password Ciphertext: {}'.format(hexlify(modified_ciphertext2).decode()))

# Send the roll number as bytes
roll_no = "22110201".encode()
r.sendlineafter(b"Enter your 8 digit roll no :", roll_no)

# Send the modified username and password ciphertexts
r.sendlineafter(b"Enter username hex string :", hexlify(modified_ciphertext1))
r.sendlineafter(b"Enter password hex string :", hexlify(modified_ciphertext2))

# Read all responses from the server
log.info("Reading all responses from the server:")
while True:
    try:
        response = r.recvline(timeout=2).strip()
        if not response:
            break
        log.info("Server Response: {}".format(response.decode()))
    except EOFError:
        break

r.close()

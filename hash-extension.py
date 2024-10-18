import hashlib
import struct
from binascii import unhexlify, hexlify

# Padding function for SHA256
def sha256_pad(message):
    message_byte_len = len(message)
    padding = b'\x80'
    padding += b'\x00' * ((56 - (message_byte_len + 1) % 64) % 64)
    padding += struct.pack('>Q', message_byte_len * 8)
    return padding

# Original values
original_message = b'username=cns431&groups=students,users,'
new_data = b'&groups=admins'
original_hash = unhexlify('c99963ab62fa272f73238a3e79f0f21d9837fa33cc34c8ae094a72d5110823ef')

# Key length (in bytes)
key_length = 16

# Construct the padded message
padded_message = original_message + sha256_pad(b'\x00' * key_length + original_message)

# Compute the new hash
sha256 = hashlib.sha256()
sha256.update(b'\x00' * key_length + padded_message + new_data)
new_hash = sha256.digest()

# Print the new cookie and new hash
print(f"New cookie (hex): {hexlify(padded_message + new_data).decode('utf-8')}")
print(f"New signature: {new_hash.hex()}")

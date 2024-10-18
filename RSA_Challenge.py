# CipherSailor: Crack the RSA Code!

# python3.9 RsaCtfTool.py --n <n> --e <e> --decrypt <ciphertext>
# Here's your super secret passcode to get the cns431ctf flag: K3yT0$ucc3$$!sSm@rtW0rk#2024


# Alice's Signature Mix-Up

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Util.number import long_to_bytes

# Load the private key (ensure this contains the private exponent `d`)
private_key_pem = """-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----"""

private_key = RSA.import_key(private_key_pem)

# Message to sign
message = "Hello Bob! This is a secret message, to be kept within CNS431"
message_hash = sum(ord(char) for char in message)

# Convert the hash to bytes (assuming hash fits in the key size)
hash_bytes = long_to_bytes(message_hash, byteorder='big')
signature = pkcs1_15.new(private_key).sign(hash_bytes)
print(signature.hex())



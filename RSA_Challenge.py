# CipherSailor: Crack the RSA Code!

# python3.9 RsaCtfTool.py --n <n> --e <e> --decrypt <ciphertext>
# Here's your super secret passcode to get the cns431ctf flag: K3yT0$ucc3$$!sSm@rtW0rk#2024


# Alice's Signature Mix-Up

message = "Hello Bob! This is a secret message, to be kept within CNS431."
message_hash = sum(ord(char) for char in message)
print("Hash:", message_hash)

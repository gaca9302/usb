import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from os import urandom
import hashlib

def AESencrypt(plaintext, key):
    k = hashlib.sha256(key).digest()
    iv = 16 * b'\x00'
    plaintext = pad(plaintext, AES.block_size)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)
    print('char AESkey[] = { 0x' + ',0x'.join(hex(x)[2:] for x in key) + ' };')
    print('char AEScip[] = { 0x' + ',0x'.join(hex(x)[2:] for x in ciphertext) + ' };')
    print(len([hex(x)[2:] for x in ciphertext]))
  
key = '123'.encode()
with open("calc.bin", "rb") as file:
    content = file.read()
    
AESencrypt(content, key)
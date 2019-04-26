import sys, getopt
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Util import Padding

#get plaintext, pad as necesary
ifile = open(inputfile, 'rb')
plaintext = ifile.read()
plaintext = Padding.pad(plaintext, AES.block_size)
ifile.close()

#get public key from keyfile
kfile = open(keyfile, 'r')
# kfile = open('rsa-test-pubkey.der', 'rb')
pubkeystr = kfile.read()
kfile.close()
pubkey = RSA.import_key(pubkeystr)

# create an AES-CBC cipher object with random private key
private_key = bytes(Random.get_random_bytes(32))
print(private_key)
iv = b'\x00'*AES.block_size
cipher = AES.new(private_key, AES.MODE_CBC, iv)

# encrypt plaintext
ciphertext = cipher.encrypt(plaintext)

# encrypt the AES key with RSA-OAEP using the public key
cipher = PKCS1_OAEP.new(pubkey)
cipherkey = cipher.encrypt(private_key)

# print(ciphertext)
print(ciphertext)
print(cipherkey)

ofile = open('rsa-enc.out', 'wb')
ofile.write(ciphertext+b'\x80\x00\x00'+cipherkey)
ofile.close()

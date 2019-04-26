import sys, getopt
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Util import Padding

keyfile = ''
inputfile = ''

try:
    opts, args = getopt.getopt(sys.argv[1:],'hk:i:o:')
except getopt.GetoptError:
    print("Usage: hybrid-encrypt.py -k <keyfile> -i <inputfile> -o <outputfile>")
    sys.exit(2)

for opt, arg in opts:
    if opt == '-h':
        print("Usage: cbcmac-gen.py -k <keyfile> -i <inputfile> -o <outputfile>")
        sys.exit()
    elif opt == '-k':
        keyfile = arg
    elif opt == '-i':
        inputfile = arg
    elif opt == '-o':
        outputfile = arg

if len(keyfile) == 0:
    print('Error: Name of keyfile is missing')
    sys.exit(2)

if len(inputfile) == 0:
    print('Error: Name of input file is missing.')
    sys.exit(2)

#get plaintext, pad as necesary
ifile = open(inputfile, 'rb')
ciphertext = ifile.read()
ifile.close()

#get public key from keyfile
kfile = open(keyfile, 'r')
# kfile = open('rsa-test-pubkey.der', 'rb')
keystr = kfile.read()
kfile.close()
key = RSA.import_key(keystr)

#parse the encrypted text from the encrypted AES key
i = 0
while(not ciphertext[i] == 128):
    i+=1

ctext = ciphertext[:i]
ckey = ciphertext[(i+3):]

#initialize RSA cipher to get decrypted AES key (private key)
cipher = PKCS1_OAEP.new(key)
key = cipher.decrypt(ckey)

#initialize AES cipher
iv = b'\x00'*AES.block_size
cipher = AES.new(key, AES.MODE_CBC, iv)

#get plaintext
plaintext = cipher.decrypt(ctext)
plaintext = Padding.unpad(plaintext, AES.block_size)

print(plaintext)

ofile = open(outputfile, 'wb')
ofile.write(plaintext)
ofile.close()

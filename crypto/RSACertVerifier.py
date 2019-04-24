import sys, getopt
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import MD5, SHA
from Crypto.PublicKey import RSA
from base64 import b64decode

def md5(data):
    h = MD5.new()
    h.update(data)
    return h.digest()
	
keyfile = ""
certfile = ""

try:
    opts, args = getopt.getopt(sys.argv[1:],'hk:i:')
except getopt.GetoptError:
    print("Usage: cert-sign.py -k <pub_key_file> -i <certificate_file>")
    sys.exit(2)

for opt, arg in opts:
    if opt == '-h':
        print("Usage: cert-sign.py -k <pub_key_file> -i <certificate_file>")
        sys.exit()
    elif opt == '-k':
        keyfile = arg
    elif opt == '-i':
        certfile = arg

if len(keyfile) == 0:
    print("Error: Name of public key file is missing.")
    sys.exit(2)

if len(certfile) == 0:
    print("Error: Name of certificate file is missing.")
    sys.exit(2)

kfile = open(keyfile, 'r')
keystr = kfile.read()
kfile.close()

pubkey = RSA.import_key(keystr)
verifier = PKCS1_PSS.new(pubkey)
	
ifile = open(certfile, 'r')
buf = ifile.read()
ifile.close()

i = buf.find('\n-----SIGNATURE-----\n')
l = len('\n-----SIGNATURE-----\n')

certdata = buf[:i].encode('ASCII')
signature = b64decode(buf[i+l:])

h = SHA.new()
h.update(md5(certdata))

if verifier.verify(h, signature):
    print('Certificate verification succeeded.')
else:
    print('Certificate verification failed.')

import sys, getopt
from Crypto.Cipher import AES
from Crypto.Hash import SHA1, HMAC, MD5
from Crypto import Random
#import pem

class MACandEncryptionKeyManager():
    #address_space = ''

    #def __init__(self):
        #self.address_space = address_space

    def create_mac_encry_key(self, address_space):

        for dst in address_space:
            ifile = open('../netsim/network/' + dst + '/shared_secret.pem', 'rb')
            #SS = pem.parse(ifile.read())
            SS = ifile.read()

            #creating unique mac key
            Km = HMAC.new(SS, digestmod=MD5)
            #Km.digest_size = 32
            Km = Km.update(b'Mac-Key')
            Km = Km.hexdigest()

            #creating unique encryption key
            Ke = HMAC.new(SS, digestmod=MD5)
            #Ke.digest_size = 32
            Ke = Ke.update(b'Encryption-Key')
            Ke = Ke.hexdigest()

            # print(Km)
            # print(len(Km))
            # print(SS)

            ofile = open('../netsim/network/' + dst + '/encrption_key.pem', 'w')
            ofile.write(Ke)

            ofile = open('../netsim/network/' + dst + '/mac_key.pem', 'w')
            ofile.write(Km)

            print("Unique Mac and Encryption keys created party member "+ dst)


# test = MACandEncryptionKeyManager()
# test.create_mac_encry_key('ABCDE')

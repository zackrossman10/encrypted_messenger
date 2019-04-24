import sys, getopt, datetime
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import MD5, SHA
from Crypto.PublicKey import RSA
from base64 import b64encode
from base64 import b64decode
import random

RSAkey_length = 1024

class RSACertGenerator():
    def __init__(self):
        #keep track of serial numbers for issued certificates
        self.serial_num_count = 1

        #declare a signer object, can be reused to sign mulitple certificates
        kfile = open('../netsim/network/ca/keypairs/rsa-key.pem', 'r')
        keystr = kfile.read()
        kfile.close()
        key = RSA.import_key(keystr)
        self.signer = PKCS1_PSS.new(key)

    @staticmethod
    def md5(data):
        h = MD5.new()
        h.update(data)
        return h.digest()

    def sign(self, certdatastr):
        h = SHA.new()
        h.update(RSACertGenerator.md5(certdatastr.encode('ASCII')))

        signature = self.signer.sign(h)
        return signature


    def initialize_participant_cert(self, participant_addr):

        #define start and end of valid period
        now = datetime.datetime.now()
        start_valid = now.year
        end_valid = str(int(now.year) + 4)

        #get participant's RSA pubkey
        kfile = open('../netsim/network/pubkeys/rsa-pubkey' + participant_addr + '.pem', 'r')
        keybuf = kfile.read()
        kfile.close()

        i = keybuf.find('-----BEGIN PUBLIC KEY-----')
        l = keybuf.find('-----END PUBLIC KEY-----')
        pubkeystr = keybuf[(i+len('-----BEGIN PUBLIC KEY-----')):l]

        #compile cert data strings
        subject = '-----SUBJECT-----\nCommon Name: Participant ' + participant_addr + '\nOrganization: Z and E company'
        issuer = '\n-----ISSUER-----\nCommon Name: Levente\nOrganization: CrySys Lab'
        serial_num = '\n-----SERIAL-NUMBER-----\n' + str(self.serial_num_count)
        validity = '\n-----VALIDITY-PERIOD-----\n' + str(start_valid) + ' - ' + str(end_valid)
        rsa_pubkey = '\n-----RSA-PUBLIC-KEY-----' + pubkeystr

        certdatastr = subject + issuer + serial_num + validity + rsa_pubkey

        #generate a signature on the certdata
        signature = self.sign(certdatastr)

        #write cert to output file
        ofile = open('../netsim/network/certs/RSA-cert' + participant_addr + '.pem', 'w')
        ofile.write(certdatastr)
        ofile.write("\n-----SIGNATURE-----\n")
        ofile.write(b64encode(signature).decode('ASCII'))
        ofile.close()

        #increment the serial numbers assigned to certificates
        self.serial_num_count = self.serial_num_count + 1

        print("Certificate generated for Participant " + participant_addr)

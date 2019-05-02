import sys, getopt
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto import Random
#import pem

class MACandEncryptionKeyManager():
    #address_space = ''

    #def __init__(self):
        #self.address_space = address_space

    def create_mac_encry_key(self, address_space):

        for dst in address_space:
            ifile = open('../netsim/network/' + dst + '/shared_secret.pem', 'rb')
            SS = ifile.read()
            ifile.close()

            #creating unique mac key
            Km = HMAC.new(SS, digestmod=SHA256)
            Km = Km.update(b'Mac-Key')
            Km = Km.hexdigest()


            #creating unique encryption key
            Ke = HMAC.new(SS, digestmod=SHA256)
            Ke = Ke.update(b'Encryption-Key')
            Ke = Ke.hexdigest()


            ofile = open('../netsim/network/' + dst + '/encrption_key.pem', 'w')
            ofile.write(Ke)
            ofile.close()

            ofile = open('../netsim/network/' + dst + '/mac_key.pem', 'w')
            ofile.write(Km)
            ofile.close()

            print("Unique Mac and Encryption keys created party member "+ dst)

    # increment a participant's sndsqn number by 1
    def update_sndsqn(self, snd_address):
        sndsqn_file = '../netsim/network/' + snd_address + '/sndsqn/sndstate'+snd_address+'.txt'
        ifile = open(sndsqn_file, 'rb')
        sndsqn_number = ifile.read()
        ifile.close()

        #increment sndsqn
        sndsqn_number = str(int(sndsqn_number) + 1)

        # update sndsqn_file
        open(sndsqn_file, 'w').close()
        upadted_rcv_file = open(sndsqn_file, 'w')
        upadted_rcv_file.write(sndsqn_number)
        upadted_rcv_file.close()

        ifile = open(sndsqn_file, 'rb')
        sndsqn_number = ifile.read()
        ifile.close()


    # update a participant's rcvsqn number for a particular sender
    def update_rcvsqn(self, rcv_address, snd_address, rcvsqn_number):
        rcvsqn_file = '../netsim/network/' + rcv_address + '/rcvsqn/rcvstate'+snd_address+'.txt'
        open(rcvsqn_file, 'w').close()
        upadted_rcv_file = open(rcvsqn_file, 'w')
        upadted_rcv_file.write(str(rcvsqn_number))
        upadted_rcv_file.close()


    # determine whether sqn number is valid
    def check_sqn_number(self, rcv_address, snd_address, sndsqn_number):
        rcvsqn_file = '../netsim/network/' + rcv_address + '/rcvsqn/rcvstate'+snd_address+'.txt'
        ifile = open(rcvsqn_file, 'rb')
        rcvsqn_number = int(ifile.read())
        ifile.close()

        # explicit sequence numbering
        if int(sndsqn_number) > rcvsqn_number:

            # if valid sqn_number, set rcvsqn = sndsqn
            rcvsqn_number = sndsqn_number
            update_rcvsqn(rcv_address, snd_address, rcvsqn_number)
            return True
        else:
            print('ERROR** Invalid sequence number received by ' + rcv_address)
            return False

# test = MACandEncryptionKeyManager()
# test.create_mac_encry_key('ABCDE')

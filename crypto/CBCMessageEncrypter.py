import sys, getopt
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto import Random

statefile = "sndstate.txt"
inputfile = ""
outputfile = ""


class CBCMessageEncrypter():
    # sender = ''
    # receiver = ''
    # payload = ""
    #
    # def __init__(self, sender, receiver, payload):
    #     self.sender = sender
    #     self.receiver = receiver
    #     self.payload = payload

    def encryptMessage(self, sender, payload):

        #CHANGE

        sndsqnFile = open('../netsim/network/' + sender + '/sndsqn/sndstate' + sender + '.txt' , 'rb')
        sndsqn = sndsqnFile.read()
        sndsqnFile.close()
        #print(type(int(sndsqn.decode('utf-8'))))

        efile = open('../netsim/network/' + sender + '/encryption_key.pem', 'rb')
        enckey = efile.read()
        enckey = bytes.fromhex(enckey.decode('utf-8'))
        #print(enckey.decode('utf-8'))

        mfile = open('../netsim/network/' + sender + '/mac_key.pem', 'rb')
        mackey = mfile.read()
        mackey = bytes.fromhex(mackey.decode('utf-8'))

        # compute payload_length, padding_length, and padding
        mac_length = 32  # SHA256 hash value is 32 bytes long
        payload_length = len(payload)
        padding_length = AES.block_size - (payload_length + mac_length)%AES.block_size
        padding = b'\x80' + b'\x00'*(padding_length-1)

        msg_length = 9 + AES.block_size + payload_length + mac_length + padding_length

        # create header
        header_version = b'\x03\x06' # protocol version 3.6
        header_type = str.encode(sender)    # message sender
        # header_type = b'\x01'    # message sender
        header_length = msg_length.to_bytes(2, byteorder='big') # message length (encoded on 2 bytes)
        header_sqn = (int(sndsqn.decode('utf-8')) + 1).to_bytes(4, byteorder='big')  # next message sequence number (encoded on 4 bytes)
        header = header_version + header_type + header_length + header_sqn

        # encrypt what needs to be encrypted (payload + padding)
        iv = Random.get_random_bytes(AES.block_size)
        ENC = AES.new(enckey, AES.MODE_CBC, iv)
        encrypted = ENC.encrypt(bytes(payload, 'utf-8') + padding)

        # compute mac on header, iv, and encrypted payload
        MAC = HMAC.new(mackey, digestmod=SHA256)
        MAC.update(header)
        MAC.update(encrypted)
        MAC.update(iv)
        mac = MAC.digest()


        payload = header + iv + encrypted + mac
        # print(payload)
        return payload



# test = CBCMessageEncrypter()
# test.encryptMessage('A','ABCDE')

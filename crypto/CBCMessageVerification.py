import sys, getopt
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto import Random
from CBCMessageEncrypter import CBCMessageEncrypter
from MACandEncryptionKeyManager import MACandEncryptionKeyManager

class CBCMessageVerification():

    def decryptMessage(self, receiver, msg):
        # parse the message
        header = msg[0:9]                         # header is 9 bytes long
        iv = msg[9:9 + AES.block_size]           # iv is AES.block_size bytes long
        encrypted = msg[(9 + AES.block_size):]         # the rest of the message is the encrypted part
        header_version = header[0:2]        # version is encoded on 2 bytes
        header_sender = header[2:3]           # type is encoded on 1 byte
        header_length = header[3:5]         # msg length is encoded on 2 bytes
        header_sqn = header[5:9]            # msg sqn is encoded on 4 bytes

        # get derived encryption and MAC keys
        efile = open('../netsim/network/' + receiver + '/encryption_key.pem', 'rb')
        enckey = efile.read()
        enckey = bytes.fromhex(enckey.decode('utf-8'))

        mfile = open('../netsim/network/' + receiver + '/mac_key.pem', 'rb')
        mackey = mfile.read()
        mackey = bytes.fromhex(mackey.decode('utf-8'))

        # check the msg length
        if len(msg) != int.from_bytes(header_length, byteorder='big'):
            print("Warning: Message length value in header is wrong!")
            print("Processing is continued nevertheless...")

        # verify sqequence numbers
        sender = header_sender.decode('utf-8')
        rcvsqnFile = open('../netsim/network/' + receiver + '/rcvsqn/rcvstate' + sender + '.txt' , 'r')
        rcvsqn = rcvsqnFile.read()
        rcvsqnFile.close()

        Mac_Encryption_manager = MACandEncryptionKeyManager()
        Mac_Encryption_manager.check_sqn_number(receiver, sender, int.from_bytes(header_sqn, byteorder='big'))

        # verify MAC value
        payload = encrypted[:-32]
        mac = encrypted[-32:]
        MAC = HMAC.new(mackey, digestmod=SHA256)   # create a HMAC object, pass the right key and specify SHA256 as the hash fn
        MAC.update(header)
        MAC.update(payload)
        MAC.update(iv)
        comp_mac = MAC.digest()    # compute the final HMAC value

        if (comp_mac != mac):
            print("Error: MAC verification failed!")
            sys.exit(1)

        # decrypt the payload
        ENC = AES.new(enckey, AES.MODE_CBC, iv)
        decrypted = ENC.decrypt(encrypted)

        # verify/remove padding
        i = -1
        decrypted = decrypted[:-32]
        while (decrypted[i] == 0x00): i -= 1
        padding = decrypted[i:]
        decrypted = decrypted[:i]
        if(padding[0] != 0x80):
            print("Error: Wrong padding detected!")
            sys.exit(1)
        printed_message = sender + ': ' + decrypted.decode('utf-8')
        return printed_message

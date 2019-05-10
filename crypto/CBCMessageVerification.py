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
        header_type = header[2:3]           # type is encoded on 1 byte
        header_length = header[3:5]         # msg length is encoded on 2 bytes
        header_sqn = header[5:9]            # msg sqn is encoded on 4 bytes

        # sender = header_type.decode('utf-8')

        #CHANGE
        # rcvsqn = 0
        # sndsqn = 1

        efile = open('../netsim/network/' + receiver + '/encryption_key.pem', 'rb')
        enckey = efile.read()
        enckey = bytes.fromhex(enckey.decode('utf-8'))

        #print(type(enckey))

        mfile = open('../netsim/network/' + receiver + '/mac_key.pem', 'rb')
        mackey = mfile.read()
        mackey = bytes.fromhex(mackey.decode('utf-8'))

        print("Message header:")
        print("   - protocol version: " + header_version.hex() + " (" + str(header_version[0]) + "." + str(header_version[1]) + ")")
        print("   - message type: " + header_type.hex() + " (" + str(int.from_bytes(header_type, byteorder='big')) + ")")
        print("   - message length: " + header_length.hex() + " (" + str(int.from_bytes(header_length, byteorder='big')) + ")")
        print("   - message sequence number: " + header_sqn.hex() + " (" + str(int.from_bytes(header_sqn, byteorder='big')) + ")")

        # check the msg length
        if len(msg) != int.from_bytes(header_length, byteorder='big'):
            print("Warning: Message length value in header is wrong!")
            print("Processing is continued nevertheless...")

        # sndsqn = int.from_bytes(header_type, byteorder='big')
        # rcvsqn = int.from_bytes(rec, byteorder='big')
        sender = header_type.decode('utf-8')
        rcvsqnFile = open('../netsim/network/' + receiver + '/rcvsqn/rcvstate' + sender + '.txt' , 'r')
        rcvsqn = rcvsqnFile.read()
        rcvsqnFile.close()

        sndsqnFile = open('../netsim/network/' + sender + '/sndsqn/sndstate' + sender + '.txt' , 'r')
        sndsqn = sndsqnFile.read()
        sndsqnFile.close()

        # check the sequence number
        print('Receiver: ' + receiver + ' -- sqn#: ' + rcvsqn)
        print('Sender: ' + sender + ' -- sqn#: ' + sndsqn)

        Mac_Encryption_manager = MACandEncryptionKeyManager()
        Mac_Encryption_manager.check_sqn_number(receiver, sender, sndsqn)

        # print("Expecting sequence number " + str(int(rcvsqn) + 1) + " or larger...")
        # if (rcvsqn >= sndsqn):
        #     print("Error: Message sequence number is too old!")
        #     sys.exit(1)
        # print("Sequence number verification is successful.")

        payload = encrypted[:-32]
        mac = encrypted[-32:]
        # verify the mac
        print("MAC verification is being performed...")
        MAC = HMAC.new(mackey, digestmod=SHA256)   # create a HMAC object, pass the right key and specify SHA256 as the hash fn
        MAC.update(header)
        MAC.update(payload)
        MAC.update(iv)
        comp_mac = MAC.digest()    # compute the final HMAC value

        # print("MAC value received: " + mac.hex())
        # print("MAC value computed: " + comp_mac.hex())
        #print(len(mac))
        if (comp_mac != mac):
            print("Error: MAC verification failed!")
            sys.exit(1)
        print("MAC verified correctly.")

        # decrypt the encrypted part
        print("Decryption is attempted...")
        ENC = AES.new(enckey, AES.MODE_CBC, iv)
        decrypted = ENC.decrypt(encrypted)

        # remove padding
        i = -1
        decrypted = decrypted[:-32]
        while (decrypted[i] == 0x00): i -= 1
        padding = decrypted[i:]
        decrypted = decrypted[:i]
        # print("Padding " + padding.hex() + " is observed")
        if(padding[0] != 0x80):
            print("Error: Wrong padding detected!")
            sys.exit(1)
        print("Padding is successfully removed.")
        return decrypted


# test = CBCMessageVerification()
# encrypter = CBCMessageEncrypter()
# testString = 'this is a long test that we run here'
# test.decryptMessage('B', encrypter.encryptMessage('A', testString))

import sys, getopt
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto import Random
from CBCMessageEncrypter import CBCMessageEncrypter

# statefile = "rcvstate.txt"
# inputfile = ""
# outputfile = ""

# try:
#     opts, args = getopt.getopt(sys.argv[1:],'hi:o:')
# except getopt.GetoptError:
#     print("Usage: msg-ver.py -i <inputfile> -o <outputfile>")
#     sys.exit(2)
#
# for opt, arg in opts:
#     if opt == '-h':
#         print("Usage: msg-ver.py -i <inputfile> -o <outputfile>")
#         sys.exit()
#     elif opt == '-i':
#         inputfile = arg
#     elif opt == '-o':
#         outputfile = arg
#
# if len(inputfile) == 0:
#     print("Error: Name of input file is missing.")
#     sys.exit(2)
#
# if len(outputfile) == 0:
#     print("Error: Name of output file is missing.")
#     sys.exit(2)
#
# # read the content of the state file
# ifile = open(statefile, 'rt')
# line = ifile.readline()
# enckey = line[len("enckey: "):len("enckey: ")+32]
# enckey = bytes.fromhex(enckey)
# line = ifile.readline()
# mackey = line[len("mackey: "):len("mackey: ")+32]
# mackey = bytes.fromhex(mackey)
# line = ifile.readline()
# rcvsqn = line[len("rcvsqn: "):]
# rcvsqn = int(rcvsqn, base=10)
# ifile.close()
#
# # read the content of the input file into msg
# ifile = open(inputfile, 'rb')
# msg = ifile.read()
# ifile.close()

class CBCMessageVerification():

    def decryptMessage(self, receiver, msg):
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

        # parse the message
        header = msg[0:9]                         # header is 9 bytes long
        iv = msg[9:9 + AES.block_size]           # iv is AES.block_size bytes long
        encrypted = msg[(9 + AES.block_size):]         # the rest of the message is the encrypted part
        header_version = header[0:2]        # version is encoded on 2 bytes
        header_type = header[2:3]           # type is encoded on 1 byte
        header_length = header[3:5]         # msg length is encoded on 2 bytes
        header_sqn = header[5:9]            # msg sqn is encoded on 4 bytes

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

        rcvsqnFile = open('../netsim/network/' + header_type + '/rvcsqn/rcvstate' + h + '.txt' , 'rb')
        rcvsqn = rcvsqnFile.read()
        rcvsqnFile.close()

        sndsqnFile = open('../netsim/network/' + receiver + '/sndsqn/sndstate' + receiver + '.txt' , 'rb')
        sndsqn = sndsqnFile.read()
        sndsqnFile.close()

        # check the sequence number
        print("Expecting sequence number " + str(rcvsqn + 1) + " or larger...")
        sndsqn = int.from_bytes(sndsqn, byteorder='big')
        if (rcvsqn >= sndsqn):
            print("Error: Message sequence number is too old!")
            print("Processing completed.")
            sys.exit(1)
        print("Sequence number verification is successful.")

        payload = encrypted[:-32]
        mac = encrypted[-32:]
        # verify the mac
        print("MAC verification is being performed...")
        MAC = HMAC.new(mackey, digestmod=SHA256)   # create a HMAC object, pass the right key and specify SHA256 as the hash fn
        MAC.update(header)
        MAC.update(payload)
        MAC.update(iv)
        comp_mac = MAC.digest()    # compute the final HMAC value

        print("MAC value received: " + mac.hex())
        print("MAC value computed: " + comp_mac.hex())
        #print(len(mac))
        if (comp_mac != mac):
            print("Error: MAC verification failed!")
            print("Processing completed.")
            sys.exit(1)
        print("MAC verified correctly.")

        # decrypt the encrypted part
        print("Decryption is attempted...")
        ENC = AES.new(enckey, AES.MODE_CBC, iv)
        decrypted = ENC.decrypt(encrypted) # decrypt the encrypted part of the message

        i = -1
        decrypted = decrypted[:-32]
        while (decrypted[i] == 0x00): i -= 1
        padding = decrypted[i:]
        decrypted = decrypted[:i]
        print("Padding " + padding.hex() + " is observed")
        if(padding[0] != 0x80):
            print("Error: Wrong padding detected!")
            print("Processing completed.")
            sys.exit(1)
        print("Padding is successfully removed.")
        print(decrypted)
        # # write payload out
        # ofile = open(outputfile, 'wb')
        # ofile.write(payload)
        # ofile.close()
        # print("Payload is saved to " + outputfile)
        #
        # # save state
        # state = "enckey: " + enckey.hex() + '\n'
        # state = state + "mackey: " + mackey.hex() + '\n'
        # state = state + "rcvsqn: " + str(sndsqn)
        # ofile = open(statefile, 'wt')
        # ofile.write(state)
        # ofile.close()
        # print("Receiving state is saved.")
        # print("Processing completed.")

test = CBCMessageVerification()
encrypter = CBCMessageEncrypter()
testString = 'this is a long test that we run here'
test.decryptMessage('A', encrypter.encryptMessage('A', testString))

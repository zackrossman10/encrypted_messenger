import sys, getopt
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto import Random

statefile = "sndstate.txt"
inputfile = ""
outputfile = ""


class CBCMessageEncrypter():
    sender = ''
    receiver = ''
    payload = ""

    def __init__(self, sender, receiver, payload):
        self.sender = sender
        self.receiver = receiver
        self.payload = payload

    #find mackey, encryption key, and sqsn from the sender and receiver
    enckey = ''
    sndsqn = ''
    mackey = ''

    def encryptMessage():

        # compute payload_length, padding_length, and padding
        mac_length = 32  # SHA256 hash value is 32 bytes long
        payload_length = len(payload)
        padding_length = AES.block_size - (payload_length + mac_length)%AES.block_size
        padding = b'\x80' + b'\x00'*(padding_length-1)

        # create header
        header_version = b'\x03\x06' # protocol version 3.6
        header_type = b'\x01'    # message type 1
        header_length = msg_length.to_bytes(2, byteorder='big') # message length (encoded on 2 bytes)
        header_sqn = (sndsqn + 1).to_bytes(4, byteorder='big')  # next message sequence number (encoded on 4 bytes)
        header = header_version + header_type + header_length + header_sqn

        # encrypt what needs to be encrypted (payload + padding)
        iv = Random.get_random_bytes(AES.block_size)
        ENC = AES.new(enckey, AES.MODE_CBC, iv)
        encrypted = ENC.encrypt(payload + padding)

        # compute mac on header, iv, and encrypted payload
        MAC = HMAC.new(mackey, digestmod=SHA256)
        MAC.update(header)
        MAC.update(encrypted)
        MAC.update(iv)
        mac = MAC.digest()


        return header + iv + encrypted + mac



#
# try:
#     opts, args = getopt.getopt(sys.argv[1:],'hi:o:')
# except getopt.GetoptError:
#     print("Usage: msg-gen.py -i <inputfile> -o <outputfile>")
#     sys.exit(2)
#
# for opt, arg in opts:
#     if opt == '-h':
#         print("Usage: msg-gen.py -i <inputfile> -o <outputfile>")
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
# sndsqn = line[len("sndsqn: "):]
# sndsqn = int(sndsqn, base=10)
# ifile.close()
#
# # read the content of the input file into variable payload
# ifile = open(inputfile, 'rb')
# payload = ifile.read()
# ifile.close()
#
#
# # write full encrypted message and MAC out
# ofile = open(outputfile, 'wb')
# ofile.write(header + iv + encrypted + mac)
# ofile.close()
#
# # save state
# state = "enckey: " + enckey.hex() + '\n'
# state = state + "mackey: " + mackey.hex() + '\n'
# state = state + "sndsqn: " + str(...)
# ofile = open(statefile, 'wt')
# ofile.write(state)
# ofile.close()

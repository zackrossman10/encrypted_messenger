import sys, getopt, datetime
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import MD5, SHA256
from Crypto.PublicKey import RSA
from Crypto import Random
from base64 import b64encode, b64decode
from netinterface import network_interface
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util import Padding
import random

# signer object for a single chat participant
class RSASigManager:

	def __init__(self, participant_address):
		self.participant_address = participant_address
		kfile = open('../netsim/network/' + participant_address + '/keypairs/rsa-key.pem', 'r')
		keystr = kfile.read()
		kfile.close()

		key = RSA.import_key(keystr)
		self.signer = PKCS1_PSS.new(key)

	# return Sigkpk-(data)
	def sign(self, data):

		# sign the payload with leader's private key
		h = SHA256.new()
		h.update(data)
		signature = self.signer.sign(h)
		return b64encode(signature).decode('ASCII')

	def ver_signature(self, signature):
		kfile = open('../netsim/network/pubkeys/rsa-pubkey' + self.participant_address + '.pem', 'r')
		pubkeystr = kfile.read()
		kfile.close()

		pubkey = RSA.import_key(pubkeystr)
		verifier = PKCS1_PSS.new(pubkey)

		# read the content of the input file into a variable
		ifile = open(inputfile, 'rb')
		msg_signed = ifile.read()
		ifile.close()

		# create a SHA256 hash object and hash the content of the input file
		h = SHA256.new()
		h.update(msg_signed)

		# read the signature from the signature file and convert to binary from base64
		sfile = open(signaturefile, 'rb')
		sfile.readline() # reading the line '--- RSA PKCS1 PSS SIGNATURE ---'
		signature = b64decode(sfile.readline())
		sfile.close()

		# verify the signature
		result = verifier.verify(h, signature)

		# print the result of the verification on the screen 
		print('Done.')
		if result:
		        print('The signature is correct.')
		else:
		        print('The signature is incorrect.')
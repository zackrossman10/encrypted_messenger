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

# class for signing & verifying signatures for a single chat participant
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

	# verify (A|K|T_Pk|Sigkpk-(B|K|T_Pk)) from the ISO protocol
	def verify(self, ver_data, signature):

		kfile = open('../netsim/network/pubkeys/rsa-pubkey' + self.participant_address + '.pem', 'r')
		pubkeystr = kfile.read()
		kfile.close()

		pubkey = RSA.import_key(pubkeystr)
		verifier = PKCS1_PSS.new(pubkey)

		# create a SHA256 hash object and hash the content of the input file
		h = SHA256.new()
		h.update(ver_data)

		# verify the signature
		result = verifier.verify(h, signature)

		if result:
		        return True
		else:
		        return False

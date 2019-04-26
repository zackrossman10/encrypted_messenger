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

SHARED_KEY_LENGTH = 32
NET_PATH = '../netsim/network/'

class ISOExchangeManager():

	def __init__(self, address_space):
		self.address_space = address_space


	# main function for sender side of ISO exchange
	def execute_send(self):
		self.elect_leader()
		shared_secret = Random.get_random_bytes(SHARED_KEY_LENGTH)
		print(shared_secret)
		self.distribute_shared_secret(shared_secret)
		print('Elected leader: ' + self.leader_address)


	# main function for receiver side of ISO exchange
	def execute_receive(self):
		for participant_address in self.address_space:
			# read, decrypt PubEnckpi+(A|K|T_Pk|Sigkpk-(B|K|T_Pk)) message 
			with open(NET_PATH + participant_address + "/IN/0000", 'rb') as f: enc_msg = f.read()	
			payload = self.hybrid_decrypt(participant_address, enc_msg)

			# verify Sigkpk-(B|K|T_Pk))

			shared_secret = payload[1:SHARED_KEY_LENGTH]
			print(shared_secret)


	# elect a random leader who (later) composes, sends PubEnckpi+(A|K|T_Pk|Sigkpk-(B|K|T_Pk))
	def elect_leader(self):

		# randomly choose leader from address space
		leader_index = random.randint(0, len(self.address_space)-1)
		self.leader_address = self.address_space[leader_index]

		#create a signer instance using leader's private key
		kfile = open('../netsim/network/' + self.leader_address + '/keypairs/rsa-key.pem', 'r')
		keystr = kfile.read()
		kfile.close()

		key = RSA.import_key(keystr)
		self.signer = PKCS1_PSS.new(key)

	# compose and send PubEnckpi+(A|K|T_Pk|Sigkpk-(B|K|T_Pk)) for each participant
	def distribute_shared_secret(self, shared_secret):

		# generate timestamp dd/mm/YY H:M:S
		now = datetime.datetime.now()
		dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

		# instantiate network for distribution
		netif = network_interface(NET_PATH, self.leader_address)

		# compose and send PubEnckpi+(A|K|T_Pk|Sigkpk-(B|K|T_Pk)) to each participant
		for recipient_address in self.address_space:
			signature = self.get_signature(recipient_address, shared_secret, dt_string)
			enc_message = self.hybrid_encrypt(recipient_address, shared_secret, dt_string, signature)

			# put in leader's OUT directory
			# network.py will move to participant's IN directory later on
			netif.send_msg(recipient_address, enc_message)

		print('Composed ISO11770 messages for each participant')	

	# return Sigkpk-(B|K|T_Pk)
	def get_signature(self, recipient_address, shared_secret, dt_string):

		# payload = B|K|T_Pk
		payload = str.encode(recipient_address) + shared_secret + str.encode(dt_string)

		# sign the payload with leader's private key
		h = SHA256.new()
		h.update(payload)
		signature = self.signer.sign(h)
		return b64encode(signature).decode('ASCII')
			

	# decrypt PubEnckpi+(A|K|T_Pk|Sigkpk-(B|K|T_Pk))
	def hybrid_decrypt(self, participant_address, enc_msg):
		
		#get private keypair from keyfile
		kfile = open(NET_PATH + '/' + participant_address + '/keypairs/rsa-key.pem', 'r')
		keystr = kfile.read()
		kfile.close()

		privkey = RSA.import_key(keystr)

		#parse the encrypted text from the encrypted AES key
		enc_payload = enc_msg[0:len(enc_msg)-131]
		enc_key = enc_msg[-128:]

		#initialize RSA cipher to get decrypted AES key (private key)
		cipher = PKCS1_OAEP.new(privkey)
		key = cipher.decrypt(enc_key)

		#initialize AES cipher
		iv = b'\x00'*AES.block_size
		cipher = AES.new(key, AES.MODE_CBC, iv)

		#get plaintext
		payload = cipher.decrypt(enc_payload)
		payload = Padding.unpad(payload, AES.block_size)
		return payload


	# return PubEnckpi+(A|K|T_Pk|Sigkpk-(B|K|T_Pk)) using hybrid encryption
	def hybrid_encrypt(self, recipient_address, shared_secret, dt_string, signature):
		# payload = A|K|T_Pk|Sigkpk-(B|K|T_Pk
		payload = str.encode(recipient_address) + shared_secret + str.encode(dt_string + signature)
		payload = Padding.pad(payload, AES.block_size)

		# get the leader's public key
		kfile = open('../netsim/network/pubkeys/rsa-pubkey' + recipient_address + '.pem', 'r')
		pubkeystr = kfile.read()
		kfile.close()

		pubkey = RSA.import_key(pubkeystr)

		# create an AES-CBC cipher object with random private key
		private_key = bytes(Random.get_random_bytes(32))
		iv = b'\x00'*AES.block_size
		cipher = AES.new(private_key, AES.MODE_CBC, iv)

		# encrypt plaintext
		ciphertext = cipher.encrypt(payload)

		# encrypt the AES key with RSA-OAEP using leader's public key
		cipher = PKCS1_OAEP.new(pubkey)
		cipherkey = cipher.encrypt(private_key)

		enc_message = ciphertext+b'\x80\x00\x00'+cipherkey
		return enc_message

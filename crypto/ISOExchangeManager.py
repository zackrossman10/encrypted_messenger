import os, sys, getopt, datetime
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import MD5, SHA256
from Crypto.PublicKey import RSA
from Crypto import Random
from base64 import b64encode, b64decode
from netinterface import network_interface
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util import Padding
import random
sys.path.insert(0, '../crypto/')
from RSASigManager import RSASigManager
from RSACertManager import RSACertManager
from RSAKeyGenerator import RSAKeyGenerator

SHARED_KEY_LENGTH = 32
SIG_LENGTH = 128
NET_PATH = '../netsim/network/'

# class for managing all aspects of setting up a secure channel for ISO11770 protocol
class ISOExchangeManager():
	address_space = ''
	leader_address = ''

	# set up params, files to be used by ISO11770 protocol
	def __init__(self, address_space):
		self.address_space = address_space

		# if needed, create RSA pub/priv keypair for network, will act as cert authority
		if not os.path.exists(NET_PATH + '/ca/keypairs/rsa-key.pem'):
			self.key_generator = RSAKeyGenerator()
			self.key_generator.initialize_ca_keypair()
		else:
			print("RSA keypair already exist for CA")

		self.cert_manager = RSACertManager()


		# if needed, create RSA pub/priv keypairs and certificates for every participant
		for addr in self.address_space:
			if not os.path.exists(NET_PATH + addr + '/keypairs/rsa-key.pem'):
				self.key_generator.initialize_participant_keypair(addr)
				self.cert_manager.initialize_participant_cert(addr)
			else:
				print("RSA keypair already exist for Participant " + addr)

	# main function for distributing shared secret
	def execute_send(self):
		self.leader_addr = self.elect_leader()
		self.sig_manager = RSASigManager(self.leader_addr)
		shared_secret = Random.get_random_bytes(SHARED_KEY_LENGTH)
		iso_msgs = self.compose_ISO_msgs(shared_secret)

		# instantiate network for distribution
		# put enc_message in leader's OUT directory
		netif = network_interface(NET_PATH, self.leader_addr)

		for recipient_addr in iso_msgs:
			iso_msg = iso_msgs[recipient_addr]
			netif.send_msg(recipient_addr, iso_msg)


	# elect a random leader who (later) composes, sends PubEnckpi+(A|K|T_Pk|Sigkpk-(B|K|T_Pk))
	def elect_leader(self):

		# randomly choose leader from address space
		leader_index = random.randint(0, len(self.address_space)-1)
		leader_addr = self.address_space[leader_index]

		print('Elected leader: ' + leader_addr)

		return leader_addr


	# compose PubEnckpi+(A|K|T_Pk|Sigkpk-(B|K|T_Pk)) for each participant
	def compose_ISO_msgs(self, shared_secret):

		# generate timestamp dd/mm/YY H:M:S
		now = datetime.datetime.now()
		dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

		iso_msgs = {}

		# compose and send PubEnckpi+(A|K|T_Pk|Sigkpk-(B|K|T_Pk)) for each participant
		for recipient_addr in self.address_space:
			sig_payload = str.encode(recipient_addr) + shared_secret + str.encode(dt_string)
			signature = self.sig_manager.sign(sig_payload)

			# payload = A|K|T_Pk|Sigkpk-(B|K|T_Pk
			payload = str.encode(self.leader_addr) + shared_secret + str.encode(dt_string + signature)
			payload = Padding.pad(payload, AES.block_size)

			iso_msgs[recipient_addr] = self.hybrid_encrypt(recipient_addr, payload)

		print('Composed ISO11770 messages for each participant')

		return iso_msgs


	# main function for receiver side of ISO exchange
	def execute_receive(self):

		for participant_address in self.address_space:
			# read, decrypt PubEnckpi+(A|K|T_Pk|Sigkpk-(B|K|T_Pk)) message
			with open(NET_PATH + participant_address + "/IN/0000", 'rb') as f: enc_msg = f.read()
			payload = self.hybrid_decrypt(participant_address, enc_msg)

			shared_secret = payload[1:SHARED_KEY_LENGTH+1]
			timestamp = payload[1+SHARED_KEY_LENGTH:20+SHARED_KEY_LENGTH]
			signature = payload[-172:]

			ver_payload = str.encode(participant_address) + shared_secret + timestamp

			if self.sig_manager.verify(ver_payload, b64decode(signature)):
				print('Participant ' + participant_address + ': received and verified ISO11770 message')
			else:
				print('** ERROR ** Participant ' + participant_address + ' could not verify a ISO11770 message')
				sys.exit(1)

			# store private key
			ofile = open(NET_PATH + participant_address + '/shared_secret.pem', 'w')
			ofile.write(b64encode(shared_secret).decode('ASCII'))
			ofile.close()

			# messages related to ISO protocol for security reasons
			sending_dir = NET_PATH + participant_address + '/OUT'
			receiving_dir = NET_PATH + participant_address + '/IN'
			for f in os.listdir(sending_dir): os.remove(sending_dir + '/' + f)
			for f in os.listdir(receiving_dir): os.remove(receiving_dir + '/' + f)


	# return PubEnckpi+(A|K|T_Pk|Sigkpk-(B|K|T_Pk)) using hybrid encryption
	def hybrid_encrypt(self, recipient_address, payload):

		# get public key for recipient
		pubkey = self.cert_manager.get_pubkey(recipient_address)

		# create an AES-CBC cipher object with random private key
		private_key = bytes(Random.get_random_bytes(32))
		iv = b'\x00'*AES.block_size
		cipher = AES.new(private_key, AES.MODE_CBC, iv)

		# encrypt plaintext
		ciphertext = cipher.encrypt(payload)

		# encrypt the AES key with RSA-OAEP using recipient's public key
		cipher = PKCS1_OAEP.new(pubkey)
		cipherkey = cipher.encrypt(private_key)

		enc_message = ciphertext+b'\x80\x00\x00'+cipherkey
		return enc_message

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

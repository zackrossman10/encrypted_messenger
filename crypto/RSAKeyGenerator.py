from Crypto.PublicKey import RSA

class RSAKeyGenerator():

	def initialize_participant_keypair(self, participant_addr):
		key = RSA.generate(1024)

		# export the entire key pair in PEM format into participant's private dir
		ofile = open('../netsim/network/' + participant_addr + '/keypairs/rsa-key.pem', 'w')
		ofile.write(key.exportKey(format='PEM').decode('ASCII'))
		ofile.close()

		# export only the public key in PEM format to the network's pubkey dir
		ofile = open('../netsim/network/pubkeys/rsa-pubkey' + participant_addr + '.pem', 'w')
		ofile.write(key.publickey().exportKey(format='PEM').decode('ASCII'))
		ofile.close()

		print("Keypair generated for Participant " + participant_addr)

	def initialize_ca_keypair(self):
		key = RSA.generate(1024)

		# export the entire key pair in PEM format into ca's private dir
		ofile = open('../netsim/network/ca/keypairs/rsa-key.pem', 'w')
		ofile.write(key.exportKey(format='PEM').decode('ASCII'))
		ofile.close()

		# export only the public key in PEM format to the network's pubkey dir
		ofile = open('../netsim/network/pubkeys/rsa-pubkeyca.pem', 'w')
		ofile.write(key.publickey().exportKey(format='PEM').decode('ASCII'))
		ofile.close()

		print("Keypair generated for CA")
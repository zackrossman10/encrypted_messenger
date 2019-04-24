from Crypto.PublicKey import RSA
key = RSA.generate(4096)

# export the entire key pair in PEM format
ofile = open('rsa-key.pem', 'w')
ofile.write(key.exportKey(format='PEM').decode('ASCII'))
ofile.close()

# export only the public key in PEM format
ofile = open('rsa-pubkey.pem', 'w')
ofile.write(key.publickey().exportKey(format='PEM').decode('ASCII'))
ofile.close()

#
## export the entire key pair in DER format
#ofile = open('rsa-test-key.der', 'wb')
#ofile.write(key.exportKey(format='DER'))
#ofile.close()
#
## export only the public key in DER format
#ofile = open('rsa-test-pubkey.der', 'wb')
#ofile.write(key.publickey().exportKey(format='DER'))
#ofile.close()

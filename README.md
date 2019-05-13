# encrypted_messenger
Peer-to-peer encrypted messaging application for Applied Cryptography

Network Files:
--------------

Instantiate a single network instance which hosts a chat application between participants A,B,C,D,E: 
python3 network.py -p './network/' -a 'ABCDE' --clean

After a network instance is created, each participant in the specified address space has the ability to send and receive messages in the group chat. Note, however, that the sender and receiver instances must be instantiated separately. Thus, it is possible for one participant to only send messages, another to only receive messages, and another to do both (though in separate terminal windows).

Instantiate a single sender instance for participant A:
python3 sender.py -p './network/' -a A

Instantiate a single sender instance for participant B:
python3 receiver.py -p './network/' -a B

Once all senders/receviers have exited the chat session, terminate the network instance and delete all data associated with the chat session (derived encryption keys & MAC keys, messages, recevier/sender sequence numbers, RSA keypairs/certificates):  
python3 network.py -p './network/' -a 'ABCDE' --wipe

For more details about the network files, refer to the docs.md file within the ./netsim directory


Crypto Files:
-------------

CBCMessageEncrypter class has one responsibility: encrypting a given message according to our encryption scheme, consisting of a header + payload + MAC

CBCMessageVerification class also has one responsibility: decrypting a given message according to our encryption scheme, veirfying sequence numbers, MAC values, and padding along the way

ISOExchangeManager class sets up all shared data amongst the participants for a secure channel. This involves randomly electing a leader amongst the participants, creating a shared secret, creating RSA keypairs/certficates for each participant (and the network, which acts as the CA), then distributing the shared secret to participants according to the ISO11770 protocol

MACAndEncryptionKeyManager derives the encryption/MAC keys from the shared secret for each participant. Also handles the cerification/updating of sequence numbers for senders and receivers

RSACertManager class handles all things related to the RSA certicates. This includes creating a certificate for a participant (using the network as CA), verifying a participant certificate using the CA's certificate, and getting a participant's RSA public key from their certificate

RSAKeyGenerator class initializes keypairs for the network (which acts as the CA) and for each participant

RSASigManager class allows participants to sign data and verify these same signatures using public key crypto. Used to protect the ISO11770 messages which establish a secure channel


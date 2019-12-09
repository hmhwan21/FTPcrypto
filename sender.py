#!/usr/bin/env python3
#sender.py

import os, sys, getopt, time
from netinterface import network_interface
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import base64
import json

NET_PATH = './'
OWN_ADDR = 'A'

# ------------       
# main program
# ------------

try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:a:', longopts=['help', 'path=', 'addr='])
except getopt.GetoptError:
	print('Usage: python sender.py -p <network path> -a <own addr>')
	sys.exit(1)

for opt, arg in opts:
	if opt == '-h' or opt == '--help':
		print('Usage: python sender.py -p <network path> -a <own addr>')
		sys.exit(0)
	elif opt == '-p' or opt == '--path':
		NET_PATH = arg
	elif opt == '-a' or opt == '--addr':
		OWN_ADDR = arg
	

if (NET_PATH[-1] != '/') and (NET_PATH[-1] != '\\'): NET_PATH += '/'

if not os.access(NET_PATH, os.F_OK):
	print('Error: Cannot access path ' + NET_PATH)
	sys.exit(1)

if len(OWN_ADDR) > 1: OWN_ADDR = OWN_ADDR[0]

if OWN_ADDR not in network_interface.addr_space:
	print('Error: Invalid address ' + OWN_ADDR)
	sys.exit(1)


user_symkey = ''

#check if the user_symkey exists 
# try:
# 	user_symkey= open("user_sym_key.txt", 'rb').read()
# 	if len(user_symkey) == 0:
# 		user_symkey = Random.get_random_bytes(16)
# 		open("user_sym_key.txt", 'wb').write(user_symkey)
# except:
# 	#create symmetric key using py cryptodome random length 16
# 	user_symkey = Random.get_random_bytes(16)
# 	open("user_sym_key.txt", 'wb').write(user_symkey)
#close file?

# main loop
netif = network_interface(NET_PATH, OWN_ADDR)
rootDirectory = os.getcwd()
print('Main loop started...')
while True:
	os.chdir(NET_PATH + "/" + OWN_ADDR)
	msg = input('Type a message: ')
	checkForLength = msg.split()
	if len(checkForLength) > 2:
		print("invalid message length (with arguments)")
		os.chdir(rootDirectory)
		continue
	msg += " " + OWN_ADDR
	if msg[:len('-sendkey')] == '-sendkey':
		#check if the user_symkey exists 
		try:
			user_symkey= open("user_sym_key.txt", 'rb').read()
			if len(user_symkey) == 0:
				#print('went ehere')
				user_symkey = Random.get_random_bytes(16)
				open("user_sym_key.txt", 'wb').write(user_symkey)
		except:
			#print('here')
			#create symmetric key using py cryptodome random length 16
			user_symkey = Random.get_random_bytes(16)
			open("user_sym_key.txt", 'wb').write(user_symkey)
		#encrypt user_symkey with the servers public key, our symkey
		publicK = RSA.import_key(open('publicKEY.pem', 'rb').read())
		RSAcipher = PKCS1_OAEP.new(publicK)
		encr_symkey = RSAcipher.encrypt(user_symkey) #can encrypt bytes
		dst = 'S'
		msg = b'-sendkey' + encr_symkey
		#print(msg)
		os.chdir(rootDirectory)
		netif.send_msg(dst, msg)
	else:
		# GCM
		try:
			user_symkey= open("user_sym_key.txt", 'rb').read()
		except:
			print("please use -sendkey to generate a key")
			os.chdir(rootDirectory)
			continue
		nonce = Random.get_random_bytes(16)
		print(user_symkey)
		AEScipher = AES.new(user_symkey, AES.MODE_GCM, nonce= nonce)
		encr_msg, tag = AEScipher.encrypt_and_digest(msg.encode('utf-8')) #do we need tag? see receiver
		print('encrypted message')
		print(encr_msg)
		dictToJSON = {}
		dictToJSON["nonce"] = base64.encodebytes(nonce).decode('ascii')
		dictToJSON["encrypted_msg"] = base64.encodebytes(encr_msg).decode('ascii')
		dictToJSON["tag"] = base64.encodebytes(tag).decode('ascii')
		msg_full_to_send = json.dumps(dictToJSON).encode('utf-8') #nonce + b"|" + tag + b"|" + encr_msg
		print(msg_full_to_send)
		dst = 'S'
		os.chdir(rootDirectory)
		netif.send_msg(dst, msg_full_to_send)

		# TODO #!! WRITE NONCE, so that the RECEIVED REPLY WILL use the NONCE, then we check if the NONCE is = to the thingy. when we start, we destroy the nonce file.
		# protection against replay
		# we dont have to specify who we are (except in upl and dnl) otherwise we show who we are by the key
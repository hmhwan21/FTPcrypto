#!/usr/bin/env python3
#receiver.py

import os, sys, getopt, time
from netinterface import network_interface
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import base64
import json

NET_PATH = './'
OWN_ADDR = 'B'

# ------------       
# main program
# ------------

try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:a:', longopts=['help', 'path=', 'addr='])
except getopt.GetoptError:
	print('Usage: python receiver.py -p <network path> -a <own addr>')
	sys.exit(1)

for opt, arg in opts:
	if opt == '-h' or opt == '--help':
		print('Usage: python receiver.py -p <network path> -a <own addr>')
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

# main loop
netif = network_interface(NET_PATH, OWN_ADDR)
rootDirectory = os.getcwd()
print('Main loop started...')
while True:
    os.chdir(rootDirectory)
# Calling receive_msg() in non-blocking mode ... 
#	status, msg = netif.receive_msg(blocking=False)    
#	if status: print(msg)      # if status is True, then a message was returned in msg
#	else: time.sleep(2)        # otherwise msg is empty

# Calling receive_msg() in blocking mode ...
    status, msg = netif.receive_msg(blocking=True)      # when returns, status is True and msg contains a message
    # if you send me something , i can just print it.
    # cmd = python
    # os.system(cmd) 
	#print(msg.decode('utf-8'))
    os.chdir(NET_PATH + "/" + OWN_ADDR)
    try:
	    user_symkey = open("user_sym_key.txt", 'rb').read()
    except:
        print("couldnt find your key")
        print(os.getcwd())
    dictMetaData = json.loads(msg.decode('utf-8'))
    nonce = base64.decodebytes(dictMetaData["nonce"].encode('ascii'))
    #nonce stuff
    repeat = False
    try:
        nonces_sent = open("nonces_sent.txt", 'rb').readlines()

        # We need to shave off the \n from each line to compare to our current nonce
        nonces_pure = []
        for i in range(len(nonces_sent)):
            nonces_pure.append(nonces_sent[i][:-1])
        # If we have already seen our current nonce
        if(nonce in nonces_pure):
            repeat = True
    except:
        # If we have never sent a nonce before
        #
        continue

    # If we have a repeat message, we want to ACCEPT the message and delete the nonce so
    # the sender's message cannot be repeated again
    if(repeat):
        nonces_pure.remove(nonce)
    else:
        print("replay detected")
        continue

    # Rewrite all other nonces back to file
    nonce_file = open("nonces_sent.txt", 'wb')
    for i in range(len(nonces_pure)):
        nonce_file.write(nonces_pure[i])
        nonce_file.write(b'\n')

    nonce_file.close()
    #end nonce stuff
    tag = base64.decodebytes(dictMetaData["tag"].encode('ascii'))
    cipher_text_to_decrypt = base64.decodebytes(dictMetaData["encrypted_msg"].encode('ascii'))
    cipher = AES.new(user_symkey, AES.MODE_GCM, nonce = nonce)
    plaintext = cipher.decrypt_and_verify(cipher_text_to_decrypt, tag)
    print(plaintext.decode('utf-8'))
#!/usr/bin/env python3
#receiver.py


import os, sys, getopt, time
import shutil
from netinterface import network_interface
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import json
import base64

NET_PATH = './'
OWN_ADDR = 'S'

# ------------       
# main program
# ------------
def copyFile(src, dst):
    shutil.copyfile(src, dst)

def generateKeysDictString():
	keys_dict = {}
	try:
		myfile = open("keys.txt", 'r')
		readfromjson = myfile.read()
		dictfromjson = json.loads(readfromjson)
		#keys_dict = dictfromjson
		for key in dictfromjson.keys():
			value = dictfromjson[key]
			tobyteskey = base64.decodebytes(key.encode('ascii'))
			#key is in rsa, go to bytes, then 
			privateK = RSA.import_key(open('privateKEY.pem', 'rb').read())
			RSAcipher = PKCS1_OAEP.new(privateK)
			symkey = RSAcipher.decrypt(tobyteskey) #can encrypt bytes
			symkey = symkey.decode('utf-8')

			keys_dict[symkey] = value
	except:
		keys_dict = {}
	return keys_dict

def generateKeysDict():
	keys_dict = {}
	try:
		myfile = open("keys.txt", 'r')
		readfromjson = myfile.read()
		dictfromjson = json.loads(readfromjson)
		# for key in dictfromjson.keys():
		# 	value = dictfromjson[key]
		# 	keys_dict[base64.decodebytes(key.encode('ascii'))] = value
		for key in dictfromjson.keys():
			value = dictfromjson[key]
			tobyteskey = base64.decodebytes(key.encode('ascii'))
			#key is in rsa, go to bytes, then 
			privateK = RSA.import_key(open('privateKEY.pem', 'rb').read())
			RSAcipher = PKCS1_OAEP.new(privateK)
			symkey = RSAcipher.decrypt(tobyteskey) #can encrypt bytes
			symkey = symkey.decode('utf-8')
			keys_dict[base64.decodebytes(symkey.encode('ascii'))] = value
		# for line in myfile:
		# 	#print(line)
		# 	#print(len(line))
		# 	#print('look here')
		# 	#print(line[86:].decode('utf-8'))
		# 	key1 = line.split(b":")
		# 	print(key1)
		# 	keys_dict[key1[0]] = key1[1]
	except:
		keys_dict = {}
	return keys_dict

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
#higherPath = os.getcwd()

own_folder = 'not real'
extraFolder = ""
print('Main loop started...')
while True:
# Calling receive_msg() in non-blocking mode ... 
#	status, msg = netif.receive_msg(blocking=False)    
#	if status: print(msg)      # if status is True, then a message was returned in msg
#	else: time.sleep(2)        # otherwise msg is empty

# Calling receive_msg() in blocking mode ...
	# os.chdir("..")
	# os.chdir("..")
	os.chdir(rootDirectory)
	status, msg = netif.receive_msg(blocking=True)      # when returns, status is True and msg contains a message
	cipher_text = msg
	length = len(b'-sendkey')
	keys_dict = {}
	print(os.getcwd())
	#
	# privateKey = RSA.import_key(open('privateKEY.pem', 'r').read())
	# RSAcipher = PKCS1_OAEP.new(privateKey)
	# try:
	# 	sentKey = RSAcipher.decrypt(ciphertext)
	# 	sentKey = a_key.decode('utf-8')
	# 	print(sentKey)
	# except:
	# 	print("didnt work")
	# 	exit(0)
	print(cipher_text)
	if (cipher_text[:length] == b'-sendkey'):
		os.chdir(NET_PATH + OWN_ADDR) #puts us into the server folder
		#print("ifed")
		keys_dict = generateKeysDictString()
		#print(keys_dict)
		#print(list(keys_dict.keys())[0])
		#print(cipher_text)
		encr_user_symkey = cipher_text[length:] #just the message (key) minus the sendkey
		privateK = RSA.import_key(open('privateKEY.pem', 'r').read())
		RSAcipher = PKCS1_OAEP.new(privateK)
		decrypted_user_key = RSAcipher.decrypt(encr_user_symkey)
		#print(decrypted_user_key.decode('utf-8'))
		decrypted_user_key = base64.encodebytes(decrypted_user_key).decode('ascii')
		#decrypted_user_key = decrypted_user_key.decode('ascii')
		#print(b"decrypted user key: " + decrypted_user_key)
		#print(keys_dict)
		if decrypted_user_key in list(keys_dict.keys()):
			print("already in")
			continue
		#create name of the new folder
		try:
			#print('try')
			#print(os.getcwd())
			folderFile = open("newFolderNumber.txt", 'r')
			newFolderNumber = folderFile.read()
			#print(newFolderNumber)
			numToInc = int(newFolderNumber)
			numToInc += 1
			#print('trying to close1')
			folderFile.close()
			#print('trying to close2')
			folderFileWrite = open("newFolderNumber.txt", 'w')
			folderFileWrite.seek(0)
			folderFileWrite.write(f'{numToInc:04}')
			folderFileWrite.close()
		except:
			# print("except")
			newFolderNumber = '0000'
			open("newFolderNumber.txt", 'w').write('0001')
		json_decrypted_user_key = decrypted_user_key
		keys_dict[json_decrypted_user_key] = newFolderNumber
		os.mkdir(newFolderNumber)
		print(keys_dict)
		#need to have path (so string of netsim/S/ + newFolderNumber)
		#then we os.mkdirectory (path)

		#make the folder in a directory
		#add to dictionary the encr user sym key with new folder
		#keys_dict[encr_user_symkey] = newFolderNumber
		# pubKey = RSA.import_key(open('publicKEY.pem', 'rb').read())
		# RSAcipher1 = PKCS1_OAEP.new(pubKey)
		# encryptedAgain = RSAcipher1.encrypt(decrypted_user_key)
		# print('encryptd again')
		toJSDict = {}
		for key in keys_dict:
			value = keys_dict[key]
			publicK = RSA.import_key(open('publicKEY.pem', 'rb').read())
			RSAcipher = PKCS1_OAEP.new(publicK)
			encr_symkey = RSAcipher.encrypt(key.encode('utf-8')) #can encrypt bytes
			toJSDict[base64.encodebytes(encr_symkey).decode('ascii')] = value
		dictToJS = json.dumps(toJSDict)
		myfile = open("keys.txt", 'w')
		myfile.seek(0)
		myfile.write(dictToJS)
		myfile.close()

	else: #tag is not send, so we want to decrypt the payload
		print("elsed")
		os.chdir(NET_PATH + OWN_ADDR) #puts us into the server folder
		#try to decrypt ciphertext
		#print(cipher_text.split(b"|"))
		dictMetaData = json.loads(cipher_text.decode('utf-8'))
		nonce = base64.decodebytes(dictMetaData["nonce"].encode('ascii'))
		tag = base64.decodebytes(dictMetaData["tag"].encode('ascii'))
		cipher_text_to_decrypt = base64.decodebytes(dictMetaData["encrypted_msg"].encode('ascii'))

		##check nonce::

		##

		#nonce, tag, cipher_text_to_decrypt = cipher_text.split(b"|")
		#for each keys in the key's dictionary
		#we want to XOR that key with the server symmmetric key and then use that to try to decrypt cipher_text_to_decrypt
		keys_dict = generateKeysDict()
		print(keys_dict)
		if len(keys_dict) == 0:
			print("please send a key over")
		command = ''
		arguments = []
		currentKey = None
		for key in list(keys_dict.keys()):
			print(b"Key : " +  key)
			# privateK = RSA.import_key(open('privateKEY.pem', 'r').read())
			# RSAcipher = PKCS1_OAEP.new(privateK)
			# a_key = RSAcipher.decrypt(key)
			# a_key = a_key.decode('utf-8')
			print("ciphertext")
			print(cipher_text_to_decrypt)
			try:
				cipher = AES.new(key, AES.MODE_GCM, nonce = nonce)
				plaintext = cipher.decrypt_and_verify(cipher_text_to_decrypt, tag) #do we need tag?
				commandArg = plaintext.split()
				command = commandArg[0].decode('utf-8')
				arguments = commandArg[1:]
				own_folder = keys_dict[key] + '/'
				currentKey = key
		
			except:
				print("Incorrect Dec while trying to decrypt message with keys from dict")
		print('end of checking keys')
		if own_folder == "not real":
			print("cannot find your folder")
			continue 
		#print(command)
		#print(arguments)
		os.chdir(own_folder + extraFolder)
		if command == "MKD":
			if len(arguments) < 2:
				#oschr(rootdirectory)
				#netif.sendmsg(arguments[1], msg.encode('utf-8'))
				print("please enter an argument")
				continue
			#make new directory
			try:
				os.mkdir(arguments[0].decode('utf-8'))
				print("created directory: " + arguments[0].decode('utf-8'))
			except:
				print("already exists")
		elif command == "CWD":
			if len(arguments) < 2:
				print("please enter an argument")
				continue
			try:
				#change working directory
				if arguments[0].decode('utf-8') == "..":
					if os.getcwd()[-4:] == own_folder[:4]:
						print("Cannot go back further")
						continue
					else:
						value = -len(os.getcwd().split('\\')[-1])
						extraFolder = extraFolder[:value - 1]
						os.chdir(arguments[0].decode('utf-8'))
				else:
					os.chdir(arguments[0].decode('utf-8'))
					extraFolder += arguments[0].decode('utf-8') + "/"
			except:
				print('does not exist')
		elif command == "RMD":
			#remove directory
			if len(arguments) < 2:
				print("please enter an argument")
				continue
			try:
				os.rmdir(arguments[0].decode('utf-8'))
				print("removed: " + arguments[0].decode('utf-8'))
			except:
				print('does not exist')
		elif command == "GWD":
			#get working directory (current folder)
			print("WORKING DIRECTORY: " + os.getcwd())
		elif command == "LST":
			#list all files
			listoffiles = os.listdir()
			if len(listoffiles) == 0:
				print("No Files Found")
			else:
				for file1 in listoffiles:
					print(file1)
		elif command == "UPL":
			#upload file
			#first argument, your directory / file name, given file name
			#to location = current directory / file name, given same file name
			#arg 0 is your folder name off of the higher path
			if len(arguments) < 2:
				print("please enter an argument")
				continue
			try:
				print('1')
				print(rootDirectory  + "\\"+ NET_PATH + arguments[1].decode('utf-8') + "/" + arguments[0].decode('utf-8'), "spcae", os.getcwd()  + "\\" + arguments[0].decode('utf-8'))
				copyFile(rootDirectory  + "\\"+ NET_PATH + arguments[1].decode('utf-8') + "/" + arguments[0].decode('utf-8'), os.getcwd()  + "\\" + arguments[0].decode('utf-8'))
				print("upload successful")
			except:
				print("file cannot be found")
		elif command == "DNL":
			#download file
			#first argument will be current directory / file name, given file name
			#to location = your directory / file name, given same file name
			# arg 0 is still your folder name (user name)
			if len(arguments) < 2:
				print("please enter an argument")
				continue
			try:
				copyFile(os.getcwd() + "\\" + arguments[0].decode('utf-8'), rootDirectory + "\\"+  NET_PATH + arguments[1].decode('utf-8') + "/" + arguments[0].decode('utf-8'))
				print("download successful")
			except:
				print("file cannot be found")
		elif command == "RMF":
			#remove file
			#given the file name, current directory / file name
			try:
				os.remove(arguments[0].decode('utf-8'))
			except:
				print("file does not exist, cannot remove")
			#print(msg.decode('utf-8'))
				
		
		 
		#try to decrypt payload with the XOR-ed key 
		#If any works, then accept the decrypted payload
		#Parse the payload 
		#
    



		#TODO  USE NONCE TO SEND STUFF BACK in gcm. (instead of print statemnts)
		#TODO  have a nonce recorder
		# (prob a text file again)
		# after implementing the sendback messages


		# TODO: if have time: implement burn (BRN) that deletes your overarching folder, and your key value pair from dictionary

		#so we grab from sendkey the gcm key to put in a dictionary, but when we want to store that dictionary, we should encrypt the
		#key again with the public key
		#when grabbing that dictionary, we need to decrypt using our private key
		# how do we store the private key securely?
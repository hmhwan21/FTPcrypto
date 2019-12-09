from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA



def createKey():
    privateKey = RSA.generate(1024)
    publicKey = privateKey.publickey()


    privatePEM = privateKey.export_key().decode()
    publicPEM = publicKey.export_key().decode()
    print(privatePEM)
    print(publicPEM)

    privKeyFile = open('privateKEY.pem', 'w')
    privKeyFile.write(privatePEM)
    privKeyFile.close()
    publicKeyFile = open('publicKEY.pem', 'w')
    publicKeyFile.write(publicPEM)
    publicKeyFile.close()
createKey()
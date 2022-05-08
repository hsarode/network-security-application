from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

# This function reads the private key and returns it 
def readPrivate(filename):
    with open(filename, "rb") as key_file:
            serverPrivateKey = serialization.load_pem_private_key(key_file.read(),password=None,backend=default_backend())
    return serverPrivateKey

# This function decrypts the received session key using the server's private key from the first function
def decryptSessionKeys(sessionBytes, serverPrivateKeyPath):
    serverPrivateKey = readPrivate(serverPrivateKeyPath)
    sessionKeys = serverPrivateKey.decrypt(sessionBytes,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    return sessionKeys

# This function uses the session keys from the above function to decrypt the data received.
def aesDecrypt(aesEncryptedData, sessionKeyBytes, iv, pathToSave):
    mode = AES.new(sessionKeyBytes, AES.MODE_CBC, iv)
    og_data = unpad(mode.decrypt(aesEncryptedData), 16)
    open(pathToSave, 'wb').write(og_data)
    return 0
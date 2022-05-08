from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

# Read in the public key of the server and return it
def read_public(filename):
    with open(filename, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

# Encrypt the session keys (large random number) with the public key of the server so only the server can decrypt it.
def encryptSessionKeys(serverPublicKeyPath):
    iv = get_random_bytes(16)
    sessionKeyBytes = get_random_bytes(16)
    serverPublicKey = read_public(serverPublicKeyPath)
    encryptedSessionKeyBytes = serverPublicKey.encrypt(sessionKeyBytes,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    encryptedIV = serverPublicKey.encrypt(iv,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    return encryptedSessionKeyBytes, sessionKeyBytes, encryptedIV, iv

# Encrypt data to be sent using AES 128
def aesEncrypt(fileToEncrypt, sessionKeyBytes, iv):
    f = open(fileToEncrypt, 'rb')
    dataBytesToSend = f.read()
    f.close()
    mode = AES.new(sessionKeyBytes, AES.MODE_CBC, iv)
    encryptedAESData = mode.encrypt(pad(dataBytesToSend, 16))
    return encryptedAESData
import socket
import ssl
import buffer
import time
import client_session_key
from OpenSSL import crypto

# Function to simply send bytes of data
def sendBytes(sbuf, byteToSend):
    sbuf.put_utf8(str(len(byteToSend)))
    time.sleep(1)
    sbuf.put_bytes(byteToSend)

# Main function that sends over the files
def init(ip, port, client_cert, client_key, ca_cert, workingDirectory):
    if(client_cert=='' ):
        client_cert = 'src/Client_Certificate.cer'
    if(client_key==''):
        client_key = 'src/Client_Private_Key.pem'
    if(ca_cert==''):
        ca_cert = 'src/CA_Certificate.cer'
    host_addr = ip
    host_port = port
    server_sni_hostname = 'server'
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_cert)
    try:
        # Try for the handshake, if verified continue to send files over. If handshake fails terminate the function.
        context.load_cert_chain(certfile=client_cert, keyfile=client_key)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn = context.wrap_socket(s, server_side=False, server_hostname=server_sni_hostname)
        conn.connect((host_addr, host_port))
        print("SSL established. Peer: {}".format(conn.getpeercert()))
    except ConnectionRefusedError:
        print('Connection refused by server')
        print(ConnectionRefusedError)
        return ConnectionRefusedError
    except ssl.SSLError:
        print('TLS handshake failed: ', ssl.SSLError.__class__)
        return ssl.SSLError

    documentSignature = workingDirectory+'/doc.sig'     # The location of the document signature to send
    document = workingDirectory+'/sign.txt'             # The location of document to send
    x509Certificate = workingDirectory+'/doc.crt'       # The location of the document's certificate

    # Create encrypted session keys and IV using server's public key
    encryptedSessionKeyBytes, sessionKeyBytes, encryptedIV, iv = client_session_key.encryptSessionKeys('src/server_public.pem')
    # Encrypt all the files to be sent using AES 128 using the session key as the password and IV as the IV from previous line.
    encryptedDocument = client_session_key.aesEncrypt(document, sessionKeyBytes, iv)
    encryptedDocumentSignature = client_session_key.aesEncrypt(documentSignature, sessionKeyBytes, iv)
    encryptedx509Certificate = client_session_key.aesEncrypt(x509Certificate, sessionKeyBytes, iv)

    # Send over the data.
    with conn:
        sbuf = buffer.Stream(conn)
        sendBytes(sbuf, encryptedSessionKeyBytes)
        print('Encrypted Session Key sent with length: ', len(encryptedSessionKeyBytes))
        sendBytes(sbuf, encryptedIV)
        print('Encrypted IV sent with length: ', len(encryptedIV))
        sendBytes(sbuf, encryptedDocument)
        print('Encrypted document sent with length: ', len(encryptedDocument))
        sendBytes(sbuf, encryptedDocumentSignature)
        print('Encrypted document signature sent with length: ', len(encryptedDocumentSignature))
        sendBytes(sbuf, encryptedx509Certificate)
        print('Encrypted x509 Certificate sent with length: ', len(encryptedx509Certificate))
        return 'sent'
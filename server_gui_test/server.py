import socket
import ssl
import buffer
import server_session_key

# Receive data from the stream and add it to a variable data until all data is sent. Once all data is received return the data.
def getBytes(file_size, connbuf):
    remaining = file_size
    data = b''
    while remaining:
        chunk_size = 4096 if remaining >= 4096 else remaining
        chunk = connbuf.get_data(chunk_size)
        if not chunk: break
        data += chunk
        remaining -= len(chunk)
    if remaining:
        print('File incomplete.  Missing',remaining,'bytes.')
    else:
        print('File received successfully.')
    return data

# The main function that sets up the server.
def receiveDocuments(ip, port, currentDirectory):
    listen_addr = ip  #'127.0.0.1'
    listen_port = port

    # We use the certificates to establish SSL
    server_cert = 'src/server.cer'          # Server's certificate 
    server_key = 'src/serverKey.pem'        # Server's private key
    ca_cert = 'src/caCertificate.cer'       # CA certificate

    # Verifying certificates to cofirm handshake
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=server_cert, keyfile=server_key)
    context.load_verify_locations(cafile=ca_cert)

    bindsocket = socket.socket()        # Start the socket and being receiving
    bindsocket.bind((listen_addr, listen_port))
    bindsocket.listen(10)
    print("Waiting for client")
    sent=True
    while sent:
        newsocket, fromaddr = bindsocket.accept()       # Accept connection from client
        print("Client connected: {}:{}".format(fromaddr[0], fromaddr[1]))
        conn = context.wrap_socket(newsocket, server_side=True)     # Perform handshake
        print("SSL established. Peer: {}".format(conn.getpeercert()))
        connbuf = buffer.Stream(conn)

        # Receive data and decrypt it.
        while True:
            file_size = int(connbuf.get_str_data())
            print('File size: ', file_size )
            encryptedSessionKey = getBytes(file_size, connbuf)
            sessionKey = server_session_key.decryptSessionKeys(encryptedSessionKey, server_key)
            print('Received session key: ', sessionKey)

            file_size = int(connbuf.get_str_data())
            print('File size: ', file_size )
            encryptedIV = getBytes(file_size, connbuf)
            iv = server_session_key.decryptSessionKeys(encryptedIV, server_key)
            print('IV for AES: ', iv)

            file_size = int(connbuf.get_str_data())
            print('File size: ', file_size )
            encryptedDocument = getBytes(file_size, connbuf)
            document = server_session_key.aesDecrypt(encryptedDocument, sessionKey, iv, currentDirectory+'/sign.txt')

            file_size = int(connbuf.get_str_data())
            print('File size: ', file_size )
            encryptedDocumentSignature = getBytes(file_size, connbuf)
            document = server_session_key.aesDecrypt(encryptedDocumentSignature, sessionKey, iv, currentDirectory+'/doc.sig')

            file_size = int(connbuf.get_str_data())
            print('File size: ', file_size )
            encryptedx509Certificate = getBytes(file_size, connbuf)
            document = server_session_key.aesDecrypt(encryptedx509Certificate, sessionKey, iv, currentDirectory+'/doc.crt')
            print('Connection closed. Restart client to reconnect.')
            conn.close()
            sent = False
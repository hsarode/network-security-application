from OpenSSL import crypto
import random
import base64
import gnupg
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA

gpg = gnupg.GPG(gnupghome='/home/hsarode/.gnupg')

##################################################################### START OF SIGN DOCUMENT WITH x509 #####################################################################

# This function reads the PKCS12 file and decrypts it to obtain the CA certificate and CA private key
def x509_import_keys(x509_Path, password):
    p12 = crypto.load_pkcs12(open(x509_Path, 'rb').read(), passphrase=password)
    ca = p12.get_certificate()
    caKey = p12.get_privatekey()
    return caKey, ca

# Generates a new key pair for the document, then generates the CSR using the private key of the newly created key pair and return the CSR
def x509_gen_csr(country, state, city, org, unit, cn, email, current_directory):
    csr_key = crypto.PKey()
    csr_key.generate_key(crypto.TYPE_RSA, 4096)
    # Creating the CRS request
    csr = crypto.X509Req()
    csr.get_subject().C = country
    csr.get_subject().ST = state
    csr.get_subject().L = city
    csr.get_subject().O = org
    csr.get_subject().OU = unit
    csr.get_subject().CN = cn
    csr.get_subject().emailAddress = email
    csr.set_pubkey(csr_key)
    csr.sign(csr_key, 'sha512')
    doc_private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, csr_key)
    doc_public_key = crypto.dump_publickey(crypto.FILETYPE_PEM, csr_key)
    csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr)
    open(current_directory+'/doc_private.pem', 'wb').write(doc_private_key)
    open(current_directory+'/doc_public.pem', 'wb').write(doc_public_key)
    return csr, csr_key

# Take in the CSR from the above function and sign the CSR using the CA's private key and write the newly created certificate for the document to a file.
def x509_sign_cert(ca_certificate, ca_private, csr_req, csr_key, current_directory):
    serial_no = random.getrandbits(64)
    certs = crypto.X509()
    csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr_req)
    certs.set_serial_number(serial_no)
    certs.gmtime_adj_notBefore(0)
    certs.gmtime_adj_notAfter(31536000)
    certs.set_subject(csr.get_subject())
    certs.set_issuer(ca_certificate.get_subject())
    certs.set_pubkey(csr_key)
    certs.set_serial_number(10)
    certs.sign(ca_private, 'sha256')
    certificate = crypto.dump_certificate(crypto.FILETYPE_PEM, certs)
    open(current_directory+'/doc.crt', 'wb').write(certificate)
    return 0

# Sign files using the private key of the document certificate that was created  and write the signature file to a file.
def signfile(docToSign ,current_directory):
    f=open(docToSign, 'rb')
    message = f.read()
    f.close()

    digest = SHA256.new()
    digest.update(message)
    # Read shared key from file
    private_key = False
    with open (current_directory+'/doc_private.pem', "r") as myfile:
        private_key = RSA.importKey(myfile.read())

    # Load private key and sign message
    signer = PKCS1_v1_5.new(private_key)
    sig = signer.sign(digest)
    open(current_directory+'/doc.sig', 'wb').write(sig)

#-##################################################################### END DOCUMENT SIGNING ###########################################################################

##################################################################### START OF VERIFY DOCUMENT WITH x509 #####################################################################
# Verify files against their signature
def verifyfile(fileToVerify, pair_x509_cert, docSignature, current_directory):

    f=open(fileToVerify, 'rb')      # Open the file to verify and store it in message
    message = f.read()
    f.close()

    digest = SHA256.new()
    digest.update(message)          # Create a digest for the file to be verified

    f = open(pair_x509_cert)        # Read the pairs x509 certificate which will be used to verify the signature.
    pair_x509_cert = f.read()
    f.close()
    pair_x509_cert = crypto.load_certificate(crypto.FILETYPE_PEM, pair_x509_cert)
    pair_public_key = pair_x509_cert.get_pubkey()       # Get the public key of the certificate
    pair_public_key = crypto.dump_publickey(crypto.FILETYPE_PEM, pair_public_key)
    open(current_directory+'/docPublicKey.pem', 'wb').write(pair_public_key)    # Write the public key of document to a file because this library needs the public key file. 
                                                                                # we can't pass an object of pyopenssl into pycryptodome library.
    
    with open(current_directory+'/docPublicKey.pem', "r") as myfile:            # Read the public key from the public key file we just created.
        public_key = RSA.importKey(myfile.read())
        
    f = open(docSignature, 'rb')        # Read the document signature
    sig = f.read()
    f.close()

    # Verify message
    verifier = PKCS1_v1_5.new(public_key)
    verified = verifier.verify(digest, sig)
    assert verified, 'Signature verification failed'
    return 'verified'

##################################################################### END OF VERIFY DOCUMENT WITH x509 #####################################################################

##################################################################### START OF CRL CHECK ##################################################################################

# Create a CRL to use to check for revoked certificates.
def createCRL(x509_Path, password, certificateToRevokePath, directoryToSaveCRL, dummy):   # The dummy variable is set to False when we want to create an empty CRL

    caKey, caCertificate = x509_import_keys(x509_Path, password)        # Get the CA cert and private key
    if(dummy):
        f = open(certificateToRevokePath, 'rb')         # Load the certificate to revoke.
        certToRevoke = f.read()
        certToRevoke = crypto.load_certificate(crypto.FILETYPE_PEM, certToRevoke)
        f.close

        serialToRevoke = certToRevoke.get_serial_number()       # Get the serial number of certificate to revoke
        serialToRevoke = hex(serialToRevoke)
        serialToRevoke = serialToRevoke[2:]
        serialToRevoke = bytes(serialToRevoke, 'utf-8')         # Convert the serial number into bytes
    else:
        serialToRevoke = b'1234'            # This is used to create a CRL file which is empty since 1234 would not be a serial number of certificate that we will use for testing.

    revokedCertificateObject = crypto.Revoked()
    revokedCertificateObject.set_serial(serialToRevoke)     # Put the serial number of certificate to revoke in the CRL
    revokedCertificateObject.set_rev_date(b"20210603050312Z")       # Provide other complimentary data pertaining to revocation
    revokedCertificateObject.set_reason(b'keyCompromise')

    crl = crypto.CRL()
    crl.set_lastUpdate(b"20210312050231Z")
    crl.set_nextUpdate(b"20210423060508Z")
    crl.add_revoked(revokedCertificateObject)
    crl.sign(caCertificate, caKey, b'sha256')           # Sign the CRL with our CA to establish trust if this will be used by other groups.

    crl = crypto.dump_crl(crypto.FILETYPE_PEM, crl)         # Write the CRL to a file that can be used by other programs to check for revocation
    open(directoryToSaveCRL+'/revocations.crl', 'wb').write(crl)
    return 0

# Read in the CRL and check if the serial number of the certificate being used in revoked or not
def checkCRL(crlPath, caCertificate, certToCheck):

    f = open(crlPath, 'rb')
    crl = f.read()
    crl = crypto.load_crl(crypto.FILETYPE_PEM, crl)
    f.close

    store = crypto.X509Store()
    store.add_cert(caCertificate)           # Trust our CA certificate in the x509 store.
    store.set_flags(crypto.X509StoreFlags.CRL_CHECK)        # Always check for CRL
    store.add_crl(crl)          # Load the CRL into the x509 store
    ctx = crypto.X509StoreContext(store, certToCheck)
    try:
        result = ctx.verify_certificate()       # Check if certificate has been revoked or not.
        if(result==None):
            return True
    except Exception as e:
        print('Error is: ', e)
        return False

################################################################# END START OF CRL CHECK ##################################################################################

##################################################################### START OF VERIFY SIGNED DOCUMENT WITH x509 #############################################################

# Verify the signatures to documents received by other pair, and if the signature is valid, sign their file using our PGP private keys.
def x509_verify_file_sign_PGP(crl_path, x509_ca, pkcs_pswd, pair_x509_cert, signature, og_file, path, harshal_pgp_pswd, summaya_pgp_pswd):

    caKey, caCertificate = x509_import_keys(x509_ca, pkcs_pswd)         # Load in our CA certificate, this is to check for CRL, as it is used to verify if the CRL is trusted or not
    pairx509PathCopy = pair_x509_cert
    f = open(pair_x509_cert)        # Read in the other pair's x509 certificate
    pair_x509_cert = f.read()
    f.close()
    pair_x509_cert = crypto.load_certificate(crypto.FILETYPE_PEM, pair_x509_cert)

    status = checkCRL(crl_path, caCertificate, pair_x509_cert)          # Check the CRL for any revocations, if cert is not revoked process to verify the signature to the file.
    if(status):
        try:
            verify_status = verifyfile(og_file, pairx509PathCopy, signature, path)
        except:
            return 'pair doc not verified'
    else:
        return 'crl failed'
    if(verify_status=='verified'):          # Check if the signature is valid or not. If valid sign their document using our PGP private key, else do not sign, return error msg.
        try:
            pgp_sign(og_file, harshal_pgp_pswd, path, 'harshal', 'F665B091DFF8D0DA')
        except:
            return 'wrongh'
        try:
            pgp_sign(og_file, summaya_pgp_pswd, path, 'summaya', 'B9E0EB37B4310E52')
        except:
            return 'wrongs'
        return 'verified'
    return 'done'


##################################################################### END OF VERIFY SIGNED DOCUMENT WITH x509 #############################################################

##################################################################### SIGN DOC WITH NEW CERT SINGED BY CA #################################################################
# This function combines the whole x509 functions into one for ease of use. Now we can generate document signature and certificate using this one function.
def part3(x509Path, password, country, state, city, org, unit, cn, email, doc_to_sign, current_directory):
    ca_private, ca_certificate = x509_import_keys(x509Path, password)
    csr, csr_key = x509_gen_csr(country, state, city, org, unit, cn, email, current_directory)
    x509_sign_cert(ca_certificate, ca_private, csr, csr_key, current_directory)
    signfile(doc_to_sign, current_directory)
    return 0

################################################################# END SIGN DOC WITH NEW CERT SINGED BY CA #################################################################

########################################################################## PGP PRIVATE SIGN DOC ##################################################################
# This function signs the other pair's document using our PGP private key and saves the signature to another file. It creates a detached signature.
def pgp_sign(file_to_sign, password, path, name, keyID):
    file_to_sign = open(file_to_sign, "rb")     # Read the file that needs to be signed
    gpg.sign_file(file_to_sign, passphrase=password, detach=True, output=path+'/doc_'+name+'_sig.asc', keyid=keyID)         # write the signature to a file
    file_to_sign.close()
    return 0

# This function is used to verify the PGP signatures to a given file.
def verify_file_pgp(signed_file, file_to_verify):
    stream = open(signed_file, "rb")        # Read the signature of the file.
    verified = gpg.verify_file(stream, file_to_verify)
    print(verified)
    if not verified:
        return 'no'
    else:
        return 'pgp_verified'

############################################################ PGP PRIVATE SIGN DOC END ##############################################################
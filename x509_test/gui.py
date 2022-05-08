from logging import log
import ssl
import tkinter as tk
from tkinter.constants import E, LEFT, W
from tkinter.filedialog import askopenfilename
from tkinter.scrolledtext import ScrolledText
import ssl_gui
import client
import tkinter.font as font


# This is the GUI and is divided into 5 frames, each frame responsible for one part of the the code. Before the start of each frame, a comment has been added to indicate
# what that part of the application it runs.
screen = tk.Tk()
screen.title('Document Verification')
screen.geometry('1330x670')

currentDirectory = tk.StringVar()
PKCS12Path = tk.StringVar()
CACertificatePath = tk.StringVar()
documentToSignPath = tk.StringVar()
otherPairCertificatePath = tk.StringVar()
otherPairSignaturePath = tk.StringVar()
otherPairDocumentPath = tk.StringVar()

def logData(data, success=False, fail=False):
    msg = format(data)
    logs.configure(state='normal')
    if(success):
        logs.insert(tk.END, msg + '\n', 'success')
    elif(fail):
        logs.insert(tk.END, msg + '\n', 'fail')
    else:
        logs.insert(tk.END, msg + '\n')
    logs.configure(state='disabled')
    logs.yview(tk.END)
    logs.tag_config('fail', foreground='red')
    logs.tag_config('success', foreground='green')

def getPKCS12():
    PKCS12Path.set(askopenfilename())
    logData("The location of PKCS12 is set as: "+PKCS12Path.get())

def getDocumentToSign():
    documentToSignPath.set(askopenfilename())
    logData("The location of document to sign is set as: "+documentToSignPath.get())
def setWorkingDirectory():
    currentDirectory.set(tk.filedialog.askdirectory())
    logData("Location of saved signature files: "+currentDirectory.get())
    logData('Creating empty CRL file, without CRL, the document will not proceed with verification!')
    createCRLSave(dummy=False)
    logData('Warning - Do not delete or move any files from this directory unless the logs sow you in green that you can!!', fail=True)
def generatex509Signature():
    country = countryVal.get()
    state = stateVal.get()
    city = cityVal.get()
    org = orgVal.get()
    unit = unitVal.get()
    cn = cnVal.get()
    email = emaiLVal.get()
    logData("Signing the certificate with below details")
    logData("Country: "+country)
    logData("State: "+state)
    logData("City: "+city)
    logData("Organisation: "+org)
    logData("Unit: "+unit)
    logData("Common Name: "+cn)
    logData("Email: "+email)
    ssl_gui.part3(PKCS12Path.get(), pkcsPassword.get(), country, state, city, org, unit, cn, email, documentToSignPath.get(), currentDirectory.get())

#-------------------------------------------------------- FRAME 1 - LOAD EVERYTHING, CREATE CSR AND SIGN DOC ------------------------------------------------------------------#

frame1 = tk.Frame(screen, padx=5, pady=5, highlightbackground='black', highlightthickness=3)
frame1.grid(row=0, column=0, padx=10, pady=10, sticky='n')
tk.Label(frame1, text='Set on Startup', font=('Arial',18, 'bold')).grid(row=0, column=0, columnspan=2)
tk.Label(frame1, text="Enter PKCS12 password").grid(row=1, column=0)
pkcsPassword = tk.StringVar(frame1)
passwordLabel = tk.Entry(frame1, show='*', textvariable=pkcsPassword).grid(row=1, column=1, sticky=W)
x509CAPrivateKey = tk.Button(frame1, text='Load PKCS12 contaning CA', command=getPKCS12).grid(row=2, column=0, columnspan=2, sticky=W)
getWorkingDirectory = tk.Button(frame1, text='Set directory for saving files', command=setWorkingDirectory).grid(row=3, column=0, columnspan=2, sticky=W)
tk.Label(frame1, text="Sign document using x509", font=('Arial',18, 'bold')).grid(row=4,column=0, columnspan=2)
loadDocumentToSign = tk.Button(frame1, text='Load the document to sign', command=getDocumentToSign).grid(row=5, column=0, columnspan=2, sticky=W)

tk.Label(frame1, text="Country", justify=LEFT).grid(row=6,column=0, sticky=W)
tk.Label(frame1, text="State", justify=LEFT).grid(row=7,column=0, sticky=W)
tk.Label(frame1, text="City", justify=LEFT).grid(row=8,column=0, sticky=W)
tk.Label(frame1, text="Organization", justify=LEFT).grid(row=9,column=0, sticky=W)
tk.Label(frame1, text="Unit", justify=LEFT).grid(row=10,column=0, sticky=W)
tk.Label(frame1, text="Common Name", justify=LEFT).grid(row=11,column=0, sticky=W)
tk.Label(frame1, text="Email", justify=LEFT).grid(row=12,column=0, sticky=W)

countryVal = tk.StringVar(frame1, value='AE')
stateVal = tk.StringVar(frame1, value='Dubai')
cityVal = tk.StringVar(frame1, value='Dubai')
orgVal = tk.StringVar(frame1, value='Heriot Watt')
unitVal = tk.StringVar(frame1, 'MACS')
cnVal = tk.StringVar(frame1, value='document')
emaiLVal=tk.StringVar(frame1, 'docsig@cns.com')

countryLabel=tk.Entry(frame1, textvariable=countryVal).grid(row=6,column=1, sticky=W)
stateLabel=tk.Entry(frame1, textvariable=stateVal).grid(row=7,column=1, sticky=W)
cityLabel=tk.Entry(frame1, textvariable=cityVal).grid(row=8,column=1, sticky=W)
orgLabel=tk.Entry(frame1, textvariable=orgVal).grid(row=9,column=1, sticky=W)
unitLabel=tk.Entry(frame1, textvariable=unitVal).grid(row=10,column=1, sticky=W)
cnLabel=tk.Entry(frame1, textvariable=cnVal).grid(row=11,column=1, sticky=W)
emailLabel=tk.Entry(frame1, textvariable=emaiLVal).grid(row=12,column=1, sticky=W)

finalButtonFont = font.Font(family='Helvetica', size=11, weight='bold')
createSignedDocument = tk.Button(frame1, text='Generate Document Signature', font=finalButtonFont, command=generatex509Signature, height=2).grid(row=13, column=0, columnspan=2, sticky=E)

#-------------------------------------------------------- FRAME 2 - SEND FILES VIA NETWORK WITH TLS/AES ENCRYPTION ------------------------------------------------------------------#
frame2 = tk.Frame(screen, padx=5, pady=5, highlightbackground='black', highlightthickness=3)
frame2.grid(row=1, column=0, padx=10, pady=10, sticky='n', rowspan=1)

tk.Label(frame2, text="Send files via network", font=('Arial',18, 'bold')).grid(row=0,column=0, columnspan=2)
tk.Label(frame2, text="Public IP of RX").grid(row=1,column=0)
publicIPVal = tk.StringVar()
publicIPLabel=tk.Entry(frame2, textvariable=publicIPVal).grid(row=1,column=1)

tk.Label(frame2, text='Port').grid(row=2, column=0)
portVal = tk.StringVar()
portLabel = tk.Entry(frame2, textvariable=portVal).grid(row=2, column=1)
clientCertificatePath = tk.StringVar()
clientKeyPath = tk.StringVar()
caCertificatePath = tk.StringVar()

def getClientCertificate():
    clientCertificatePath.set(askopenfilename())
    logData('The location of client certificate is set as: '+clientCertificatePath.get())
def getClientKey():
    clientKeyPath.set(askopenfilename())
    logData('The location of client key is set as: '+clientKeyPath.get())
def getCACertificate():
    caCertificatePath.set(askopenfilename())
    logData('The location of CA certificate is set as: '+caCertificatePath.get())
def sendFilesTo():
    if(currentDirectory.get()==''):
        logData('Directory to get files for sending not set!', fail=True)
        logData('Select directory containing the files to send')
        currentDirectory.set(tk.filedialog.askdirectory())
    status = client.init(publicIPVal.get(), int(portVal.get()), clientCertificatePath.get(), clientKeyPath.get(), caCertificatePath.get(), currentDirectory.get())
    if(status=='sent'):
        logData('All files sent.', success=True)
        logData('You can now safely delete or move the files from the working directory', success=True)
    elif(status==ssl.SSLError):
        logData('TLS Handshake FAILED. Certificate mismatch.'+str(status), fail=True)
    elif(status==ConnectionRefusedError):
        logData('Connection refused'+str(status), fail=True)
        logData('Please ensure the server is running or try changing ports', fail=True)
    else:
        logData('There was an error in transmission, please retry.', fail=True)

loadClientCertificate = tk.Button(frame2, text='Select client certificate', command=getClientCertificate, width=17).grid(row=3, column=0, columnspan=2, sticky=W)
loadClientKey = tk.Button(frame2, text='Select client key', command=getClientKey, width=17).grid(row=4, column=0, columnspan=2, sticky=W)
loadCACertificate = tk.Button(frame2, text='Select CA certificate', command=getCACertificate, width=17).grid(row=5, column=0, columnspan=2, sticky=W)
sendFilesOnNetwork = tk.Button(frame2, text='Send documents over network', font=finalButtonFont, command=sendFilesTo, height=2).grid(row=6, column=0, columnspan=2, sticky=E)
#-------------------------------------------------------- FRAME 3 - VERIFY OTHER PAIR'S DOC AND SIGN DOC ------------------------------------------------------------------#
frame3 = tk.Frame(screen, padx=5, pady=5, highlightbackground='black', highlightthickness=3)
frame3.grid(row=1, column=1, padx=10, pady=10, sticky='w')

def getPairx509Certificate():
    otherPairCertificatePath.set(askopenfilename())
    logData("The location of other PAIR x509 Ceritificate is set as: "+otherPairCertificatePath.get())
def getPairDocumentSignature():
    otherPairSignaturePath.set(askopenfilename())
    logData("The location of other PAIR signature is set as: "+otherPairSignaturePath.get())
def getPairDocument():
    otherPairDocumentPath.set(askopenfilename())
    logData("The location of PAIR document is set as: "+otherPairDocumentPath.get())
def getPairDocumentVerification():
    if(crlPath.get()==''):
        logData('CRL file not loaded, please load it in the open window.', fail=True)
        crlPath.set(askopenfilename())
        logData('CRL file loaded from: '+crlPath.get())
    status = ssl_gui.x509_verify_file_sign_PGP(crlPath.get(), PKCS12Path.get(), pkcsPassword.get(), otherPairCertificatePath.get(), otherPairSignaturePath.get(), otherPairDocumentPath.get(), currentDirectory.get(), pgpPrivateKeyPasswordVal.get(), pgpPrivateKeyPassword1Val.get())
    pgpPrivateKeyPasswordVal.set('')
    pgpPrivateKeyPassword1Val.set('')

    if(status=='pair doc not verified'):
        logData("File from other could not be verified. Not signing their document!", fail=True)
    elif(status=='crl failed'):
        logData('Used Certificate from {} is revoked. Please try with a valid certificate'.format(otherPairCertificatePath.get()), fail=True)
    elif(status=='wrongh'):
        logData('Please enter the correct PGP password for Harshal', fail=True)
    elif(status=='wrongs'):
        logData('Please enter the correct PGP password for Summaya', fail=True)
    else:
        logData('Files verified and signed with our PGP.', success=True)
        logData('The PGP signed files signed by us are stored in \n {}'.format(currentDirectory.get()))
def loadCRL():
    crlPath.set(askopenfilename())
    logData('CRL file read in from: '+crlPath.get())

tk.Label(frame3, text="Document verification and signing", font=('Arial',18, 'bold')).grid(row=0,column=0, columnspan=2)
crlPath = tk.StringVar()
crl = tk.Button(frame3, text='Load CRL file', command=loadCRL).grid(row=1, column=0, columnspan=2, sticky=W)
pairx509Certificate = tk.Button(frame3, text='Load pairs x509 Certificate', command=getPairx509Certificate, width=25).grid(row=2, column=0, columnspan=2, sticky=W)
pairDocumentSignature = tk.Button(frame3, text='Load the signature of the document', command=getPairDocumentSignature, width=25).grid(row=3, column=0, columnspan=2, sticky=W)
pairDocument = tk.Button(frame3, text='Load the document to verify', command=getPairDocument, width=25).grid(row=4, column=0, columnspan=2, sticky=W)

pgpPrivateKeyPasswordVal = tk.StringVar(frame3)
tk.Label(frame3, text='Enter password PGP Harshal', justify=LEFT).grid(row=5, column=0)
pgpPrivateKeyPasswordLabel = tk.Entry(frame3, show='*', textvariable=pgpPrivateKeyPasswordVal).grid(row=5, column=1)

pgpPrivateKeyPassword1Val = tk.StringVar(frame3)
tk.Label(frame3, text='Enter password PGP Summaya', justify=LEFT).grid(row=6, column=0)
pgpPrivateKeyPassword1Label = tk.Entry(frame3, show='*', textvariable=pgpPrivateKeyPassword1Val).grid(row=6, column=1)

verifyPairDocument = tk.Button(frame3, text='Verify & Sign the document', font=finalButtonFont, command=getPairDocumentVerification, width=25, height=2).grid(row=7, column=0, columnspan=2, sticky=E)
#-------------------------------------------------------- FRAME 4 - PRINT LOGS FROM CURRENT USER OPERATIONS ------------------------------------------------------------------#
frame4 = tk.Frame(screen, padx=5, pady=5, highlightbackground='black', highlightthickness=3)
frame4.grid(row=0, column=1, padx=10, pady=10, rowspan=1, sticky='n')
tk.Label(frame4, text="Logs", font=('Arial',18, 'bold')).grid(row=0,column=0)

logs = ScrolledText(frame4, state='disabled')
logs.configure(font='TkFixedFont', height=20)
logs.grid(row=1, column=0)

#--------------------------------------------------------- FRAME 3 - CRL LISTS -------------------------------------------------------------------------------

tk.Label(frame3, text="CRL", font=('Arial',18, 'bold')).grid(row=0,column=3)

def getCertificateToRevoke():
    certificateToRevokePath.set(askopenfilename())
    logData('Certificate to revoke selected at: '+certificateToRevokePath.get())
def createCRLSave(dummy=True):
    if(currentDirectory.get()==''):
        logData('Current directory not selected, please select in the window open now', fail=True)
        currentDirectory.set(tk.filedialog.askdirectory())
        logData('Current directory set as: '+currentDirectory.get())
    if(PKCS12Path.get()==''):
        logData('PKCS12 path not set, please set it in the window open now', fail=True)
        PKCS12Path.set(askopenfilename())
        logData('PKCS12 path set as: '+ PKCS12Path.get())
    if(pkcsPassword.get==''):
        logData('Please enter PKCS12 password before creating CRL and retry', fail=True)
    else:
        ssl_gui.createCRL(PKCS12Path.get(), pkcsPassword.get(), certificateToRevokePath.get(), currentDirectory.get(), dummy)
        logData('CRL Created succesfully at location: '+currentDirectory.get(), success=True)

certificateToRevokePath = tk.StringVar()
certificateToRevoke = tk.Button(frame3, text='Load certificate to revoke', command=getCertificateToRevoke).grid(row=1, column=3, columnspan=2, sticky=W)
createCRLList = tk.Button(frame3, text='Create CRL', command=createCRLSave).grid(row=2, column=3, columnspan=2, sticky=W)

#---------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#------------------------------------------------------------------------ FRAME 5 PGP RECEIVE VERIFICATION -----------------------------------------------------------------
frame5 = tk.Frame(screen, padx=5, pady=5, highlightbackground='black', highlightthickness=3)
frame5.grid(row=0, column=2, padx=10, pady=10, sticky='w')

tk.Label(frame5, text="Verify received files - PGP", font=('Arial',18, 'bold')).grid(row=0,column=0, columnspan=2)
def getSignature1Path():
    pgpSignature1Path.set(askopenfilename())
    logData('PGP signature 1 path set as: '+pgpSignature1Path.get())
def getSignature2Path():
    pgpSignature2Path.set(askopenfilename())
    logData('PGP signature 2 path set as: '+pgpSignature2Path.get())

def verifyPGPSignatures():
    if(returnedDocumentPath.get()==''):
        logData('Document to verify not loaded, please load it now in the current window')
        returnedDocumentPath.set(askopenfilename())
    status = ssl_gui.verify_file_pgp(pgpSignature1Path.get(), returnedDocumentPath.get())
    if(status=='no'):
        logData('Invalid Signature for first fileloaded', fail=True)
    elif(status=='pgp_verified'):
        logData('First signature verified', success=True)
    else:
        logData('Unexpected error')

    status1 = ssl_gui.verify_file_pgp(pgpSignature2Path.get(), returnedDocumentPath.get())
    if(status1=='no'):
        logData('Invalid Signature for second fileloaded', fail=True)
    elif(status1=='pgp_verified'):
        logData('Second signature verified', success=True)
    else:
        logData('Unexpected error')
def getReturnedDocument():
    returnedDocumentPath.set(askopenfilename())

returnedDocumentPath = tk.StringVar()    
pgpSignature1Path = tk.StringVar()
signature1 = tk.Button(frame5, text='Load PGP signature 1', command=getSignature1Path).grid(row=1, column=0, sticky=W)
pgpSignature2Path = tk.StringVar()
signature1 = tk.Button(frame5, text='Load PGP signature 2', command=getSignature2Path).grid(row=1, column=1, sticky=W)
verifySignature = tk.Button(frame5, text='Verify Signatures', command=verifyPGPSignatures).grid(row=3, column=0, columnspan=2)
loadDocument = tk.Button(frame5, text='Load document to verify', command=getReturnedDocument).grid(row=2, column=0, columnspan=2)


screen.mainloop()

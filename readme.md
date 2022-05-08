READ ME

This application was developed on CentOS 8 and will need major changes to function properly on a windows operating system.

This is an application created by Harshal and Summaya for signature verification and signature recording. It is capable of creating certificates 
signed by CA, signing files with the new certificate created. Send the document, document signature and the corresponding x509 certificate over 
network anywhere in a secure encrypted way (AES-128). The application also has a separate application called Receive Documents which is used by 
others to receive your files. The application is also capable of verifying the signatures to a document and sign the verified document with your 
PGP private key. Finally one can verify the PGP signatures to a document.

The library versions used during development and testing are stated below.
- cryptography==36.0.0
- gnupg==2.3.1
- pycryptodome==3.11.0
- pyOpenSSL==21.0.0
- python_gnupg==0.4.8

To install these libraries on your system, run the following commands for each of the library.
- pip install cryptography
- pip install python-gnupg
- pip install pycryptodome
- pip install pyopenssl


-------------------------------------------------- INITAL SETUP BEFORE RUNNING THE APP ----------------------------------------------------------
Before running the application, please change the PGP path to your system's. Without this, the application will throw errors and not run
Modify line number 9 in python file 'ssl_gui.py' to the location of your gnupghome which will be 
gpg = gnupg.GPG(gnupghome='/home/insert_your_username_here/.gnupg')

------------------------------------------------ TO CREATE AN APPLICATION FROM THE SOURCE FILES -------------------------------------------------
Download the package pyinstaller using pip.
Open the .spec files in both directories ('x509_test' and 'server_gui_spec') and change the paths before /src/filename to that of the directory 
the folder is in.
Then open terminal in the folder 'server_gui_test' and run 'pyinstaller server_gui.spec' to create an application for the server side.
Then open terminal in the folder 'x509_test' and run 'pyinstaller gui.spec' in terminal to create an application for the document verification.

-------------------------------------------------- SENDING FILES VIA NETWORK --------------------------------------------------------------------
This is to inform you that now the certificates for client are loaded in automatically and there is no need to use the buttons to import the 
client certificate, client key and CA certificate. If you want to verify if handshake really occurs, you can use the buttons to import other 
certificates which will result in a handshake fail.

-------------------------------------------------- RUNNING THE FILE ON TERMINAL -----------------------------------------------------------------
The file works perfectly when run using terminal.
Below are the instructions to run the application using terminal - 
To run the application on your system, goto x509_test and open a terminal there and run the python file named gui.py by running the command 
'python3 gui.py'. This should start a GUI.
When you need to send the files via a network, goto server_gui_test and launch the file server_gui.py from terminal by running 
'python3 server_gui.py'

------------------------------------------------- RUNNING FILE ON VS CODE -----------------------------------------------------------------------
WARNING - FOR VS CODE USERS - 
If you are trying the code in Visual Studio Code, beware that relative path works differently in VS Code. To run the application using VS code 
without errors you will have to manually set the correct working directory where the python file is stored because VS code by default user the 
directory of the opened folder as current directory. If you dont change the current working directory in VS code the code will throw mulitple 
errors saying file not found. 
An easy fix for this is to open the code and manually change the paths of required documents to an absolute path to where your files are.

NOTE - Please do not move, replace or change the filenames of all files present in 'saved_files' folder when the application is running.

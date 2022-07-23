
# Network Security Application
:warning: This application was developed on CentOS 8 and will need major changes to function properly on a windows operating system.

![image](https://user-images.githubusercontent.com/88155960/180601592-9168c20a-70b4-4f05-8137-2b54d006fb34.png)

Network Interface

![image](https://user-images.githubusercontent.com/88155960/180601604-45690fe9-4686-43b3-83e2-06e975a91e1f.png)


The application is capable of creating certificates signed by CA, signing files with the new certificate created. Send the document, document signature and the corresponding x509 certificate over network anywhere in a secure encrypted way (AES-128). The application also has a separate application called Receive Documents which is used by others to receive your files. The application is also capable of verifying the signatures to a document and sign the verified document with your PGP private key. Finally one can verify the PGP signatures to a document.


## Features

- Sign documents using x509
- Verify x509 signatures
- Send and receive files via a network interface
- Load and create CRL
- Sign document using PGP
- Verify PGP signatures to a document
## Run Locally
The app requires a CentOS 8 operating system, the below libraries are required. The code has been 
developed and tested for the below versions of the libraries on CentOS 8.

- cryptography - 36.0.0
- gnupg - 2.3.1
- pycryptodome - 3.11.0
- pyOpenSSL - 21.0.0
- python_gnupg - 0.4.8

To install these libraries use the below commands.
```bash
  pip install cryptography==36.0.0
  pip install gnupg==2.3.1
  pip install pycryptodome==3.11.0
  pip install pyOpenSSL==21.0.0
  pip install python_gnupg==0.4.8
```
### Initial Setup
Before running the application, please change the PGP path to your 
system's. Without this, the application will throw errors and not 
run. Modify **line number 9** in python file `ssl_gui.py` to the 
location of your gnupghome which will be 
``` bash
gpg = gnupg.GPG(gnupghome='/home/insert_your_username_here/.gnupg')
```

:warning: Please do not move, replace or change the filenames of 
all files present in `saved_files` folder when the application is 
running.

### Running on terminal
The code works perfectly when run using terminal. To run the 
application on your system, goto x509_test and open a terminal 
there and run the python file named `gui.py` by running the command 
`python3 gui.py`. 

This should start a GUI. When you need to send 
the files via a network, goto `server_gui_test` and launch the file 
`server_gui.py` from terminal by running `python3 server_gui.py`

### Running in VSCode
:warning: If you are trying the code in Visual Studio Code, beware 
that relative path works differently in VS Code.

To run the application using VS code without errors you will have 
to manually set the correct working directory where the python 
file is stored because VS code by default uses the directory of 
the opened folder as current directory. If you dont change the 
current working directory in VS code the code will throw mulitple 
errors saying file not found. 

An easy fix for this is to open the 
code and manually change the paths of required documents to an 
absolute path to where your files are.
### Create an application from the source files
Download the package pyinstaller using the below command. 

`pip install pyinstaller`

Open the .spec files in both directories `x509_test` and 
`server_gui_spec` and change the paths before `/src/filename` 
to that of the directory the folder is in. Then open terminal in 
the folder `server_gui_test` and run the command 
`pyinstaller server_gui.spec` to create an application for the 
server side. Then open terminal in the folder `x509_test` and run 
`pyinstaller gui.spec` in terminal to create an application for the document verification.

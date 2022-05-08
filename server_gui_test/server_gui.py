from logging import log
import tkinter as tk
import tkinter.font as font
from tkinter.constants import E, LEFT, W
from tkinter.filedialog import askopenfilename
from tkinter.scrolledtext import ScrolledText
import server

# This function is used for the logs generated in the GUI, we configure it such that by passing in a variable success=True we can set the color of logs to green
# and setting the variable fail=True we can set the color of logs to red. This is used to display warnings and success messages on the log.
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

# Create a main instance for the GUI where all elements will be placed.
screen = tk.Tk()
screen.title('Receive Documents')
screen.geometry('870x280')

receiveDocumentsFrame = tk.Frame(screen, height=100, width=100, padx=5, pady=5)
receiveDocumentsFrame.grid(row=0, column=0)

tk.Label(receiveDocumentsFrame, text="Public IP of TX").grid(row=1,column=0)
publicIPVal = tk.StringVar()
publicIPLabel=tk.Entry(receiveDocumentsFrame, textvariable=publicIPVal).grid(row=1,column=1)

tk.Label(receiveDocumentsFrame, text='Port').grid(row=2, column=0)
portVal = tk.StringVar()
portLabel = tk.Entry(receiveDocumentsFrame, textvariable=portVal).grid(row=2, column=1)

# Selects the path from user and sets it to currentDirectory.
def getcurrentDirectory():
    currentDirectory.set(tk.filedialog.askdirectory())
    logData("Location of saved signature files: "+currentDirectory.get())
def receiveDocuments():
    server.receiveDocuments(publicIPVal.get(), int(portVal.get()), currentDirectory.get())
    logData('Files received successfully!', success=True)

currentDirectory = tk.StringVar(receiveDocumentsFrame)
loadcurrentDirectory = tk.Button(receiveDocumentsFrame, text='Set saving directory', command=getcurrentDirectory).grid(row=6, column=0, columnspan=2, sticky=W)
receive = tk.Button(receiveDocumentsFrame, text='Receive', command=receiveDocuments, height=2).grid(row=7, column=0, columnspan=2, sticky=E)

logFrame = tk.Frame(screen, padx=5, pady=5)
logFrame.grid(row=0, column=1)
tk.Label(logFrame, text='Logs').grid(row=0, column=0)
logs = ScrolledText(logFrame, state='disabled')
logs.configure(font='TkFixedFont', height=15)
logs.grid(row=2, column=0)

screen.mainloop()
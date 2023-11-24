# 127.0.0.1:9999
# only used for test in case of input port for user
import socket
import tkinter
import tkinter.messagebox
import threading
import json
import tkinter.filedialog
import datetime
from tkinter.scrolledtext import ScrolledText
from tkinter import Text, messagebox
import base64

import DES # Import the DES module finished in project 1

IP = ''
PORT = ''
user = ''
listbox1 = ''  # Listbox for displaying online users
show = 1  # Flag to track whether the listbox is open or closed
users = []  # Online users list
chat = '------Group chat-------'  # Default chat room

# Login window
root0 = tkinter.Tk()
root0.geometry("300x150")
root0.title('Login')
root0.resizable(0, 0)
one = tkinter.Label(root0, width=300, height=150)
one.pack()

IP0 = tkinter.StringVar()
IP0.set('')
USER = tkinter.StringVar()
USER.set('')

labelIP = tkinter.Label(root0, text='IP')
labelIP.place(x=20, y=20, width=100, height=40)
entryIP = tkinter.Entry(root0, width=60, textvariable=IP0)
entryIP.place(x=120, y=25, width=100, height=30)

labelUSER = tkinter.Label(root0, text='User name')
labelUSER.place(x=20, y=70, width=100, height=40)
entryUSER = tkinter.Entry(root0, width=60, textvariable=USER)
entryUSER.place(x=120, y=75, width=100, height=30)


def Login(*args):
    global IP, PORT, user
    IP, PORT = entryIP.get().split(':')
    user = entryUSER.get()
    if not user:
        tkinter.messagebox.showwarning('warning', message='user name can not be empty!')
    else:
        root0.destroy()


loginButton = tkinter.Button(root0, text="Login", command=Login)
loginButton.place(x=135, y=110, width=40, height=25)
root0.bind('<Return>', Login)

root0.mainloop()

# Establish connection
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((IP, int(PORT)))
if user:
    s.send(user.encode())  # Send the username
else:
    s.send('user name not exist'.encode())
    user = IP + ':' + PORT

# Chat window
root1 = tkinter.Tk()
root1.geometry("640x480")
root1.title('20372118 project2')
root1.resizable(0, 0)

# ScrolledText for displaying messages
listbox = ScrolledText(root1)
listbox.place(x=5, y=0, width=640, height=320)
listbox.tag_config('tag1', foreground='red')
listbox.insert(tkinter.END, 'Welcome to ZJH20372118 Chat Room with DES!', 'tag1')

INPUT = tkinter.StringVar()
INPUT.set('')

# Text input area
entryIuput = Text(root1, width=120)
entryIuput.place(x=5, y=320, width=640, height=85)

# Online users listbox
listbox1 = tkinter.Listbox(root1)
listbox1.place(x=510, y=0, width=130, height=320)

encryption_key = None


def send(*args):
    """
    Function to send messages
    """
    global encryption_key  # Reference the global encryption key variable

    if encryption_key is None:  # If the key has not been set yet
        key = tkinter.simpledialog.askstring("Input", "Enter encryption key for your message:")
        if key is not None:  # Ensure the user entered a key
            encryption_key = key  # Save the user-entered key

    if encryption_key is not None:  # If a key is available
        message = entryIuput.get("1.0", "end-1c")  # Get the user-input message
        cipher_text = DES.all_des_encrypt(message, encryption_key)
        encrypted_message = DES.bit_str(cipher_text)  # Encrypt the message using DES

        # Build the format of the message to be sent (encrypted message + user information + recipient)
        message_to_send = encrypted_message + '~' + user + '~' + chat
        s.send(message_to_send.encode())  # Send the encrypted message
        entryIuput.delete("1.0", tkinter.END)  # Clear the input box


# Send button
sendButton = tkinter.Button(root1, text="Send", command=send)
sendButton.place(x=510, y=320, width=130, height=40)
root1.bind('<Return>', send)


def sendFile(*args):
    """
    Function to send files
    """
    file_path = tkinter.filedialog.askopenfilename()
    if file_path:
        with open(file_path, 'rb') as file:
            file_data = file.read()
        encoded_data = base64.b64encode(file_data).decode('utf-8')
        message = f'File~{encoded_data}~{user}~{chat}'
        s.send(message.encode())

        # Display a message in the sender's UI
        sent_message = f'\nFile sent successfully at {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'
        listbox.insert(tkinter.END, sent_message + '\n')

sendFileButton = tkinter.Button(root1, text="Send File", command=sendFile)
sendFileButton.place(x=510, y=360, width=130, height=40)


def decryptMessages():
    """
    Function to decrypt messages
    """
    key = tkinter.simpledialog.askstring("Input", "Enter decryption key:")
    if key is not None:  # 如果用户输入了密钥
        decrypt_with_key(key)


def decrypt_with_key(key):
    messages = listbox.get("1.0", "end-1c")  # Get all messages from the chat window
    encrypted_messages = messages.split("\n")  # Split messages into individual lines

    for index, msg in enumerate(encrypted_messages[::-1]):
        if "Welcome to ZJH20372118 Chat Room with DES!" not in msg:  # If the message is not the welcome message
            encrypted_data = msg.split(":", 1)[1].strip()
            decrypted_text = DES.bit_str(DES.all_des_decrypt(encrypted_data, key))
            # Display the decrypted message in the chat window, excluding messages sent by the user
            if f"{user}~{chat}" not in msg:
                decrypted_message = f"\nDecrypted Message: {decrypted_text}"
                listbox.insert(tkinter.END, decrypted_message)
                break  # Decrypt only the latest message and then exit the loop


decryptButton = tkinter.Button(root1, text="Decrypt Messages", command=decryptMessages)
decryptButton.place(x=240, y=410, width=150, height=30)


def receive():
    """
    Function to receive messages and files
    """
    global uses
    while True:
        data = s.recv(1024)
        data = data.decode()
        try:
            # Handle user list updates
            uses = json.loads(data)
            listbox1.delete(0, tkinter.END)
            listbox1.insert(tkinter.END, "Users in this room")
            listbox1.insert(tkinter.END, "------Group chat-------")
            for x in range(len(uses)):
                listbox1.insert(tkinter.END, uses[x])
            users.append('------Group chat-------')
        except:
            if data.startswith('File~'):
                # Handle file reception
                file_data = data.split('~', 3)
                sender = file_data[2]
                file_content = base64.b64decode(file_data[1])
                file_name = f"received_file_{sender}_{file_data[3]}"
                with open(file_name, 'wb') as file:
                    file.write(file_content)
                print(f"File received: {file_name}")
                # Display a message in the receiver's UI
                received_message = f'File received from {sender}\nTime: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'
                listbox.insert(tkinter.END, received_message + '\n')
                messagebox.showinfo("File Received", f"File received: {file_name}")
            else:
                # Handle regular text messages
                data = data.split('~')
                message = data[0]
                userName = data[1]
                chatwith = data[2]
                message = '\n' + message
                # Display messages based on the chat context
                if chatwith == '------Group chat-------':  # Group chat
                    if userName == user:
                        listbox.insert(tkinter.END, message)
                    else:
                        listbox.insert(tkinter.END, message)
                elif userName == user or chatwith == user:  # Private chat
                    if userName == user:
                        listbox.tag_config('tag2', foreground='red')
                        listbox.insert(tkinter.END, message, 'tag2')
                    else:
                        listbox.tag_config('tag3', foreground='green')
                        listbox.insert(tkinter.END, message, 'tag3')

                listbox.see(tkinter.END)


# Create a thread to receive messages
r = threading.Thread(target=receive)
r.start()

# Start the GUI main loop
root1.mainloop()
s.close()

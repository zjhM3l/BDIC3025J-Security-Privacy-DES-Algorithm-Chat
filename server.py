import socket
import threading
import queue
import json
import os
import os.path
import sys
import base64

# Server IP and Port
IP = '127.0.0.1'
PORT = 9999

# Global variables
messages = queue.Queue()
users = []  # 0:userName 1:connection
lock = threading.Lock()


def onlines():
    """
    Function to get a list of currently online users.
    """
    online = []
    for i in range(len(users)):
        online.append(users[i][0])
    return online


class ChatServer(threading.Thread):
    global users, que, lock

    def __init__(self):
        """
        Constructor for ChatServer class.
        """
        threading.Thread.__init__(self)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        os.chdir(sys.path[0])

    def receive(self, conn, addr):
        """
        Function to handle receiving messages from clients.
        Accept the username from the client. If the username is empty, use the user's IP and port as the username.
        If duplicate usernames occur, append the suffix '2', '3', '4', and so on to the duplicate usernames
        """
        user = conn.recv(1024)
        user = user.decode()
        if user == 'user name not exist':
            user = addr[0] + ':' + str(addr[1])
        tag = 1
        temp = user
        for i in range(len(users)):  # Check for duplicates, then add numbers after duplicate usernames
            if users[i][0] == user:
                tag = tag + 1
                user = temp + str(tag)
        users.append((user, conn))
        USERS = onlines()
        self.Load(USERS, addr)
        # After obtaining the username, continuously receive messages from the client side (i.e., chat content),
        # and close the connection after completion
        try:
            while True:
                data = conn.recv(1024).decode()
                if data.startswith('File~'):
                    file_data = data.split('~', 2)
                    file_content = base64.b64decode(file_data[1])
                    file_name = f"received_file_{file_data[2]}"
                    with open(file_name, 'wb') as file:
                        file.write(file_content)
                    print(f"File received: {file_name}")
                else:
                    message = user + ':' + data
                    self.Load(message, addr)
            conn.close()
        # If a user disconnects, remove that user from the user list, and then update the user list
        except:
            j = 0  # User has disconnected
            for man in users:
                if man[0] == user:
                    users.pop(j)  # Server removes the logged-out user
                    break
                j = j + 1

            USERS = onlines()
            self.Load(USERS, addr)
            conn.close()

    def Load(self, data, addr):
        """
        Function to load data (address and data to be sent) into the messages queue.
        """
        lock.acquire()
        try:
            messages.put((addr, data))
        finally:
            lock.release()

    def sendData(self):
        """
        Function to send data from the messages queue to clients.
        """
        while True:
            if not messages.empty():
                message = messages.get()
                if isinstance(message[1], str):
                    for i in range(len(users)):
                        data = ' ' + message[1]
                        users[i][1].send(data.encode())
                        print(data)
                        print('\n')

                if isinstance(message[1], list):
                    data = json.dumps(message[1])
                    for i in range(len(users)):
                        try:
                            users[i][1].send(data.encode())
                        except:
                            pass

    def send_file(self, file_path, receiver, user, addr):
        """
        Function to send a file to a specific user.
        """
        lock.acquire()
        try:
            with open(file_path, 'rb') as file:
                file_data = file.read()
            encoded_data = base64.b64encode(file_data).decode('utf-8')
            message = f'File~{encoded_data}~{user}~{receiver}'
            self.Load(message, addr)
        finally:
            lock.release()

    def run(self):
        """
        Run function for the ChatServer thread.
        """
        self.s.bind((IP, PORT))
        self.s.listen(5)
        q = threading.Thread(target=self.sendData)
        q.start()
        while True:
            conn, addr = self.s.accept()
            t = threading.Thread(target=self.receive, args=(conn, addr))
            t.start()
        self.s.close()


if __name__ == '__main__':
    cserver = ChatServer()
    cserver.start()

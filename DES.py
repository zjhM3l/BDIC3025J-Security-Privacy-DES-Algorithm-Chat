import tkinter as tk
from tkinter import Text, filedialog, Menu
from config import *
import os

# Global variables for storing cipher text and key and others
cipher_text = ""
key = ""
result_text = None
root = None


def read_file(filename):
    """
    filename : The name of the file to open.
    return : The content of the file as a string.
    """
    try:
        fp = open(filename, "r", encoding='utf-8')
        message = fp.read()
        fp.close()
        return message
    except:
        print("Open file error!")


def write_file(file_name, message):
    """
    file_name : The name of the file to write.
    message : The content to write into the file.
    """
    try:
        with open(file_name, 'w', encoding='utf-8') as fp:
            fp.write(message)
    except:
        print("Write file error!")


def str_bit(message):
    """
    message : Input string.
    return : Binary bit string representation of the input string.
    """
    bits = ""
    for i in message:
        asc2i = bin(ord(i))[2:]  # Convert ASCII to binary
        # Ensure each character is represented by 8 bits
        for j in range(8 - len(asc2i)):
            asc2i = '0' + asc2i
        bits += asc2i
    return bits


def bit_str(bits):
    """
    bits : Binary bit string (length should be a multiple of 8).
    returns : Corresponding character string.
    """
    temp = ""
    for i in range(len(bits) // 8):
        temp += chr(int(bits[i * 8:(i + 1) * 8], 2))
    return temp


def process_key(key):
    """
    key : Input key string.
    return : 64-bit binary key sequence (using even parity).
    """
    key_bits = ""
    for i in key:
        count = 0
        asc2i = bin(ord(i))[2:]
        # Ensure each ASCII character is represented by 7 bits with the 8th bit as a parity bit
        for j in asc2i:
            count += int(j)
        if count % 2 == 0:
            asc2i += '0'
        else:
            asc2i += '1'

        for j in range(7 - len(asc2i)):
            asc2i = '0' + asc2i
        key_bits += asc2i
    if len(key_bits) > 64:
        return key_bits[0:64]
    else:
        for i in range(64 - len(key_bits)):
            key_bits += '0'
        return key_bits


def process_key2(key):
    """
    key : Input key string.
    return : 64-bit binary key sequence with direct character padding to 8 bits.
    """
    bin_key = str_bit(key)
    ans = len(bin_key)
    if ans < 64:
        for i in range(64 - ans):  # Pad with zeros if it's less than 64 bits
            bin_key += '0'
    return bin_key


def divide(bits, bit):
    """
    bits : Split the binary bit string into groups of 'bit' size.
    return : List of binary bit strings split according to the given 'bit' size.
    """
    m = len(bits) // bit
    N = ["" for i in range(m)]
    for i in range(m):
        N[i] = bits[i * bit:(i + 1) * bit]

    if len(bits) % bit != 0:
        N.append(bits[m * bit:])
        for i in range(bit - len(N[m])):
            N[m] += '0'
    return N


def IP_change(bits):
    """
    bits: A group of 64-bit binary bit strings.
    return: 64-bit binary bit string after initial permutation (IP).
    """
    ip_str = ""
    for i in IP:
        ip_str = ip_str + bits[i - 1]
    return ip_str


def PC_1_change(key):
    """
    key: 64-bit effective key in binary bit string.
    return: 56-bit binary bit string after key permutation (PC-1).
    """
    pc_1 = ""
    for i in PC_1:
        pc_1 = pc_1 + key[i - 1]
    return pc_1


def key_leftshift(key_str, num):
    """
    key_str : 28-bit binary bit string after PC-1 permutation.
    return : 28-bit binary bit string after left shifting by 'num' bits.
    """
    left = key_str[num:28]
    left += key_str[0:num]
    return left


def PC_2_change(key):
    """
    key : 56-bit key after key shift.
    return : 48-bit binary bit string after key permutation (PC-2).
    """
    pc_2 = ""
    for i in PC_2:
        pc_2 = pc_2 + key[i - 1]
    return pc_2


def generate_key(key):
    """
    key : 64-bit binary key sequence.
    return : List of 16 round keys, each 48-bit binary bit string, in order from 1 to 16.
    """
    key_list = ["" for i in range(16)]
    key = PC_1_change(key)  # Permute using PC_1
    key_left = key[0:28]
    key_right = key[28:]
    for i in range(len(SHIFT)):
        key_left = key_leftshift(key_left, SHIFT[i])
        key_right = key_leftshift(key_right, SHIFT[i])
        key_i = PC_2_change(key_left + key_right)  # Permute using PC_2
        key_list[i] = key_i
    return key_list


def E_change(bits):
    """
    bits : 32-bit binary bit string.
    return : 48-bit binary bit string after expansion permutation (E).
    """
    e = ""
    for i in E:
        e = e + bits[i - 1]
    return e


def xor(bits, ki):
    """
    bits : 48-bit binary bit string or 32-bit binary output of the F function.
    ki : 48-bit binary key sequence or 32-bit binary Li.
    return : 48-bit or 32-bit binary bit string resulting from the XOR operation between bits and ki.
    """
    bits_xor = ""
    for i in range(len(bits)):
        if bits[i] == ki[i]:
            bits_xor += '0'
        else:
            bits_xor += '1'
    return bits_xor


def s(bits, i):
    """
    bits : 6-bit binary bit string.
    i : Index of the S-box to be used.
    return : 4-bit binary bit string.
    """
    row = int(bits[0] + bits[5], 2)
    col = int(bits[1:5], 2)
    num = bin(S[i - 1][row * 16 + col])[2:]
    for i in range(4 - len(num)):
        num = '0' + num
    return num


def S_change(bits):
    """
    bits : 48-bit binary bit string after XOR.
    return : 32-bit binary bit string after substitution through S-boxes.
    """
    s_change = ""
    for i in range(8):
        temp = bits[i * 6:(i + 1) * 6]
        temp = s(temp, i + 1)
        s_change += temp
    return s_change


def P_change(bits):
    """
    bits : 32-bit binary bit string after S-box substitution.
    returns : 32-bit binary output sequence after permutation (P).
    """
    p = ""
    for i in P:
        p = p + bits[i - 1]
    return p


def F(bits, ki):
    """
    bits : 32-bit binary Ri input.
    ki : 48-bit i-th round key.
    return : 32-bit binary output sequence from the F function.
    """
    bits = xor(E_change(bits), ki)
    bits = P_change(S_change(bits))
    return bits


def IP_RE_change(bits):
    """
    bits : 64-bit binary bit string after 16 rounds of iteration.
    returns : 64-bit binary ciphertext bit string after inverse initial permutation (IP-RE).
    """
    ip_re = ""
    for i in IP_RE:
        ip_re += bits[i - 1]
    return ip_re
    return ip_re


def des_encrypt(bits, key):
    """
    bits : 64-bit binary plaintext string.
    key : 64-bit binary key.
    return : 64-bit binary ciphertext sequence after encryption.
    """
    bits = IP_change(bits)
    # Split into two 32-bit parts
    L = bits[0:32]
    R = bits[32:]
    key_list = generate_key(key)  # 16 keys
    for i in range(16):
        L_next = R
        R = xor(L, F(R, key_list[i]))
        L = L_next
    result = IP_RE_change(R + L)
    return result


def des_decrypt(bits, key):
    """
    bits : 64-bit binary encrypted string.
    key : 64-bit binary key.
    return : 64-bit binary plaintext sequence after decryption.
    """
    bits = IP_change(bits)
    # Split into two 32-bit parts
    L = bits[0:32]
    R = bits[32:]
    key_list = generate_key(key)  # 16 keys
    for i in range(16):
        L_next = R
        R = xor(L, F(R, key_list[15 - i]))
        L = L_next
    result = IP_RE_change(R + L)
    return result


# Main function for DES encryption and decryption
def all_des_encrypt(message, key):
    """
    message : Input plaintext string.
    key : Input encryption key.
    returns : Encrypted ciphertext as a binary bit string.
    """
    message = str_bit(message)  # Convert the input message to binary bit string
    key = process_key(key)  # Process the input key

    mess_div = divide(message, 64)  # Divide the message into 64-bit blocks
    result = ""

    # Encrypt each block using DES
    for i in mess_div:
        result += des_encrypt(i, key)  # Perform DES encryption on each block

    return result


def all_des_decrypt(message, key):
    """
    message : Input ciphertext string in binary format.
    key : Input key string.
    returns : Decrypted plaintext in binary format.
    """
    message = str_bit(message)
    key = process_key(key)
    mess_div = divide(message, 64)
    result = ""
    for i in mess_div:
        result += des_decrypt(i, key)
    return result


# Function to open a file dialog for selecting a file to encrypt
def encrypt_file():
    file_path = filedialog.askopenfilename(title="Select a file to encrypt")
    if file_path:
        key_window = tk.Toplevel(root)
        key_window.title("Enter Key")

        key_label = tk.Label(key_window, text="Enter the key:")
        key_label.pack()

        key_entry = tk.Entry(key_window)
        key_entry.pack()

        encrypt_button = tk.Button(key_window, text="Encrypt",
                                   command=lambda: perform_file_encryption(file_path, key_entry.get()))
        encrypt_button.pack()


# Function to open a file dialog for selecting a file to decrypt
def decrypt_file():
    file_path = filedialog.askopenfilename(title="Select a file to decrypt")
    if file_path:
        key_window = tk.Toplevel(root)
        key_window.title("Enter Key")

        key_label = tk.Label(key_window, text="Enter the key:")
        key_label.pack()

        key_entry = tk.Entry(key_window)
        key_entry.pack()

        decrypt_button = tk.Button(key_window, text="Decrypt",
                                   command=lambda: perform_file_decryption(file_path, key_entry.get()))
        decrypt_button.pack()


# Function to perform file encryption
def perform_file_encryption(file_path, key):
    try:
        message = read_file(file_path)
        cipher_text = all_des_encrypt(message, key)
        cipher_result = bit_str(cipher_text)

        # Get the base name of the original file (excluding path)
        file_name = os.path.basename(file_path)

        # Build the output file name with "_encrypt" suffix
        output_file = file_name.split('.')[0] + "_encrypt.txt"

        # Write the encrypted content to the new output file
        write_file(output_file, cipher_result)

        # Display the result message in the result_text widget
        result_text.config(state="normal")
        result_text.delete(1.0, "end")
        result_text.insert("end", f"File encryption successful. Encrypted file: {os.path.abspath(output_file)}")
        result_text.config(state="disabled")
    except Exception as e:
        result_text.config(state="normal")
        result_text.delete(1.0, "end")
        result_text.insert("end", f"File encryption failed: {str(e)}")
        result_text.config(state="disabled")


# Function to perform file decryption
def perform_file_decryption(file_path, key):
    try:
        cipher_text = read_file(file_path)
        message = all_des_decrypt(cipher_text, key)
        message_result = bit_str(message)

        # Get the base name of the original file (excluding path)
        file_name = os.path.basename(file_path)

        # Build the output file name with "_decrypt" suffix
        output_file = file_name.split('.')[0] + "_decrypt.txt"

        write_file(output_file, message_result)  # Use the new output file name

        result_text.config(state="normal")
        result_text.delete(1.0, "end")
        result_text.insert("end", f"File decryption successful. Decrypted file: {os.path.abspath(output_file)}")
        result_text.config(state="disabled")
    except Exception as e:
        result_text.config(state="normal")
        result_text.delete(1.0, "end")
        result_text.insert("end", f"File decryption failed: {str(e)}")
        result_text.config(state="disabled")


# Function to perform encryption or decryption operation
def perform_operation(operation):
    global cipher_text, key
    if operation == "Encrypt":
        # Get the input message and key from the GUI
        message = text_input.get("1.0", "end-1c")
        key = key_input.get()
        # Execute the encryption operation and store the result in cipher_text
        cipher_text = all_des_encrypt(message, key)
        result_str = bit_str(cipher_text)
    elif operation == "Decrypt":
        # Get the input ciphertext and key from the GUI
        message = text_input.get("1.0", "end-1c")
        print("message is ", message)
        key = key_input.get()
        print("key is ", key)
        # Execute the decryption operation and store the result in cipher_text
        cipher_text = all_des_decrypt(message, key)
        print("cipher text is", cipher_text)
        result_str = bit_str(cipher_text)
        print("result to be seen is", result_str)

    # Clear the result_text widget
    result_text.config(state="normal")
    result_text.delete(1.0, "end")

    # Insert the result into the result_text widget
    result_text.insert("end", f"{operation} successful:\n{result_str}\n")

    # Disable editing of the result_text widget
    result_text.config(state="disabled")


# Function to open a new window for encryption or decryption
def open_operation_window(operation):
    operation_window = tk.Toplevel(root)
    operation_window.title(f"{operation} Operation")

    info_label = tk.Label(operation_window, text=f"Enter the {operation} text:")
    info_label.pack()

    global text_input, key_input
    text_input = Text(operation_window, height=5, width=40)
    text_input.pack()

    key_label = tk.Label(operation_window, text="Enter the key:")
    key_label.pack()

    key_input = tk.Entry(operation_window)
    key_input.pack()

    perform_button = tk.Button(operation_window, text=f"Perform {operation}", command=lambda: perform_operation(operation))
    perform_button.pack()


def create_des_gui():
    global result_text, root  # Make result_text and root global

    # Create the main GUI window
    root = tk.Tk()
    root.title("DES Encryption and Decryption")

    # Create a text widget for displaying results with initial state as "disabled"
    result_text = Text(root, height=10, width=40, state="disabled")
    result_text.pack()

    # Create a menu bar
    menubar = Menu(root)
    root.config(menu=menubar)

    # Create an "Operations" menu in the menu bar
    operation_menu = Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Operations", menu=operation_menu)

    # Add "Encrypt" and "Decrypt" options to the "Operations" menu
    operation_menu.add_command(label="Encrypt", command=lambda: open_operation_window("Encrypt"))
    operation_menu.add_command(label="Decrypt", command=lambda: open_operation_window("Decrypt"))

    # Add a separator line in the "Operations" menu
    operation_menu.add_separator()

    # Add "Encrypt File" and "Decrypt File" options to the "Operations" menu
    operation_menu.add_command(label="Encrypt File", command=encrypt_file)
    operation_menu.add_command(label="Decrypt File", command=decrypt_file)

    # Create an "Exit" button for quitting the application
    exit_button = tk.Button(root, text="Exit", command=root.quit)
    exit_button.pack()

    return result_text, root  # Return the result_text and root


if __name__ == "__main__":
    result_text, root = create_des_gui()  # get returned value result_text and root

    # Start the main GUI loop to display the application
    root.mainloop()






"""
    The code defines a cryptographic system for encryption and decryption, including key generation,
    message exchange between client and server using sockets, and a text-based user interface for
    sending and receiving encrypted messages.
"""
import curses
from curses import wrapper
from curses.textpad import Textbox, rectangle
import numpy as np
import socket
import selectors
import types
import sys
import time
import hashlib

# A small constant used in key generation
epsilon = 1


def is_prime(x):
    """
    Check if a number is prime.

    Parameters:
    x (int): The number to check for primality.

    Returns:
    bool: True if the number is prime, False otherwise.
    """
    for i in range(2, x // 2 + 1):
        if x % i == 0:
            return False
    return True


def distribution(n, p):
    """
    Generate a discrete Gaussian-like noise sample.

    Parameters:
    n (int): Security parameter defining the system's size.
    p (int): Prime modulus used in encryption.

    Returns:
    int: A discrete noise sample mod p.
    """
    alpha_n = 1.0 / (np.sqrt(n) * np.log2(n) *
                     np.log2(n))  # Noise scaling factor
    normal_sample = np.random.normal(
        0.0, alpha_n / np.sqrt(2.0 * np.pi))  # Generate normal noise
    discrete_normal_sample = normal_sample % 1.0  # Convert to discrete values
    distribution_sample = np.rint(
        discrete_normal_sample * p) % p  # Map to modulo p
    return distribution_sample


class CryptoSystem:
    """
    A simple lattice-based encryption system with key generation, encryption, and decryption.
    """

    def __init__(self, n: int):
        """
        Initialize the cryptographic system with a given security parameter.

        Parameters:
        n (int): Security parameter defining the size of keys and encryption parameters.
        """
        self.n = n
        self.n = 32  # Hardcoded security parameter

    def gen_keys(self):
        """
        Generate public and private keys.
        """
        self.p = 0
        prime_list = []
        # Generate a list of prime numbers in the range [n^2, 2*n^2]
        for i in np.arange(self.n * self.n, 2 * self.n * self.n):
            if is_prime(i):
                prime_list.append(i)
        self.p = np.random.choice(prime_list)  # Choose a prime modulus
        self.m = (1 + epsilon) * (self.n + 1) * \
            int(np.log2(self.p))  # Compute matrix size
        self.gen_pvt_key()  # Generate private key
        self.gen_pub_key()  # Generate public key

    def gen_pvt_key(self):
        """
        Generate a private key.
        """
        self.pvt_key = np.random.choice(
            self.p, self.n)  # Random private key from Z_p^n
        return self.pvt_key

    def gen_pub_key(self):
        """
        Generate a public key using the private key.
        """
        a = np.empty((self.m, self.n), dtype=np.int64)
        for i in np.arange(self.m):
            # Generate random matrix A
            a[i][:] = np.random.choice(self.p, self.n)

        e = np.array([distribution(self.n, self.p)
                      for i in range(self.m)])  # Generate error vector
        # Compute b = A * sk + e mod p
        b = (np.dot(a, self.pvt_key) + e) % self.p

        self.b2 = np.asarray(b)  # Store b values
        self.pub_key = (a, b)  # Public key is (A, b)
        return self.pub_key

    def encrypt_one_bit(self, bit):
        """
        Encrypt a single bit using the public key.

        Parameters:
        bit (int): The bit (0 or 1) to encrypt.

        Returns:
        np.ndarray: The encrypted bit represented as a vector.
        """
        choose_i = np.random.choice(
            2, self.m)  # Choose a random subset of rows
        a_subset = self.pub_key[0][choose_i == 1, :]
        b_subset = self.pub_key[1][choose_i == 1]

        a_sum = np.sum(a_subset, axis=0) % self.p  # Sum selected A rows
        b_sum = np.sum(b_subset, axis=0) % self.p  # Sum selected b values

        if bit == 1:
            # Encode bit by shifting b
            b_sum = (b_sum + self.p // 2) % self.p

        enc = np.zeros(self.n + 1, dtype=np.int16)
        enc[:self.n] = a_sum  # Store sum of A
        enc[self.n] = b_sum  # Store sum of b

        return enc

    def decrypt_one_pair(self, enc):
        """
        Decrypt a single encrypted bit.

        Parameters:
        enc (np.ndarray): The encrypted bit vector.

        Returns:
        int: The decrypted bit (0 or 1).
        """
        x = (enc[self.n] - (np.dot(enc[:self.n], self.pvt_key) %
                            self.p) + self.p) % self.p

        if np.abs(x - self.p // 2) > min(x, self.p - x):
            return 0
        return 1

    def encrypt_bytes(self, buf):
        """
        Encrypt a byte array.

        Parameters:
        buf (bytes): The data to encrypt.

        Returns:
        bytes: The encrypted byte sequence.
        """
        enc_bytes = bytes()
        for byte in buf:
            for bit_ind in np.arange(8):
                bit = (byte >> bit_ind) & 1  # Extract bit from byte
                enc_bit = self.encrypt_one_bit(bit)  # Encrypt bit
                enc_bytes += enc_bit.tobytes()  # Append encrypted bit
        return enc_bytes

    def decrypt_bytes(self, buf):
        """
        Decrypt an encrypted byte array.

        Parameters:
        buf (bytes): The encrypted data.

        Returns:
        bytes: The decrypted plaintext data.
        """
        dec_bytes = bytes()
        for enc_byte_start in np.arange(0, len(buf), 8 * 66):
            dec_byte = 0
            for bit_ind in np.arange(8):
                enc_bit_start = enc_byte_start + bit_ind * 66
                enc_bit = buf[enc_bit_start: enc_bit_start + 66]
                dec_bit = self.decrypt_one_pair(
                    np.frombuffer(enc_bit, dtype=np.int16))
                # Reconstruct decrypted byte
                dec_byte |= (dec_bit << bit_ind)
            dec_bytes += bytes((dec_byte,))
        return dec_bytes

    def debug(self):
        """
        Print debugging information about the cryptosystem.
        """
        print("====================================")
        print("n =", self.n)
        print("p =", self.p)
        print("m =", self.m)
        print("Private key:", self.pvt_key)
        print("Public key A:", self.pub_key[0])
        print("Public key B:", self.pub_key[1])
        print("====================================")


def send_bytes(conn, mesg):
    """
    Sends a message over a socket connection in chunks until fully transmitted.

    Parameters:
        conn: The socket connection object.
        mesg: The message to send, in bytes.
    """
    while mesg:
        transmitted = conn.send(mesg)  # Send a portion of the message
        mesg = mesg[transmitted:]  # Remove the transmitted portion


def send_pub_key(conn, CS):
    """
    Sends the public key components (p, A, B) over a socket connection.

    Parameters:
        conn: The socket connection object.
        CS: The cryptographic system object containing the public key.
    """
    # Convert public key components to bytes
    send_list = bytes(CS.p.tobytes())  # Send p (8 bytes)
    send_list += np.asarray(CS.pub_key[0]).tobytes()  # Send A (168960 bytes)
    # Send B (5280 bytes)
    send_list += np.asarray(CS.pub_key[1]).astype('<i8').tobytes()

    # Transmit the public key data in chunks
    while send_list:
        transmitted = conn.send(send_list)
        send_list = send_list[transmitted:]


def recv_pub_key(conn, CS):
    """
    Receives the public key components (p, A, B) from a socket connection.

    Parameters:
        conn: The socket connection object.
        CS: The cryptographic system object where the public key will be stored.
    """
    # Receive p (8 bytes)
    send_list = conn.recv(8)
    p = np.frombuffer(send_list, dtype=np.int64)
    CS.p = p[0]
    CS.m = (1 + epsilon) * (CS.n + 1) * int(np.log2(CS.p))  # Recalculate m

    # Receive A (168960 bytes)
    send_list = b''
    time.sleep(1)  # Allow time for transmission
    for i in range(168960):
        temp = conn.recv(1)
        send_list += temp

    pub_key_total = np.frombuffer(send_list, dtype=np.int64)

    # Convert received data into matrix A
    A = []
    l = 0
    while l < len(pub_key_total):
        A.append(pub_key_total[l:l+32])
        l += 32
    A = np.asarray(A)

    # Receive B (5280 bytes)
    send_list = b''
    time.sleep(1)  # Allow time for transmission
    while len(send_list) < 5280:
        temp = conn.recv(5280 - len(send_list))
        if not temp:
            raise ConnectionError("Socket connection lost")
        send_list += temp

    B = np.frombuffer(send_list, dtype='<i8')

    CS.pub_key = (A, B)  # Store received public key


def send_pvt_key(conn, CS):
    """
    Sends the private key over a socket connection.

    Parameters:
        conn: The socket connection object.
        CS: The cryptographic system object containing the private key.
    """
    send_list = bytes(CS.p.tobytes())  # Send p (8 bytes)
    send_list += bytes(CS.pvt_key.tobytes())  # Send private key (256 bytes)

    # Transmit the private key data in chunks
    while send_list:
        transmitted = conn.send(send_list)
        send_list = send_list[transmitted:]


def recv_pvt_key(conn, CS):
    """
    Receives the private key from a socket connection.

    Parameters:
        conn: The socket connection object.
        CS: The cryptographic system object where the private key will be stored.
    """
    # Receive p (8 bytes)
    send_list = conn.recv(8)
    p = np.frombuffer(send_list, dtype=np.int64)
    CS.p = p[0]
    CS.m = (1 + epsilon) * (CS.n + 1) * int(np.log2(CS.p))  # Recalculate m

    # Receive private key (256 bytes)
    send_list = b''
    time.sleep(1)  # Allow time for transmission
    while len(send_list) < 256:
        temp = conn.recv(256 - len(send_list))
        if not temp:
            raise ConnectionError("Socket connection lost")
        send_list += temp

    pvt_key = np.frombuffer(send_list, dtype=np.int64)
    CS.pvt_key = pvt_key  # Store received private key


def trial_test(CS):
    """
    Tests the encryption and decryption functions by encrypting and decrypting a sample text.

    Parameters:
        CS: The cryptographic system object used for encryption and decryption.
    """
    print("============================================")
    print("Testing Encryption and Decryption System")

    # Define test message
    text = 'Hello'
    b_text = bytes(text, 'utf-8')
    print("Text:", text)
    print("In Bytes:", b_text)

    # Encrypt message
    b_text = CS.encrypt_bytes(b_text)
    l1 = len(b_text).to_bytes(8)
    print("Length of Encrypted Text:", len(b_text), "=", l1)

    # Decrypt message
    b_text = CS.decrypt_bytes(b_text)
    print("Decrypted Text In Bytes:", b_text)
    print("Decrypted Text:", b_text.decode('utf-8'))
    print("============================================")


# Define host and port for communication
HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

# Generate cryptographic keys for encryption and authentication

# For client public key
CS_encrypt_obj = CryptoSystem(32)  # Initialize encryption system for client
CS_encrypt_obj.gen_keys()  # Generate public and private keys

# For server public key
CS_decrypt_obj = CryptoSystem(32)  # Initialize encryption system for server
CS_decrypt_obj.gen_keys()  # Generate public and private keys

# For server authentication
# Initialize authentication encryption for server
A_CS_encrypt = CryptoSystem(32)
A_CS_encrypt.gen_keys()  # Generate authentication keys

# For client authentication
# Initialize authentication encryption for client
A_CS_decrypt = CryptoSystem(32)
A_CS_decrypt.gen_keys()  # Generate authentication keys

# Initialize and bind the socket
# Create a TCP socket
lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
while True:
    try:
        # Bind the socket to the specified host and port
        lsock.bind((HOST, PORT))
        break  # Exit loop if binding is successful
    except OSError as e:
        print(f"Bind failed: {e}. Retrying in 2 seconds...")
        time.sleep(2)  # Wait before retrying

lsock.listen()  # Start listening for incoming connections
print(f"Listening on {(HOST, PORT)}")

# Accept incoming client connection
conn, addr = lsock.accept()  # Accept a new connection

# Declare selector for monitoring I/O events
sel = selectors.DefaultSelector()  # Create a selector object

# Register the connection socket for monitoring
# This will allow the program to react to incoming data
# "inb" stores received data, "outb" stores outgoing data
dataType1 = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
# Register connection for read events
sel.register(conn, selectors.EVENT_READ, data=dataType1)

# Perform key exchange between client and server
send_pub_key(conn, CS_decrypt_obj)  # Send server's public key to client
recv_pub_key(conn, CS_encrypt_obj)  # Receive client's public key
send_pvt_key(conn, A_CS_encrypt)  # Send server's private authentication key
recv_pvt_key(conn, A_CS_decrypt)  # Receive client's private authentication key

# Set the connection to non-blocking mode
conn.setblocking(False)  # Enables asynchronous communication


def console_textpad(stdscr):
    curses.init_pair(1, 2, 0)
    curses.init_pair(2, 3, 0)
    curses.halfdelay(1)
    curses.curs_set(0)
    stdscr.addstr(0, 0, "")
    rows, cols = stdscr.getmaxyx()
    disp_pad = curses.newpad(1024, cols - 2)
    rectangle(stdscr, 0, 0, rows - 4, cols - 1)
    stdscr.refresh()
    msg_type_names = [" Client ", " Server "]
    messages = []
    msg_types = []

    text_pad_y = rows - 3
    text_pad_xl = 1
    text_pad_wl = cols - 6
    text_pad_HIDE_WORDS = False
    text_pad_wl += text_pad_xl + 2
    text_pad_s = ''
    text_pad_cp = 0
    rectangle(stdscr, text_pad_y, text_pad_xl, text_pad_y + 2, text_pad_wl)
    stdscr.addstr(text_pad_y + 1, text_pad_xl + 1, '')

    curr_row = 0
    msg_width = cols-6
    disp_pad.addstr('\n ')
    while True:
        if len(messages) > 0:
            for i in range(0, len(messages[0]), msg_width):
                disp_pad.addstr(
                    messages[0][i:min(len(messages[0]), i+msg_width)] + '\n ')

            msg_rect_y2, _ = disp_pad.getyx()
            msg_rect_y1 = msg_rect_y2 - 1 - \
                (len(messages[0])+msg_width)//msg_width
            msg_rect_y1 = max(0, msg_rect_y1)
            disp_pad.addstr('\n\n ')
            stored_y, stored_x = disp_pad.getyx()
            disp_pad.attron(curses.color_pair(msg_types[0]+1))
            rectangle(disp_pad, msg_rect_y1, 0, msg_rect_y2, msg_width+1)
            disp_pad.addstr(msg_rect_y1, 3, msg_type_names[msg_types[0]])
            disp_pad.attroff(curses.color_pair(msg_types[0]+1))
            disp_pad.move(stored_y, stored_x)
            messages.pop(0)
            msg_types.pop(0)
            disp_pad.refresh(max(0, msg_rect_y2-(rows-6)),
                             0, 1, 2, rows-5, cols-2)
            stdscr.refresh()

        events = sel.select(timeout=0)
        for key, mask in events:
            # recieve length of message from client
            text = conn.recv(30)
            if not text:
                return
            c_mesg = ""

            # convert length in bytes to length in integer
            l1 = int.from_bytes(text, byteorder='big')
            time.sleep(1)

            # recieve ciphertext of length l1
            text = b''
            while len(text) < l1:
                temp = conn.recv(l1 - len(text))
                if not temp:
                    raise ConnectionError("Socket connection lost")
                text += temp

            # split hash and ciphertext
            recv_hash = text[-16896:]
            mesg = text[:-16896]

            # decrypt hash
            recv_hash = A_CS_decrypt.decrypt_bytes(recv_hash)

            c_mesg = "Encrypted Text = " + \
                str(mesg[:10]) + "..." + str(mesg[-10:])

            # Decrypt Ciphertext
            mesg = CS_decrypt_obj.decrypt_bytes(mesg)

            # Calculate hash of decrypted ciphertext
            mesg_hash = hashlib.sha256(mesg).digest()
            mesg = mesg.decode('ascii')
            c_mesg += " | Decrypted Message = " + mesg

            # if calculated hash == recieved hash, valid message
            # else, invalid message
            if (mesg_hash != recv_hash):
                messages.append("Integrity compromised. Message discarded")
            else:
                messages.append(c_mesg)
            msg_types.append(0)

        # handle all keyboard inputs
        stdscr.addstr(text_pad_y + 1, text_pad_xl + 1 + text_pad_cp, '')
        k = stdscr.getch()
        if k == curses.ERR:
            continue
        if k == curses.KEY_ENTER or k in [10, 13]:
            if text_pad_s == '!quit' or text_pad_s == '!q':
                return
            mesg = text_pad_s

            text_pad_y = rows - 3
            text_pad_xl = 1
            text_pad_wl = cols - 6
            text_pad_HIDE_WORDS = False
            text_pad_wl += text_pad_xl + 2

            text_pad_cp = 0
            stdscr.addstr(text_pad_y + 1, text_pad_xl + 1, ' '*(text_pad_wl-2))
            stdscr.refresh()

            mesg = mesg.encode('utf-8')

            # Calculate Hash of message
            hash = hashlib.sha256(mesg).digest()

            # Encrypt hash using server's private key
            # encrypted hash length = 16896
            hash = A_CS_encrypt.encrypt_bytes(hash)

            # Encrypt plaintext using client's public key
            mesg = CS_encrypt_obj.encrypt_bytes(mesg)
            text_pad_s += " | Encrypted Form = " + \
                str(mesg[:10]) + "..." + str(mesg[-10:])

            # Concatenate ciphertext and hash
            mesg = mesg + hash

            # Find length of total ciphertext
            l1 = len(mesg)

            # Convert length in integer to length in bytes
            l1 = l1.to_bytes(30, byteorder='big')

            # Send length to client
            send_bytes(conn, l1)

            # Send ciphertext to client
            send_bytes(conn, mesg)
            messages.append(text_pad_s)
            msg_types.append(1)
            text_pad_s = ''

        elif k == curses.KEY_UP or k == curses.KEY_DOWN:
            pass
        elif k == curses.KEY_BACKSPACE or k == 8:
            if text_pad_cp > 0:
                text_pad_cp -= 1
            stdscr.addstr(text_pad_y + 1, text_pad_xl +
                          1, " " * len(text_pad_s))
            text_pad_s = text_pad_s[:text_pad_cp]+text_pad_s[text_pad_cp+1:]
            if text_pad_HIDE_WORDS:
                stdscr.addstr(text_pad_y + 1, text_pad_xl + 1 +
                              text_pad_cp, "*"*len(text_pad_s[text_pad_cp:]))
                stdscr.addstr(text_pad_y + 1, text_pad_xl + 1,
                              "*"*len(text_pad_s[:text_pad_cp]))
            else:
                stdscr.addstr(text_pad_y + 1, text_pad_xl + 1 +
                              text_pad_cp, text_pad_s[text_pad_cp:])
                stdscr.addstr(text_pad_y + 1, text_pad_xl +
                              1, text_pad_s[:text_pad_cp])

        elif k == curses.KEY_LEFT or k == 27:
            if not text_pad_cp:
                pass
            else:
                text_pad_cp -= 1
                if text_pad_HIDE_WORDS:
                    stdscr.addstr(text_pad_y + 1, text_pad_xl + 1 +
                                  text_pad_cp, "*"*len(text_pad_s[text_pad_cp:]))
                    stdscr.addstr(text_pad_y + 1, text_pad_xl + 1,
                                  "*"*len(text_pad_s[:text_pad_cp]))
                else:
                    stdscr.addstr(text_pad_y + 1, text_pad_xl +
                                  1 + text_pad_cp, text_pad_s[text_pad_cp:])
                    stdscr.addstr(text_pad_y + 1, text_pad_xl +
                                  1, text_pad_s[:text_pad_cp])
        elif k == curses.KEY_RIGHT or k == 26:
            if text_pad_cp == len(text_pad_s):
                pass
            else:
                text_pad_cp += 1
                if text_pad_HIDE_WORDS:
                    stdscr.addstr(text_pad_y + 1, text_pad_xl + 1 +
                                  text_pad_cp, "*"*len(text_pad_s[text_pad_cp:]))
                    stdscr.addstr(text_pad_y + 1, text_pad_xl + 1,
                                  "*"*len(text_pad_s[:text_pad_cp]))
                else:
                    stdscr.addstr(text_pad_y + 1, text_pad_xl +
                                  1 + text_pad_cp, text_pad_s[text_pad_cp:])
                    stdscr.addstr(text_pad_y + 1, text_pad_xl +
                                  1, text_pad_s[:text_pad_cp])
        elif k in [curses.KEY_DC, 127]:
            if text_pad_HIDE_WORDS:
                stdscr.addstr(text_pad_y + 1, text_pad_xl + 1 + text_pad_cp, "*" *
                              len(text_pad_s[text_pad_cp + 1:] + " "))
                stdscr.addstr(text_pad_y + 1, text_pad_xl + 1,
                              "*"*len(text_pad_s[:text_pad_cp]))
            else:
                stdscr.addstr(text_pad_y + 1, text_pad_xl + 1 +
                              text_pad_cp, text_pad_s[text_pad_cp + 1:] + " ")
                stdscr.addstr(text_pad_y + 1, text_pad_xl +
                              1, text_pad_s[:text_pad_cp])
            text_pad_s = text_pad_s[:text_pad_cp] + \
                text_pad_s[text_pad_cp + 1:]
        else:
            if len(text_pad_s) < text_pad_wl - text_pad_xl - 2:
                if text_pad_cp == len(text_pad_s):
                    text_pad_s += str(chr(k))
                    if text_pad_HIDE_WORDS:
                        stdscr.addstr(text_pad_y + 1,
                                      text_pad_xl + 1, "*"*len(text_pad_s))
                    else:
                        stdscr.addstr(text_pad_y + 1,
                                      text_pad_xl + 1, text_pad_s)
                else:
                    text_pad_s = text_pad_s[:text_pad_cp] + \
                        str(chr(k)) + text_pad_s[text_pad_cp:]
                    if text_pad_HIDE_WORDS:
                        stdscr.addstr(text_pad_y + 1, text_pad_xl + 1 +
                                      len(text_pad_s[:text_pad_cp + 1]), "*"*len(text_pad_s[text_pad_cp + 1:]))
                        stdscr.addstr(text_pad_y + 1, text_pad_xl + 1,
                                      "*"*len(text_pad_s[:text_pad_cp + 1]))
                    else:
                        stdscr.addstr(text_pad_y + 1, text_pad_xl + 1 +
                                      len(text_pad_s[:text_pad_cp + 1]), text_pad_s[text_pad_cp + 1:])
                        stdscr.addstr(text_pad_y + 1, text_pad_xl +
                                      1, text_pad_s[:text_pad_cp + 1])
                text_pad_cp += 1


try:
    wrapper(console_textpad)
except Exception as e:
    print(e)
finally:
    lsock.close()
    conn.close()
    sel.close()

import socket
import selectors
import types
import sys
import hashlib

KEY = {"public":3,"private":4}#PUBLIC, PRIVATE

def encrypt_public(message,key = ""):
    return message

def encrypt_private(message,key = ""):
    return message

def decrypt_private(message,key = ""):
    return message

def decrypt_public(message,key = ""):
    return message

def hash_mesg(mesg):
    return hashlib.sha256(mesg).hexdigest()

def create_message(mesg):
    hash = hash_mesg(mesg)
    mesg = mesg + encrypt_private(hash,KEY["private"])
    return mesg

def derive_message(text):
    mesg_length = int(text[:4])
    mesg = text[4:mesg_length+4]
    hash = text[mesg_length+4:]
    return mesg,hash


def send_data(conn,mesg):
    print("=========")
    print("Original Message:",mesg)
    if isinstance(mesg, str): mesg = mesg.encode("utf-8")
    else: mesg = mesg.to_bytes(4,byteorder='little')
    print("Bytes Message: ",mesg)
    conn.sendall(mesg)

def recv_data(conn,t = 'int'):
    text = conn.recv(1024)
    if (not text): return None
    if (t == 'str'):
        return text.decode('utf-8')
    else: 
        return int.from_bytes(text, byteorder='little')

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

#socket initialization
lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
lsock.connect((HOST, PORT))

#selector declaration
sel = selectors.DefaultSelector()

#add socket to select queue
dataType1 = types.SimpleNamespace(addr=(HOST, PORT),inb=b"", outb=b"")
sel.register(lsock,selectors.EVENT_READ,data=dataType1)
sel.register(sys.stdin,selectors.EVENT_READ,data=None)

#key exchange
send_data(lsock,KEY["public"])
PUB_C1 = recv_data(lsock)
#print(PUB_C1)

try:
    while True:

        #poll sockets
        events = sel.select(timeout=None)
        for key,mask in events:
            if (key.data) is None:
                #stdin
                mesg = input("")
                mesg = create_message(mesg)
                mesg = encrypt_public(mesg,PUB_C1)
                send_data(lsock,mesg)
            else:
                text = recv_data(lsock,'str')
                if (text is None):
                    print(f"Closing connection to {key.data.addr}")
                    sel.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                text = decrypt_private(text,KEY["private"])
                mesg,e_hash = derive_message(text)
                recv_hash = decrypt_public((e_hash,PUB_C1))
                hash = hash_mesg(mesg)
                print(text)
except:
    print("Interrupted, exiting")
finally:
    lsock.close()
    sel.close()

    
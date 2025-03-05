import sys
import socket
import selectors
import types
import time

KEY = {"public":1,"private":2}#PUBLIC, PRIVATE

def encrypt(message,key = ""):
    return message

def decrypt(message,key = ""):
    return message

def send_data(conn,mesg):
    print("=========")
    print("Original Message:",mesg)
    if isinstance(mesg,str): mesg = mesg.encode("utf-8")
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
while True:
    try:
        lsock.bind((HOST, PORT))
        break  # Exit loop if binding is successful
    except OSError as e:
        print(f"Bind failed: {e}. Retrying in 2 seconds...")
        time.sleep(2)
lsock.listen()
print(f"Listening on {(HOST, PORT)}")

#accept
conn,addr = lsock.accept()
conn.setblocking(False)

#selector declaration
sel = selectors.DefaultSelector()

#add socket and sys.stdin to selector queue
dataType1 = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
sel.register(conn,selectors.EVENT_READ,data=dataType1)
sel.register(sys.stdin,selectors.EVENT_READ,data=None)

#key exchange
PUB_C2 = recv_data(conn)
send_data(conn,KEY["public"])
#print(PUB_C2)

try:
    while True:
        #poll sockets
        events = sel.select(timeout=None)
        for key,mask in events:
            if (key.data) is None:
                #stdin
                mesg = input("")
                send_data(conn,mesg)
            else:
                text = recv_data(conn,'str')
                if (text is None):
                    print(f"Closing connection to {key.data.addr}")
                    sel.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                print(text)
except:
    print("Interrupted, exiting")
finally:
    lsock.close()
    sel.close()

    
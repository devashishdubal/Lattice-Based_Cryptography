import socket
import selectors
import types
import sys
import time
import hashlib
import numpy as np

KEY = {"public":3,"private":4}#PUBLIC, PRIVATE

def encrypt_public(message,key = ""):
    return message

def encrypt_private(message,key = ""):
    return message

def decrypt_private(message,key = ""):
    return message

def decrypt_public(message,key = ""):
    return message


epsilon = 1
def is_prime(x):
  for i in np.arange(2,x/2):
    if x%i == 0:
      return False
  return True

'''
256 - 7
128 - 4
64 - 2
32 - 1
'''
def distribution(n, p):
  # alpha_n = 1.0/(np.sqrt(n)*np.log2(np.log2(n)))
  alpha_n = 1.0/(np.sqrt(n)*np.log2(n)*np.log2(n))
  normal_sample = np.random.normal(0.0, alpha_n/np.sqrt(2.0*np.pi))
  discrete_normal_sample = normal_sample%1.0
  distribution_sample = np.rint(discrete_normal_sample*p)%p
  return distribution_sample

class crypto_system:
  def __init__(self, n: int):
    self.n = n
    self.n = 32
  def gen_keys(self):
    self.p = 0
    prime_list = []
    for i in np.arange(self.n*self.n, 2*self.n*self.n):
      if is_prime(i):
        prime_list.append(i)
    self.p = np.random.choice(prime_list)
    self.m = (1 + epsilon)*(self.n + 1)*int(np.log2(self.p))
    self.gen_pvt_key()
    self.gen_pub_key()
  def gen_pvt_key(self):
    self.pvt_key = np.random.choice(self.p, self.n)
    return self.pvt_key
  def gen_pub_key(self):
    a = np.empty((self.m,self.n), dtype=np.int64)
    for i in np.arange(self.m):
      a[i][:] = np.random.choice(self.p, self.n)
    e = np.array([distribution(self.n,self.p) for i in range(self.m)])
    b = (np.dot(a, self.pvt_key)+e) % self.p
    # b = (np.dot(a, self.pvt_key)+self.p-4) % self.p
    # b = (np.dot(a, self.pvt_key) + np.random.choice(self.p, self.m, True, self.chi)) % self.p
    # b = (np.dot(a, self.pvt_key) + np.random.choice(np.arange(-10,10+1), self.m, True) + self.p) % self.p
    self.pub_key = (a, b)
    return self.pub_key
  def encrypt_one_bit(self, bit):
    choose_i = np.random.choice(2, self.m)
    print("HELLO45", choose_i, self.m)
    a_subset = self.pub_key[0][choose_i==1, :]
    b_subset = self.pub_key[1][choose_i==1]
    a_sum = np.sum(a_subset, axis=0) % self.p
    b_sum = np.sum(b_subset, axis=0) % self.p
    if(bit==1):
      b_sum = (b_sum + self.p//2)%self.p
    enc = np.zeros(self.n + 1, dtype=np.int16)
    enc[:self.n] = a_sum
    enc[self.n] = b_sum
    return enc
  def decrypt_one_pair(self, enc):
    x = (enc[self.n] - (np.dot(enc[:self.n], self.pvt_key) % self.p) + self.p) % self.p
    if np.abs(x-self.p//2) > min(x, self.p-x):
      return 0
    return 1
  def encrypt_bytes(self, buf):
    enc_bytes = bytes()
    for byte in buf:
      for bit_ind in np.arange(8):
        bit = (byte >> bit_ind) & 1
        enc_bit = self.encrypt_one_bit(bit)
        enc_bytes = enc_bytes + enc_bit.tobytes()
    return enc_bytes
  def decrypt_bytes(self, buf):
    dec_bytes = bytes()
    for enc_byte_start in np.arange(0, len(buf), 8*66):
      dec_byte = 0
      for bit_ind in np.arange(8):
        enc_bit_start = enc_byte_start+bit_ind*66
        enc_bit = buf[enc_bit_start: enc_bit_start+66]
        dec_bit = self.decrypt_one_pair(np.frombuffer(enc_bit, dtype=np.int16))
        dec_byte = dec_byte | (dec_bit << bit_ind)
      dec_bytes += bytes((dec_byte,))
    return dec_bytes
  def debug(self):
    print("====================================")
    print("n = ", self.n)
    print("p = ", self.p)
    print("m = ", self.m)
    print("pvt_key = \n", self.pvt_key)
    print("pub_key ai = \n", self.pub_key[0])
    print("pub_key bi = \n", self.pub_key[1])
    print("====================================")


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

def send_bytes(conn,mesg):
    print("=========")
    print("Original Message:",mesg)
    print("Bytes Message: ",mesg)
    conn.sendall(mesg)

def recv_data(conn,t = 'int'):
    text = conn.recv(1024)
    if (not text): return None
    if (t == 'str'):
        return text.decode('utf-8')
    else: 
        return int.from_bytes(text, byteorder='little')

def send_pub_key(conn,CS):
  #sending p length = 8
  send_list = bytes(CS.p.tobytes())
  #print(len(send_list))
  #print(send_list)
  
  #sending A length = 168960
  send_list += np.asarray(CS.pub_key[0]).tobytes()
  #print(len(send_list))

  #sending B length = 5280
  send_list += np.asarray(CS.pub_key[1]).tobytes()
  #print(len(send_list))
  t = 0
  while send_list:
    transmitted = conn.send(send_list)
    t+=transmitted
    send_list = send_list[transmitted:]
  #print(t)

def recv_pub_key(conn,CS):
  send_list = conn.recv(8) #its correct
  p = np.frombuffer(send_list,dtype=np.int64)
  CS.p = p[0]
  CS.m = (1 + epsilon)*(CS.n + 1)*int(np.log2(CS.p))

  send_list = b''
  time.sleep(1)
  for i in range(168960):
    temp = conn.recv(1)
    send_list += temp
  #print(len(send_list))


  pub_key_total = np.frombuffer(send_list,dtype=np.int64)
  A = []
  l = 0
  while(l<len(pub_key_total)):
    A.append(pub_key_total[l:l+32])
    l+=32
  A = np.asarray(A)
  #print(A.shape)
  
  send_list = b''
  time.sleep(1)
  for i in range(5280):
    temp = conn.recv(1)
    send_list += temp
  #print(len(send_list))
  B =  np.frombuffer(send_list,dtype=np.int64)
  #print(B.shape)
  CS.pub_key = (A,B)

def encrypt_message(mesg,CS):
  mesg = bytes(mesg,'utf-8')
  print("Bytes Message:",mesg)
  mesg = CS.encrypt_bytes(mesg)
  return mesg

def decrypt_message(text):
   text = decrypt_message(text,CS_decrypt_obj)
   return text
   

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

#for server public key
CS_encrypt_obj = crypto_system(32)
CS_encrypt_obj.gen_keys()

#for client
CS_decrypt_obj = crypto_system(32)
CS_decrypt_obj.gen_keys()

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
recv_pub_key(lsock,CS_encrypt_obj)
send_pub_key(lsock,CS_decrypt_obj)
#print(PUB_C1)

print("KEY exchange done")


try:
    while True:

        #poll sockets
        events = sel.select(timeout=None)
        for key,mask in events:
            if (key.data) is None:
                #stdin
                mesg = input("")
                mesg = encrypt_message(mesg,CS_encrypt_obj)
                print("enrypted successfully",mesg)
                send_bytes(lsock,mesg)
            else:
                #text = recv_data(lsock,'str')
                text = lsock.recv(1024)
                if (text is None):
                    print(f"Closing connection to {key.data.addr}")
                    sel.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                text = decrypt_message(text)
                print(text)
except Exception as err:
    print("Interrupted, exiting",err)
finally:
    lsock.close()
    sel.close()

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
    self.b2 = np.asarray(b)
    
    # b = (np.dot(a, self.pvt_key)+self.p-4) % self.p
    # b = (np.dot(a, self.pvt_key) + np.random.choice(self.p, self.m, True, self.chi)) % self.p
    # b = (np.dot(a, self.pvt_key) + np.random.choice(np.arange(-10,10+1), self.m, True) + self.p) % self.p
    self.pub_key = (a, b)
    return self.pub_key
  def encrypt_one_bit(self, bit):
    choose_i = np.random.choice(2, self.m)
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
    #print("B in bytes: \n",self.b2.tobytes())
    print("====================================")


def send_data(conn,mesg):
    print("=========")
    print("Original Message:",mesg)
    if isinstance(mesg,str): mesg = mesg.encode("utf-8")
    else: mesg = mesg.to_bytes(4,byteorder='little')
    print("Bytes Message: ",mesg)
    conn.sendall(mesg)

def send_bytes(conn,mesg):
  while mesg:
    transmitted = conn.send(mesg)
    mesg = mesg[transmitted:]

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
  send_list += np.asarray(CS.pub_key[1]).astype('<i8').tobytes()
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
  while len(send_list) < 5280:
    temp = conn.recv(5280 - len(send_list))
    if not temp:
        raise ConnectionError("Socket connection lost")
    send_list += temp
  #print(len(send_list))
  #print(send_list)
  B = np.frombuffer(send_list,dtype='<i8')
  #print(B.shape)
  CS.pub_key = (A,B)

def send_pvt_key(conn,CS):
  send_list = bytes(CS.p.tobytes())#8 bytes
  send_list += bytes(CS.pvt_key.tobytes()) #256 bytes
  #print(len(send_list))
  #print(send_list)
  t = 0
  while send_list:
    transmitted = conn.send(send_list)
    t+=transmitted
    send_list = send_list[transmitted:]

def recv_pvt_key(conn,CS):
  send_list = conn.recv(8)
  p = np.frombuffer(send_list,dtype=np.int64)
  CS.p = p[0]
  CS.m = (1 + epsilon)*(CS.n + 1)*int(np.log2(CS.p))

  send_list = b''
  time.sleep(1)
  while len(send_list) < 256:
    temp = conn.recv(256 - len(send_list))
    if not temp:
        raise ConnectionError("Socket connection lost")
    send_list += temp
  pvt_key = np.frombuffer(send_list,dtype=np.int64)
  CS.pvt_key = pvt_key

def encrypt_message(mesg,CS): #mesg in Bytes format
  #print("Original Message:",mesg)
  #mesg = bytes(mesg,'utf-8')
  #print("Bytes Message:",mesg)
  mesg = CS.encrypt_bytes(mesg)
  #print("Encrypted Message:",mesg)
  return mesg
def decrypt_message(text,CS):
  #print("Recieved Text: ",text)
  text = CS.decrypt_bytes(text)
  #print("Decrypted Text In Bytes:",text)
  #text = text.decode('utf-8')
  #print("Decrypted Text:",text)
  return text #returns text in Bytes Format

def gen_hashed_message(mesg,CS): #mesg in string format
   mesg = bytes(mesg,'utf-8')
   hash = hashlib.sha256(mesg).digest()
   hash = CS.encrypt_bytes(hash)
   mesg = mesg + hash # mesg + (32 bytes of hash)
   return mesg

def verify_hash(text,CS):#text in Bytes format
   recv_hash = text[-32:]
   recv_hash = CS.decrypt_bytes(recv_hash)
   mesg = text[:-32]
   mesg_hash = hashlib.sha256(mesg).digest()
   if (recv_hash == mesg_hash):
      mesg = mesg.decode('utf-8')
      return mesg
   else:
      return ''
   
def trial_test(CS):
  print("============================================")
  print("Testing Encryption and Decryption System")
  text = 'Hello'
  b_text = bytes(text,'utf-8')
  print("Text: ",text)
  print("In Bytes:",b_text)
  b_text = CS.encrypt_bytes(b_text)
  l1 = len(b_text).to_bytes(8)
  print("Length of Encrypted Text:",len(b_text),"=",l1)
  b_text = CS.decrypt_bytes(b_text)
  print("Decrypted Text In Bytes:",b_text)
  print("Decrypted Text:",b_text.decode('utf-8'))
  print("============================================")
  
#HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
HOST = "172.20.10.3"
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

#for client public key
CS_encrypt_obj = crypto_system(32)
CS_encrypt_obj.gen_keys()

#for server
CS_decrypt_obj = crypto_system(32)
CS_decrypt_obj.gen_keys()

#for server
A_CS_encrypt = crypto_system(32)
A_CS_encrypt.gen_keys()

#for client
A_CS_decrypt = crypto_system(32)
A_CS_decrypt.gen_keys()

#socket initialization
lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
lsock.connect((HOST, PORT))

#selector declaration
sel = selectors.DefaultSelector()

#add socket to select queue
dataType1 = types.SimpleNamespace(addr=(HOST, PORT),inb=b"", outb=b"")
sel.register(lsock,selectors.EVENT_READ,data=dataType1)
#sel.register(sys.stdin,selectors.EVENT_READ,data=None)

#key exchange
recv_pub_key(lsock,CS_encrypt_obj)
send_pub_key(lsock,CS_decrypt_obj)
recv_pvt_key(lsock,A_CS_decrypt)
send_pvt_key(lsock,A_CS_encrypt)
print("KEY exchange done")
lsock.setblocking(False)

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
    msg_type_names = [" Server ", " Client "]
    messages = ["dummy"]
    msg_types = [1]

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
          text = lsock.recv(30)
          #print(text)
          l1 = int.from_bytes(text,byteorder='big')
          #print("Received Message Length =",l1)
          time.sleep(1)
          text = b''
          #text = lsock.recv(l1)
          while len(text) < l1:
            temp = lsock.recv(l1 - len(text))
            if not temp:
              raise ConnectionError("Socket connection lost")
            text += temp
          
          recv_hash = text[-16896:]
          recv_hash = A_CS_decrypt.decrypt_bytes(recv_hash)
          mesg = text[:-16896]
          mesg = CS_decrypt_obj.decrypt_bytes(mesg)
          mesg_hash = hashlib.sha256(mesg).digest()
          mesg = mesg.decode('utf-8')
          if (mesg_hash != recv_hash):
              messages.append("Integrity compromised. Message discarded")
          else:
              messages.append(f"{mesg}")
          msg_types.append(0)
        '''
        if np.random.randint(0,100)>90:
            messages.append(f"blah blah - {np.random.randint(0,100)}")
            msg_types.append(0)
        '''
        stdscr.addstr(text_pad_y + 1, text_pad_xl + 1 + text_pad_cp, '')
        k = stdscr.getch()
        if k == curses.ERR:
            continue
        if k == curses.KEY_ENTER or k in [10, 13]:
            if text_pad_s == '!quit' or text_pad_s == '!q':
                return
            mesg = text_pad_s
            messages.append(text_pad_s)
            msg_types.append(1)
            text_pad_y = rows - 3
            text_pad_xl = 1
            text_pad_wl = cols - 6
            text_pad_HIDE_WORDS = False
            text_pad_wl += text_pad_xl + 2
            text_pad_s = ''
            text_pad_cp = 0
            stdscr.addstr(text_pad_y + 1, text_pad_xl + 1, ' '*text_pad_wl)
            stdscr.refresh()
            
            mesg = mesg.encode('utf-8')
            #mesg2 = mesg.decode('utf-8')
            #messages.append(f"{text_pad_s==mesg2}")
            #msg_types.append(0)
            hash = hashlib.sha256(mesg).digest()
            hash = A_CS_encrypt.encrypt_bytes(hash) #encrypted hash length = 16896
            mesg = CS_encrypt_obj.encrypt_bytes(mesg)
            mesg = mesg + hash
            l1 = len(mesg)
            #print("Length =",l1)
            l1 = l1.to_bytes(30,byteorder='big')
            #print("Length of Encrypted Message: ",len(mesg),'=',l1)
            lsock.sendall(l1)
            send_bytes(lsock,mesg)

        elif k == curses.KEY_UP or k == curses.KEY_DOWN:
            pass
        elif k == curses.KEY_BACKSPACE or k == 8:
            if text_pad_cp > 0:
                text_pad_cp -= 1
            stdscr.addstr(text_pad_y + 1, text_pad_xl + 1, " " * len(text_pad_s))
            text_pad_s = text_pad_s[:text_pad_cp]+text_pad_s[text_pad_cp+1:]
            if text_pad_HIDE_WORDS:
                stdscr.addstr(text_pad_y + 1, text_pad_xl + 1 + text_pad_cp, "*"*len(text_pad_s[text_pad_cp:]))
                stdscr.addstr(text_pad_y + 1, text_pad_xl + 1, "*"*len(text_pad_s[:text_pad_cp]))
            else:
                stdscr.addstr(text_pad_y + 1, text_pad_xl + 1 + text_pad_cp, text_pad_s[text_pad_cp:])
                stdscr.addstr(text_pad_y + 1, text_pad_xl + 1, text_pad_s[:text_pad_cp])

        elif k == curses.KEY_LEFT or k == 27:
            if not text_pad_cp:
                pass
            else:
                text_pad_cp -= 1
                if text_pad_HIDE_WORDS:
                    stdscr.addstr(text_pad_y + 1, text_pad_xl + 1 + text_pad_cp, "*"*len(text_pad_s[text_pad_cp:]))
                    stdscr.addstr(text_pad_y + 1, text_pad_xl + 1, "*"*len(text_pad_s[:text_pad_cp]))
                else:
                    stdscr.addstr(text_pad_y + 1, text_pad_xl + 1 + text_pad_cp, text_pad_s[text_pad_cp:])
                    stdscr.addstr(text_pad_y + 1, text_pad_xl + 1, text_pad_s[:text_pad_cp])
        elif k == curses.KEY_RIGHT or k == 26:
            if text_pad_cp == len(text_pad_s):
                pass
            else:
                text_pad_cp += 1
                if text_pad_HIDE_WORDS:
                    stdscr.addstr(text_pad_y + 1, text_pad_xl + 1 + text_pad_cp, "*"*len(text_pad_s[text_pad_cp:]))
                    stdscr.addstr(text_pad_y + 1, text_pad_xl + 1, "*"*len(text_pad_s[:text_pad_cp]))
                else:
                    stdscr.addstr(text_pad_y + 1, text_pad_xl + 1 + text_pad_cp, text_pad_s[text_pad_cp:])
                    stdscr.addstr(text_pad_y + 1, text_pad_xl + 1, text_pad_s[:text_pad_cp])
        elif k in [curses.KEY_DC, 127]:
            if text_pad_HIDE_WORDS:
                stdscr.addstr(text_pad_y + 1, text_pad_xl + 1 + text_pad_cp, "*" *
                              len(text_pad_s[text_pad_cp + 1:] + " "))
                stdscr.addstr(text_pad_y + 1, text_pad_xl + 1, "*"*len(text_pad_s[:text_pad_cp]))
            else:
                stdscr.addstr(text_pad_y + 1, text_pad_xl + 1 + text_pad_cp, text_pad_s[text_pad_cp + 1:] + " ")
                stdscr.addstr(text_pad_y + 1, text_pad_xl + 1, text_pad_s[:text_pad_cp])
            text_pad_s = text_pad_s[:text_pad_cp] + text_pad_s[text_pad_cp + 1:]
        else:
            if len(text_pad_s) < text_pad_wl - text_pad_xl - 2:
                if text_pad_cp == len(text_pad_s):
                    text_pad_s += str(chr(k))
                    if text_pad_HIDE_WORDS:
                        stdscr.addstr(text_pad_y + 1, text_pad_xl + 1, "*"*len(text_pad_s))
                    else:
                        stdscr.addstr(text_pad_y + 1, text_pad_xl + 1, text_pad_s)
                else:
                    text_pad_s = text_pad_s[:text_pad_cp] + str(chr(k)) + text_pad_s[text_pad_cp:]
                    if text_pad_HIDE_WORDS:
                        stdscr.addstr(text_pad_y + 1, text_pad_xl + 1 +
                                      len(text_pad_s[:text_pad_cp + 1]), "*"*len(text_pad_s[text_pad_cp + 1:]))
                        stdscr.addstr(text_pad_y + 1, text_pad_xl + 1, "*"*len(text_pad_s[:text_pad_cp + 1]))
                    else:
                        stdscr.addstr(text_pad_y + 1, text_pad_xl + 1 +
                                      len(text_pad_s[:text_pad_cp + 1]), text_pad_s[text_pad_cp + 1:])
                        stdscr.addstr(text_pad_y + 1, text_pad_xl + 1, text_pad_s[:text_pad_cp + 1])
                text_pad_cp += 1


wrapper(console_textpad)

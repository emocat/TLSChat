import select, sys
import socket
import pickle
import OpenSSL
from Crypto.Hash import SHA
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

server_public_cert = "server.crt"
server_private_cert = "server.key"
session_key = ""

class TLS_Record_Layer:
    def __init__(self):
        self.Content = []
        self.Version = "TLS 1.3"
        self.Handshake_Protocol = ""
        self.Certificate = ""
        self.Certificate_Request = False
        self.Sessionkey = 0
        self.Data = ""
        self.DataHash = ""

class Handshake_Protocol:
    def __init__(self):
        self.Handshake_type = ""
        self.Cipher_Suite = ["TLS_RSA_WITH_AES_128_CFB_SHA"]

# Extract Server's Private RSA Key from Server's Certificate
def PrivateKey_Extract(cert):
    key = RSA.importKey(open(cert).read())
    return key.d, key.n

# Decrypt ciphertext with RSA
def rsa_decrypt(c, d, n):
    c = int(c)
    sessionkey = pow(c, d, n)
    print "hex(sessionKey): %s " % sessionkey
    sessionkey = hex(sessionkey)[2:-1].decode("hex")
    return sessionkey

"""
# initiate AES cipher with a key and zero iv
def session_init(sessionKey):
    iv = '\x00'*16
    cipher = AES.new(sessionKey, AES.MODE_CFB, iv)
    return cipher
"""

# Use AES to encrypt message with sessionkey 
def session_encrypt(sessionkey, msg):
    iv = '\x00'*16
    cipher = AES.new(sessionkey, AES.MODE_CFB, iv)
    return cipher.encrypt(msg)

# Use AES to decrypt data with sessionkey, and check data's hash
def session_decrypt(sessionkey, data, datahash):
    iv = '\x00'*16
    cipher = AES.new(sessionkey, AES.MODE_CFB, iv)
    msg = cipher.decrypt(data)
    hash_check(msg, datahash)
    return msg

# Encrypt data with SHA1
def hash_encrypt(data):
    h = SHA.new()
    h.update(data)
    return h.hexdigest()

# Encrypt data with SHA1 and check it with data's hash
def hash_check(data, datahash):
    h = SHA.new()
    h.update(data)
    if h.hexdigest() != datahash:
        print "Hash check error!"
        exit(1)

def handshake(sock):
    global session_key

    # Part 2: Server Hello
    cRecord1 = pickle.loads(sock.recv(2048))
    if "Handshake" not in cRecord1.Content or cRecord1.Version != "TLS 1.3" or cRecord1.Handshake_Protocol.Handshake_type != "Client Hello":
        print "Incorrect Client Hello"
        exit(1)
    print "Agreed Encryption Algorythm: " + cRecord1.Handshake_Protocol.Cipher_Suite[0]
    sRecord1 = TLS_Record_Layer()
    sRecord1.Content.append("Handshake")
    hsprotocol = Handshake_Protocol()
    hsprotocol.Handshake_type = "Server Hello"
    sRecord1.Handshake_Protocol = hsprotocol
    sRecord1.Content.append("Certificate")
    sRecord1.Certificate = open(server_public_cert).read()
    sock.send(pickle.dumps(sRecord1))

    # Part 4
    cRecord2 = pickle.loads(sock.recv(2048))
    d, n = PrivateKey_Extract(server_private_cert)
    session_key = rsa_decrypt(cRecord2.Sessionkey, d, n)
    msg = session_decrypt(session_key, cRecord2.Data, cRecord2.DataHash)
    if msg != "Finished":
        print "Finished error!"
        exit(1)
    sRecord2 = TLS_Record_Layer()
    sRecord2.Content.append("Change Cipher Spec")
    sRecord2.Content.append("Encrypt Data")
    sRecord2.Data = session_encrypt(session_key, "Finished")
    sRecord2.DataHash = hash_encrypt("Finished")
    sock.send(pickle.dumps(sRecord2))
    
    print "Handshake done."    

# Send encrypted data and data's hash
def send_encrypt_data(sock):
    msg = sys.stdin.readline().strip()
    Record = TLS_Record_Layer()
    Record.Content.append("Encrypt Data")
    Record.Data = session_encrypt(session_key, msg)
    Record.DataHash = hash_encrypt(msg)
    sock.send(pickle.dumps(Record))

# receive encrypted data and decrypt it
def recv_encrypt_data(sock):
    Record = pickle.loads(sock.recv(2048))
    msg = session_decrypt(session_key, Record.Data, Record.DataHash)
    print "[client] %s" % msg

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 12345))
    s.listen(1)
    sock, addr = s.accept()
    handshake(sock)

    while True:
        fin, fout, ferr = select.select([sock, sys.stdin], [], [])
        for i in fin:
            if i == sock:
                recv_encrypt_data(sock)
            else:
                send_encrypt_data(sock)

    sock.close()
    s.close()

if __name__ == "__main__":
    main()



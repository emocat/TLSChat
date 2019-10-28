import os
import select, sys
import socket
import pickle
import OpenSSL
from Crypto import Random
from Crypto.Hash import SHA
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

client_cert = "client.crt"
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

# Verify Server's Certificate from commandline with openssl
def Cert_Verify(cert):
    if os.system("openssl verify -CAfile ../ca/ca.crt ./server.crt") != 0:
        print "Server Cert Verify Error!"
        exit(1)

# Extract Server's public RSA key from Server's certificate
def Cert_Extract(cert):
    server_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    data = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, server_cert.get_pubkey()).decode("utf-8")
    key = RSA.importKey(data)
    return key.e, key.n

# Encrypt ciphertext with RSA
def rsa_encrypt(sessionkey, e, n):
    m = int(sessionkey.encode("hex"), 16)
    print "hex(sessionKey): %s" % m
    c = pow(m, e, n)
    return str(c)

# Generate random 16-bit sessionkey
def session_init():
    sessionKey = Random.new().read(AES.key_size[0])
    iv = '\x00'*16
    cipher = AES.new(sessionKey, AES.MODE_CFB, iv)
    return sessionKey

# Use AES to encrypt data with sessionkey
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

    # Part 1: Client Hello
    cRecord1 = TLS_Record_Layer()
    cRecord1.Content.append("Handshake")
    hsprotocol = Handshake_Protocol()
    hsprotocol.Handshake_type = "Client Hello"
    cRecord1.Handshake_Protocol = hsprotocol
    sock.send(pickle.dumps(cRecord1))

    # Part 3: 
    sRecord1 = pickle.loads(sock.recv(2048))
    cert = sRecord1.Certificate
    with open("server.crt", 'wb') as f:
        f.write(cert)
    Cert_Verify(cert)
    print "Agreed Encryption Algorythm: " + sRecord1.Handshake_Protocol.Cipher_Suite[0]
    e, n = Cert_Extract(cert)
    session_key = session_init()
    cRecord2 = TLS_Record_Layer()
    cRecord2.Content.append("Client Key exchange")
    cRecord2.Sessionkey = rsa_encrypt(session_key, e, n)
    cRecord2.Content.append("Change Cipher Spec")
    cRecord2.Content.append("Encrypt Data")
    cRecord2.Data = session_encrypt(session_key, "Finished")
    cRecord2.DataHash = hash_encrypt("Finished")
    sock.send(pickle.dumps(cRecord2))

    # Finally
    sRecord2 = pickle.loads(sock.recv(2048))
    msg = session_decrypt(session_key, cRecord2.Data, cRecord2.DataHash)
    if msg != "Finished":
        print "Finished error!"
        exit(1)

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
    print "[server] %s" % msg

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 12345))
    handshake(s)

    while True:
        fin, fout, ferr = select.select([s, sys.stdin], [], [])
        for i in fin:
            if i == s:
                recv_encrypt_data(s)
            else:
                send_encrypt_data(s)
                
    s.close()


if __name__ == "__main__":
    main()
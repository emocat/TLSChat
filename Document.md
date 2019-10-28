# TLS Designed Document

- 证书认证：单向认证
- 加密方式：`"TLS_RSA_WITH_AES_128_CFB_SHA"`

## Client and Server connection

### Socket 通信

本实验主要实现了 `client` 和 `server` 的双向握手与通信，其中通过调用 `select` 库实现了 I/O 的多路复用。

- Server.py

  ```python
  import select
  import socket
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
  ```

- Client.py

  ```python
  import select
  import socket
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
  ```

### TLS Protocol 的简单实现

因为需要简单模拟 TLS 的整个握手阶段，考虑到实际情况下 TLS 握手的复杂性，将会对 TLS Layer 的各数据包头的长度、数据类型有着非常严格的定义，这无疑会加大实验的难度。在参阅过相关的资料后，我决定在本次实验中，用 python 的类来封装 TLS Layer，只涉及到实验所需要的头部信息，并且通过序列化传输，从而实验一个简化版的 TLS Protocol。

- `TLS Record Layer` 的定义

  ```python
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
  ```

  - Content 用来存放本次传输涉及到的 Protocol，如 `Handshake`、`Client Key exchange` 等；
  - Version 默认为 TLS 1.3 版本；
  - Handshake_Protocol 用来存放握手协议的具体数据；
  - Certificate 用来传输证书，只有在 `Server Hello` 阶段才会被用到；
  - Certificate_Request 默认为 False，因为本次实验采用单向认证；
  - Sessionkey 用来存放加密过的对称密钥
  - Data 和 Datahash 是传输的具体消息。

- `Handshake Protocol` 的定义

  ```python
  class Handshake_Protocol:
      def __init__(self):
          self.Handshake_type = ""
          self.Cipher_Suite = ["TLS_RSA_WITH_AES_128_CFB_SHA"]
  ```

  - Handshake_type: 主要是 `Server_hello`、`Client Hello`
  - Cipher_Suite: 默认为 `"TLS_RSA_WITH_AES_128_CFB_SHA"` 加密方式

- TLS 握手的过程
  整个握手过程大致如下图所示

  ![](https://cshihong.github.io/2019/05/09/SSL%E5%8D%8F%E8%AE%AE%E8%AF%A6%E8%A7%A3/%E5%8D%8F%E5%95%86%E8%BF%87%E7%A8%8B.png)
  例如：

  ```python
      # Part 1: Client Hello
      cRecord1 = TLS_Record_Layer()
      cRecord1.Content.append("Handshake")
      hsprotocol = Handshake_Protocol()
      hsprotocol.Handshake_type = "Client Hello"
      cRecord1.Handshake_Protocol = hsprotocol
      sock.send(pickle.dumps(cRecord1))
      
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
  ```

  由此可见，通过发送对象类的序列化消息，我们可以很好的模拟出 TLS 的握手阶段，能够着重点出这个阶段所强调的几个数据，也能够更加方便地从交换数据中提取不同的信息。

## Session key production

**实现思路：服务器在 `Server Hello` 阶段会发送自己的证书给客户端，客户端认证证书后，从证书中提取出服务器的 RSA 公钥。然后通过生成 16-bit 的随机数作为 AES 加密的 `Session key`，并用服务器的 RSA 公钥加密后发送给服务器。**

### 证书的生成

由于实验关系，我们使用的是本地的自签证书，通过 openssl 分别生成了 ca server client 的证书及密钥

```bash
# private key generation
openssl genrsa -out ca.key 1024
openssl genrsa -out server.key 1024
openssl genrsa -out client.key 1024

# cert requests
openssl req -out ca.req -key ca.key -new \
            -config ./ca_cert.conf
openssl req -out server.req -key server.key -new \
            -config ./server_cert.conf 
openssl req -out client.req -key client.key -new \
            -config ./client_cert.conf 

# generate the actual certs.
openssl x509 -req -in ca.req -out ca.crt \
            -sha1 -days 5000 -signkey ca.key
openssl x509 -req -in server.req -out server.crt \
            -sha1 -CAcreateserial -days 5000 \
            -CA ca.crt -CAkey ca.key
openssl x509 -req -in client.req -out client.crt \
            -sha1 -CAcreateserial -days 5000 \
            -CA ca.crt -CAkey ca.key
```

项目结构如下：

```bash
.
├── ca
│   ├── ca.crt
│   └── ca.key
├── client
│   ├── client.crt
│   ├── client.key
│   └── client.py
└── server
    ├── server.crt
    ├── server.key
    └── server.py
```

### 证书的认证与解析

通过 os.system 调用 `openssl` 的命令行进行认证

```python
# Verify Server's Certificate from commandline with openssl
def Cert_Verify(cert):
    if os.system("openssl verify -CAfile ../ca/ca.crt ./server.crt") != 0:
        print "Server Cert Verify Error!"
        exit(1)
```

在客户端，可以用 `OpenSSL` 库提取证书中保存的公钥信息

```python
# Extract Server's public RSA key from Server's certificate
def Cert_Extract(cert):
    server_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    data = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, server_cert.get_pubkey()).decode("utf-8")
    key = RSA.importKey(data)
    return key.e, key.n
```

在服务器上，可以用同样的方式提取服务器端的密钥

```python
# Extract Server's Private RSA Key from Server's Certificate
def PrivateKey_Extract(cert):
    key = RSA.importKey(open(cert).read())
    return key.d, key.n
```

这样我们就能得到服务器证书中的公钥了。

### Session key 的生成

由于本实验并非采用 Diffie-Hellman 的密钥交换方式，因此对 session key 的生成方式没有特别严格的要求。因为是采用了 AES 作为对称加密算法，本实验通过产生 16-bit 的随机数作为 session key。

```python
def session_init():
    sessionKey = Random.new().read(AES.key_size[0])
    iv = '\x00'*16
    cipher = AES.new(sessionKey, AES.MODE_CFB, iv)
    return sessionKey
```

### Session key 的交换

本实验采用 RSA 的密钥交换方式，用服务器证书的公钥私钥加解密。客户端加密 session key，服务器解密 session key

```python
# Encrypt ciphertext with RSA
def rsa_encrypt(sessionkey, e, n):
    m = int(sessionkey.encode("hex"), 16)
    print "hex(sessionKey): %s" % m
    c = pow(m, e, n)
    return str(c)

# Decrypt ciphertext with RSA
def rsa_decrypt(c, d, n):
    c = int(c)
    sessionkey = pow(c, d, n)
    print "hex(sessionKey): %s " % sessionkey
    sessionkey = hex(sessionkey)[2:-1].decode("hex")
    return sessionkey
```



## Encryption and Decryption

本实验主要采用 `AES_128_CFB` 作为对称加密算法，采用 AES 而非过时的 DES 算法，采用 CFB 而非 CBC 模式是因为 CFB 模式更难以被破解。

```python
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
```



## MAC and verify

消息发送端使用 `SHA1` 算法加密信息，将信息和 hash 值一起发给接收端

```python
# Encrypt data with SHA1
def hash_encrypt(data):
    h = SHA.new()
    h.update(data)
    return h.hexdigest()

Record.Data = session_encrypt(session_key, message)
Record.DataHash = hash_encrypt(message)
```

接收端接收到数据后，解密密文，并验证信息的加密值是否和接收的 hash 值相等，从而完成验证

```python
# Encrypt data with SHA1 and check it with data's hash
def hash_check(data, datahash):
    h = SHA.new()
    h.update(data)
    if h.hexdigest() != datahash:
        print "Hash check error!"
        exit(1)
        
hash_check(msg, datahash)
```



## 完整代码

### Client.py

```python
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
```



### Server.py

```python
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
```








# Py-babytls

## About

一个用 python 简单实现的 TLS 聊天室，支持 `server` 和 `client` 的点对点聊天。

## Environment

Build on Ubuntu 16.04

```bash
// requirements.txt
pycrypto
pyOpenSSL
```

## File Struct

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

## Use

Server: `python server.py`
Client: `python client.py`

#!/usr/bin/env python3
"""A one-response HTTP/1.1 backend for the QUIC oracle. Prints its port on stdout."""
import socket
import threading

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0))
s.listen(64)
print(s.getsockname()[1], flush=True)


def handle(c):
    c.recv(8192)
    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nhello-from-h3")
    c.close()


while True:
    conn, _ = s.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()

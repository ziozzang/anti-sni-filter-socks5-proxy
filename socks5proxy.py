#!/usr/bin/python
# -*- coding:utf-8 -*-
#
# Socks5 Proxy Service with Avoid SNI based Contents Filtering.
# This sample is for test purpose.
# - code by Jioh L. Jung(ziozzang@gmail.com)
#
# Threaded Socks5 Server in Python
#
# Source: http://xiaoxia.org/2011/03/29/written-by-python-socks5-server/
#
#

#from gevent import monkey
#monkey.patch_all()

import socket, os, sys, select, struct, time
import hexdump

if sys.version_info.major == 2:
  import SocketServer
elif sys.version_info.major == 3:
  import socketserver as SocketServer

class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer): pass
class Socks5Server(SocketServer.StreamRequestHandler):
    def handle_tcp(self, sock, remote):
        fdset = [sock, remote]
        self.marked = False
        self.sent = False
        self.reqtype = None
        self.cbuf = None
        
        # Basic Loop for contents passing.
        while True:
            r, w, e = select.select(fdset, [], [])
            if sock in r:
                buf = sock.recv(4096)
                if not self.marked:
                    # 1st packet marking
                    self.marked = True
                    if len(buf) == 0:
                        break
                    if buf[0] ==  '\x16':
                        # TLS start
                        p = min(len(buf) / 5, 100) # Tricky Code. split by specific size or split by some...
                        self.sent = True
                        remote.send(buf[:p])
                        if remote.send(buf[p:]) <= 0: break
                    elif  buf[0].lower() >= ord('a')  or buf[0].lower() <= ord('z'):
                        # Generic HTTP?
                        lp = buf.lower().find("host:")
                        if lp != -1:
                            self.sent = True
                            remote.send(buf[:lp+4])
                            if remote.send(buf[lp+4:]) <= 0: break
                    if not self.sent:
                        self.sent = True
                        if remote.send(buf) <= 0: break
                else:
                    if remote.send(buf) <= 0: break
            
            if remote in r:
                buf = remote.recv(4096)
                # no filtering

                if not buf: break
                if sock.send(buf) <= 0: break
    def handle(self):
        addr = ""
        try:
            #>> 'socks connection from ', self.client_address
            sock = self.connection
            # 1. Version
            sock.recv(262)
            sock.send(b"\x05\x00");
            # 2. Request
            data = self.rfile.read(4)
            print(">> LEN:",len(data))
            hexdump.hexdump(data)
            if len(data) < 4:
                return
            mode = data[1]
            addrtype = data[3]
            print("> mode:", data[1]," / addrtype:", data[3])
            if addrtype == 1:       # IPv4
                addr = socket.inet_ntop(socket.AF_INET, self.rfile.read(4))
            elif addrtype == 3:     # Domain name
                addr = self.rfile.read(ord(sock.recv(1)[0]))
            elif addrtype == 4:     # IPv6
                addr = socket.inet_ntop(socket.AF_INET6, self.rfile.read(16))
                print("-> IPv6:", addr)
            port = struct.unpack('>H', self.rfile.read(2))
            reply = b"\x05\x00\x00\x01"
            try:
                if mode == 1:  # 1. Tcp connect
                    self.addr = addr
                    self.port = port[0]
                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    remote.connect((addr, port[0]))
                    print(">> 'Tcp connect to'", addr,":", port[0])
                else:
                    reply = b"\x05\x07\x00\x01" # Command not supported
                local = remote.getsockname()
                reply += socket.inet_aton(local[0]) + struct.pack(">H", local[1])
            except socket.error:
                # Connection refused
                reply = '\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00'
            sock.send(reply)
            # 3. Transfering
            if reply[1] == '\x00':  # Success
                if mode == 1:    # 1. Tcp connect
                    self.handle_tcp(sock, remote)
        except socket.error:
            pass
            #print 'socket error'
def main():
    server = ThreadingTCPServer(('', 18080), Socks5Server)
    server.serve_forever()

if __name__ == '__main__':
    main()

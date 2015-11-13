#!/usr/bin/env python
#coding=utf-8
import socket
import ipaddress
import sys
from multiprocessing.dummy import Lock, Pool as ThreadPool
import time
from itertools import product


class assassin:
    def __init__(self, ipfile, store_file, thread_num, port):
        self.ipfile = open(ipfile, "r")
        self.thread_num = thread_num
        self.port = port
        self.vuls = set()
        self.store_file = store_file
        self.lock = Lock()
        
    def _ips(self):
        for line in self.ipfile:
            line = line.strip()
            if( len(line) == 0):
                continue
            for ip in ipaddress.ip_network(unicode(line), strict=False):
                yield '%s' % ip 

    def run(self, host):
        vul = False 
        try:
            sock = socket.socket()
            socket.setdefaulttimeout(3)
            sock.connect((host, self.port))
            payload = '\x2a\x31\x0d\x0a\x24\x34\x0d\x0a\x69\x6e\x66\x6f\x0d\x0a'
            sock.send(payload)
            recvdata = sock.recv(1024)
            if recvdata and 'redis_version' in recvdata:
                self.lock.acquire()
                print '[+] maybe vul: %s' % host
                self.vuls.add(host)
                self.lock.release()
                vul = True
                return vul
            else:
                return vul 
        except:
            return vul
        finally:
            sock.close()
            
    def multi_assasin(self):
        start = time.time()
        ip_set = self._ips()
        pool = ThreadPool(self.thread_num)
        results = pool.map(self.run, ip_set)
        pool.close()
        pool.join()
        with open(self.store_file, "w") as f:
            for _ in self.vuls:
                f.write(_ + "\n")
        print "%s\ttotal vuln sites:%s \n used %s minutes." % (time.ctime(),\
                len(self.vuls), (time.time()-start)/ 60.0)
         
if __name__ == '__main__':
    if(len(sys.argv) != 4):
        print "Usage: %s <url_file> <output_file> <thread_num>" % sys.argv[0]
        sys.exit()
    port = 6379
    thread_num = sys.argv[3] 
    store_file = sys.argv[2]
    with open(sys.argv[1], "r") as f:
        count = 0
        for _ in f:
            if(len(_) == 0):
                continue
            index = (32 - int(_.strip().split('/')[1])) if '/' in _ else 0
            count += 2 ** index
    print '%s\t\t %s ips|%s threads' % (time.ctime(), count, thread_num)
    j = assassin(sys.argv[1],store_file, thread_num, port)
    j.multi_assasin()

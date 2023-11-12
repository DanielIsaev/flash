#!/usr/bin/python3

import time
import signal
import socket
import sys
import threading 
from queue import Queue
from struct import *
from datetime import datetime
from Packet import Packet
from Objects import *
    

def sig_handler(signum, frame):
    #   Catch Ctrl-C and terminate.
    event.set()
    print(f'\n\nCaught Ctrl-C, Terminating...')
    time.sleep(0.5)
    sys.exit(0)


def get_source_ip(target):
    res = [(s.connect((target, 53)), s.getsockname()[0], s.close()) \
            for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]
    
    return res


def listener():
    listen = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    while not event.is_set():
        packet = listen.recv(65565)
        ip_header = unpack('!BBHHHBBH4s', packet[0:16])
        ip_head_len = (ip_header[0] & 0xf) * 4

        tcp_header_raw = packet[ip_head_len:ip_head_len+14]
        tcp_header = unpack('!HHLLBB', tcp_header_raw)

        src_port = tcp_header[0]
        flag = tcp_header[5]

        if flag == 18:  # SYN-ACK
            open_ports.add(src_port)


def scan(port):
    #   Main port scanner
    packet = Packet(src_ip, target, port)

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.sendto(packet.raw, (target, 0))
    s.close()
    
    pkt_counter.increment()
    
    progress = (pkt_counter/65535) * 100
    progress = format(progress, '0.1f')
    
    if q.empty():       #   To fix scan ending on less then 100 %
        time.sleep(0.1)

    with print_lock:
        print(f'Progress: % {progress}', end='')
        print(f'\r', end='')

  
def scan_thread():
    while not event.is_set():
        port = q.get()      
        scan(port)          
        q.task_done()       
               

if __name__ == '__main__':
    
    signal.signal(signal.SIGINT, sig_handler)
    
    #   Sanity  #
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} <target>')
        sys.exit(1)
    try:
        target = socket.gethostbyname(sys.argv[1])
    except Exception:
        print(f'\nFailed to resolve hostname: {sys.argv[1]}\nExisintg.')
        sys.exit(1)
    
    #   Init  #    
    open_ports = Ports()
    jobs = Ports()
    jobs.fill()
    q = Queue()
    print_lock = Printer()
    pkt_counter = Counter()
    N_THREADS = 200
    event = threading.Event()
    src_ip = get_source_ip(target)

    start = datetime.now()
    start_str = start.strftime("%a, %b %d %Y at %H:%M:%S")
    
    print(f'\nTCP port scan started on {start_str}', end='')
    
    if sys.argv[1] == target:
        print(f'\nTarget: {target}\n')
    else:
        print(f'\nTarget: {sys.argv[1]} ({target})\n')
    
    listener_thread = threading.Thread(target=listener, daemon=1)
    listener_thread.start()

    for worker in jobs.ports:
        q.put(worker) # put each port into the queue for scanning

    for t in range(N_THREADS):
        # for each thread, start it
        t = threading.Thread(target=scan_thread, daemon=1) # set daemon to true, 
        t.start()   # start the daemon thread
   
    q.join()

    #   Get scan time  #
    end = datetime.now()
    end_str = end.strftime("%a, %b %d %Y at %H:%M:%S")
    
    diff = end - start
    secs = diff.total_seconds()
    secs = format(secs, '0.1f')
    
    open_ports.get_services()

    print(f'\n')
    open_ports.show_results()

    print(f'Total scan time: {secs} seconds.')

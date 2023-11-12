#!/usr/bin/python3

import re
import random
import threading 
    

#   Open ports object    #
class Ports:
    def __init__(self):
        self.lock = threading.Lock()
        self.ports = []
    
    def __len__(self):
        return len(self.ports)

    def add(self, port):
        with self.lock:
            self.ports.append(port)
    
    def fill(self):
        self.ports = [i for i in range(1,65536)]
        random.shuffle(self.ports)

    def show(self):
        for port in self.ports:
            yield port
    
    def get_services(self):
        self.services = {}
        with open('nmap-services', 'rt') as file:
            for port in sorted(self.ports):
                regex = re.compile(r'^.+\s' + re.escape(str(port)) + r'/tcp\s.+$')
                for line in file:
                    if regex.search(line):
                        line = line.strip('\n').split()
                        self.services[port] = {'PORT': line[1], 'STATE': 'open', 'SERVICE': line[0]}
                        break
                else:
                    self.services[port] = {'PORT': f'{port}/tcp', 'STATE': 'open', 'SERVICE': 'unknown'}
    

    def show_results(self):
        print('{:<10} {:<7} {:<7}'.format('PORT', 'STATE', 'SERVICE'))
        for d in self.services.values():
            port, state, service = d.values()
            print('{:<10} {:<7} {:<7}'.format(port, state, service))
        print('\n', end='')


#   Packet Counter  #
class Counter:
    def __init__(self):
        self.lock = threading.Lock()
        self.packets = 0
    
    def __str__(self):
        return str(self.packets)
    
    def __truediv__(self, other):
        return self.packets / other

    def increment(self):
        with self.lock:
            self.packets += 1
        

#   Print Lock
class Printer:
    def __init__(self):
        self.lock = threading.Lock()

    def __enter__(self):
        return self.lock
    
    def __exit__(self, type, value, tb):
        pass

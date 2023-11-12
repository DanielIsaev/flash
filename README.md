# Flash

flash is a TCP-SYN port scanner written in Python! 

Desgined with speed and efficiency in mind, it utilizes multi-threading to achive concurrency, as well as an OOP approach for creating raw TCP/IP packets from scratch (without using the Scapy module!). All of this makes for a blazing fast runtime, with a scan of all 65535 TCP ports lasting about 8 seconds. 

Each port is then mapped to a service via the `nmap-services` database, so `nmap` users should feel right at home! 
for example:

![out-exmp]()


## Install

On a Linux platform, simply clone the reposetory to your directory of choice with:

```bash
git clone https://github.com/DanielIsaev/flash
cd flash
```

After that it should be good to go. 


## Usage

The script takes one argumnet, the target which can either be an IP or a hostname. For example:

```bash
./flash.py solidstate.htb 
./flash.py 10.129.227.181
```

The script scans all 65535 TCP ports by default, and prints the results. No other arguments besides the target host is needed, and therefore there is no `argparse` module. 

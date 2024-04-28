import socket
import threading
import sys
import argparse
import pyfiglet
from datetime import datetime

# some colors
class bcolors:
    BLUE = '\033[94m'
    RED = '\033[31m'
    GREEN = '\033[92m'
    GOLD = '\033[93m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


# creating the tcp socket
def portscan(target, port, lock, isfilter):
    # use IPv4, tcp
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # socket connetcion setup-time limit for 0.5s
    s.settimeout(0.5)
    isOpen = False
    try:
        con = s.connect((target,port))
        lock.acquire()  
        print(bcolors.GREEN + "[+] " + 'Port:', port, "status: Open")
        open_ports.append(port)
        lock.release()
    except socket.timeout as e:
        lock.acquire()  
        if not isfilter:
            print(bcolors.RED + "[x] " + 'Port:', port, "Status: Timeout")
            # print(bcolors.WARNING + "[-] " + str(e))
        lock.release()
    except socket.error as e:
        lock.acquire()  
        if not isfilter:
            print(bcolors.RED + "[x] " + 'Port:', port, "Status: Error:", str(e))
        lock.release()
    finally:
        s.close()
# add banner
def printBanner(width):
    ascii_banner = pyfiglet.figlet_format('TCP Port Scanner', font="slant", width=100)
    print (bcolors.BLUE + ascii_banner)
    print (bcolors.BLUE + "writed by @slacr".rjust(width))
    print (bcolors.BLUE + "inspired by @bvr0n".rjust(width) + bcolors.ENDC)


open_ports = []
def main():
    target = ""
    width = 80
    printBanner(width)

    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help='set Target')
    parser.add_argument('-p', '--port', help='set Port Range (e.g. 1-2000 or 80)')
    parser.add_argument('-f', '--filter', action='store_true', help='only show open ports')
    args = parser.parse_args()


    if not args.target or not args.port:
        parser.print_help()
        exit()
    else:
        target = args.target
        port_range = args.port
    
    print(bcolors.GOLD + "-" * width)
    print("Scanning Target: " + target)
    start_time = datetime.now()
    print("Scanning started at:" + str(start_time))
    print("-" * width)
    print (bcolors.BOLD + "[+] Scanning TCP Ports: " + port_range)

    if '-' in port_range:
        start_port, end_port = port_range.split('-')
        start_port = int(start_port)
        end_port = int(end_port)
    else:
        start_port = int(port_range)
        end_port = int(port_range)
    
    # create thread lock, synchronize print out
    lock = threading.Lock() 

    # thread list
    threads = []
    
    # muti-thread portscan
    for port in range(start_port, end_port+1):
        t = threading.Thread(target=portscan,kwargs={'target':target, 'port':port, 'lock':lock, 'isfilter':args.filter})
        threads.append(t)
        t.start()
    
    # wait for all threads to finish
    for t in threads:
        t.join()
    
    # end
    print(bcolors.GOLD + "-" * width)
    print(bcolors.GOLD + "open_ports:" + " ".join(map(str, open_ports)))
    end_time = datetime.now()
    print("Scanning finished at:" + str(end_time))
    print("Scanning duration:", format((end_time - start_time).total_seconds() * 1000, '.6f'), "ms")
    print("-" * width)
if __name__ == '__main__':
    main()
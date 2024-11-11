#!/usr/bin/env python3

import os
import signal
from scapy.all import *
from netfilterqueue import NetfilterQueue
import argparse

window_size = 17

def modify_window(pkt):
    try:
        ip = IP(pkt.get_payload())
        print(ip)
        if ip.haslayer(TCP) and ip[TCP].flags == "SA":
            ip[TCP].window = window_size
            del ip[IP].chksum
            del ip[TCP].chksum
            pkt.set_payload(bytes(ip))
        elif ip.haslayer(TCP) and ip[TCP].flags == "FA":
            ip[TCP].window = window_size
            del ip[IP].chksum
            del ip[TCP].chksum
            pkt.set_payload(bytes(ip))
        elif ip.haslayer(TCP) and ip[TCP].flags == "PA":
            ip[TCP].window = window_size
            del ip[IP].chksum
            del ip[TCP].chksum
            pkt.set_payload(bytes(ip))
        elif ip.haslayer(TCP) and ip[TCP].flags == "A":
            ip[TCP].window = window_size
            del ip[IP].chksum
            del ip[TCP].chksum
            pkt.set_payload(bytes(ip))
    except:
        pass

    pkt.accept()

def parsearg():
    global window_size  
    parser = argparse.ArgumentParser(description='Description of your program')

    parser.add_argument('-q', '--queue', type=int, help='iptables Queue Num')
    parser.add_argument('-w', '--window_size', type=int, help='Tcp Window Size')

    args = parser.parse_args()
	
    if args.queue is None or args.window_size is None:
        exit(1)
    
    window_size = args.window_size  

    return args.queue

def main():
    queue_num = parsearg()
    nfqueue = NetfilterQueue()
    nfqueue.bind(queue_num, modify_window)

    try:
        print("Starting netfilter_queue process...")
        nfqueue.run()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    #sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
    signal.signal(signal.SIGINT, lambda signal, frame: sys.exit(0))
    main()



C 使用其他更底层的库实现上方python 一摸一样的功能

# 访问后打印
# Starting netfilter_queue process...
# IP / TCP 10.3.4.6:8123 > 106.225.239.7:57212 SA




# Ubuntu安装依赖(Ubuntu 22测试已通过)
# sudo apt-get install build-essential python3-dev libnetfilter-queue-dev libffi-dev libssl-dev iptables python3-pip -y
# pip3 install scapy netfilterqueue
#
# 运行处理程序
# nohup python3 geneva.py -q 100 -w 17 &
# nohup python3 geneva.py -q 101 -w 4 &
# iptables -I OUTPUT -p tcp --sport 80 --tcp-flags SYN,RST,ACK,FIN,PSH SYN,ACK -j NFQUEUE --queue-num 100
# iptables -I OUTPUT -p tcp --sport 443 --tcp-flags SYN,RST,ACK,FIN,PSH SYN,ACK -j NFQUEUE --queue-num 101
#
#
# 使用C++ 的 libtins 结合 libnetfilter_queue 和 iptables，实现完全上面python程序一摸一样的功能


# python3 -m venv ~/genv/env
# source ~/genv/env/bin/activate
# deactivate

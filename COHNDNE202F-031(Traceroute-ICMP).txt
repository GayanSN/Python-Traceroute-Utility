#! /usr/bin/python3

import socket
import sys
from struct import *
from ctypes import *
import time
import random
import netifaces as ni

ETH_P_IP = 0x0800

class IPv4(Structure):
    _fields_ = [
            ("ver", c_ubyte, 4),
            ("ihl", c_ubyte, 4),
            ("tos", c_ubyte),
            ("len", c_ushort),
            ("id", c_ushort),
            ("offset", c_ushort),
            ("ttl_val", c_ubyte),
            ("protocol_num", c_ubyte),
            ("checksum", c_ushort),
            ("src", c_uint),
            ("dst", c_uint)
            ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):

        self.src_address = socket.inet_ntoa(pack("@I",self.src))
        self.dst_address = socket.inet_ntoa(pack("@I",self.dst))
        self.ttl = self.ttl_val


class ICMP(Structure):
    _fields_ = [
            ("typ", c_ubyte),
            ("codee", c_ubyte),
            ("checksum", c_ushort),
            ("identifier", c_ushort),
            ("seq_num", c_ushort)
            ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):

        self.type = self.typ
        self.code = self.codee


def create_icmp(sq):

    ts = int(time.time())       ##get the timestamp
    timestamp = pack(">i", ts)  ##convert into byte order (">i" --> big-endian,int) 

    icmp_type = 8         ##8 --> ICMP echo request
    icmp_code = 0
    icmp_checksum = 0
    icmp_identifier = 123
    icmp_seq_num = sq     ##increasing Sequence number 
    icmp_time = timestamp   ##Timestamp of the echo request

    icmp_header = pack('!BBHHH8s', icmp_type, icmp_code, icmp_checksum, icmp_identifier, icmp_seq_num, icmp_time)

    dataa = b'!"#$%&()*+,-./0123456789!"#$%&()*+,-./0123456789'       ##create a  48-byte data field 

    cal_checksum = checksum(icmp_header + dataa)  ##calculating checksum of the header + data

    icmp_header = pack('!BBHHH8s', icmp_type, icmp_code, socket.htons(cal_checksum), icmp_identifier, icmp_seq_num, icmp_time) 

    return icmp_header + dataa   ##return icmp header and data field to add to the ip header 


def checksum(msg):

    sum = 0
    count_to = (len(msg) / 2) * 2
    count = 0

    while count < count_to:
        val = (msg[count + 1])*256+(msg[count])
        sum = sum + val
        count = count + 2

        if count_to < len(msg):
            sum = sum + (msg[len(msg) - 1])

    #Add the higher 16 bits to the lower 16 bits
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)   #If there are more than 16 bits, it will continue to add to the lower 16 bits
    ans = ~sum & 0xffff    #Negating sum (returned in decimal)

    return ans


def create_ip(idn, ttl, icmp_h):

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 84
    ip_id = idn
    ip_frag_off = 0
    ip_ttl_val = ttl
    ip_prot = 1
    ip_checksum = 0
    ip_saddr = socket.inet_aton(ip)
    ip_daddr = socket.inet_aton(host)

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl_val, ip_prot, ip_checksum, ip_saddr, ip_daddr)

    packet = ip_header + icmp_h    ##create packet including IP header and ICMP header

    sock.sendto(packet, (host, 0))

def cal_rtt(send_time, recv_time):

    time = (recv_time - send_time)*1000   ##calculate round trip time and covert to miliseconds
    time = round(time, 3)
    return time


def traceroute():
        idn = random.randint(0,65535)
        ttl = 1         ##initial Time to Live value is 1 and counting up to 30
        count = 1
        sq = 1

        while True:
            try:
                icmp_h = create_icmp(sq)
                send_time = time.time()
                create_ip(idn, ttl, icmp_h)
                idn += 1

                s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('enp0s3', 0))
                s.settimeout(5)

                data = s.recvfrom(65565)[0]
                ip = IPv4(data[14:])
                icmp = ICMP(data[34:])

                if icmp.typ == 11:              ##check for "time exceeded" message
                    recv_time = time.time()
                    rtt = cal_rtt(send_time, recv_time) ##calling function to calculate round trip time

                    try:
                        (hostname, _, ip_list) = socket.gethostbyaddr(ip.src_address)
                        ip_address = ip_list[0]
                        print(f"{count}  {hostname}  ({ip_address})  {rtt} ms")
                        count += 1
                    except socket.herror:
                        ip_address = ip.src_address
                        print(f"{count}  {ip_address}   {rtt} ms")
                        count += 1
                
                elif icmp.type == 3 and icmp.code == 3:  ##check for "protocol unreachable" message
                    recv_time = time.time()
                    rtt = cal_rtt(send_time, recv_time)  ##calling function to calculate round trip time

                    try:
                        (hostname, _, ip_list) = socket.gethostbyaddr(ip.src_address)
                        ip_address = ip_list[0]
                        print(f"{count}  {hostname}  ({ip_address})  {rtt} ms")
                        count += 1
                    except socket.herror:
                        ip_address = ip.src_address
                        print(f"{count}  {ip_address}   {rtt} ms")
                        count += 1

                    break

                if ttl == 30:
                    break

                ttl += 1
                sq += 1
            
            except socket.timeout:
                print(f"{count}  *  *  *")  ##executes if a timeout is occured
                count += 1
                continue

            except KeyboardInterrupt:
                exit(1)

            except Exception as e:
                print(e)
                exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("[-]usage: " + str(sys.argv[0]) + " <IP_address>")
        exit(1)

    host = str(sys.argv[1])
    ip = ni.ifaddresses('enp0s3')[ni.AF_INET][0]['addr']  ##get the IP address of the interface

    traceroute()  ##calling traceroute function

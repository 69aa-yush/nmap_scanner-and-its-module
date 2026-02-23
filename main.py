#syn scanning
#UDP scanning
#comprehensive

import nmap
scanner = nmap.PortScanner()
print("Welcome to our NMAP Port scanner !")
print("<------------------------------------->")

ip_addr = input("Please enter your IP Address you want to scan: ")
print("The IP address is:", ip_addr)
type(ip_addr)
resp = input("""\n Please enter the type of scan you want to perform

1. SYN ACK scan
2. UDP scan
3. Comprehensive scan
""")
print("You have selected option:",resp)
if resp == '1':
    print("Nmap Version:",scanner.nmap_version())
    scanner.scan(ip_addr,'1-1024','-v -sS')
    print(scanner.scaninfo())
    print("IP status:",scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports:",scanner[ip_addr]['tcp'].keys())
elif resp == '2':
    print("Nmap Version:",scanner.nmap_version())
    scanner.scan(ip_addr,'1-1024','-v -sU')
    print(scanner.scaninfo())
    print("IP status:",scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports:",scanner[ip_addr]['udp'].keys())
elif resp == '3':
    print("Nmap Version:",scanner.nmap_version())
    scanner.scan(ip_addr,'1-1024','-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("IP status:",scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports:",scanner[ip_addr]['tcp'].keys())
elif resp >='4':
    print("Invalid please enter a valid option")

import scapy.all as scapy
def scanner(ip):
    request = scapy.ARP(pdst = ip)

    broadcast = scapy.Ether()
    broadcast.dst = "ff:ff:ff:ff:ff:ff" #broadcastMAC

    request_broadcast = broadcast/request

    resp1 = scapy.srp(request_broadcast,timeout = 1) [0]
    for el in resp1:
        print(el[1].psrc)
        print(el[1].hwsrc)
        print("...............//////")

scanner("192.168.1.1/24")
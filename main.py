from scapy.all import *
from colorama import Fore, init

init(autoreset=True)

dst_ip = "192.168.0.1/24"
arp = ARP(pdst=dst_ip)

ether = Ether(dst="ff:ff:ff:ff:ff:ff")
packet = ether/arp

result = srp(packet, timeout=3)[0]

clients = []
ips = []
macs = []

for sent, received in result:
    clients.append({'ip': received.psrc, 'mac': received.hwsrc, 'name': received.payload.name})
    if received.psrc != "192.168.0.8" and received.hwsrc != "5c:ba:ef:9a:65:9f":
        ips.append(received.psrc)
        macs.append(received.hwsrc)

print(Fore.GREEN + "Available devices:")
print(Fore.GREEN + "IP" + " "*18 + "MAC" + " "*18 + "Name")
for client in clients:
    print(Fore.YELLOW + "{:16}    {}    {}".format(client['ip'], client['mac'], client['name']))


for i in range(0, len(ips)):
    print(Fore.YELLOW + f"Now scanning ports for {ips[i]}")
    for port in range(0, 1000):
        pkt = IP(dst=ips[i])/TCP(flags="S", dport=port)
        result = sr(pkt, timeout=1, verbose=0)[0]
        if result:
            for sent, received in result:
                if received[TCP].flags == 18:
                    print(Fore.GREEN + f"Port {port} is open.")


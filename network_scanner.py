import scapy.all as scapy
from scapy.all import getmacbyip
import optparse
def get_aruguments(): #Function to parse command-line arguments.
    parser=optparse.OptionParser()
    parser.add_option("--target", dest="ip", help="enter the target ip ")
    (options,argumets)=parser.parse_args()
    if options.ip:
        return options
    else:
        parser.error("please specify a IP to scan in the format of --target {ip}")

def scanner(ip):
    arp_request=scapy.ARP(pdst=ip)  #Creating ARP request packet
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  #Creating broadcast packet
    arp_request_broadcast=broadcast/arp_request #combining both request packet and broadcast packet
    answer_list=scapy.srp(arp_request_broadcast, timeout=1,verbose=False)[0]  #Sending packets and receiving responses
    print("IP\t\t\tMAC_ADDRESS\t\t\tVENDOR_NAME\n---------------------------------------------------------------------------")
    for value in answer_list:
        print(value[1].psrc+"\t\t"+value[1].hwsrc+"\t\t"+get_vendor(value[1].hwsrc))
    print("---------------------------------------------------------------------------")
def get_vendor(mac_address):
    try:
        vendor = getmacbyip(mac_address) #Retrieving vendor name
    except:
        vendor = "N/A"
    return vendor

result=get_aruguments()
scanner(result.ip)



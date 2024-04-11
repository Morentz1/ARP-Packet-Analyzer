import sys
import dpkt



# given byte info, return mac_addr in string format
def get_mac_addr(addr):
    addr = addr.hex()
    mac = ""

    for index, num in enumerate(addr):
        if index % 2 == 0:
            mac += ":"
        mac += str(num)
    return mac[1:]

# given byte info, return ip in string format
def get_ip(ip):
    res = ""
    for num in ip:
        res += (str(num) + ".")    

    return res[:-1]

if __name__ == "__main__":
    # handles case if no files is provided as input
    if len(sys.argv) == 1:
        print("No pcap file provided")
        exit()
    
    file = sys.argv[1]

    # handles case if file given is not pcap file
    if not file or not ".pcap" in file:
        print("Not a valid pcap file")
        exit()
    
    arp_packets = []
    # reads pcap file
    with open(file, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        packets = pcap.readpkts()
        # filter for arp packets
        for ts,buf in packets:
            if buf[12:14] == b'\x08\x06':
                arp_packets.append(buf)
    
    request = []
    reply = []
    # filter through request and reply packet
    for p in arp_packets:
        # if packet is not broadcast packet
        if p[0:6] != b'\xff\xff\xff\xff\xff\xff':
            # check if opCode is 1 for request. else then it is a reply
            if p[20:22] == b'\x00\x01':
                request.append(p)
            else:
                reply.append(p)
    
    # if no arp packets are found, alert user and exit
    if len(arp_packets) == 0:
        print("No ARP packets found")
        exit()
    
    # print # of arp packets
    print("ARP packets found:", len(arp_packets))


    # if request packets exist, print first one, else alert user
    if len(request) != 0:
        req = request[0]
        print("-" * 10 + "ARP Request" + "-" * 10)
        print("Hardware Type:", str(int.from_bytes(req[14:16], "big")))
        print("Protocol Type: 0x" + str(req[16:18].hex()))
        print("Hardware Size:", str(req[18]))
        print("Protocol Size:", str(req[19]))
        print("OpCode: request (" + str(int.from_bytes(req[20:22], "big")) + ")")
        print("Sender MAC Address:", get_mac_addr(req[22:28]))
        print("Sender IP Address:", get_ip(req[28:32]))
        print("Target MAC Address:", get_mac_addr(req[32:38]))
        print("Target IP Address:", get_ip(req[38:42]))
    else:
        print("No request packets found")

    # if reply packets exist, print first one. else alert user
    if len(reply) != 0:
        req = reply[0]
        print("-" * 10 + "ARP Reply" + "-" * 10)
        print("Hardware Type:", str(int.from_bytes(req[14:16], "big")))
        print("Protocol Type: 0x" + str(req[16:18].hex()))
        print("Hardware Size:", str(req[18]))
        print("Protocol Size:", str(req[19]))
        print("OpCode: reply (" + str(int.from_bytes(req[20:22], "big")) + ")")
        print("Sender MAC Address:", get_mac_addr(req[22:28]))
        print("Sender IP Address:", get_ip(req[28:32]))
        print("Target MAC Address:", get_mac_addr(req[32:38]))
        print("Target IP Address:", get_ip(req[38:42]))
    else:
        print("No reply packets found")


    
    




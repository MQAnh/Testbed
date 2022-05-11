from collections import Counter
from scapy.all import sniff

packet_counts = Counter()

capturedPacketsSize = 0

## Define our Custom Action function
def custom_action(packet):
    # Create tuple of Src/Dst in sorted order
    global capturedPacketsSize
    global packet_counts
    capturedPacketsSize += len(packet)     #here occurs error
    key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
    packet_counts.update([key])
    #return "Packet #{0}: {1} ==> {2}".format(sum(packet_counts.values()), packet[0][1].src, packet[0][1].dst)



print("_____.:|Entering infinite while loop|:._____")

while 1:
    print("Analysing Multicast packets")
    pkt = sniff(filter="ip", prn=custom_action, timeout=1)
    print("\n".join("{0} <--> {1} :{2}".format(key[0], key[1], count) for key, count in packet_counts.items()))
    total_packet = sum(packet_counts.values())
    packet_counts.clear()
    print("Byterate for this moment is equal to: {0} Bytes per second - {1} pps".format(capturedPacketsSize, total_packet))

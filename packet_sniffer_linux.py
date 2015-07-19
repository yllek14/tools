##__author__ = 'Kelly'
##packet_sniffer_linux.py


import socket
import sys
import struct
import re



def receiveData(s):
    data = ''
    try:
        data = s.recvfrom(65565)
    except timeout:
        data = ''
    except:
        print("An error occured")
        sys.exc_info()
    return data[0]

# get the Type of Service
def getTOS(data):
    tabs = '\n\t\t\t' #to make the concatenation of data easier

    #this is the type of data that is in the TOS of an IP header
    #I've created dictionaries and the bit number will correspond with
    #each value

    precedence = {0: "Routine", 1: "Priority", 2: "Immediate", 3: "Flash", 4: "Flash Override", 5: "CRITIC/ECP",6: "Internetwork Control", 7: "Network Control"}
    delay = {0: 'Normal Delay', 1: 'Low Delay'}
    throughput = {0: 'Normal Throughput', 1: 'High Throughput'}
    reliability = {0: 'Normal Reliablity', 1: 'High Reliablity'}
    cost = {0: 'Normal Cost', 1: 'Minimize Cost'}
    #this section collects the data and 'ANDS' to remove all but the
    #bits that will give the length then moves over the corresponding bits
    D = data & 0x10
    D >>= 4
    T = data & 0x8
    T >>= 3
    R = data & 0x4
    R >>= 2
    M = data & 0x2
    M >>= 1

    TOS = precedence[data >> 5] + tabs + delay[D] + tabs + throughput[T] + tabs + reliability[R] + tabs + cost[M]
    return TOS

def getFlags(data):
    tabs = '\n\t\t\t'

    flagR = {0: "0 - Reserved bit"}
    flagDF = {0: "0 - Fragment if necessary", 1: "1 - Do not fragment"}
    flagMF = {0: "0 - Last fragment", 1: "1 - More fragments"}

    R = data & 0x8000
    R >>= 15
    DF = data & 0x4000
    DF >>= 14
    MF = data & 0x2000
    MF >>= 13

    flags = flagR[R] + tabs + flagDF[DF] + tabs + flagMF[MF]
    return flags

def getProtocol(protocolNr):
    protocolFile = open('Protocol.txt', 'r')
    protocolData = protocolFile.read()
    protocol = re.findall(r'\n' + str(protocolNr) + ' (?:.)+\n', protocolData)
    if protocol:
        protocol = protocol[0]
        protocol = protocol.replace('\n', '')
        protocol = protocol.replace(str(protocolNr), '')
        protocol = protocol.lstrip()
        return protocol
    else:
        return 'No such protocol'

#This should have the program capture multiple packets and put them in list
attempts = input("\n\nHow many packets would you like to capture? ") #syntax error edit
dataList = []

for i in range(attempts):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    data = receiveData(s)
    #appends the data to the list
    dataList.append(data)
    i += 1
#dataList should have 10 objects.
#This will pick out each object and unpack it
for ii in range(len(dataList)):
    #dataList is actually a list of lists. this next line of code pulls out a specific object
    #(which happens to be a list) and unpacks the up to the 20th position in THAT list
    unpackedData = struct.unpack('!BBHHHBBH4s4s' , dataList[ii][:20])

    #assigning variables to each part of a packet
    version_IHL = unpackedData[0] #this will give us the IP version(IP4 or IP6)
    version = version_IHL >> 4 #reads the first 4 bits of data
    IHL = version_IHL & 0xF #ands the data
    TOS = unpackedData[1]
    totalLength = unpackedData[2]
    ID = unpackedData[3]
    flags = unpackedData[4]
    fragmentOffset = unpackedData[4] & 0x1FFF
    TTL = unpackedData[5]
    protocolNr = unpackedData[6]
    checksum = unpackedData[7]
    sourceAddress= socket.inet_ntoa(unpackedData[8])
    destinationAddress = socket.inet_ntoa(unpackedData[9])

    print("\n\nAn IP packet with the size %i was captured." % (unpackedData[2]))
    #print("Raw data: " + str(data)) #Too bulky and not necessary at this time.
    print("\n\nParsed data")
    print("Version:\t\t" + str(version))
    print("Header Length:\t\t" + str(IHL*4) + " bytes")
    print("Type of Service:\t" + getTOS(TOS))
    print("Length:\t\t\t" + str(totalLength))
    print("ID:\t\t\t" + str(hex(ID)) + " (" + str(ID) + ")")
    print("Flags:\t\t\t" + getFlags(flags))
    print("Fragment offset:\t" + str(fragmentOffset))
    print("TTL:\t\t\t" + str(TTL))
    print("Protocol:\t\t" + getProtocol(protocolNr))
    #print("Protocol:\t\t" + str(protocolNr)) #A test run while trying to parse the data
    print("Checksum:\t\t" + str(checksum))
    print("Source:\t\t\t" + sourceAddress)
    print("Destination:\t\t" + destinationAddress)
    #print("Payload:\n" + str(data[20:])) #unnecessary at this time
    ii =+ 1

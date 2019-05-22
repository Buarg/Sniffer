import socket
import struct

def CompruebaChecksum(Cabecera):
    suma = 0
    for word in Cabecera:
        suma = suma + word
    suma = (suma % 65536) + (suma // 65536)
    suma = 65535 - suma
    return suma == 0

def IPHeader(datos):
    packetdata = datos

    CabeceraIP = struct.unpack('!BBHHHBBHBBBBBBBB', packetdata[:20])
    CabeceraChecksum = struct.unpack('!HHHHHHHHHH', packetdata[:20])
    datos = packetdata[20:]

    print("Cabecera IP = ", CabeceraIP)
    print("Datos = ")

    TotalLength = CabeceraIP[2]
    i2 = (TotalLength // 4)
    for i in (range(i2)):
        print('{0:3d}: {1:4d} {2:4d} {3:4d} {4:4d}'.format(i, packetdata[4 * i], packetdata[4 * i + 1], packetdata[4 * i + 2], packetdata[4 * i + 3]))

    VersionIPandHeaderLength = CabeceraIP[0]
    VersionIP = VersionIPandHeaderLength >> 4
    print("Version IP = ", VersionIP)
    IHL = VersionIPandHeaderLength & 0x0F
    print("IHL = ", IHL)

    DifferentiatedServices = CabeceraIP[1]
    print("Differentiated Services = ", DifferentiatedServices)

    TotalLength = CabeceraIP[2]
    print("Total Length = ", TotalLength)

    Identification = CabeceraIP[3]
    print("Identification = ", Identification)

    Flags = CabeceraIP[4] >> 13
    print("Flags = ", Flags)
    if(Flags & 0b010):
        print("Don't Fragment")
    else:
        print("Fragment")
    if(Flags & 0b001):
        print("More fragments follow this fragmant")
    else:
        print("Last fragment")

    TTL = CabeceraIP[5]
    print("TTL = ", TTL)

    Protocol = CabeceraIP[6]
    print("Protocol = ", Protocol)

    Checksum = CabeceraIP[7]
    print("Checksum = ", Checksum, CompruebaChecksum(CabeceraChecksum))

    Source1 = CabeceraIP[8]
    Source2 = CabeceraIP[9]
    Source3 = CabeceraIP[10]
    Source4 = CabeceraIP[11]
    print("Source = ", Source1, ".", Source2, ".", Source3, ".", Source4)

    Destiny1 = CabeceraIP[12]
    Destiny2 = CabeceraIP[13]
    Destiny3 = CabeceraIP[14]
    Destiny4 = CabeceraIP[15]
    print("Destiny = ", Destiny1, ".", Destiny2, ".", Destiny3, ".", Destiny4)

    if (Protocol == 1):
        ICMPHeader(datos)
    elif (Protocol == 6):
        TCPHeader(datos)
    elif (Protocol == 17):
        UDPHeader(datos)

def UDPHeader(datos):
    packetdata = datos

    CabeceraUDP = struct.unpack('!HHHH', packetdata[:8])
    datos = packetdata[8:]

    print("Cabecera UDP = ", CabeceraUDP)

    SourcePort = CabeceraUDP[0]
    print("Source Port = ", SourcePort)

    DestinyPort = CabeceraUDP[1]
    print("Destiny Port = ", DestinyPort)

    TotalLength = CabeceraUDP[2]
    print("Total Length = ", TotalLength)

    Checksum = CabeceraUDP[3]
    print("Checksum = ", Checksum)

    DNSHeader(datos)

def TCPHeader(datos):
    packetdata = datos

    CabeceraTCP = struct.unpack('!HHLLHHHH', packetdata[:20])
    datos = packetdata[20:]

    print("Cabecera TCP = ", CabeceraTCP)

    SourcePort = CabeceraTCP[0]
    print("Source Port = ", SourcePort)

    DestinyPort = CabeceraTCP[1]
    print("Destiny Port = ", DestinyPort)

    SecuenceNumber = CabeceraTCP[2]
    print("Secuence Number = ", SecuenceNumber)

    AckNumber = CabeceraTCP[3]
    print("Acknowledgement Number = ", AckNumber)

    Length = CabeceraTCP[4] >> 12
    print("Length = ", Length)

    Flags = CabeceraTCP[4] << 10
    Flags = Flags >> 10
    print("Flags = ", Flags)

    if(Flags & 0b100000):
        print("URG")
    if(Flags & 0b010000):
        print("ACK")
    if(Flags & 0b001000):
        print("PSH")
    if(Flags & 0b000100):
        print("RST")
    if(Flags & 0b000010):
        print("SYN")
    if(Flags & 0b000001):
        print("FIN")

    WindowSize = CabeceraTCP[5]
    print("Window Size = ", WindowSize)

    Checksum = CabeceraTCP[6]
    print("Checksum = ", Checksum)

    UrgentPointer = CabeceraTCP[7]
    print("Urgent Pointer = ", UrgentPointer)

def ICMPHeader(datos):
    packetdata = datos

    CabeceraICMP = struct.unpack('!BBH', packetdata[:4])
    datos = packetdata[4:]

    print("Cabecera ICMP = ", CabeceraICMP)

    Type = CabeceraICMP[0]
    if(Type == 0):
        print("Type = ", Type, " = Echo reply")
    elif(Type == 3):
        print("Type = ", Type, " = Destination unreachable")
    elif(Type == 4):
        print("Type = ", Type, " = Source quench")
    elif(Type == 5):
        print("Type = ", Type, " = Redirect")
    elif(Type == 6):
        print("Type = ", Type, " = Alternate host address")
    elif(Type == 8):
        print("Type = ", Type, " = Echo request")
    elif(Type == 9):
        print("Type = ", Type, " = Router advertisement")
    elif(Type == 10):
        print("Type = ", Type, " = Router solicitation")
    elif(Type == 11):
        print("Type = ", Type, " = Time exceeded")
    elif(Type == 12):
        print("Type = ", Type, " = Parameter problem")
    elif(Type == 13):
        print("Type = ", Type, " = Timestamp request")
    elif(Type == 14):
        print("Type = ", Type, " = Timestamp reply")
    elif(Type == 17):
        print("Type = ", Type, " = Address mask request")
    elif(Type == 18):
        print("Type = ", Type, " = Address mask reply")
    elif(Type == 30):
        print("Type = ", Type, " = Traceroute")
    elif(Type == 31):
        print("Type = ", Type, " = Conversion error")
    elif(Type == 32):
        print("Type = ", Type, " = Mobile Host Redirect")
    elif(Type == 33):
        print("Type = ", Type, " = IPv6 Where-Are-You")
    elif(Type == 34):
        print("Type = ", Type, " = IPv6 I-Am-Here")
    elif(Type == 35):
        print("Type = ", Type, " = Mobile Registration Request")
    elif(Type == 36):
        print("Type = ", Type, " = Mobile Registration Reply")
    elif(Type == 37):
        print("Type = ", Type, " = Domain Name Request")
    elif(Type == 38):
        print("Type = ", Type, " = Domain Name Reply")
    elif(Type == 39):
        print("Type = ", Type, " = SKIP Algorithm Discovery Protocol")

    Code = CabeceraICMP[1]
    if(Type == 3 and Code == 0):
        print("Code = ", Code, " = Net is unreachable")
    elif(Type == 3 and Code == 1):
        print("Code = ", Code, " = Host is unreachable")
    elif(Type == 3 and Code == 2):
        print("Code = ", Code, " = Protocol is unreachable")
    elif(Type == 3 and Code == 3):
        print("Code = ", Code, " = Port is unreachable")
    elif(Type == 3 and Code == 4):
        print("Code = ", Code, " = Fragmentation is needed and Don't Fragment was set")
    elif(Type == 3 and Code == 5):
        print("Code = ", Code, " = Source route failed")
    elif(Type == 3 and Code == 6):
        print("Code = ", Code, " = Destination network is unknown")
    elif(Type == 3 and Code == 7):
        print("Code = ", Code, " = Destination host is unknown")
    elif(Type == 3 and Code == 8):
        print("Code = ", Code, " = Source host is isolated")
    elif(Type == 3 and Code == 9):
        print("Code = ", Code, " = Communication with destination network is administratively prohibited")
    elif(Type == 3 and Code == 10):
        print("Code = ", Code, " = Communication with destination host is administratively prohibited")
    elif(Type == 3 and Code == 11):
        print("Code = ", Code, " = Destination network is unreachable for type of service")
    elif(Type == 3 and Code == 12):
        print("Code = ", Code, " = Destination host is unreachable for type of service")
    elif(Type == 3 and Code == 13):
        print("Code = ", Code, " = Communication is administratively prohibited")
    elif(Type == 3 and Code == 14):
        print("Code = ", Code, " = Host precedence violation")
    elif(Type == 3 and Code == 15):
        print("Code = ", Code, " = 	Precedence cutoff is in effect")
    elif(Type == 5 and Code == 0):
        print("Code = ", Code, " = Redirect datagram for the network (or subnet")
    elif(Type == 5 and Code == 1):
        print("Code = ", Code, " = Redirect datagram for the hos")
    elif (Type == 5 and Code == 2):
        print("Code = ", Code, " = Redirect datagram for the type of service and network")
    elif(Type == 5 and Code == 3):
        print("Code = ", Code, " = Redirect datagram for the type of service and host")
    elif(Type == 11 and Code == 0):
        print("Code = ", Code, " = 	Time to Live exceeded in transit")
    elif(Type == 11 and Code == 1):
        print("Code = ", Code, " = 	Fragment reassembly time exceeded")
    elif(Type == 12 and Code == 0):
        print("Code = ", Code, " = Pointer indicates the error")
    elif(Type == 12 and Code == 1):
        print("Code = ", Code, " = Missing a required option")
    elif(Type == 12 and Code == 2):
        print("Code = ", Code, " = 	Bad length")

    Checksum = CabeceraICMP[2]
    print("Checksum = ", Checksum)

def DNSHeader(datos):
    packetdata = datos

    CabeceraDNS = struct.unpack('!LHBBLLLL', packetdata[:24])
    datos = packetdata[24:]

    ID = CabeceraDNS[0]
    print("ID = ", ID)

    QR = CabeceraDNS[1] >> 7
    print("QR = ", QR)

    Opcode = CabeceraDNS[1] << 1
    Opcode = Opcode >> 4
    print("Opcode = ", Opcode)

    AA = CabeceraDNS[1] << 5
    AA = AA >> 7
    print("AA = ", AA)

    TC = CabeceraDNS[1] << 6
    TC = TC >> 7
    print("TC = ", TC)

    RD = CabeceraDNS[1] << 7
    RD = RD >> 7
    print("RD = ", RD)

    RA = CabeceraDNS[2] >> 3
    print("RA = ", RA)

    RCode = CabeceraDNS[3]
    print("RCode = ", RCode)

    QDCount = CabeceraDNS[4]
    print("QDCount = ", QDCount)

    ANCount = CabeceraDNS[5]
    print("ANCount = ", ANCount)

    NSCount = CabeceraDNS[6]
    print("NSCount = ", NSCount)

    ARCount = CabeceraDNS[7]
    print("ARCount = ", ARCount)

# the public network interface
print(socket.gethostname())
HOST = socket.gethostbyname(socket.gethostname())
INFO = socket.gethostbyname_ex(HOST)
print(INFO)
print(HOST)

# create a raw socket and bind it to the public interface
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
s.bind((HOST, 0))

# Include IP headers
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# receive all packages
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# receive a package
datos = s.recvfrom(65565)
IPHeader(datos[0])

# disabled promiscuous mode
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)



import net
import parseopt
from strutils import parseInt, split, toHex


var foundOpen: seq[string]

const banner = """
 _   _ ___ __  __    _    ____  
| \ | |_ _|  \/  |  / \  |  _ \ 
|  \| || || |\/| | / _ \ | |_) |
| |\  || || |  | |/ ___ \|  __/ 
|_| \_|___|_|  |_/_/   \_\_|    
                                
"""
echo (banner)

var
    startPort = -1
    endPort = -1
    host = "localhost"

for kind, key, val in getopt():
    case kind
    of cmdArgument:
        host = key
    else:
        case key
        of "startPort":
            startPort = parseInt(val)
        of "endPort":
            endPort = parseInt(val)
        else:
            echo "Argument not recognised: ", key

if startPort == -1 or endPort == -1:
    echo "Must set startPort and endPort"
    quit(QuitFailure)

proc ipToHexString(ip: string): string =
    var ip = ip
    if ip == "localhost":
        ip = "127.0.0.1"
    assert ip.isIpAddress()
    let parts = ip.split(".")
    for part in parts:
        result.add(chr(parseInt(part)))

proc portToHexString(port: int): string =
    let a = (port shr 8) and 0xff
    let b = port and 0xff
    return chr(a) & chr(b)

proc generateIpHeader(sourceAddress: string, destinationAddress: string): string =
    var ipHeader: string
    ipHeader.add("\x45\x00\x00\x28")  # Version, IHL, Type of Service | Total Length
    ipHeader.add("\xab\xcd\x00\x00")  # Identification | Flags, Fragment Offset
    ipHeader.add("\x40\x06\xa6\xec")  # TTL, Protocol | Header Checksum
    ipHeader.add(ipToHexString(sourceAddress))  # Source Address
    ipHeader.add(ipToHexString(destinationAddress))  # Destination Addressor
    return ipHeader

proc generateTcpHeader(sourcePort: int, destinationPort: int): string =
    var tcpHeader: string
    tcpHeader.add(portToHexString(sourcePort) & portToHexString(destinationPort)) # Source Port | Destination Port
    tcpHeader.add("\x00\x00\x00\x00") # Sequence Number
    tcpHeader.add("\x00\x00\x00\x00") # Acknowledgement Number
    tcpHeader.add("\x50\x02\x71\x10") # Data Offset, Reserved, Flags | Window Size
    tcpHeader.add("\xe6\x32\x00\x00") # Checksum | Urgent Pointer)
    return tcpHeader

assert "\x7f\x00\x00\x01" == ipToHexString("localhost")
assert "\x13\x8d" == portToHexString(5005)

echo "Scanning ", host, " from ", startPort, " to ", endPort
for port in startPort..endPort:
    let socket = newSocket(AF_INET, SOCK_RAW, IPPROTO_RAW)
    # socket.setSockOpt()
    try:
        socket.connect(host, Port(port))
        let (laddr, lport) = socket.getLocalAddr()
        let ipHeader = generateIpHeader("localhost", host)
        let tcpHeader = generateTcpHeader(int(lport), port)
        socket.send(ipHeader & tcpHeader)
        let data = socket.recv(1024, timeout=5000)
        echo data
        foundOpen.add($port)
    except:
        let m = getCurrentExceptionMsg()
        case m
        of "Connection refused":
            discard
        else:
            echo "Could not connect to \"", host, "\". ", m 
            quit(QuitFailure)
    finally:
        socket.close()

for port in foundOpen:
    echo "Found open port: ", port

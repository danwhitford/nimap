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

proc ipToWords(ip: string): string =
    var ip = ip
    if ip == "localhost":
        ip = "127.0.0.1"
    assert ip.isIpAddress()
    let parts = ip.split(".")
    for part in parts:
        result.add(chr(parseInt(part)))

proc intToWord(port: int): string =
    let a = (port shr 8) and 0xff
    let b = port and 0xff
    return chr(a) & chr(b)

proc wordToInt(w: string): int =
  let a = ord(w[0]) shl 8
  let b = ord(w[1])
  return a + b

proc generateTcpPseudoHeader(sourceIp: string, destIp: string, length: int): string =
    var header: string
    header.add("\x00\x06") # Protocol
    header.add(ipToWords(sourceIp))
    header.add(ipToWords(destIp))
    header.add(intToWord(length))
    return header

proc generateIpHeader(sourceAddress: string, destinationAddress: string): string =
    var ipHeader: string
    ipHeader.add("\x45\x00\x00\x28")  # Version, IHL, Type of Service | Total Length
    ipHeader.add("\xab\xcd\x00\x00")  # Identification | Flags, Fragment Offset
    ipHeader.add("\x40\x06\x00\x00")  # TTL, Protocol | Header Checksum
    ipHeader.add(ipToWords(sourceAddress))  # Source Address
    ipHeader.add(ipToWords(destinationAddress))  # Destination Addressor
    return ipHeader

proc generateTcpHeader(sourcePort: int, destinationPort: int): string =
    var tcpHeader: string
    tcpHeader.add(intToWord(sourcePort) & intToWord(destinationPort)) # Source Port | Destination Port
    tcpHeader.add("\x00\x00\x00\x00") # Sequence Number
    tcpHeader.add("\x00\x00\x00\x00") # Acknowledgement Number
    tcpHeader.add("\x50\x02\x71\x10") # Data Offset, Reserved, Flags | Window Size
    tcpHeader.add("\x00\x00\x00\x00") # Checksum | Urgent Pointer)
    return tcpHeader

proc getCarryOver(i: int): int =
    return i shr 16

proc checksumForTcpHeader(sourceIp: string, sourcePort: int, destIp: string, destPort: int): string =
    let header = generateTcpPseudoHeader(sourceIp, destIp, 20) & generateTcpHeader(sourcePort, destPort)
    var sum: int
    for i in countup(0, header.len - 2, 2):
        let a = header.substr(i, i+1)
        sum += wordToInt(a)
    
    sum += getCarryOver(sum) # Removing the carryover
    sum = 0xffff - sum # Negate
    return intToWord(sum)

proc checksumForIpHeader(ipHeader: string): string =
    var sum: int
    for i in countup(0, ipHeader.len - 2, 2):
        let a = ipHeader.substr(i, i+1)
        sum += wordToInt(a)
    
    sum += getCarryOver(sum) # Removing the carryover
    sum = 0xffff - sum # Negate
    return intToWord(sum)

proc generateTcpFullHeader(sourceIp: string, sourcePort: int, destIp: string, destPort: int): string =
    let header = generateTcpHeader(sourcePort, destPort)
    let checksum = checksumForTcpHeader(sourceIp, sourcePort, destIp, destPort)
    return header.substr(0, 15) & checksum & "\x00\x00"

proc generateIpFullHeader(sourceIp: string, destIp: string): string =
    let header = generateIpHeader(sourceIp, destIp)
    let checksum = checksumForIpHeader(header)
    return header.substr(0, 9) & checksum & header.substr(12)

assert "\x7f\x00\x00\x01" == ipToWords("localhost")
assert "\x13\x8d" == intToWord(5005)

echo "Scanning ", host, " from ", startPort, " to ", endPort
for port in startPort..endPort:
    let socket = newSocket(AF_INET, SOCK_RAW, IPPROTO_RAW)
    # socket.setSockOpt()
    try:
        socket.connect(host, Port(port))
        let (laddr, lport) = socket.getLocalAddr()
        let (paddr, pport) = socket.getPeerAddr()
        let ipHeader = generateIpFullHeader(laddr, paddr)
        let tcpHeader = generateTcpFullHeader(laddr, int(lport), paddr, int(pport))
        socket.send(ipHeader & tcpHeader)
        let data = socket.recv(1, timeout=5000)
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

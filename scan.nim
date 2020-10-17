import net
import parseopt
from strutils import parseInt
import nativesockets

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

var hostIp: string
if host.isIpAddress():
    hostIp = host
else:
    let aiAddr = getAddrInfo(host, Port(0))
    hostIp = aiAddr.ai_addr.getAddrString()
    freeaddrinfo(aiAddr)

echo "Scanning ", host, " from ", startPort, " to ", endPort
for port in startPort..endPort:
    let socket = newSocket()

    try:        
        socket.connect(hostIp, Port(port))
        foundOpen.add($port)
    except:
        let m = getCurrentExceptionMsg()
        case m
        of "Connection refused":
            discard
        else:
            echo "Could not connect to \"", host, ":", port, "\". ", m 
    finally:
        socket.close()

for port in foundOpen:
    echo "Found open port: ", port

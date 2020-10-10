import net
import os
import strutils

var port = parseInt(paramStr(1))

echo "Listening on localhost:", port

var socket = newSocket()
socket.bindAddr(Port(port))
socket.listen()

var client: Socket
var address = ""
while true:
  socket.acceptAddr(client, address)
  echo("Client connected from: ", address)

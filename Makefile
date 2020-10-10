clean:
	rm -f scan testPorts

scan:
	nim c -d:release scan

testPorts:
	nim c -d:release testPorts


all: echoserver echoclient udpproxy

echoserver : UdpEchoServer.class makefile

echoclient : UdpClientEchoChecker.class makefile

UdpEchoServer.class: UdpEchoServer.java makefile
	javac UdpEchoServer.java

UdpClientEchoChecker.class: UdpClientEchoChecker.java makefile
	javac UdpClientEchoChecker.java

.PHONY: clean

clean:
	rm -f udpproxy udpproxy.o core *~ *.*~ *.class

udpproxy: udpproxy.cpp makefile
	g++ -Ofast -fwhole-program -Wall -ggdb3 -Wextra -pedantic udpproxy.cpp -o udpproxy -lstdc++


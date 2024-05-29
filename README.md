# udpproxy
I had the need for UDP traffic from multiple clients to be sent to a backend host
through ONE frontend host for security reasons.

# build
`make clean all`  

# run
`./udpproxy localhost:1025 localhost:1026 -v -s &`  
`java UdpEchoServer localhost 1026 &`  
`java UdpClientEchoChecker localhost 1025 1 'Text to verify'`  

# signals
stats:  
`kill -14 $(pidof udpproxy)`  
disable verbose:  
`kill -8 $(pidof udpproxy)`  
clear connections map:  
`kill -1 $(pidof udpproxy)`  
terminate:  
`kill -15 $(pidof udpproxy)`  

# verbose stats
`UDPPROXY_USEFDS=9999 UDPPROXY_REUSEPORT=true ./udpproxy localhost:1025 localhost:1026 -s -v &`  
`kill -14 $(pidof udpproxy)`
```
2024-05-28 13:33:50.149912 DEBUG  Alarm signal received.
2024-05-28 13:33:50.149939 INFO   Size of sendMap        = 8  Size of receiveMap = 8
2024-05-28 13:33:50.149939 INFO   Size of keyToAddrAndFd = 7  Size of fdToIter   = 7
2024-05-28 13:33:50.149939 INFO   7756 packets received since last message
2024-05-28 13:33:50.149939 INFO           IP : Port        |   Bytes received
2024-05-28 13:33:50.149939 INFO   -------------------------+------------------
2024-05-28 13:33:50.149939 INFO   127.0.0.1       :  1026  |           178388
2024-05-28 13:33:50.149939 INFO   127.0.0.1       : 55329  |             4554
2024-05-28 13:33:50.149939 INFO   127.0.0.1       : 47225  |            38640
2024-05-28 13:33:50.149939 INFO   127.0.0.1       : 42630  |             4278
2024-05-28 13:33:50.149939 INFO   127.0.0.1       : 43404  |             2806
2024-05-28 13:33:50.149939 INFO   127.0.0.1       : 46230  |             5658
2024-05-28 13:33:50.149939 INFO   127.0.0.1       : 38105  |             1058
2024-05-28 13:33:50.149939 INFO   127.0.0.1       : 41973  |           121394
2024-05-28 13:33:50.149939 INFO   7756 packets send since last message
2024-05-28 13:33:50.149939 INFO           IP : Port        |     Bytes send
2024-05-28 13:33:50.149939 INFO   -------------------------+------------------
2024-05-28 13:33:50.149939 INFO   127.0.0.1       :  1026  |           178388
2024-05-28 13:33:50.149939 INFO   127.0.0.1       : 55329  |             4554
2024-05-28 13:33:50.149939 INFO   127.0.0.1       : 47225  |            38640
2024-05-28 13:33:50.149939 INFO   127.0.0.1       : 42630  |             4278
2024-05-28 13:33:50.149939 INFO   127.0.0.1       : 43404  |             2806
2024-05-28 13:33:50.149939 INFO   127.0.0.1       : 46230  |             5658
2024-05-28 13:33:50.149939 INFO   127.0.0.1       : 38105  |             1058
2024-05-28 13:33:50.149939 INFO   127.0.0.1       : 41973  |           121394
```

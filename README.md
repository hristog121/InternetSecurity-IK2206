# InternetSecurity-IK2206-2020

This repo is containing solutions to task in the IK2206 - Internet Security and Privacy course given by KTH. 

This project is written in java and implements a VPN - portforwarder. Durning the handshake the VPN is using RSA to set up session key for AES encryption.


In order to run the program, you will need:
A server.pem certificate, signed by a CA.
a server-private.der key, associated with that certificate.
A ca.pem certificate, signed by itself.
A client.pem certificate, signed by the same CA.
a client-private.der key, associated with that certificate.

The code is written for a specific KTH task, which means that we have an extra requirement and that is to verify the CN. If you wasnt to use the code fot your implementation please edit the code first.  The points bellow show what CN I am checking for.
The CN for the CA cert: “ca-pf.ik2206.kth.se”.
The CN for the server cert: “server-pf.ik2206.kth.se”.
The CN for the client cert: “client-pf.ik2206.kth.se”.

To run the server, use the following command: 

Terminal 1:
$ java ForwardServer --handshakeport=2206 --usercert=server.pem --cacert=ca.pem --key=server-private.der

To run the client, use the following command:

Terminal 2:
$ java ForwardClient --handshakehost=localhost --handshakeport=2206 --proxyport=1337 --targethost=localhost --targetport=6789 --usercert=client.pem --cacert=ca.pem --key=client-private.der


Test if the VPN forwards correctly:
Terminal 3:           Terminal 4:
$ nc -l 6789          $ nc localhost 1773
 

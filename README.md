# Packet-Sniffer
Packet Sniffer with detection and traditional sniffer modules.

Requires GTK libraries to run. 

#This program is implmented in two modules. They are listed below:

#1 Detection:

This module deals with Detecting the presence of an intruder (with packet sniffer)on the network .The main objective of this module is to create a packet with fake address and transmit it over the network.

#2 Traditional sniffer software:

This module deals with the sniffer software which doesn’t have the capabilities to detect an intruder in the network. This software in turn can be divided into two small modules ,they are

2.1 sniffing module

This module deals with setting the NIC(network interface card)  cardin promiscuous mode and capturing the packets flowing through the network.

2.2 displaying module

This module deals with displaying the captured packets in a presentable and understandable format like the user and data in the packets.


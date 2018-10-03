# What is it and how to run?

## What is trace_dest_ips?

This is simple script for output all track 

## pre requirements

intstall python > 2.5

scapy python library (https://scapy.readthedocs.io/en/latest/installation.html)

    bash# pip install scapy
    


## how to run?

Extract pcap from tcpdump

		tcpdump src 192.168.0.1

Covert to txt file with destination ip fields only 

    bash# tshark -r <input file> -T fields -e ip.dst > path\output.txt
 
Put in output.txt in the same diractory 

And run py file.

	bash# python trace_it.py  


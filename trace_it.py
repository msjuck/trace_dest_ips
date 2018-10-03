import socket 

from scapy.all import *

def my_get_hostname(x):
	try:
		return socket.gethostbyaddr(x) 
	except:
		return ""



f = open('output.txt')
txt = f.read()
ips = txt.split()
ip_list = []
for ip in ips:
	if ip not in ip_list:
		ip_list.append(ip)

print " < Content IPs and Hostname >"
for x in ip_list:
	print x, my_get_hostname(x)


print "\n\n\n\n"
print "< And Trace it >"
count = 0
for ip in ip_list:
	count+=1
	print count
	target = [ip]
	print "trace", target
	result, unans = traceroute(target, maxttl=32)
	print result, unans



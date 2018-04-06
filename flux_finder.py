from scapy.all import *
import argparse

# These are the command line arguments for this program 
parser = argparse.ArgumentParser()
parser.add_argument('-f','--filename',help='please enter path to file...',required=True)
parser.add_argument('-F','--fastflux',action='store_true',help='Enter -F or --filename to retrieve fast flux information')
parser.add_argument('-d','--domainflux',action='store_true',help='Enter -d or --domainflux to retrieve domainflux information')
args = parser.parse_args()

# Parses pcap and shows amount of IP's associated with domain
if args.fastflux:
	dnsRecords = {}
	def fastFlux(pkt):
		if pkt.haslayer(DNSRR):
			rrname = pkt.getlayer(DNSRR).rrname
			rdata = pkt.getlayer(DNSRR).rdata
			if rrname in dnsRecords:
				if rdata not in dnsRecords[rrname]:
					dnsRecords[rrname].append(rdata)

			else:
				dnsRecords[rrname] = []
				dnsRecords[rrname].append(rdata)

# Parses pcap looking requests for domains that don't exist
if args.domainflux:
	def dnsQRTest(pkt):
		if pkt.haslayer(DNSRR) and pkt.getlayer(UDP).sport == 53:
			rcode = pkt.getlayer(DNS).rcode
			qname = pkt.getlayer(DNSQR).qname
			if rcode == 3:
				print('[!] Name request lookup failed: ' + qname.decode('Latin-1'))
				return True
			else:
				return False

# This is my main program which calls the functions that parse the pcap information
def main():
	
	# Reads in my pcap
	pkts = rdpcap(args.filename)

	# Calls fastFlux function
	if args.fastflux:
		for pkt in pkts:
			fastFlux(pkt)
		for item in dnsRecords:
			print('[+] ' + item.decode('Latin-1') + ' has ' + str(len(dnsRecords[item])) + ' unique IPs.') 

	# Calls domainFlux function		
	if args.domainflux:
		unAnsReqs = 0
		for pkt in pkts:
			if dnsQRTest(pkt):
				unAnsReqs += 1
		print('[!] ' + str(unAnsReqs) + ' Total Unanswered Name Requests')

# Calls my main function
if __name__ == '__main__':
    main() 
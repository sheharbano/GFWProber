#!/usr/bin/env python
# To get this to work, you need to first
# run the bash command for Linux: 
#    sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s <IP of machine from which conducting tests> -j DROP
# or,  for Mac OS:
#    sudo ipfw add 100 drop tcp from <your_IP_address> to any out tcpflags rst src-port any
# For details, please refer to:
# http://stackoverflow.com/questions/9058052/unwanted-rst-tcp-packet-with-scapy
#
# Code corresponds to this work: https://www.usenix.org/conference/foci13/workshop-program/presentation/Khattak
#
# @author: Sheharbano (Sheharbano.Khattak@cl.cam.ac.uk)

import random
from pprint import pprint
from scapy.all import *
from cStringIO import StringIO
from time import sleep
import sys
import re 

class GFCProber(object):
	def __init__(self, host, test_name):
		self.host = host 
		self.test_name = test_name
		self.curr_src_port = 1024

	def probe(self):
		host = self.host
		uri="peacehall/"
		dst_port = 80
		random.seed()			
		self.curr_src_port=random.randrange(1024,65535)
		# Get IP address of the host
		# I am getting it in advance as .show2()
		# does not work with url's, and I need
		# the checksum through this method.
		ping = sr1(IP(dst=host)/ICMP(),verbose=0)
        ###X Why not  dst_ip = gethostbyname(host) ?
		dst_ip = ping.getlayer(IP).src
		dst_ip = host # ping.getlayer(IP).src
		# This will be needed for fragmentatiom tests.
		# If you need to carry out multiple fragmentation
		#  tests simultaneously, you will need to use a 
		#  *different* IP ID for each fragmented packet.
		#  (Remember, IP ID helps the reassembler figure out
		#   which fragments belong to which packet)  
		ip_id = 12345
		# HTTP GET statement
		http_get = 'GET /'+uri+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'

		# TCP handshake
		ip=IP(dst=dst_ip,id=12345,proto=6)		 
		syn = ip/TCP(sport=self.get_src_port(), dport=80, flags='S')
		syn_ack = sr1(syn)
			# Not sending a dataless ack

		if self.test_name=="test0" or self.test_name=="all":
			# --------Test 0: Testing---------
			# Just a regular HTTP GET request
			pkt=IP(dst=dst_ip,proto=6)/TCP(dport=dst_port, sport=self.get_src_port(),
		 		seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA') / http_get
			send(pkt)
		
		# --------Test 1: Header Length---------
		# 5 <= Valid header length <=15
		# Test 1a: Packet length less than 5, which is illegal
		#          and will be dropped by an end device, but GFC
		#          might accept. It's possible that the packet will
		#          be dropped by an intermediate device before it 
		#          even reaches GFC 
		if self.test_name=="test1a" or self.test_name=="all":
			pkt=IP(dst=dst_ip,proto=6,ihl=4)/TCP(dport=dst_port, sport=self.get_src_port(),
		 		seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA') / http_get
			send(pkt)
        ###X: but,  ihl=4, Header Length = 16

		# Test 1b: Same as Test 1a, except that now packet length
		#          is 65535 bytes (bigger than actual length)
		if self.test_name=="test1b" or self.test_name=="all":
			pkt=IP(dst=dst_ip,proto=6,ihl=15)/TCP(dport=dst_port, sport=self.get_src_port(),
		 		seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA') / http_get
			send(pkt)

        ###X: ihl=15, means HeaderLength = 60 bytes.
        ###X: to make packet leangth = 65535, means TL=65535

		# --------Test 2: Total Length---------
		# Test 2a: total length < 20 bytes (minimum header size), 
		# 		   which is illegal
		#          and will be dropped by an end device, but GFC
		#          might accept. It's possible that the packet will
		#          be dropped by an intermediate device before it 
		#          even reaches GFC 
		if self.test_name=="test2a" or self.test_name=="all":
			pkt=IP(dst=dst_ip,proto=6,len=19)/TCP(dport=dst_port, sport=self.get_src_port(),
		 		seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA') / http_get
			send(pkt)

		# Test 2b: total length > actual length (98 bytes for this packet via wireshark)
		if self.test_name=="test2b" or self.test_name=="all":
			pkt=IP(dst=dst_ip,proto=6,len=150)/TCP(dport=dst_port, sport=self.get_src_port(),
		 		seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA') / http_get
			send(pkt)

		# --------Test 3: Flags---------
		# These tests exploit bad flag values or their invalid combination
		# with other header fields
		# Test 3a: DF=1 && FragOffset!=0
		if self.test_name=="test3a" or self.test_name=="all":
			pkt=IP(dst=dst_ip,proto=6,frag=3,flags=2)/TCP(dport=dst_port, sport=self.get_src_port(),
		 		seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA') / http_get
			send(pkt)

		# Test 3b: Must Be Zero != 0
		# The bit between IP ID and DF must be 0. If it is non-zero 
		# then there is a possibility that an end system might reject 
		# the packet. If a NIDS does not validate the value of this bit, 
		# packets can be inserted to it.
		if self.test_name=="test3b" or self.test_name=="all":
			pkt=IP(dst=dst_ip,proto=6,flags=4)/TCP(dport=dst_port, sport=self.get_src_port(),
		 		seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA') / http_get
			send(pkt)

		# Test 3c: DF Flag manipulation
		# TODO manually!

		# --------Test 4: TTL---------
		# Test 4a: 
		if self.test_name=="test4a" or self.test_name=="all":
			pkt=IP(dst=dst_ip,proto=6,ttl=9)/TCP(dport=dst_port, sport=self.get_src_port(),
		 		seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA') / http_get
			send(pkt)
	
		# --------Test 5: Checksum---------
		# Test 5a: 
		if self.test_name=="test5a" or self.test_name=="all":
			pkt=IP(dst=dst_ip,proto=6,chksum=0x7ce7)/TCP(dport=dst_port, sport=self.get_src_port(),
		 		seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA') / http_get
			send(pkt)
		 
		# --------Test 6: (IP ID + Frag offset) Fragmentation---------
		# ====Tests 6.1========
		# subsequent fragment has a lower offset than 
		#       the original fragment
		# ___________________________
		#         |frag_original|
		#  |frag_subsequent|     
		# ___________________________
		# ====Tests 6.1.1========
		# subsequent fragment ends before 
		#       the original fragment
		# ___________________________
		#         |frag_original|
		#  |frag_subsequent|     
		# ======================
		# Test 6.1.1a: see below
		# ___________________________
		#         |WORD|
		# |....KEY...|
		
		if self.test_name=="test6.1.1a" or self.test_name=="all":
			# HTTP GET statement
			http_get_frag_orig = 'GET /'+'bbpeacehallxxxx/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			http_get_frag_sub  = 'GET /'+'bbpeaceyyyyxxxx/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'

			# Getting packet checksum for fragmentation tests.
			# While manually fragmenting a packet, we have to
			# calculate this in advance, and include in the packet
			# header by hand.
			#
			# The unframented packet with frag and flags relevant to 
			#    the first fragment.(Note flags=1 means More Fragments 
			#    flag is set, and Don't fragment and Reserved Bit are unset) 
			unfragmented_pkt_orig = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_orig
			unfragmented_pkt_sub = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_sub
		
			chksum_orig = self.get_chksum(unfragmented_pkt_orig)
			if chksum_orig==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			chksum_sub = self.get_chksum(unfragmented_pkt_sub)
			if chksum_sub==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1

			# Sending with checksum assuming one style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_orig) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=4,flags=1)/'hallxxxx'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/ '/bbpeaceyyyy'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

			# Sending with checksum assuming another style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_sub) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=4,flags=1)/'hallxxxx'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/ '/bbpeaceyyyy'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

		# ======================
		# Test 6.1.1b: see below
		# ___________________________
		#         |    WORD|
		# |........KEY|

		if self.test_name=="test6.1.1b" or self.test_name=="all":
			# HTTP GET statement
			http_get_frag_orig = 'GET /'+'bbbbbbpeacehall/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			http_get_frag_sub = 'GET /'+'bbbbbbpaaaahall/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'

			# Getting packet checksum for fragmentation tests.
			# While manually fragmenting a packet, we have to
			# calculate this in advance, and include in the packet
			# header by hand.
			#
			# The unframented packet with frag and flags relevant to 
			#    the first fragment.(Note flags=1 means More Fragments 
			#    flag is set, and Don't fragment and Reserved Bit are unset) 
			unfragmented_pkt_orig = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_orig
			unfragmented_pkt_sub = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_sub
	
			chksum_orig = self.get_chksum(unfragmented_pkt_orig)
			if chksum_orig==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			chksum_sub = self.get_chksum(unfragmented_pkt_sub)
			if chksum_sub==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1

			# Sending with checksum assuming one style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_orig) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=4,flags=1)/'aaaahall'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/ '/bbbbbbpeace'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

			# Sending with checksum assuming another style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_sub) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=4,flags=1)/'aaaahall'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/ '/bbbbbbpeace'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)
    
		# ___________________________
		# ====Tests 6.1.2========
		# subsequent fragment ends at the same offset 
		#       as the original fragment
		# ___________________________
		#         |frag_original|
		#     | frag_subsequent |     
		# ======================
		# Test 6.1.2a: see below
		# ___________________________
		#         |......|
		# |.....keyword..|

		if self.test_name=="test6.1.2a" or self.test_name=="all":
			# HTTP GET statement
			http_get_frag_orig = 'GET /'+'bbpeacehallyyyy/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			http_get_frag_sub  = 'GET /'+'bbpeaceaaaaaaaa/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'

			# Getting packet checksum for fragmentation tests.
			# While manually fragmenting a packet, we have to
			# calculate this in advance, and include in the packet
			# header by hand.
			#
			# The unframented packet with frag and flags relevant to 
			#    the first fragment.(Note flags=1 means More Fragments 
			#    flag is set, and Don't fragment and Reserved Bit are unset) 
			unfragmented_pkt_orig = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_orig
			unfragmented_pkt_sub = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_sub

			chksum_orig = self.get_chksum(unfragmented_pkt_orig)
			if chksum_orig==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			chksum_sub = self.get_chksum(unfragmented_pkt_sub)
			if chksum_sub==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1

			# Sending with checksum assuming one style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_orig) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=4,flags=1)/'aaaaaaaa'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/ '/bbpeacehallyyyy'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

			# Sending with checksum assuming another style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_sub) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=4,flags=1)/'aaaaaaaa'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/ '/bbpeacehallyyyy'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)
	
		# ======================
		# Test 6.1.2b: see below
		# ___________________________
		#         |word..|
		# |.....key.......|

		if self.test_name=="test6.1.2b" or self.test_name=="all":
			# HTTP GET statement
			http_get_frag_orig = 'GET /'+'bbpeacehallxxxx/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			http_get_frag_sub =  'GET /'+'bbpeaceyyyyyyyy/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'

			# Getting packet checksum for fragmentation tests.
			# While manually fragmenting a packet, we have to
			# calculate this in advance, and include in the packet
			# header by hand.
			#
			# The unframented packet with frag and flags relevant to 
			#    the first fragment.(Note flags=1 means More Fragments 
			#    flag is set, and Don't fragment and Reserved Bit are unset) 
			unfragmented_pkt_orig = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_orig
			unfragmented_pkt_sub = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_sub
	
			chksum_orig = self.get_chksum(unfragmented_pkt_orig)
			if chksum_orig==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			chksum_sub = self.get_chksum(unfragmented_pkt_sub)
			if chksum_sub==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1

			# Sending with checksum assuming one style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_orig) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=4,flags=1)/'hallxxxx'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/ '/bbpeaceyyyyyyyy'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

			# Sending with checksum assuming another style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_sub) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=4,flags=1)/'hallxxxx'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/ '/bbpeaceyyyyyyyy'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)
		# ___________________________
		# ====Tests 6.1.3========
		# subsequent fragment ends past 
		#       the original fragment
		# ___________________________
		#         |frag_original|
		#     |  frag_subsequent    |     
		# ======================
		# Test 6.1.3a: see below
		# ___________________________
		#         |.......|
		# |........keyword..|

		if self.test_name=="test6.1.3a" or self.test_name=="all":
			# HTTP GET statement
			http_get_frag_orig = 'GET /'+'bbbbbbpaaaaaaaayyyyyyyy/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			http_get_frag_sub = 'GET /'+'bbbbbbpeacehallyyyyyyyy/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'

			# Getting packet checksum for fragmentation tests.
			# While manually fragmenting a packet, we have to
			# calculate this in advance, and include in the packet
			# header by hand.
			#
			# The unframented packet with frag and flags relevant to 
			#    the first fragment.(Note flags=1 means More Fragments 
			#    flag is set, and Don't fragment and Reserved Bit are unset) 
			unfragmented_pkt_orig = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_orig
			unfragmented_pkt_sub = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_sub
		
			chksum_orig = self.get_chksum(unfragmented_pkt_orig)
			if chksum_orig==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			chksum_sub = self.get_chksum(unfragmented_pkt_sub)
			if chksum_sub==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			# Sending with checksum assuming one style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_orig) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=4,flags=1)/'aaaaaaaa'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/ '/bbbbbbpeacehallyyyyyyyy'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=6,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

			# Sending with checksum assuming another style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_sub) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=4,flags=1)/'aaaaaaaa'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/ '/bbbbbbpeacehallyyyyyyyy'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=6,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

		# ======================
		# Test 6.1.3b: see below
		# ___________________________
		#         |ywo|
		# |.....ke.....rd|

		if self.test_name=="test6.1.3b" or self.test_name=="all":
			# HTTP GET statement
			http_get_frag_orig = 'GET /'+'bbbbbbpeacehall/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			http_get_frag_sub = 'GET /'+'bbbbbbpyyyyyall/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'

			# Getting packet checksum for fragmentation tests.
			# While manually fragmenting a packet, we have to
			# calculate this in advance, and include in the packet
			# header by hand.
			#
			# The unfragmented packet with frag and flags relevant to 
			#    the first fragment.(Note flags=1 means More Fragments 
			#    flag is set, and Don't fragment and Reserved Bit are unset) 
			unfragmented_pkt_orig = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_orig
			unfragmented_pkt_sub = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_sub
		
			chksum_orig = self.get_chksum(unfragmented_pkt_orig)
			if chksum_orig==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			chksum_sub = self.get_chksum(unfragmented_pkt_sub)
			if chksum_sub==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			# Sending with checksum assuming one style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_orig) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=4,flags=1)/'eaceh'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/ '/bbbbbbpyyyyyall'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

			# Sending with checksum assuming another style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_sub) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=4,flags=1)/'eaceh'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/ '/bbbbbbpyyyyyall'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

		# ====Tests 6.2========
		# subsequent fragment has the same offset as 
		#       the original fragment
		# ___________________________
		#         |frag_original|
		#         |frag_subsequent|     
		# ___________________________
		# ====Tests 6.2.1========
		# subsequent fragment ends at the same 
		# offset as the original fragment
		# ___________________________
		#         |frag_original|
		#         |frag_subseq  |     
		# ======================
		# Test 6.2.1a: see below
		# ___________________________
		# |KEYWORD|
		# |.......|

		if self.test_name=="test6.2.1a" or self.test_name=="all":
			# HTTP GET statement
			http_get_frag_orig = 'GET /'+'peacehallxxxxxx/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			http_get_frag_sub = 'GET /'+'bbbbbbbbbbbbbbb/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'

			# Getting packet checksum for fragmentation tests.
			# While manually fragmenting a packet, we have to
			# calculate this in advance, and include in the packet
			# header by hand.
			#
			# The unfragmented packet with frag and flags relevant to 
			#    the first fragment.(Note flags=1 means More Fragments 
			#    flag is set, and Don't fragment and Reserved Bit are unset) 
			unfragmented_pkt_orig = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_orig
			unfragmented_pkt_sub = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_sub
		
			chksum_orig = self.get_chksum(unfragmented_pkt_orig)
			if chksum_orig==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			chksum_sub = self.get_chksum(unfragmented_pkt_sub)
			if chksum_sub==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			# Sending with checksum assuming one style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_orig) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/'/peacehallxxxxxx'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/ '/bbbbbbbbbbbbbbb'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

			# Sending with checksum assuming another style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_sub) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/'/peacehallxxxxxx'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/ '/bbbbbbbbbbbbbbb'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

		# ======================
		# Test 6.2.1b: see below
		# ___________________________
		# |.......|
		# |KEYWORD|

		if self.test_name=="test6.2.1b" or self.test_name=="all":
			# HTTP GET statement
			http_get_frag_orig = 'GET /'+'aaaaaaaaaaaaaaa/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			http_get_frag_sub = 'GET /'+'peacehallyyyyyy/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'

			# Getting packet checksum for fragmentation tests.
			# While manually fragmenting a packet, we have to
			# calculate this in advance, and include in the packet
			# header by hand.
			#
			# The unfragmented packet with frag and flags relevant to 
			#    the first fragment.(Note flags=1 means More Fragments 
			#    flag is set, and Don't fragment and Reserved Bit are unset) 
			unfragmented_pkt_orig = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_orig
			unfragmented_pkt_sub = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_sub

			chksum_orig = self.get_chksum(unfragmented_pkt_orig)
			if chksum_orig==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			chksum_sub = self.get_chksum(unfragmented_pkt_sub)
			if chksum_sub==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			# Sending with checksum assuming one style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_orig) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/'/aaaaaaaaaaaaaaa'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/ '/peacehallyyyyyy'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

			# Sending with checksum assuming another style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_sub) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/'/aaaaaaaaaaaaaaa'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/ '/peacehallyyyyyy'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)
	
		# ___________________________
		# ====Tests 6.2.2========
		# subsequent fragment ends before 
		# the original fragment
		# ___________________________
		#         | frag_original |
		#         |frag_subseq|     
		# ======================
		# Test 6.2.2a: see below
		# ___________________________
		# |.......word|
		# |...key|
	
		if self.test_name=="test6.2.2a" or self.test_name=="all":
			# HTTP GET statement
			http_get_frag_orig = 'GET /'+'aaaaaaaaaaahall/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			http_get_frag_sub = 'GET /'+'bbbbbbpeacehall/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'

			# Getting packet checksum for fragmentation tests.
			# While manually fragmenting a packet, we have to
			# calculate this in advance, and include in the packet
			# header by hand.
			#
			# The unfragmented packet with frag and flags relevant to 
			#    the first fragment.(Note flags=1 means More Fragments 
			#    flag is set, and Don't fragment and Reserved Bit are unset) 
			unfragmented_pkt_orig = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_orig
			unfragmented_pkt_sub = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_sub

			chksum_orig = self.get_chksum(unfragmented_pkt_orig)
			if chksum_orig==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			chksum_sub = self.get_chksum(unfragmented_pkt_sub)
			if chksum_sub==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			# Sending with checksum assuming one style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_orig) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/'/aaaaaaaaaaahall'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/ '/bbbbbbpeace'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

			# Sending with checksum assuming another style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_sub) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/'/aaaaaaaaaaahall'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/ '/bbbbbbpeace'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

		# ======================
		# Test 6.2.2b: see below
		# ___________________________
		# |....keyword|
		# |......|

		if self.test_name=="test6.2.2b" or self.test_name=="all":
						# HTTP GET statement
			http_get_frag_orig = 'GET /'+'aaaaaapeacehall/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			http_get_frag_sub = 'GET /'+'bbbbbbbbbbb/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'

			# Getting packet checksum for fragmentation tests.
			# While manually fragmenting a packet, we have to
			# calculate this in advance, and include in the packet
			# header by hand.
			#
			# The unfragmented packet with frag and flags relevant to 
			#    the first fragment.(Note flags=1 means More Fragments 
			#    flag is set, and Don't fragment and Reserved Bit are unset) 
			unfragmented_pkt_orig = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_orig
			unfragmented_pkt_sub = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_sub

			chksum_orig = self.get_chksum(unfragmented_pkt_orig)
			if chksum_orig==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			chksum_sub = self.get_chksum(unfragmented_pkt_sub)
			if chksum_sub==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			# Sending with checksum assuming one style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_orig) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/'/aaaaaapeacehall'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/ '/bbbbbbbbbbb'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

			# Sending with checksum assuming another style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_sub) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/'/aaaaaapeacehall'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/ '/bbbbbbbbbbb'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

		# ___________________________
		# ====Tests 6.2.3========
		# subsequent fragment ends after 
		# the original fragment
		# ___________________________
		#         | frag_original|
		#         |      frag_subseq|     
		# ======================
		# Test 6.2.3a: see below
		# ___________________________
		# |.......|
		# |.....keyword|

		if self.test_name=="test6.2.3a" or self.test_name=="all":
			# HTTP GET statement
			http_get_frag_orig = 'GET /'+'aaaaaaaaaaaahall/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			http_get_frag_sub = 'GET /'+'bbbbbbpeacehall/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'

			# Getting packet checksum for fragmentation tests.
			# While manually fragmenting a packet, we have to
			# calculate this in advance, and include in the packet
			# header by hand.
			#
			# The unfragmented packet with frag and flags relevant to 
			#    the first fragment.(Note flags=1 means More Fragments 
			#    flag is set, and Don't fragment and Reserved Bit are unset) 
			unfragmented_pkt_orig = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_orig
			unfragmented_pkt_sub = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_sub

			chksum_orig = self.get_chksum(unfragmented_pkt_orig)
			if chksum_orig==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			chksum_sub = self.get_chksum(unfragmented_pkt_sub)
			if chksum_sub==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			# Sending with checksum assuming one style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_orig) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/'/aaaaaaaaaaa'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/ '/bbbbbbpeacehall'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

			# Sending with checksum assuming another style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_sub) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/'/aaaaaaaaaaa'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/ '/bbbbbbpeacehall'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

		# ======================
		# Test 6.2.3b: see below
		# ___________________________
		# |....key|
		# |........word|

		if self.test_name=="test6.2.3b" or self.test_name=="all":
			# HTTP GET statement
			http_get_frag_orig = 'GET /'+'aaaaaapeacehall/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			http_get_frag_sub = 'GET /'+'bbbbbbbbbbbhall/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'

			# Getting packet checksum for fragmentation tests.
			# While manually fragmenting a packet, we have to
			# calculate this in advance, and include in the packet
			# header by hand.
			#
			# The unfragmented packet with frag and flags relevant to 
			#    the first fragment.(Note flags=1 means More Fragments 
			#    flag is set, and Don't fragment and Reserved Bit are unset) 
			unfragmented_pkt_orig = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_orig
			unfragmented_pkt_sub = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_sub

			chksum_orig = self.get_chksum(unfragmented_pkt_orig)
			if chksum_orig==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			chksum_sub = self.get_chksum(unfragmented_pkt_sub)
			if chksum_sub==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			# Sending with checksum assuming one style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_orig) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/'/aaaaaapeace'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/ '/bbbbbbbbbbbhall'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

			# Sending with checksum assuming another style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_sub) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/'/aaaaaapeace'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/ '/bbbbbbbbbbbhall'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

		# ====Tests 6.3========
		# subsequent fragment has higher offset than 
		#       the original fragment
		# ___________________________
		#         |frag_original|
		#             |frag_subsequent|     
		# ___________________________
		# ====Tests 6.3.1========
		# subsequent fragment ends at the same 
		# offset as the original fragment
		# ___________________________
		#       |  frag_original|
		#           |frag_subseq|     
		# ======================
		# Test 6.3.1a: see below
		# ___________________________
		# |.KEYWORD...|
		#     |.......|

		if self.test_name=="test6.3.1a" or self.test_name=="all":
			# HTTP GET statement
			http_get_frag_orig = 'GET /'+'aapeacehallxxxx/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			http_get_frag_sub = 'GET /'+'aapeacebbbbbbbb/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'

			# Getting packet checksum for fragmentation tests.
			# While manually fragmenting a packet, we have to
			# calculate this in advance, and include in the packet
			# header by hand.
			#
			# The unfragmented packet with frag and flags relevant to 
			#    the first fragment.(Note flags=1 means More Fragments 
			#    flag is set, and Don't fragment and Reserved Bit are unset) 
			unfragmented_pkt_orig = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_orig
			unfragmented_pkt_sub = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_sub
		
			chksum_orig = self.get_chksum(unfragmented_pkt_orig)
			if chksum_orig==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			chksum_sub = self.get_chksum(unfragmented_pkt_sub)
			if chksum_sub==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			# Sending with checksum assuming one style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_orig) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/'/aapeacehallxxxx'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=4,flags=1)/ 'bbbbbbbb'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

			# Sending with checksum assuming another style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_sub) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/'/aapeacehallxxxx'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=4,flags=1)/ 'bbbbbbbb'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

		# ======================
		# Test 6.3.1b: see below
		# ___________________________
		# |.KEY.......|
		#     |WORD...|

		if self.test_name=="test6.3.1b" or self.test_name=="all":
			# HTTP GET statement
			http_get_frag_orig = 'GET /'+'aapeacexxxxxxxx/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			http_get_frag_sub = 'GET /'+'aapeacehallyyyy/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'

			# Getting packet checksum for fragmentation tests.
			# While manually fragmenting a packet, we have to
			# calculate this in advance, and include in the packet
			# header by hand.
			#
			# The unfragmented packet with frag and flags relevant to 
			#    the first fragment.(Note flags=1 means More Fragments 
			#    flag is set, and Don't fragment and Reserved Bit are unset) 
			unfragmented_pkt_orig = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_orig
			unfragmented_pkt_sub = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_sub
		
			chksum_orig = self.get_chksum(unfragmented_pkt_orig)
			if chksum_orig==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			chksum_sub = self.get_chksum(unfragmented_pkt_sub)
			if chksum_sub==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			# Sending with checksum assuming one style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_orig) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/'/aapeacexxxxxxxx'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=4,flags=1)/ 'hallyyyy'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

			# Sending with checksum assuming another style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_sub) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/'/aapeacexxxxxxxx'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=4,flags=1)/ 'hallyyyy'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

		# ====Tests 6.3.2========
		# subsequent fragment ends before
		#    the original fragment
		# ___________________________
		#       |  frag_original |
		#           |frag_sub|     
		# ======================
		# Test 6.3.2a: see below
		# ___________________________
		# |..KEYWORD...|
		#     |..|

		if self.test_name=="test6.3.2a" or self.test_name=="all":
			# HTTP GET statement
			http_get_frag_orig = 'GET /'+'aaaaaapeacehall/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			http_get_frag_sub = 'GET /'+'aaaaaapbbbbhall/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'

			# Getting packet checksum for fragmentation tests.
			# While manually fragmenting a packet, we have to
			# calculate this in advance, and include in the packet
			# header by hand.
			#
			# The unfragmented packet with frag and flags relevant to 
			#    the first fragment.(Note flags=1 means More Fragments 
			#    flag is set, and Don't fragment and Reserved Bit are unset) 
			unfragmented_pkt_orig = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_orig
			unfragmented_pkt_sub = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_sub
		
			chksum_orig = self.get_chksum(unfragmented_pkt_orig)
			if chksum_orig==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			chksum_sub = self.get_chksum(unfragmented_pkt_sub)
			if chksum_sub==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			# Sending with checksum assuming one style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_orig) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/'/aaaaaapeacehall'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=4,flags=1)/ 'bbbb'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

			# Sending with checksum assuming another style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_sub) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/'/aaaaaapeacehall'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=4,flags=1)/ 'bbbb'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

		# ======================
		# Test 6.3.2b: see below
		# ___________________________
		# |..KE..ORD...|
		#     |YW|

		if self.test_name=="test6.3.2b" or self.test_name=="all":
			# HTTP GET statement
			http_get_frag_orig = 'GET /'+'aaaaaapxxxxhall/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			http_get_frag_sub = 'GET /'+'aaaaaapeacehall/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'

			# Getting packet checksum for fragmentation tests.
			# While manually fragmenting a packet, we have to
			# calculate this in advance, and include in the packet
			# header by hand.
			#
			# The unfragmented packet with frag and flags relevant to 
			#    the first fragment.(Note flags=1 means More Fragments 
			#    flag is set, and Don't fragment and Reserved Bit are unset) 
			unfragmented_pkt_orig = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_orig
			unfragmented_pkt_sub = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_sub
		
			chksum_orig = self.get_chksum(unfragmented_pkt_orig)
			if chksum_orig==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			chksum_sub = self.get_chksum(unfragmented_pkt_sub)
			if chksum_sub==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			# Sending with checksum assuming one style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_orig) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/'/aaaaaapxxxxhall'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=4,flags=1)/ 'eace'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

			# Sending with checksum assuming another style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_sub) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/'/aaaaaapxxxxhall'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=4,flags=1)/ 'eace'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

		# ====Tests 6.3.3========
		# subsequent fragment ends after
		#    the original fragment
		# ___________________________
		#       |  frag_original |
		#           |   frag_sub    |     
		# ======================
		# Test 6.3.3a: see below
		# ___________________________
		# |........KEYWO|
		#            |..RD.......|

		if self.test_name=="test6.3.3a" or self.test_name=="all":
			# HTTP GET statement
			http_get_frag_orig = 'GET /'+'aaaaaapeacehall/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			http_get_frag_sub = 'GET /'+'aaaaaapbbbbhall/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'

			# Getting packet checksum for fragmentation tests.
			# While manually fragmenting a packet, we have to
			# calculate this in advance, and include in the packet
			# header by hand.
			#
			# The unfragmented packet with frag and flags relevant to 
			#    the first fragment.(Note flags=1 means More Fragments 
			#    flag is set, and Don't fragment and Reserved Bit are unset) 
			unfragmented_pkt_orig = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_orig
			unfragmented_pkt_sub = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_sub
		
			chksum_orig = self.get_chksum(unfragmented_pkt_orig)
			if chksum_orig==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			chksum_sub = self.get_chksum(unfragmented_pkt_sub)
			if chksum_sub==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			# Sending with checksum assuming one style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_orig) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/'/aaaaaapeace'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=4,flags=1)/ 'bbbbhall'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

			# Sending with checksum assuming another style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_sub) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/'/aaaaaapeace'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=4,flags=1)/ 'bbbbhall'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

		# ======================
		# Test 6.3.3b: see below
		# ___________________________
		# |........KEY..|
		#            |WORD.......|

		if self.test_name=="test6.3.3b" or self.test_name=="all":
			# HTTP GET statement
			http_get_frag_orig = 'GET /'+'aaaaaapxxxxhall/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			http_get_frag_sub = 'GET /'+'aaaaaapeacehall/'+' HTTP/1.0\r\nHost: '+host+'\r\n\r\n'

			# Getting packet checksum for fragmentation tests.
			# While manually fragmenting a packet, we have to
			# calculate this in advance, and include in the packet
			# header by hand.
			#
			# The unfragmented packet with frag and flags relevant to 
			#    the first fragment.(Note flags=1 means More Fragments 
			#    flag is set, and Don't fragment and Reserved Bit are unset) 
			unfragmented_pkt_orig = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_orig
			unfragmented_pkt_sub = IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(), seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA')/http_get_frag_sub
		
			chksum_orig = self.get_chksum(unfragmented_pkt_orig)
			if chksum_orig==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			chksum_sub = self.get_chksum(unfragmented_pkt_sub)
			if chksum_sub==-1:
				print "Error calculating IP checksum; Now exiting...";
				return -1
			# Sending with checksum assuming one style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_orig) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/'/aaaaaapxxxx'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=4,flags=1)/ 'eacehall'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)

			# Sending with checksum assuming another style of reassembly
			frag1=IP(dst=dst_ip,id=ip_id,proto=6,frag=0,flags=1)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=syn_ack.ack, ack=syn_ack.seq+1, flags='PA', chksum=chksum_sub) / 'GET '
			send(frag1)

			frag2=IP(dst=dst_ip,id=ip_id,proto=6,frag=3,flags=1)/'/aaaaaapxxxx'
			send(frag2)

			frag3=IP(dst=dst_ip,id=ip_id,proto=6,frag=4,flags=1)/ 'eacehall'
			send(frag3)

			frag4=IP(dst=dst_ip,id=ip_id,proto=6,frag=5,flags=0)/'/ HTTP/1.0\r\nHost: xxxxxxxxxxxxxxxxxx.xxx\r\n\r\n'
			send(frag4)



	

			    
	def get_chksum(self,pkt):
		# Redirecting stdout to StringIO so that I can get
		# output of scapy function show2() in a string
		old_stdout = sys.stdout
		sys.stdout = mystdout = StringIO()

		pkt.payload.show2()
		sys.stdout = old_stdout
		pkt_summary=mystdout.getvalue()

		old_stdout = sys.stdout
		sys.stdout = mystdout = StringIO()

		# extracting checksum
		matchObj = re.search( r'0x[0-9a-f]{4}', pkt_summary, re.M|re.I)
		str_chksum_orig=""
		if matchObj:
		   str_chksum_orig=matchObj.group()  
		else:
		   print "Could not find frag checksum."

		try:
		    chksum = int(str_chksum_orig, 16)
		except Exception,e:
		    print e
		    print "Now exiting..."
		    return -1

		return chksum

	def get_src_port(self):
#		if self.test_name == "all":
#		++self.curr_src_port
#		if self.curr_src_port > 65535:
#			print "Warning: Source port number exceeded 65535, hence staring again from 1024. Note that if you differentiate between test cases by source port, you will no longer be able to do so!"
#			self.curr_src_port = 1024
#		else:
#			random.seed()
#			self.curr_src_port=random.randrange(1024,65535)

		return self.curr_src_port		


if __name__ == "__main__":
	if len(sys.argv) < 2:
		print "usage: %s host [test_number]" % (sys.argv[0])
		sys.exit(1)

	try:
        ###X: get IP of host 
	    ipaddress = socket.gethostbyname(sys.argv[1])
	except:
	    print "Cannot resolve IP address of host: %s" % (sys.argv[1])
	    sys.exit(1)

	if len(sys.argv)  == 2:
		prober = GFCProber(ipaddress, "all")
	elif len(sys.argv) ==3: 
		prober = GFCProber(ipaddress, sys.argv[2])
	prober.probe()


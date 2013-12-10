#!/usr/bin/env python
# To get this to work, you need to first
# run the bash command: 
# sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s <IP of machine from which conducting tests> -j DROP
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
	def __init__(self, test_name):
		self.test_name = test_name
		self.curr_src_port = 1024

	def probe(self):
		## FIXME: Put your own host here
		host="xxxxxxxxxxxxxxxxxx.xxx"
		uri="peacehall/"

		dst_port = 80
		random.seed()			
		self.curr_src_port=random.randrange(1024,65535)

		# Get IP address of the host
		ping = sr1(IP(dst=host)/ICMP(),verbose=0)
		dst_ip = ping.getlayer(IP).src

		# HTTP GET statement
		http_get = 'GET /'+uri+' HTTP/1.0\r\nConnection: Keep-Alive\r\nHost: '+host+'\r\n\r\n'
		http_get_benign = 'GET /'+'pineapple/'+' HTTP/1.0\r\nConnection: Keep-Alive\r\nHost: '+host+'\r\n\r\n'
		pay1='GET /'+uri
		pay2='/ HTTP/1.0\r\nHost: '
		pay3=host+'\r\n\r\n'

		# We disinclude tcb_create* tests because we handle handshake 
		#   a bit differently for those tests
		if not('tcb_create' in self.test_name):
			# TCP handshake
			ip=IP(dst=dst_ip,proto=6)		 
			syn = ip/TCP(sport=self.get_src_port(), dport=dst_port, flags='S')
			syn_ack = sr1(syn)
			# Not sending a dataless ack

		
		# --------test_srcport_: HTTP request for censored stuff from different src ports ---
		if self.test_name=="test_srcport" or self.test_name=="all":
			# Note: For this test, I put the line:
			#  return <src_port>
			# in the function self.get_src_port()
			# and comment out the other return.
			# Remember to revert the changes once done with this test.
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1

			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / http_get
			send(seg1)
	
		# --------test0: Simple HTTP request sent in segments ---------
		if self.test_name=="test0" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1

			pay1='GET /'
			seq1=next_seq
			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / pay1
			send(seg1)

			next_seq=next_seq+len(pay1)

			pay2=uri
			seg2=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / pay2
			send(seg2)

			next_seq=next_seq+len(pay2)

			pay3='/ HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			seg3=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / pay3
			send(seg3) 
			
		
		# --------Tests filtering_*: GFC filtering style ---------
		# filtering_1: Does GFC check individual TCP segment for keywords?
                #              Only send one segment containing the sensitive keyword 
		if self.test_name=="filtering_1" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1

			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
					seq=next_seq, ack=next_ack, flags='PA') / pay1
			send(seg1)

		# --------Tests stream_*: TCP Stream Reassembly---------
		# ====Test stream_1====
		# Out of order TCP segments with delay
		if self.test_name=="stream_1" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1

			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, ack=next_ack, flags='PA') / pay1
			send(seg1)

			next_seq=next_seq+len(pay1)
			 
			next_seq=next_seq+len(pay2)
			seg3=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, ack=next_ack, flags='PA') / pay3
			send(seg3) 

			delay=120
			sleep(delay)

			next_seq=syn_ack.ack
			next_seq=next_seq+len(pay1)
			seg2=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, ack=next_ack, flags='PA') / pay2
			send(seg2)

		# ===Tests stream_2*: Desync GFC's reassembly===== 
		# Test stream_2a: Send TCP syn packet with bad seq number 
		# between data to desync GFC 
		if self.test_name=="stream_2a" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1

			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, ack=next_ack, flags='PA') / pay1
			send(seg1)

			next_seq=next_seq+len(pay1)
			seg2=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, ack=next_ack, flags='PA') / pay2
			send(seg2) 

			random_seq=555
			syn_bad = IP(dst=dst_ip,proto=6)/TCP(sport=self.get_src_port(), dport=dst_port, flags='S', seq=random_seq)
			send(syn_bad)

			next_seq=next_seq+len(pay2)
			seg3=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, ack=next_ack, flags='PA') / pay3
			send(seg3) 

		# stream_2b: Send TCP pakcets with random seq and ack
		if self.test_name=="stream_2b" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1

			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, ack=next_ack, flags='PA') / pay1
			send(seg1)

			# Here is bad segment 1
			random_seq=4444
			random_ack=5555
			bad_seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=random_seq, ack=random_ack, flags='PA') / pay1
			send(bad_seg1)

			next_seq=next_seq+len(pay1)
			seg2=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, ack=next_ack, flags='PA') / pay2
			send(seg2) 

			# Here is bad segment 2
			random_seq=6666
			random_ack=7777
			bad_seg2=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=random_seq, ack=random_ack, flags='PA') / pay2
			send(bad_seg2) 

			next_seq=next_seq+len(pay2)
			seg3=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, ack=next_ack, flags='PA') / pay3
			send(seg3) 

		# Test stream_2c: Send TCP seg with bad ack number 
		if self.test_name=="stream_2c" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1

			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, ack=next_ack, flags='PA') / pay1
			send(seg1)

			next_seq=next_seq+len(pay1)
			seg2=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, ack=next_ack, flags='PA') / pay2
			send(seg2) 

			next_seq=next_seq+len(pay2)
			bad_ack=555
			seg3=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, ack=bad_ack, flags='PA') / pay3
			send(seg3) 	

		# stream_2d: Set window size to 0 midway
		# TODO: You have to manually inject a window size 0 packet
		#       from the server half way through 
	#	if self.test_name=="stream_2c" or self.test_name=="all":
	#		next_seq=syn_ack.ack
	#		next_ack=syn_ack.seq+1 

	#		seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
	#			 seq=next_seq, ack=next_ack, flags='PA', window=8192) / pay1
	#		send(seg1)

	#		next_seq=next_seq+len(pay1)
	#		seg2=ip/TCP(dport=dst_port, sport=self.get_src_port(),
	#			 seq=next_seq, ack=next_ack, flags='PA', window=0) / pay2
	#		send(seg2) 

	#		next_seq=next_seq+len(pay2)
	#		seg3=ip/TCP(dport=dst_port, sport=self.get_src_port(),
	#			 seq=next_seq, ack=next_ack, flags='PA', window=8192) / pay3
	#		send(seg3)
		
		# TODO
		# Test stream_2e: Send TCP packet with data more than the 
		#		 receiver's window size 
		if self.test_name=="stream_2e" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			# Warning: This doesn't accommodate for wrapping around maximum
			#           value of window size
			big_data='peacehall'+('x'*syn_ack.window)
			seg_big=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / big_data
			send(seg_big)

			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / http_get
			send(seg)

		# TODO: Manual
		# Test stream_2f (TODO): As we have seen in TCP segment overlap tests that GFC 
		#			cannot properly assemble overlap cases. The question is 
		#			if the overlap desyncs entire stream and we can get subsequent 
		#			HTTP requests with sensitive keywords?

		# TODO: Manual
		# Test stream-2g (TODO): Set the window to 0, and then send a seg with URG 
		#			 pointer pointing to an HTTP request (inspiration rfc 793: 
		#			"However, even when the receive window is zero, a TCP must 
		#			process the RST and URG fields of all incoming segments).

		# =====Test stream_3===== 
		# Do handshake, send half the data, tear down conn, then do a new handshake 
		# with diff seq nums and send the remaining data with the 
		# corresponding seq numbers. If server has 
		# state for the old data, it will accept it. If GFC doesn't, 
		# it will be tricked.
		if self.test_name=="stream_3" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1 
	 
			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
					seq=next_seq, ack=next_ack, flags='PA') / pay1
			send(seg1)

			next_seq=next_seq+len(pay1)

			# reset the conn
			seg_rst=ip/TCP(dport=dst_port, sport=self.get_src_port(),
					seq=next_seq, ack=next_ack, flags='RA')
			send(seg_rst)

			# Do the handshake and send remaining data
			syn = ip/TCP(sport=self.get_src_port(), dport=dst_port, flags='S',seq=500)
			syn_ack = sr1(syn)

			# send remaining segs from last conn
			seg2=ip/TCP(dport=dst_port,sport=self.get_src_port(),
				 seq=next_seq, ack=next_ack, flags='PA') / pay2
			send(seg2) 

			next_seq=next_seq+len(pay2)
			seg3=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, ack=next_ack, flags='PA') / pay3
			send(seg3) 

		# %%%%%% Tests overlap_4*: Overlapping segments %%%%% 
		# ==== Tests overlap_4.1* =====
		# subsequent segment has a lower offset than 
		#       the original segment
		# ___________________________
		#         |seg_original|
		#  |seg_subsequent|     
		# ___________________________
		# ==== Tests overlap_4.1.1* ========
		# subsequent segment ends before 
		#       the original segment
		# ___________________________
		#         |seg_orig|
		#   |seg_sub|     
		# ======================
		# Test overlap_4.1.1a: see below
		# ___________________________
		#         |WORD|
		# |....KEY...|
		if self.test_name=="overlap_4.1.1a" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1 

			pay1='GET '
			seq1=next_seq
			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / pay1
			send(seg1)

			next_seq=next_seq+len(pay1)

			pay2_orig='hall'+('x'*4)
			seq2_orig=next_seq+8
			seg2_orig=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_orig, ack=next_ack, flags='PA') / pay2_orig
			send(seg2_orig)

			pay2_sub='/bbpeace'+('y'*4)
			seq2_sub=next_seq
			seg2_sub=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_sub, ack=next_ack, flags='PA') / pay2_sub
			send(seg2_sub)
			
			pay3='/ HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			seq3=seq2_orig+len(pay2_orig)
			seg3=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq3, ack=next_ack, flags='PA') / pay3
			send(seg3) 
		
		# Test overlap_4.1.1a_extended: Same as 4.1.1a except that I send additional
		# HTTP  'bad' requests after the initial request comprising overlapping segments
		# to see if stream reassembly of GFC is permanently damaged
		if self.test_name=="overlap_4.1.1a_extended" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1 

			pay1='GET '
			seq1=next_seq
			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / pay1
			send(seg1)

			next_seq=next_seq+len(pay1)

			pay2_orig='hall'+('x'*4)
			seq2_orig=next_seq+8
			seg2_orig=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_orig, ack=next_ack, flags='PA') / pay2_orig
			send(seg2_orig)

			pay2_sub='/bbpeace'+('y'*4)
			seq2_sub=next_seq
			seg2_sub=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_sub, ack=next_ack, flags='PA') / pay2_sub
			send(seg2_sub)
			
			pay3='/ HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			seq3=seq2_orig+len(pay2_orig)
			seg3=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq3, ack=next_ack, flags='PA') / pay3
			send(seg3) 


			seq_end=seq3+len(pay3)
			# This is hard coded. I know from trace file that this request
			# 	is preceded by the server sending 505 bytes of HTTP 404 not 
			# 	found response.
			ack_end=next_ack+505
			seg_end=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq_end, ack=next_ack, flags='PA') / http_get
			send(seg_end)

		# ======================
		# Test overlap_4.1.1b: see below
		# ___________________________
		#         |    WORD|
		# |........KEY|

		if self.test_name=="overlap_4.1.1b" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1 

			pay1='GET '
			seq1=next_seq
			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / pay1
			send(seg1)

			next_seq=next_seq+len(pay1)

			pay2_orig=('a'*4)+'hall'
			seq2_orig=next_seq+8
			seg2_orig=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_orig, ack=next_ack, flags='PA') / pay2_orig
			send(seg2_orig)

			pay2_sub='/'+('b'*6)+'peace'
			seq2_sub=next_seq
			seg2_sub=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_sub, ack=next_ack, flags='PA') / pay2_sub
			send(seg2_sub)
			
			pay3='/ HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			seq3=seq2_orig+len(pay2_orig)
			seg3=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq3, ack=next_ack, flags='PA') / pay3
			send(seg3)
    
		# ___________________________
		# ===== Tests overlap_4.1.2* ========
		# subsequent segments end at the same offset 
		#       as the original segment
		# ___________________________
		#         |seg_original|
		#     | seg_subsequent |     
		# ======================
		# Test overlap_4.1.2a: see below
		# ___________________________
		#         |......|
		# |.....keyword..|

		if self.test_name=="overlap_4.1.2a" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1 

			pay1='GET '
			seq1=next_seq
			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / pay1
			send(seg1)

			next_seq=next_seq+len(pay1)

			pay2_orig='aaaaaaaa'
			seq2_orig=next_seq+8
			seg2_orig=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_orig, ack=next_ack, flags='PA') / pay2_orig
			send(seg2_orig)

			pay2_sub='/bbpeacehall'+('y'*4)
			seq2_sub=next_seq
			seg2_sub=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_sub, ack=next_ack, flags='PA') / pay2_sub
			send(seg2_sub)
			
			pay3='/ HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			seq3=seq2_orig+len(pay2_orig)
			seg3=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq3, ack=next_ack, flags='PA') / pay3
			send(seg3)

		# ======================
		# Test overlap_4.1.2b: see below
		# ___________________________
		#         |word..|
		# |....key.......|

		if self.test_name=="overlap_4.1.2b" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1 

			pay1='GET '
			seq1=next_seq
			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / pay1
			send(seg1)

			next_seq=next_seq+len(pay1)

			pay2_orig='hall'+('x'*4)
			seq2_orig=next_seq+8
			seg2_orig=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_orig, ack=next_ack, flags='PA') / pay2_orig
			send(seg2_orig)

			pay2_sub='/bbpeace'+('y'*8)
			seq2_sub=next_seq
			seg2_sub=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_sub, ack=next_ack, flags='PA') / pay2_sub
			send(seg2_sub)
			
			pay3='/ HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			seq3=seq2_orig+len(pay2_orig)
			seg3=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq3, ack=next_ack, flags='PA') / pay3
			send(seg3)
		# ___________________________
		# ===== Tests overlap_4.1.3 ========
		# subsequent segment ends past 
		#       the original segment
		# ___________________________
		#         |seg_original|
		#     |  seg_subsequent    |     
		# ======================
		# Test overlap_4.1.3a: see below
		# ___________________________
		#         |.......|
		# |........keyword..|

		if self.test_name=="overlap_4.1.3a" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1 

			pay1='GET '
			seq1=next_seq
			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / pay1
			send(seg1)

			next_seq=next_seq+len(pay1)

			pay2_orig='a'*8
			seq2_orig=next_seq+8
			seg2_orig=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_orig, ack=next_ack, flags='PA') / pay2_orig
			send(seg2_orig)

			pay2_sub='/'+('b'*6)+'peacehall'+('y'*8)
			seq2_sub=next_seq
			seg2_sub=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_sub, ack=next_ack, flags='PA') / pay2_sub
			send(seg2_sub)
			
			pay3='/ HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			seq3=seq2_sub+len(pay2_sub)
			seg3=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq3, ack=next_ack, flags='PA') / pay3
			send(seg3)

		# ======================
		# Test overlap_4.1.3b: see below
		# ___________________________
		#         |ywo|
		# |.....ke.....rd|

		if self.test_name=="overlap_4.1.3b" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1 

			pay1='GET '
			seq1=next_seq
			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / pay1
			send(seg1)

			next_seq=next_seq+len(pay1)

			pay2_orig='eaceh'
			seq2_orig=next_seq+8
			seg2_orig=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_orig, ack=next_ack, flags='PA') / pay2_orig
			send(seg2_orig)

			pay2_sub='/'+('b'*6)+'p'+('y'*5)+'all'
			seq2_sub=next_seq
			seg2_sub=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_sub, ack=next_ack, flags='PA') / pay2_sub
			send(seg2_sub)
			
			pay3='/ HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			seq3=seq2_sub+len(pay2_sub)
			seg3=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq3, ack=next_ack, flags='PA') / pay3
			send(seg3)

		# ==== Tests overlap_4.2* ========
		# subsequent segment has the same offset as 
		#       the original segment
		# ___________________________
		#         |seg_original|
		#         |seg_subsequent|     
		# ___________________________
		# ==== Tests overlap_4.2.1* ========
		# subsequent segment ends at the same 
		# offset as the original segment
		# ___________________________
		#         |seg_original|
		#         |seg_subseq  |     
		# ======================
		# Test overlap_4.2.1a: see below
		# ___________________________
		# |KEYWORD|
		# |.......|

		if self.test_name=="overlap_4.2.1a" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1 

			pay1='GET '
			seq1=next_seq
			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / pay1
			send(seg1)

			next_seq=next_seq+len(pay1)

			pay2_orig='/peacehall'+('x'*6)
			seq2_orig=next_seq
			seg2_orig=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_orig, ack=next_ack, flags='PA') / pay2_orig
			send(seg2_orig)

			pay2_sub='/'+('b'*15)
			seq2_sub=next_seq
			seg2_sub=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_sub, ack=next_ack, flags='PA') / pay2_sub
			send(seg2_sub)
			
			pay3='/ HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			seq3=seq2_orig+len(pay2_orig)
			seg3=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq3, ack=next_ack, flags='PA') / pay3
			send(seg3)

		# Test overlap_4.2.1a_extended: Same as 4.2.1a except that I send additional
		# HTTP  'bad' requests after the initial request comprising overlapping segments
		# to see if stream reassembly of GFC is permanently damaged
		if self.test_name=="overlap_4.2.1a_extended" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1 

			pay1='GET '
			seq1=next_seq
			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / pay1
			send(seg1)

			next_seq=next_seq+len(pay1)

			pay2_orig='/peacehall'+('x'*6)
			seq2_orig=next_seq
			seg2_orig=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_orig, ack=next_ack, flags='PA') / pay2_orig
			send(seg2_orig)

			pay2_sub='/'+('b'*15)
			seq2_sub=next_seq
			seg2_sub=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_sub, ack=next_ack, flags='PA') / pay2_sub
			send(seg2_sub)
			
			pay3='/ HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			seq3=seq2_orig+len(pay2_orig)
			seg3=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq3, ack=next_ack, flags='PA') / pay3
			send(seg3)

			seq_end=seq3+len(pay3)
			# This is hard coded. I know from trace file that this request
			# 	is preceded by the server sending 505 bytes of HTTP 404 not 
			# 	found response.
			ack_end=next_ack+505
			seg_end=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq_end, ack=next_ack, flags='PA') / http_get
			send(seg_end)


		# ======================
		# Test overlap_4.2.1b: see below
		# ___________________________
		# |.......|
		# |KEYWORD|

		if self.test_name=="overlap_4.2.1b" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1 

			pay1='GET '
			seq1=next_seq
			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / pay1
			send(seg1)

			next_seq=next_seq+len(pay1)

			pay2_orig='/'+('a'*15)
			seq2_orig=next_seq
			seg2_orig=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_orig, ack=next_ack, flags='PA') / pay2_orig
			send(seg2_orig)

			pay2_sub='/peacehall'+('y'*6)
			seq2_sub=next_seq
			seg2_sub=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_sub, ack=next_ack, flags='PA') / pay2_sub
			send(seg2_sub)
			
			pay3='/ HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			seq3=seq2_orig+len(pay2_orig)
			seg3=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq3, ack=next_ack, flags='PA') / pay3
			send(seg3)

		# Test overlap_4.2.1b_extended: Same as 4.2.1b except that I send additional
		# HTTP  'bad' requests after the initial request comprising overlapping segments
		# to see if stream reassembly of GFC is permanently damaged
		if self.test_name=="overlap_4.2.1b_extended" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1 

			pay1='GET '
			seq1=next_seq
			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / pay1
			send(seg1)

			next_seq=next_seq+len(pay1)

			pay2_orig='/'+('a'*15)
			seq2_orig=next_seq
			seg2_orig=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_orig, ack=next_ack, flags='PA') / pay2_orig
			send(seg2_orig)

			pay2_sub='/peacehall'+('y'*6)
			seq2_sub=next_seq
			seg2_sub=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_sub, ack=next_ack, flags='PA') / pay2_sub
			send(seg2_sub)
			
			pay3='/ HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			seq3=seq2_orig+len(pay2_orig)
			seg3=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq3, ack=next_ack, flags='PA') / pay3
			send(seg3)

			seq_end=seq3+len(pay3)
			# This is hard coded. I know from trace file that this request
			# 	is preceded by the server sending 505 bytes of HTTP 404 not 
			# 	found response.
			ack_end=next_ack+505
			seg_end=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq_end, ack=next_ack, flags='PA') / http_get
			send(seg_end)
	
	
		# ___________________________
		# ==== Tests overlap_4.2.2* ========
		# subsequent segment ends before 
		# the original segment
		# ___________________________
		#         | seg_original |
		#         |seg_subseq|     
		# ======================
		# Test overlap_4.2.2a: see below
		# ___________________________
		# |.......word|
		# |...key|
	
		if self.test_name=="overlap_4.2.2a" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1 

			pay1='GET '
			seq1=next_seq
			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / pay1
			send(seg1)

			next_seq=next_seq+len(pay1)

			pay2_orig='/'+('a'*11)+'hall'
			seq2_orig=next_seq
			seg2_orig=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_orig, ack=next_ack, flags='PA') / pay2_orig
			send(seg2_orig)

			pay2_sub='/'+('b'*6)+'peace'
			seq2_sub=next_seq
			seg2_sub=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_sub, ack=next_ack, flags='PA') / pay2_sub
			send(seg2_sub)
			
			pay3='/ HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			seq3=seq2_orig+len(pay2_orig)
			seg3=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq3, ack=next_ack, flags='PA') / pay3
			send(seg3)

		# ======================
		# Test overlap_4.2.2b: see below
		# ___________________________
		# |....keyword|
		# |......|

		if self.test_name=="overlap_4.2.2b" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1 

			pay1='GET '
			seq1=next_seq
			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / pay1
			send(seg1)

			next_seq=next_seq+len(pay1)

			pay2_orig='/'+('a'*6)+'peacehall'
			seq2_orig=next_seq
			seg2_orig=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_orig, ack=next_ack, flags='PA') / pay2_orig
			send(seg2_orig)

			pay2_sub='/'+('b'*11)
			seq2_sub=next_seq
			seg2_sub=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_sub, ack=next_ack, flags='PA') / pay2_sub
			send(seg2_sub)
			
			pay3='/ HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			seq3=seq2_orig+len(pay2_orig)
			seg3=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq3, ack=next_ack, flags='PA') / pay3
			send(seg3)

		# ___________________________
		# ==== Tests overlap_4.2.3* ========
		# subsequent segment ends after 
		# the original segment
		# ___________________________
		#         | seg_original|
		#         |      seg_subseq|     
		# ======================
		# Test overlap_4.2.3a: see below
		# ___________________________
		# |.......|
		# |.....keyword|

		if self.test_name=="overlap_4.2.3a" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1 

			pay1='GET '
			seq1=next_seq
			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / pay1
			send(seg1)

			next_seq=next_seq+len(pay1)

			pay2_orig='/'+('a'*11)
			seq2_orig=next_seq
			seg2_orig=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_orig, ack=next_ack, flags='PA') / pay2_orig
			send(seg2_orig)

			pay2_sub='/'+('b'*6)+'peacehall'
			seq2_sub=next_seq
			seg2_sub=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_sub, ack=next_ack, flags='PA') / pay2_sub
			send(seg2_sub)
			
			pay3='/ HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			seq3=seq2_sub+len(pay2_sub)
			seg3=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq3, ack=next_ack, flags='PA') / pay3
			send(seg3)

		# ======================
		# Test overlap_4.2.3b: see below
		# ___________________________
		# |....key|
		# |........word|

		if self.test_name=="overlap_4.2.3b" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1 

			pay1='GET '
			seq1=next_seq
			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / pay1
			send(seg1)

			next_seq=next_seq+len(pay1)

			pay2_orig='/'+('a'*6)+'peace'
			seq2_orig=next_seq
			seg2_orig=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_orig, ack=next_ack, flags='PA') / pay2_orig
			send(seg2_orig)

			pay2_sub='/'+('b'*11)+'hall'
			seq2_sub=next_seq
			seg2_sub=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_sub, ack=next_ack, flags='PA') / pay2_sub
			send(seg2_sub)
			
			pay3='/ HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			seq3=seq2_sub+len(pay2_sub)
			seg3=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq3, ack=next_ack, flags='PA') / pay3
			send(seg3)

		# ====Tests overlap_4.3*========
		# subsequent segment has higher offset than 
		#       the original segment
		# ___________________________
		#         |seg_original|
		#             |seg_subsequent|     
		# ___________________________
		# ====Tests overlap_4.3.1*========
		# subsequent segment ends at the same 
		# offset as the original segment
		# ___________________________
		#       |  seg_original|
		#           |seg_subseq|     
		# ======================
		# Test overlap_4.3.1a: see below
		# ___________________________
		# |.KEYWORD...|
		#     |.......|

		if self.test_name=="overlap_4.3.1a" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1 

			pay1='GET '
			seq1=next_seq
			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / pay1
			send(seg1)

			next_seq=next_seq+len(pay1)

			pay2_orig='/aapeacehall'+('x'*4)
			seq2_orig=next_seq
			seg2_orig=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_orig, ack=next_ack, flags='PA') / pay2_orig
			send(seg2_orig)

			pay2_sub=('b'*8)
			seq2_sub=next_seq+8
			seg2_sub=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_sub, ack=next_ack, flags='PA') / pay2_sub
			send(seg2_sub)
			
			pay3='/ HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			seq3=seq2_orig+len(pay2_orig)
			seg3=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq3, ack=next_ack, flags='PA') / pay3
			send(seg3)

		# ======================
		# Test overlap_4.3.1b: see below
		# ___________________________
		# |.KEY.......|
		#     |WORD...|

		if self.test_name=="overlap_4.3.1b" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1 

			pay1='GET '
			seq1=next_seq
			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / pay1
			send(seg1)

			next_seq=next_seq+len(pay1)

			pay2_orig='/aapeace'+('x'*8)
			seq2_orig=next_seq
			seg2_orig=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_orig, ack=next_ack, flags='PA') / pay2_orig
			send(seg2_orig)

			pay2_sub='hall'+('y'*4)
			seq2_sub=next_seq+8
			seg2_sub=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_sub, ack=next_ack, flags='PA') / pay2_sub
			send(seg2_sub)
			
			pay3='/ HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			seq3=seq2_orig+len(pay2_orig)
			seg3=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq3, ack=next_ack, flags='PA') / pay3
			send(seg3)

		# ===== Tests overlap_4.3.2* ========
		# subsequent segment ends before
		#    the original segment
		# ___________________________
		#       |  seg_original |
		#           |seg_sub|     
		# ======================
		# Test overlap_4.3.2a: see below
		# ___________________________
		# |..KEYWORD...|
		#     |..|

		if self.test_name=="overlap_4.3.2a" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1 

			pay1='GET '
			seq1=next_seq
			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / pay1
			send(seg1)

			next_seq=next_seq+len(pay1)

			pay2_orig='/'+('a'*6)+'peacehall'
			seq2_orig=next_seq
			seg2_orig=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_orig, ack=next_ack, flags='PA') / pay2_orig
			send(seg2_orig)

			pay2_sub=('b'*4)
			seq2_sub=next_seq+8
			seg2_sub=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_sub, ack=next_ack, flags='PA') / pay2_sub
			send(seg2_sub)
			
			pay3='/ HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			seq3=seq2_orig+len(pay2_orig)
			seg3=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq3, ack=next_ack, flags='PA') / pay3
			send(seg3)

		# ======================
		# Test overlap_4.3.2b: see below
		# ___________________________
		# |..KE..ORD...|
		#     |YW|

		if self.test_name=="overlap_4.3.2b" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1 

			pay1='GET '
			seq1=next_seq
			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / pay1
			send(seg1)

			next_seq=next_seq+len(pay1)

			pay2_orig='/'+('a'*6)+'p'+('x'*4)+'hall'
			seq2_orig=next_seq
			seg2_orig=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_orig, ack=next_ack, flags='PA') / pay2_orig
			send(seg2_orig)

			pay2_sub='eace'
			seq2_sub=next_seq+8
			seg2_sub=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_sub, ack=next_ack, flags='PA') / pay2_sub
			send(seg2_sub)
			
			pay3='/ HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			seq3=seq2_orig+len(pay2_orig)
			seg3=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq3, ack=next_ack, flags='PA') / pay3
			send(seg3)

		# ====Tests overlap_4.3.3*========
		# subsequent segment ends after
		#    the original segment
		# ___________________________
		#       |  seg_original |
		#           |   seg_sub    |     
		# ======================
		# Test overlap_4.3.3a: see below
		# ___________________________
		# |........KEYWO|
		#            |..RD.......|

		if self.test_name=="overlap_4.3.3a" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1 

			pay1='GET '
			seq1=next_seq
			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / pay1
			send(seg1)

			next_seq=next_seq+len(pay1)

			pay2_orig='/'+('a'*6)+'peace'
			seq2_orig=next_seq
			seg2_orig=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_orig, ack=next_ack, flags='PA') / pay2_orig
			send(seg2_orig)

			pay2_sub=('b'*4)+'hall'
			seq2_sub=next_seq+8
			seg2_sub=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_sub, ack=next_ack, flags='PA') / pay2_sub
			send(seg2_sub)
			
			pay3='/ HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			seq3=seq2_sub+len(pay2_sub)
			seg3=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq3, ack=next_ack, flags='PA') / pay3
			send(seg3)

		# ======================
		# Test overlap_4.3.3b: see below
		# ___________________________
		# |........KEY..|
		#            |WORD.......|
		if self.test_name=="overlap_4.3.3b" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1 

			pay1='GET '
			seq1=next_seq
			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / pay1
			send(seg1)

			next_seq=next_seq+len(pay1)

			pay2_orig='/'+('a'*6)+'p'+('x'*4)
			seq2_orig=next_seq
			seg2_orig=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_orig, ack=next_ack, flags='PA') / pay2_orig
			send(seg2_orig)

			pay2_sub='eacehall'
			seq2_sub=next_seq+8
			seg2_sub=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq2_sub, ack=next_ack, flags='PA') / pay2_sub
			send(seg2_sub)
			
			pay3='/ HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			seq3=seq2_sub+len(pay2_sub)
			seg3=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=seq3, ack=next_ack, flags='PA') / pay3
			send(seg3)

		# %%%% Tests syntax_*: Invalid header field values/combination %%%%% 

		# Test syntax_1: Bad TCP checksum
		if self.test_name=="syntax_1" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			 	seq=next_seq, ack=next_ack, flags='PA', chksum=0x7ce7) / http_get
			send(seg) 

		# Test syntax_1b: Check if GFC TCP reassembly desyncd by syntax_1
		#                 Send HTTP request with correct checksum after the first one
		#                 that now carries benign payload just to desync GFC
		if self.test_name=="syntax_1b" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			seg1=IP(dst=dst_ip,proto=6,ttl=10)/TCP(dport=dst_port, sport=self.get_src_port(),
					seq=next_seq, ack=next_ack, flags='PA', chksum=0x7ce7) / http_get_benign
			send(seg1) 

			seg2=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			 	seq=next_seq, ack=next_ack, flags='PA') / http_get
			send(seg2) 


		# ===== Tests syntax_2* ========
		# Bad flag combination
		# ======================
		# Test syntax_2a-->NULL control flags
		if self.test_name=="syntax_2a" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, flags='') / http_get
			send(seg)
			
		# ======================
		# Test syntax_2b-->Syn and Rst set in data segment
		if self.test_name=="syntax_2b" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, ack=next_ack, flags='SRPA') / http_get
			send(seg)

		# ======================
		# Test syntax_2c-->Set both Syn and Fin set in data segment
		if self.test_name=="syntax_2c" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, ack=next_ack, flags='SFPA') / http_get
			send(seg)

		# ======================
		# Test syntax_2d-->Ack flag not set in data segment
		if self.test_name=="syntax_2d" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, flags='P') / http_get
			send(seg)

		# ======================
		# Test syntax_2e-->Syn flag set in data segment
		if self.test_name=="syntax_2e" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, ack=next_ack, flags='SPA') / http_get
			send(seg)

		# ======================
		# Test syntax_2f-->Ack flag not set, but ack number specified
		if self.test_name=="syntax_2f" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, ack=next_ack, flags='P') / http_get
			send(seg)

		# Test syntax_3: Send TCP packet with seq beyond the 
		#		 receiver's window size 
		# Note: This isn't really related to syntax. Putting
		#       it here for now for lack of other ideas :-S
		if self.test_name=="syntax_3" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			# Warning: This doesn't accommodate for wrapping around maximum
			#           value of window size when selecting the seq number
			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq+syn_ack.window+50, ack=next_ack, flags='PA') / http_get
			send(seg)

		# ===== Tests syntax_4* ========
		# Bad ack number
		# ======================
		# Test syntax_4a-->Back ack number (> expected/correct value)
		if self.test_name=="syntax_4a" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, ack=next_ack+666, flags='PA') / http_get
			send(seg)
			
		# ======================
		# Test syntax_4b-->Bad ack number (< expected/correct value)
		if self.test_name=="syntax_4b" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, ack=next_ack-5, flags='PA') / http_get
			send(seg)

		# ======================
		# Test syntax_4c-->Does syntax_4b desync GFC? See if subsequent HTTP req 
		#		  for censored content can be retrieved  following a seg 
		#		  with Bad ack number (< expected/correct value)
		#                 that now carries benign payload just to desync GFC
		if self.test_name=="syntax_4c" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, ack=next_ack-5, flags='PA') / http_get_benign
			send(seg1)

			# Server ignores seg1, lets send seg2 with right seq and ack
			seg2=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, ack=next_ack, flags='PA') / http_get
			send(seg2)

		# ======================
		# Test syntax_4d-->same as syntax_4c, but seg1 has low ttl so that only GFC
		#		   may see it
		if self.test_name=="syntax_4d" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			seg1=IP(dst=dst_ip,proto=6,ttl=17)/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, ack=next_ack-5, flags='PA') / http_get_benign
			send(seg1)

			# Server ignores seg1, lets send seg2 with right seq and ack
			seg2=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, ack=next_ack, flags='PA') / http_get
			send(seg2)
			# ======================

		# Test syntax_4e-->same as syntax_4c, but seg1 has low ttl so that only GFC
		#		   may see it
		if self.test_name=="syntax_4e" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1

			seg1=IP(dst=dst_ip,proto=6)/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq+5, ack=next_ack, flags='PA') / http_get
			send(seg1)

			# Server ignores seg1, lets send seg2 with right seq and ack
#			seg2=ip/TCP(dport=dst_port, sport=self.get_src_port(),
#				 seq=next_seq, ack=next_ack, flags='PA') / http_get
#			send(seg2)
#		
#			next_seq=next_seq+len(http_get_benign)

#			seg2=ip/TCP(dport=dst_port, sport=self.get_src_port(),
#				 seq=(next_seq), ack=next_ack, flags='PA') / http_get
#			send(seg2)
			
		# Test syntax_4f-->same as syntax_4c, but seg1 has low ttl so that only GFC
		#		   may see it
		if self.test_name=="syntax_4f" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1

			seg1=IP(dst=dst_ip,proto=6)/TCP(dport=dst_port, sport=self.get_src_port(),
			seq=next_seq, ack=next_ack-5, flags='PA') / http_get_benign
			send(seg1)

			seg1=IP(dst=dst_ip,proto=6)/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq-1, ack=next_ack, flags='PA') / http_get
			send(seg1)

			# Server ignores seg1, lets send seg2 with right seq and ack
#			seg2=ip/TCP(dport=dst_port, sport=self.get_src_port(),
#				 seq=next_seq+1000, ack=next_ack, flags='PA') / http_get
#			send(seg2)
		
#			next_seq=next_seq+len(http_get_benign)

#			seg2=ip/TCP(dport=dst_port, sport=self.get_src_port(),
#				 seq=((next_seq+syn_ack.window)/16), ack=next_ack, flags='PA') / http_get
#			send(seg2)

		# Test syntax_5: Reserved bits set
		if self.test_name=="syntax_5" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, ack=next_ack, flags='PA', reserved=7) / http_get
			send(seg)

		# ===== Tests syntax_6* ========
		# Bad data offset
		# ======================
		# Test syntax_6a-->Back data offset (< correct value)
		if self.test_name=="syntax_6a" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, ack=next_ack, flags='PA', dataofs=4) / http_get
			send(seg)
			
		# ======================
		# Test syntax_6b-->Back data offset (> correct value)
		if self.test_name=="syntax_6b" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, ack=next_ack, flags='PA', dataofs=14) / http_get
			send(seg)

		# ===== Tests syntax_7* ========
		# Bad values with URG pointer
		# ======================
		# Test syntax_7a-->urg flag unset but urgptr is non-zero.
		if self.test_name=="syntax_7a" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, ack=next_ack, flags='PA', urgptr=50) / http_get
			send(seg)
			
		# ======================
		# Test syntax_7b-->urg flag set but urg ptr pointing beyond end of packet (65534)
		if self.test_name=="syntax_7b" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, ack=next_ack, flags='PAU', urgptr=65532) / http_get
			send(seg)

		# %%%% Tests tcb_create_*: TCB Creation %%%%% 

		# Test tcb_create_1: Syn packet missing
		# TODO: Manually send syn-ack from server, and then ack 
		#       from client, then client requests the filtered uri

		# ===== Tests tcb_create_2* ========
		# Syn-ack packet missing
		# ======================
		# Test tcb_create_2a-->(i) client sends syn packet with low ttl, 
		#		       (ii) client requests filtered URI, 
		#			    assuming a random ack for the server
		if self.test_name=="tcb_create_2a" or self.test_name=="all":
			# TCP handshake
			my_seq=0
			ip=IP(dst=dst_ip,proto=6,ttl=10)		 
			syn = ip/TCP(sport=self.get_src_port(), dport=dst_port, flags='S', seq=my_seq)
			send(syn)
			# Not sending a dataless ack
			
			# Send HTTP request
			next_seq=my_seq+1
			# Pick any random ack
			next_ack=555
			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, ack=next_ack, flags='PA') / http_get
			send(seg)
			
		# ======================
		# Test tcb_create_2b-->(i) client sends syn packet with low ttl, 
		#                      (ii) client sends ack with low ttl, 
		#                      (iii) server sends syn-ack,
		#		       (iv) client requests filtered URI
		# TODO: Manual because of (iii)

		# Test tcb_create_3: Send HTTP req without handshake 
		#                    (assuming a random seq for the other party)
                #                    to see if GFC syncs on data.
		if self.test_name=="tcb_create_3" or self.test_name=="all": 
			random_seq=555
			random_ack=555
			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
					 seq=random_seq, ack=random_ack, flags='PA') / http_get
			send(seg)

		# Test tcb_create_4: Can we split route the tcp handshake, e.g. 
		#                        just send the syn-ack through a different 
		#    			 route (presuming GFC does not routinely establish 
		#			 TCB when syn-ack is missing)
		# TODO: MANUAL

		# ======================
		# TODO MANUAL
		# Test tcb_create_5-->(i) client sends syn packet with low ttl, 
		#		     (ii) client performs a proper 3-way handshake
		#                    (iii) client requests filtered content
		if self.test_name=="tcb_create_5" or self.test_name=="all":
			# Insert syn on GFC only
			my_seq=50
			ip=IP(dst=dst_ip,proto=6,ttl=10)		 
			syn = ip/TCP(sport=6666, dport=dst_port, flags='S', seq=my_seq)
			send(syn)
		
			# A new handshake
			ip=IP(dst=dst_ip,proto=6)		 
			syn = ip/TCP(sport=self.get_src_port(), dport=dst_port, flags='S')
			my_timeout=30
			syn_ack = sr1(syn, timeout=my_timeout)
			# Send HTTP request
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1 
			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
				 seq=next_seq, ack=next_ack, flags='PA') / http_get
			send(seg)

		# test tcb_create_6 (TODO-Manual): If the web server sends the initial 
		#	syn to client, and then  the client requests HTTP resources, is 
		#	it served? The idea is to see if HTTP requests of connection 
		#	initiator alone are filtered, or is it two-way?.

		
		# %%%% Tests tcb_destroy_*: TCB teardown %%%%% 

		# Test tcb_destory_1: Does gfc confuse back to back connections
		#                     sharing similar connection tuple values
		# Note: This test is exactly the same as stream_3
		if self.test_name=="tcb_destroy_1" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1

			pay1='GET /'
			seq1=next_seq
			seg1=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / pay1
			send(seg1)

			next_seq=next_seq+len(pay1)

			seg_rst=ip/TCP(dport=dst_port, sport=self.get_src_port(),
		         		seq=next_seq, ack=next_ack, flags='RA')
			send(seg_rst)

			# New handshake
			syn = ip/TCP(sport=self.get_src_port(), dport=dst_port, flags='S')
			syn_ack = sr1(syn)
			
			pay2=uri
			seg2=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / pay2
			send(seg2)

			next_seq=next_seq+len(pay2)

			pay3='/ HTTP/1.0\r\nHost: '+host+'\r\n\r\n'
			seg3=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / pay3
			send(seg3)


		# ===== Tests tcb_destroy_2* ========
		# Cases related to reset packets
		# ======================
		#	RA cases
		# ======================
		# Test tcb_destroy_2_RA_ttl: Correct RST packet with low ttl	
		if self.test_name=="tcb_destroy_2_RA_ttl" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			
			seg_rst=IP(dst=dst_ip,proto=6,ttl=10)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='RA')
			send(seg_rst)

			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / http_get
			send(seg)
		
		# Test tcb_destroy_2a: RST packet with seq number
		#			that is > snd_nxt but within window	
		if self.test_name=="tcb_destroy_2a" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			
			bad_seq = next_seq+5
			if syn_ack.window < 10:
				print "Warning: This test won't work as receiver's window is too small"
			seg_rst=IP(dst=dst_ip,proto=6)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=bad_seq, ack=next_ack, flags='RA')
			send(seg_rst)

			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / http_get
			send(seg)

		# Test tcb_destroy_2b: RST packet with incorrect seq number
		#			(>snd_nxt+window)
		if self.test_name=="tcb_destroy_2b" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			
			# Warning: Seq wrap around check not there. Will work for
			#          now as initial seq num is 0
			bad_seq = next_seq+syn_ack.window+5
			seg_rst=IP(dst=dst_ip,proto=6)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=bad_seq, ack=next_ack, flags='RA')
			send(seg_rst)

			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / http_get
			send(seg)

		# Test tcb_destroy_2c: RST packet with incorrect ack number
		if self.test_name=="tcb_destroy_2c" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			
			random_increment = 5
			seg_rst=IP(dst=dst_ip,proto=6)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack+random_increment, flags='RA')
			send(seg_rst)

			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / http_get
			send(seg)

		# ======================
		#	R cases
		# ======================
		# Test tcb_destroy_2_R_ttl: Correct RST packet with low ttl	
		if self.test_name=="tcb_destroy_2_R_ttl" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			
			seg_rst=IP(dst=dst_ip,proto=6,ttl=10)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, flags='R')
			send(seg_rst)

			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / http_get
			send(seg)

		# Test tcb_destroy_2d: RST packet with seq number
		#			that is > snd_nxt but within window	
		if self.test_name=="tcb_destroy_2d" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			
			bad_seq = next_seq+5
			if syn_ack.window < 10:
				print "Warning: This test won't work as receiver's window is is too small"
			seg_rst=IP(dst=dst_ip,proto=6)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=bad_seq, ack=next_ack, flags='R')
			send(seg_rst)

			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / http_get
			send(seg)


		# Test tcb_destroy_2e: RST packet with incorrect seq number
		#			(>snd_nxt+window)
		if self.test_name=="tcb_destroy_2e" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			
			# Warning: Seq wrap around check not there. Will work for
			#          now as initial seq num is 0
			bad_seq = next_seq+syn_ack.window+5
			seg_rst=IP(dst=dst_ip,proto=6)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=bad_seq, ack=next_ack, flags='R')
			send(seg_rst)

			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / http_get
			send(seg)
		

		# ===== Tests tcb_destroy_3* ========
		# Cases related to FIN packets
		# ======================
		# Cases related to FA
		# ======================
		# Test tcb_destroy_3_FA_ttl: Correct FinAck packet sent by me, 
		#                      low ttl so visible to GFC only.
		#                      The idea is to see if filtering is 
		#                      uni-directional
		if self.test_name=="tcb_destroy_3_FA_ttl" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			
			seg_fin=IP(dst=dst_ip,proto=6,ttl=10)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='FA')
			send(seg_fin)

			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / http_get
			send(seg)
		
		# Test tcb_destroy_3a: FA packet with seq number
		#			that is > snd_nxt but within window	
		if self.test_name=="tcb_destroy_3a" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			
			bad_seq = next_seq+5
			if syn_ack.window < 10:
				print "Warning: This test won't work as receiver's window is is too small"
			seg_rst=IP(dst=dst_ip,proto=6)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=bad_seq, ack=next_ack, flags='FA')
			send(seg_rst)

			# Incrementing next_seq because of FIN (the FA should be accepted
			#                 as it is within window)
			next_seq=next_seq+1
			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / http_get
			send(seg)

		# Test tcb_destroy_3b: FA packet with incorrect seq number
		#			(>snd_nxt+window)
		if self.test_name=="tcb_destroy_3b" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			
			# Warning: Seq wrap around check not there. Will work for
			#          now as initial seq num is 0
			bad_seq = next_seq+syn_ack.window+5
			seg_rst=IP(dst=dst_ip,proto=6)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=bad_seq, ack=next_ack, flags='FA')
			send(seg_rst)

			# Server should reject it (as it is beyond window)
			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / http_get
			send(seg)

		# Test tcb_destroy_3c: FA packet with incorrect ack number
		if self.test_name=="tcb_destroy_3c" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			
			random_increment = 5
			seg_rst=IP(dst=dst_ip,proto=6)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack+random_increment, flags='FA')
			send(seg_rst)

			# Server should reject it (as ack is bad)
			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / http_get
			send(seg)

		# ======================
		# Cases related to F
		# ======================
		# Test tcb_destroy_3_F_ttl: Correct F packet with low ttl	
		if self.test_name=="tcb_destroy_3_F_ttl" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			
			seg_rst=IP(dst=dst_ip,proto=6,ttl=10)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, flags='F')
			send(seg_rst)

			# F won't be accepted by server as it doesn't have an ack

			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / http_get
			send(seg)

		# Test tcb_destroy_3d: F packet with seq number
		#			that is > snd_nxt but within window	
		if self.test_name=="tcb_destroy_3d" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			
			bad_seq = next_seq+5
			if syn_ack.window < 10:
				print "Warning: This test won't work as receiver's window is is too small"
			seg_rst=IP(dst=dst_ip,proto=6)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=bad_seq, ack=next_ack, flags='F')
			send(seg_rst)

			# Server should reject the previous FIN (as it is beyond window)
			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / http_get
			send(seg)


		# Test tcb_destroy_3e: F packet with incorrect seq number
		#			(>snd_nxt+window)
		if self.test_name=="tcb_destroy_3e" or self.test_name=="all":
			next_seq=syn_ack.ack
			next_ack=syn_ack.seq+1
			
			# Warning: Seq wrap around check not there. Will work for
			#          now as initial seq num is 0
			bad_seq = next_seq+syn_ack.window+5
			seg_rst=IP(dst=dst_ip,proto=6)/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=bad_seq, ack=next_ack, flags='F')
			send(seg_rst)

			# Server should reject the previous FIN (as it is beyond window)
			seg=ip/TCP(dport=dst_port, sport=self.get_src_port(),
			         seq=next_seq, ack=next_ack, flags='PA') / http_get
			send(seg)

		
		# ======================
		# Test tcb_destroy_5(TODO: MANUAL): (i) Client sends syn, 
		# (ii) server sends reset with bad ack which should be rejected by the client
		# (iii) server sends syn-ack, then client sends httP request. 
		# If GFC bought the reset, it should not be able to follow the conn any more
		# RFC 793:  "In the SYN-SENT state (a RST received in response
		#  to an initial SYN), the RST is acceptable if the ACK field
		#  acknowledges the SYN.

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
	if len(sys.argv) > 2:
		print "usage: %s [test_number]" % (sys.argv[0])
		sys.exit(1)

	# TODO: The 'all' option doesn't work at the moment.
	if len(sys.argv) < 2:
		prober = GFCProber("all")
	else:
		prober = GFCProber(sys.argv[1])
	prober.probe()


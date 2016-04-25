"""
Thrift PD interface basic tests
"""

import time
import sys
import logging

import unittest
import random
import os
import sys
import importlib

from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol, TMultiplexedProtocol

from utils import *

this_dir = os.path.dirname(os.path.abspath(__file__))

def mac2string(mac):
	return "".join(chr(i) for i in map(lambda x: eval("0x%s"%x), mac.split(':')))

class Control:
	def __init__(self, sw_name, thrift_port, pd_thrift_path):
		print sw_name
		self.sw_name = sw_name
		self.thrift_port = thrift_port
		self.pd_thrift_path = pd_thrift_path

		sys.path.insert(0, pd_thrift_path)
		print pd_thrift_path

		self.p4_client_module = importlib.import_module(".".join(["p4_pd_rpc", "simple_router"]))
		self.mc_client_module = importlib.import_module(".".join(["mc_pd_rpc", "mc"]))
		self.conn_mgr_client_module = importlib.import_module(".".join(["conn_mgr_pd_rpc", "conn_mgr"]))

		# Set up thrift client and contact server
		self.transport = TSocket.TSocket('localhost', thrift_port)
		self.transport = TTransport.TBufferedTransport(self.transport)
		bprotocol = TBinaryProtocol.TBinaryProtocol(self.transport)

		mc_protocol = TMultiplexedProtocol.TMultiplexedProtocol(bprotocol, "mc")
		conn_mgr_protocol = TMultiplexedProtocol.TMultiplexedProtocol(bprotocol, "conn_mgr")
		p4_protocol = TMultiplexedProtocol.TMultiplexedProtocol(bprotocol, "simple_router")
	
		self.client = self.p4_client_module.Client(p4_protocol)
		self.mc = self.mc_client_module.Client(mc_protocol)
		self.conn_mgr = self.conn_mgr_client_module.Client(conn_mgr_protocol)
		self.transport.open()

		sys.path.pop(0)


	def close(self):
		self.transport.close()
		
	def get_flow_radar(self):
		sys.path.insert(0, self.pd_thrift_path)
		from p4_pd_rpc.ttypes import *
		from res_pd_rpc.ttypes import *

		sess_hdl = self.conn_mgr.client_init(16)
		dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))
		flow_radar = self.client.dump_flow_radar(sess_hdl, dev_tgt)
		sys.path.pop(0)

		return flow_radar

	def get_flow_filter(self, index):
		sys.path.insert(0, self.pd_thrift_path)
		from p4_pd_rpc.ttypes import *
		from res_pd_rpc.ttypes import *

		sess_hdl = self.conn_mgr.client_init(16)
		dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))

		bit = self.client.register_read_flow_filter(sess_hdl, dev_tgt, index)

		sys.path.pop(0)

		return bit
	
	def get_whole_flow_filter(self):
		sys.path.insert(0, self.pd_thrift_path)
		from p4_pd_rpc.ttypes import *
		from res_pd_rpc.ttypes import *

		sess_hdl = self.conn_mgr.client_init(16)
		dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))
		
		ret = self.client.register_read_whole_flow_filter(sess_hdl, dev_tgt)
		sys.path.pop(0)
		
		return ret

	def get_whole_counting_table(self):
		sys.path.insert(0, self.pd_thrift_path)
		from p4_pd_rpc.ttypes import *
		from res_pd_rpc.ttypes import *

		sess_hdl = self.conn_mgr.client_init(16)
		dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))
		
		srcip = self.client.register_read_whole_flow_xor_srcip(sess_hdl, dev_tgt)
		dstip = self.client.register_read_whole_flow_xor_dstip(sess_hdl, dev_tgt)
		srcport = self.client.register_read_whole_flow_xor_srcport(sess_hdl, dev_tgt)
		dstport = self.client.register_read_whole_flow_xor_dstport(sess_hdl, dev_tgt)
		prot = self.client.register_read_whole_flow_xor_prot(sess_hdl, dev_tgt)
		flow_count = self.client.register_read_whole_flow_count(sess_hdl, dev_tgt)
		packet_count = self.client.register_read_whole_packet_count(sess_hdl, dev_tgt)
		
		print len(srcip), len(dstip), len(srcport), len(dstport), len(prot)
		print srcip
		print dstip
		print srcport
		print dstport
		print prot
		print flow_count
		print packet_count

	def add_ipv4_lpm_with_set_nhop(self, ipprefix, masklen, nhop_ip, egress_port):
		sys.path.insert(0, self.pd_thrift_path)
		from p4_pd_rpc.ttypes import *
		from res_pd_rpc.ttypes import *

		sess_hdl = self.conn_mgr.client_init(16)
		dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))

		match = simple_router_ipv4_lpm_match_spec_t(ipprefix, masklen)
		action = simple_router_set_nhop_action_spec_t(nhop_ip, egress_port)
		self.client.ipv4_lpm_table_add_with_set_nhop(sess_hdl, dev_tgt, match, action)

		sys.path.pop(0)

	def add_ipv4_lpm_with_drop(self, ipprefix, masklen):
		sys.path.insert(0, self.pd_thrift_path)
		from p4_pd_rpc.ttypes import *
		from res_pd_rpc.ttypes import *

		sess_hdl = self.conn_mgr.client_init(16)
		dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))

		match = simple_router_ipv4_lpm_match_spec_t(ip, masklen)
		self.client.ipv4_lpm_table_add_with_set_nhop(sess_hdl, dev_tgt, match)

		sys.path.pop(0)

	def add_forward_with_set_dmac(self, ip, dmac):
		sys.path.insert(0, self.pd_thrift_path)
		from p4_pd_rpc.ttypes import *
		from res_pd_rpc.ttypes import *

		sess_hdl = self.conn_mgr.client_init(16)
		dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))

		dstmac = mac2string(dmac)
	
		match = simple_router_forward_match_spec_t(ip)
		action = simple_router_set_dmac_action_spec_t(dstmac)
		self.client.forward_table_add_with_set_dmac(sess_hdl, dev_tgt, match, action)

		sys.path.pop(0)

	def add_send_frame_with_rewrite_mac(self, egress_port, smac):
		sys.path.insert(0, self.pd_thrift_path)
		from p4_pd_rpc.ttypes import *
		from res_pd_rpc.ttypes import *

		sess_hdl = self.conn_mgr.client_init(16)
		dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))

		srcmac = mac2string(smac)
	
		match = simple_router_send_frame_match_spec_t(egress_port)
		action = simple_router_rewrite_mac_action_spec_t(srcmac)
		self.client.send_frame_table_add_with_rewrite_mac(sess_hdl, dev_tgt, match, action)

		sys.path.pop(0)

	def add_flow_radar_default_action(self):
		sys.path.insert(0, self.pd_thrift_path)
		from p4_pd_rpc.ttypes import *
		from res_pd_rpc.ttypes import *

		sess_hdl = self.conn_mgr.client_init(16)
		dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))

		self.client.flow_radar_set_default_action_update_flow_radar(sess_hdl, dev_tgt)

		sys.path.pop(0)

'''
	def add_route(self, enable_flowlet):
		sys.path.insert(0, self.pd_thrift_path)
		from pd_commons import populate_routes
		from p4_pd_rpc.ttypes import *
		from res_pd_rpc.ttypes import *

		sess_hdl = self.conn_mgr.client_init(16)
		dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))

		print "Cleaning state"
		self.client.tables_clean_all(sess_hdl, dev_tgt)

		self.conn_mgr.rmt_log_level_set(P4LogLevel_t.P4_LOG_LEVEL_ERROR)
		
		populate_routes(self.client, self.sw_name, sess_hdl, dev_tgt, enable_flowlet)

		if self.thrift_port == 23000:
			pg_header = [ 0 for x in range(16) ]
			pg_header[12:14] = [ -120, -120 ] # This is a PG packet (0x8888 in ethertype)
			pg_header[14:16] = [ 1, 1 ] # Generate BFD packets from this PG packet (0x0101)
			self.client.pg_start(101, pg_header, 2000)
			pg_header = [ 0 for x in range(16) ]
			pg_header[12:14] = [ -120, -120 ] # This is a PG packet (0x8888 in ethertype)
			pg_header[14:16] = [ 2, 2 ] # Generate BFD packets from this PG packet (0x0101)
			self.client.pg_start(102, pg_header, 2000)
		
		sys.path.pop(0)
'''

#!/usr/bin/python

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import Node, Switch, OVSSwitch
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.util import isShellBuiltin
from mininet.link import TCLink

from p4_mininet import P4Switch, P4Host
import control

import subprocess
import select
import time
import re
import json
from time import sleep

nh = 3

def _get_switch_config(config_path = "flow_radar/config.json"):
	with open(config_path, 'r') as config_file:
		return json.load(config_file)

class MyTopo(Topo):
	"Topology corresponding to the traffic split scenario (formerly known as topo2)"
	def __init__(self, config, **opts):
		# Initialize topology and default options
		Topo.__init__(self, **opts)
		sw_path = config["simple_router"]["binary_path"]

		s1 = self.addSwitch('s1', sw_path = sw_path, thrift_port = 23000, pcap_dump = True)
		for i in range(1, nh+1):
			h = self.addHost('h%d'%i, ip = "10.0.%d.10/24"%i, mac = "00:aa:bb:00:00:%02d"%i)
			self.addLink(h, s1)

def main():
	switch_config = _get_switch_config()
	topo = MyTopo(switch_config)
	net = Mininet(topo = topo, host = P4Host, switch = P4Switch, controller = None)
	net.start()
 
	sw_mac = ["00:aa:bb:00:%02d:%02d"%(i,i) for i in range(1, nh+1)]
	sw_addr = ["10.0.%d.1"%i for i in range(1,nh+1)]

	# There is a command in Mininet to do this, TODO fix
	print "Initializaing host stack config"
	for n in range(nh):
		h = net.get('h%s' % (n + 1))	
		print "[Host: h%s]" % (n + 1)
		h.defaultIntf().rename("eth0")
		cmd = "arp -i eth0 -s %s %s" % (sw_addr[n], sw_mac[n])
		print cmd
		h.cmd(cmd)
		cmd = "route add default gw %s" % sw_addr[n]
		print cmd
		h.cmd(cmd)
		for off in ["rx", "tx", "sg"]:
			cmd = "/sbin/ethtool --offload eth0 %s off" % off
			print cmd
			h.cmd(cmd)
		print "disable ipv6"
		h.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
		h.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
		h.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")
		h.cmd("iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP")

	sleep(1)

	print "Adding table entries"

	ctrl = control.Control('s1', 23000, str(switch_config["simple_router"]["pd_thrift_path"]))
	for i in range(1, nh+1):
		ctrl.add_ipv4_lpm_with_set_nhop(0x0a00000a + i * 0x100, 24, 0x0a00000a + i * 0x100, i)
		ctrl.add_forward_with_set_dmac(0x0a00000a + i * 0x100, "00:aa:bb:00:00:%02d"%i)
		ctrl.add_send_frame_with_rewrite_mac(i, "00:aa:bb:00:%02d:%02d"%(i,i))
	ctrl.add_flow_radar_default_action()
	ctrl.close()

	print "Done"

	CLI( net )
	net.stop()

if __name__ == '__main__':
	setLogLevel( 'info' )
	main()


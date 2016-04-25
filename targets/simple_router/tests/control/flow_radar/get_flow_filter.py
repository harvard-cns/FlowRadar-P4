#!/usr/bin/python

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import Node, Switch, OVSSwitch
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.util import isShellBuiltin
from mininet.link import TCLink

import control

import subprocess
import select
import time
import re
import json

def _get_switch_config(config_path = "flow_radar/config.json"):
	with open(config_path, 'r') as config_file:
		return json.load(config_file)

def main():
	switch_config = _get_switch_config()

	ctrl = control.Control('s1', 23000, str(switch_config["simple_router"]["pd_thrift_path"]))
	ret = ctrl.get_whole_flow_filter()
	print len(ret)
	print ret
	ctrl.close()


if __name__ == '__main__':
	setLogLevel( 'info' )
	main()



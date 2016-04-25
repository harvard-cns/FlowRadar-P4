import re

def changed(lines, token):
	for line in lines:
		if line.find(token) != -1:
			return True
	return False

# change actions.c to add flow_radar lock
def change_actions_c():
	actions_c = open("../build/bm/src/actions.c","r")
	lines = actions_c.readlines()
	actions_c.close()
	if changed(lines, '#include "flow_radar.h"'):
		return

	actions_c = open("../build/bm/src/actions.c","w")
	lock_flag = 0
	include_flag = 1
	for line in lines:
		if lock_flag == 1:
			m = re.search("^}$", line)
			if m != None:
				actions_c.write("  unlock_flow_radar();\n")
				lock_flag = 0
		actions_c.write(line)
		if include_flag == 1:
			m = re.search("^\*/", line)
			if m != None:
				actions_c.write('#include "flow_radar.h"\n')
				include_flag = 0
		if line.find("void action_update_flow_radar") != -1:
			actions_c.write("  lock_flow_radar();\n")
			lock_flag = 1
	actions_c.close()

# change p4_pd_rpc_server.ipp
def change_p4_pd_rpc_server_ipp():
	file = open("../build/bm/src/p4_pd_rpc_server.ipp","r")
	lines = file.readlines()
	file.close()
	if changed(lines, '#include "flow_radar.h"'):
		return

	file = open("../build/bm/src/p4_pd_rpc_server.ipp","w")
	key_reg = ["flow_xor_srcip","flow_xor_dstip", "flow_xor_srcport", "flow_xor_dstport", "flow_xor_prot", "flow_count", "packet_count", "flow_filter"]
	size = {}
	field = ""
	for line in lines:
		for key in key_reg:
			if line.find("void register_read_whole_%s"%key) != -1:
				field = key
		if field != "":
			m = re.search("int8_t ret\[(.*)\];", line)
			if m != None:
				size[field] = m.group(1)
				field = ""

	total_size = "(%s)"%size[key_reg[0]]
	for key in key_reg[1:]:
		total_size += " + (%s)"%size[key]
	file.write('extern "C" {\n')
	file.write('#include "flow_radar.h"\n')
	file.write('}\n')
	for line in lines:
		file.write(line)
		if line.find("// REGISTERS") != -1:
			file.write("    void dump_flow_radar(std::vector<int8_t> & _return, const SessionHandle_t sess_hdl, const  DevTarget_t& dev_tgt) {\n")
			file.write("      p4_pd_dev_target_t pd_dev_tgt;\n")
			file.write("      pd_dev_tgt.device_id = dev_tgt.dev_id;\n")
			file.write("      pd_dev_tgt.dev_pipe_id = dev_tgt.dev_pipe_id;\n")
			file.write("      int8_t ret[%s];\n"%total_size)
			file.write("      lock_flow_radar();\n")
			ret = "ret"
			for key in key_reg:
				file.write("      p4_pd_simple_router_register_read_whole_%s(sess_hdl, pd_dev_tgt, %s);\n"%(key, ret))
				file.write("      p4_pd_simple_router_register_clean_%s(sess_hdl, pd_dev_tgt);\n"%(key))
				ret += " + (%s)"%size[key]
				
			file.write("      unlock_flow_radar();\n")
			file.write("      _return.resize(%s);\n"%total_size)
			file.write("      for (int i = 0; i < _return.size(); i++)\n")
			file.write("        _return[i] = ret[i];\n")
			file.write("    }\n")
	file.close()

def change_p4_pd_rpc_thrift():
	file = open("../build/bm/thrift/p4_pd_rpc.thrift","r")
	lines = file.readlines()
	file.close()
	if changed(lines, "list<byte> dump_flow_radar"):
		return

	file = open("../build/bm/thrift/p4_pd_rpc.thrift","w")
	for line in lines:
		file.write(line)
		if line.find("# registers") != -1:
			file.write("    list<byte> dump_flow_radar(1:res.SessionHandle_t sess_hdl,\n")
			file.write("    2:res.DevTarget_t dev_tgt);\n")
	file.close()

if __name__ == "__main__":
	change_actions_c()
	change_p4_pd_rpc_server_ipp()
	change_p4_pd_rpc_thrift()

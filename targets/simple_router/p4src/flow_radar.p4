field_list flow{
	ipv4.srcAddr;
	ipv4.dstAddr;
	tcp.srcPort;
	tcp.dstPort;
	ipv4.protocol;
}

#define FLOW_FILTER_SIZE 32768
#define FLOW_FILTER_IDX_WIDTH 15

#define COUNTING_TABLE_SIZE 16 
#define COUNTING_TABLE_SUB_SIZE 4
#define COUNTING_TABLE_IDX_WIDTH 4 
#define COUNTING_TABLE_SUB_IDX_WIDTH 2 

field_list_calculation flow_filter_hash1{
	input{
		flow;
	}
	algorithm: my_hash1;
	output_width: FLOW_FILTER_IDX_WIDTH;
}

field_list_calculation flow_filter_hash2{
	input{
		flow;
	}
	algorithm: my_hash2;
	output_width: FLOW_FILTER_IDX_WIDTH;
}

field_list_calculation flow_filter_hash3{
	input{
		flow;
	}
	algorithm: my_hash3;
	output_width: FLOW_FILTER_IDX_WIDTH;
}

field_list_calculation flow_filter_hash4{
	input{
		flow;
	}
	algorithm: my_hash4;
	output_width: FLOW_FILTER_IDX_WIDTH;
}

field_list_calculation flow_filter_hash5{
	input{
		flow;
	}
	algorithm: my_hash5;
	output_width: FLOW_FILTER_IDX_WIDTH;
}

field_list_calculation flow_filter_hash6{
	input{
		flow;
	}
	algorithm: my_hash6;
	output_width: FLOW_FILTER_IDX_WIDTH;
}

field_list_calculation flow_filter_hash7{
	input{
		flow;
	}
	algorithm: my_hash7;
	output_width: FLOW_FILTER_IDX_WIDTH;
}

field_list_calculation flow_filter_hash8{
	input{
		flow;
	}
	algorithm: my_hash8;
	output_width: FLOW_FILTER_IDX_WIDTH;
}

field_list_calculation flow_filter_hash9{
	input{
		flow;
	}
	algorithm: my_hash9;
	output_width: FLOW_FILTER_IDX_WIDTH;
}

field_list_calculation flow_filter_hash10{
	input{
		flow;
	}
	algorithm: my_hash10;
	output_width: FLOW_FILTER_IDX_WIDTH;
}

field_list_calculation flow_filter_hash11{
	input{
		flow;
	}
	algorithm: my_hash11;
	output_width: FLOW_FILTER_IDX_WIDTH;
}

field_list_calculation flow_filter_hash12{
	input{
		flow;
	}
	algorithm: my_hash12;
	output_width: FLOW_FILTER_IDX_WIDTH;
}

field_list_calculation flow_filter_hash13{
	input{
		flow;
	}
	algorithm: my_hash13;
	output_width: FLOW_FILTER_IDX_WIDTH;
}

field_list_calculation flow_filter_hash14{
	input{
		flow;
	}
	algorithm: my_hash14;
	output_width: FLOW_FILTER_IDX_WIDTH;
}

field_list_calculation flow_filter_hash15{
	input{
		flow;
	}
	algorithm: my_hash15;
	output_width: FLOW_FILTER_IDX_WIDTH;
}

field_list_calculation flow_filter_hash16{
	input{
		flow;
	}
	algorithm: my_hash16;
	output_width: FLOW_FILTER_IDX_WIDTH;
}

field_list_calculation flow_filter_hash17{
	input{
		flow;
	}
	algorithm: my_hash17;
	output_width: FLOW_FILTER_IDX_WIDTH;
}

field_list_calculation flow_filter_hash18{
	input{
		flow;
	}
	algorithm: my_hash18;
	output_width: FLOW_FILTER_IDX_WIDTH;
}

field_list_calculation flow_filter_hash19{
	input{
		flow;
	}
	algorithm: my_hash19;
	output_width: FLOW_FILTER_IDX_WIDTH;
}

field_list_calculation flow_filter_hash20{
	input{
		flow;
	}
	algorithm: my_hash20;
	output_width: FLOW_FILTER_IDX_WIDTH;
}

field_list_calculation flow_filter_hash21{
	input{
		flow;
	}
	algorithm: my_hash21;
	output_width: FLOW_FILTER_IDX_WIDTH;
}

field_list_calculation flow_filter_hash22{
	input{
		flow;
	}
	algorithm: my_hash22;
	output_width: FLOW_FILTER_IDX_WIDTH;
}

field_list_calculation flow_filter_hash23{
	input{
		flow;
	}
	algorithm: my_hash23;
	output_width: FLOW_FILTER_IDX_WIDTH;
}

field_list_calculation flow_filter_hash24{
	input{
		flow;
	}
	algorithm: my_hash24;
	output_width: FLOW_FILTER_IDX_WIDTH;
}

field_list_calculation flow_filter_hash25{
	input{
		flow;
	}
	algorithm: my_hash25;
	output_width: FLOW_FILTER_IDX_WIDTH;
}

field_list_calculation flow_filter_hash26{
	input{
		flow;
	}
	algorithm: my_hash26;
	output_width: FLOW_FILTER_IDX_WIDTH;
}

field_list_calculation flow_filter_hash27{
	input{
		flow;
	}
	algorithm: my_hash27;
	output_width: FLOW_FILTER_IDX_WIDTH;
}

// Flow filter
register flow_filter{
	width:1;
	instance_count: FLOW_FILTER_SIZE;
}

field_list_calculation counting_table_hash1{
	input{
		flow;
	}
	algorithm: my_hash1;
	output_width: COUNTING_TABLE_SUB_IDX_WIDTH;
}

field_list_calculation counting_table_hash2{
	input{
		flow;
	}
	algorithm: my_hash2;
	output_width: COUNTING_TABLE_SUB_IDX_WIDTH;
}

field_list_calculation counting_table_hash3{
	input{
		flow;
	}
	algorithm: my_hash3;
	output_width: COUNTING_TABLE_SUB_IDX_WIDTH;
}

field_list_calculation counting_table_hash4{
	input{
		flow;
	}
	algorithm: my_hash4;
	output_width: COUNTING_TABLE_SUB_IDX_WIDTH;
}

// counting table
register flow_xor_srcip{
	width:32;
	instance_count: COUNTING_TABLE_SIZE;
}
register flow_xor_dstip{
	width:32;
	instance_count: COUNTING_TABLE_SIZE;
}
register flow_xor_srcport{
	width:16;
	instance_count: COUNTING_TABLE_SIZE;
}
register flow_xor_dstport{
	width:16;
	instance_count: COUNTING_TABLE_SIZE;
}
register flow_xor_prot{
	width:8;
	instance_count: COUNTING_TABLE_SIZE;
}
register flow_count{
	width:8;
	instance_count:COUNTING_TABLE_SIZE;
}
register packet_count{
	width:32;
	instance_count:COUNTING_TABLE_SIZE;
}

register debug{
	width:1;
	instance_count:1;
}

header_type flow_filter_metadata_t{
	fields{
		new_flow: 1;
		tmp:1;
		h1: FLOW_FILTER_IDX_WIDTH;
		h2: FLOW_FILTER_IDX_WIDTH;
		h3: FLOW_FILTER_IDX_WIDTH;
		h4: FLOW_FILTER_IDX_WIDTH;
		h5: FLOW_FILTER_IDX_WIDTH;
		h6: FLOW_FILTER_IDX_WIDTH;
		h7: FLOW_FILTER_IDX_WIDTH;
		h8: FLOW_FILTER_IDX_WIDTH;
		h9: FLOW_FILTER_IDX_WIDTH;
		h10: FLOW_FILTER_IDX_WIDTH;
		h11: FLOW_FILTER_IDX_WIDTH;
		h12: FLOW_FILTER_IDX_WIDTH;
		h13: FLOW_FILTER_IDX_WIDTH;
		h14: FLOW_FILTER_IDX_WIDTH;
		h15: FLOW_FILTER_IDX_WIDTH;
		h16: FLOW_FILTER_IDX_WIDTH;
		h17: FLOW_FILTER_IDX_WIDTH;
		h18: FLOW_FILTER_IDX_WIDTH;
		h19: FLOW_FILTER_IDX_WIDTH;
		h20: FLOW_FILTER_IDX_WIDTH;
		h21: FLOW_FILTER_IDX_WIDTH;
		h22: FLOW_FILTER_IDX_WIDTH;
		h23: FLOW_FILTER_IDX_WIDTH;
		h24: FLOW_FILTER_IDX_WIDTH;
		h25: FLOW_FILTER_IDX_WIDTH;
		h26: FLOW_FILTER_IDX_WIDTH;
		h27: FLOW_FILTER_IDX_WIDTH;
	}
}

metadata flow_filter_metadata_t ff_meta;

header_type counting_table_metadata_t{
	fields{
		flow_mask: 32;
		srcip: 32;
		cur_srcip: 32;
		dstip: 32;
		cur_dstip: 32;
		srcport: 16;
		cur_srcport :16;
		dstport: 16;
		cur_dstport: 16;
		prot: 8;
		cur_prot: 8;
		flow_count: 8;
		packet_count: 32;
		h1: COUNTING_TABLE_IDX_WIDTH;
		h2: COUNTING_TABLE_IDX_WIDTH;
		h3: COUNTING_TABLE_IDX_WIDTH;
		h4: COUNTING_TABLE_IDX_WIDTH;
	}
}

metadata counting_table_metadata_t ct_meta;

action update_flow_radar(){
	//get flow_filter indices
	modify_field_with_hash_based_offset(ff_meta.h1, 0, flow_filter_hash1, FLOW_FILTER_SIZE);
	modify_field_with_hash_based_offset(ff_meta.h2, 0, flow_filter_hash2, FLOW_FILTER_SIZE);
	modify_field_with_hash_based_offset(ff_meta.h3, 0, flow_filter_hash3, FLOW_FILTER_SIZE);
	modify_field_with_hash_based_offset(ff_meta.h4, 0, flow_filter_hash4, FLOW_FILTER_SIZE);
	modify_field_with_hash_based_offset(ff_meta.h5, 0, flow_filter_hash5, FLOW_FILTER_SIZE);
	modify_field_with_hash_based_offset(ff_meta.h6, 0, flow_filter_hash6, FLOW_FILTER_SIZE);
	modify_field_with_hash_based_offset(ff_meta.h7, 0, flow_filter_hash7, FLOW_FILTER_SIZE);
	modify_field_with_hash_based_offset(ff_meta.h8, 0, flow_filter_hash8, FLOW_FILTER_SIZE);
	modify_field_with_hash_based_offset(ff_meta.h9, 0, flow_filter_hash9, FLOW_FILTER_SIZE);
	modify_field_with_hash_based_offset(ff_meta.h10, 0, flow_filter_hash10, FLOW_FILTER_SIZE);
	modify_field_with_hash_based_offset(ff_meta.h11, 0, flow_filter_hash11, FLOW_FILTER_SIZE);
	modify_field_with_hash_based_offset(ff_meta.h12, 0, flow_filter_hash12, FLOW_FILTER_SIZE);
	modify_field_with_hash_based_offset(ff_meta.h13, 0, flow_filter_hash13, FLOW_FILTER_SIZE);
	modify_field_with_hash_based_offset(ff_meta.h14, 0, flow_filter_hash14, FLOW_FILTER_SIZE);
	modify_field_with_hash_based_offset(ff_meta.h15, 0, flow_filter_hash15, FLOW_FILTER_SIZE);
	modify_field_with_hash_based_offset(ff_meta.h16, 0, flow_filter_hash16, FLOW_FILTER_SIZE);
	modify_field_with_hash_based_offset(ff_meta.h17, 0, flow_filter_hash17, FLOW_FILTER_SIZE);
	modify_field_with_hash_based_offset(ff_meta.h18, 0, flow_filter_hash18, FLOW_FILTER_SIZE);
	modify_field_with_hash_based_offset(ff_meta.h19, 0, flow_filter_hash19, FLOW_FILTER_SIZE);
	modify_field_with_hash_based_offset(ff_meta.h20, 0, flow_filter_hash20, FLOW_FILTER_SIZE);

	//check new flow
	modify_field(ff_meta.new_flow, 1);
	register_read(ff_meta.tmp, flow_filter, ff_meta.h1);
	bit_and(ff_meta.new_flow, ff_meta.new_flow, ff_meta.tmp);
	register_read(ff_meta.tmp, flow_filter, ff_meta.h2);
	bit_and(ff_meta.new_flow, ff_meta.new_flow, ff_meta.tmp);
	register_read(ff_meta.tmp, flow_filter, ff_meta.h3);
	bit_and(ff_meta.new_flow, ff_meta.new_flow, ff_meta.tmp);
	register_read(ff_meta.tmp, flow_filter, ff_meta.h4);
	bit_and(ff_meta.new_flow, ff_meta.new_flow, ff_meta.tmp);
	register_read(ff_meta.tmp, flow_filter, ff_meta.h5);
	bit_and(ff_meta.new_flow, ff_meta.new_flow, ff_meta.tmp);
	register_read(ff_meta.tmp, flow_filter, ff_meta.h6);
	bit_and(ff_meta.new_flow, ff_meta.new_flow, ff_meta.tmp);
	register_read(ff_meta.tmp, flow_filter, ff_meta.h7);
	bit_and(ff_meta.new_flow, ff_meta.new_flow, ff_meta.tmp);
	register_read(ff_meta.tmp, flow_filter, ff_meta.h8);
	bit_and(ff_meta.new_flow, ff_meta.new_flow, ff_meta.tmp);
	register_read(ff_meta.tmp, flow_filter, ff_meta.h9);
	bit_and(ff_meta.new_flow, ff_meta.new_flow, ff_meta.tmp);
	register_read(ff_meta.tmp, flow_filter, ff_meta.h10);
	bit_and(ff_meta.new_flow, ff_meta.new_flow, ff_meta.tmp);
	register_read(ff_meta.tmp, flow_filter, ff_meta.h11);
	bit_and(ff_meta.new_flow, ff_meta.new_flow, ff_meta.tmp);
	register_read(ff_meta.tmp, flow_filter, ff_meta.h12);
	bit_and(ff_meta.new_flow, ff_meta.new_flow, ff_meta.tmp);
	register_read(ff_meta.tmp, flow_filter, ff_meta.h13);
	bit_and(ff_meta.new_flow, ff_meta.new_flow, ff_meta.tmp);
	register_read(ff_meta.tmp, flow_filter, ff_meta.h14);
	bit_and(ff_meta.new_flow, ff_meta.new_flow, ff_meta.tmp);
	register_read(ff_meta.tmp, flow_filter, ff_meta.h15);
	bit_and(ff_meta.new_flow, ff_meta.new_flow, ff_meta.tmp);
	register_read(ff_meta.tmp, flow_filter, ff_meta.h16);
	bit_and(ff_meta.new_flow, ff_meta.new_flow, ff_meta.tmp);
	register_read(ff_meta.tmp, flow_filter, ff_meta.h17);
	bit_and(ff_meta.new_flow, ff_meta.new_flow, ff_meta.tmp);
	register_read(ff_meta.tmp, flow_filter, ff_meta.h18);
	bit_and(ff_meta.new_flow, ff_meta.new_flow, ff_meta.tmp);
	register_read(ff_meta.tmp, flow_filter, ff_meta.h19);
	bit_and(ff_meta.new_flow, ff_meta.new_flow, ff_meta.tmp);
	register_read(ff_meta.tmp, flow_filter, ff_meta.h20);
	bit_and(ff_meta.new_flow, ff_meta.new_flow, ff_meta.tmp);
	bit_xor(ff_meta.new_flow, ff_meta.new_flow, 1);
	subtract(ct_meta.flow_mask, 0, ff_meta.new_flow);
	
	//update flow_filter
	register_write(flow_filter, ff_meta.h1, 1);
	register_write(flow_filter, ff_meta.h2, 1);
	register_write(flow_filter, ff_meta.h3, 1);
	register_write(flow_filter, ff_meta.h4, 1);
	register_write(flow_filter, ff_meta.h5, 1);
	register_write(flow_filter, ff_meta.h6, 1);
	register_write(flow_filter, ff_meta.h7, 1);
	register_write(flow_filter, ff_meta.h8, 1);
	register_write(flow_filter, ff_meta.h9, 1);
	register_write(flow_filter, ff_meta.h10, 1);
	register_write(flow_filter, ff_meta.h11, 1);
	register_write(flow_filter, ff_meta.h12, 1);
	register_write(flow_filter, ff_meta.h13, 1);
	register_write(flow_filter, ff_meta.h14, 1);
	register_write(flow_filter, ff_meta.h15, 1);
	register_write(flow_filter, ff_meta.h16, 1);
	register_write(flow_filter, ff_meta.h17, 1);
	register_write(flow_filter, ff_meta.h18, 1);
	register_write(flow_filter, ff_meta.h19, 1);
	register_write(flow_filter, ff_meta.h20, 1);

	//update counting_table
	modify_field_with_hash_based_offset(ct_meta.h1, 0, counting_table_hash1, COUNTING_TABLE_SUB_SIZE);
	modify_field_with_hash_based_offset(ct_meta.h2, COUNTING_TABLE_SUB_SIZE, counting_table_hash2, COUNTING_TABLE_SUB_SIZE);
	modify_field_with_hash_based_offset(ct_meta.h3, COUNTING_TABLE_SUB_SIZE * 2, counting_table_hash3, COUNTING_TABLE_SUB_SIZE);
	modify_field_with_hash_based_offset(ct_meta.h4, COUNTING_TABLE_SUB_SIZE * 3, counting_table_hash4, COUNTING_TABLE_SUB_SIZE);

	// update all srcip
	bit_and(ct_meta.cur_srcip, ipv4.srcAddr, ct_meta.flow_mask);

	register_read(ct_meta.srcip, flow_xor_srcip, ct_meta.h1);
	bit_xor(ct_meta.srcip, ct_meta.srcip, ct_meta.cur_srcip);
	register_write(flow_xor_srcip, ct_meta.h1, ct_meta.srcip);

	register_read(ct_meta.srcip, flow_xor_srcip, ct_meta.h2);
	bit_xor(ct_meta.srcip, ct_meta.srcip, ct_meta.cur_srcip);
	register_write(flow_xor_srcip, ct_meta.h2, ct_meta.srcip);

	register_read(ct_meta.srcip, flow_xor_srcip, ct_meta.h3);
	bit_xor(ct_meta.srcip, ct_meta.srcip, ct_meta.cur_srcip);
	register_write(flow_xor_srcip, ct_meta.h3, ct_meta.srcip);

	register_read(ct_meta.srcip, flow_xor_srcip, ct_meta.h4);
	bit_xor(ct_meta.srcip, ct_meta.srcip, ct_meta.cur_srcip);
	register_write(flow_xor_srcip, ct_meta.h4, ct_meta.srcip);

	// update all dstip
	bit_and(ct_meta.cur_dstip, ipv4.dstAddr, ct_meta.flow_mask);

	register_read(ct_meta.dstip, flow_xor_dstip, ct_meta.h1);
	bit_xor(ct_meta.dstip, ct_meta.dstip, ct_meta.cur_dstip);
	register_write(flow_xor_dstip, ct_meta.h1, ct_meta.dstip);

	register_read(ct_meta.dstip, flow_xor_dstip, ct_meta.h2);
	bit_xor(ct_meta.dstip, ct_meta.dstip, ct_meta.cur_dstip);
	register_write(flow_xor_dstip, ct_meta.h2, ct_meta.dstip);

	register_read(ct_meta.dstip, flow_xor_dstip, ct_meta.h3);
	bit_xor(ct_meta.dstip, ct_meta.dstip, ct_meta.cur_dstip);
	register_write(flow_xor_dstip, ct_meta.h3, ct_meta.dstip);

	register_read(ct_meta.dstip, flow_xor_dstip, ct_meta.h4);
	bit_xor(ct_meta.dstip, ct_meta.dstip, ct_meta.cur_dstip);
	register_write(flow_xor_dstip, ct_meta.h4, ct_meta.dstip);

	// update all srcport
	bit_and(ct_meta.cur_srcport, tcp.srcPort, ct_meta.flow_mask);

	register_read(ct_meta.srcport, flow_xor_srcport, ct_meta.h1);
	bit_xor(ct_meta.srcport, ct_meta.srcport, ct_meta.srcport);
	register_write(flow_xor_srcport, ct_meta.h1, ct_meta.srcport);

	register_read(ct_meta.srcport, flow_xor_srcport, ct_meta.h2);
	bit_xor(ct_meta.srcport, ct_meta.srcport, ct_meta.srcport);
	register_write(flow_xor_srcport, ct_meta.h2, ct_meta.srcport);

	register_read(ct_meta.srcport, flow_xor_srcport, ct_meta.h3);
	bit_xor(ct_meta.srcport, ct_meta.srcport, ct_meta.srcport);
	register_write(flow_xor_srcport, ct_meta.h3, ct_meta.srcport);

	register_read(ct_meta.srcport, flow_xor_srcport, ct_meta.h4);
	bit_xor(ct_meta.srcport, ct_meta.srcport, ct_meta.srcport);
	register_write(flow_xor_srcport, ct_meta.h4, ct_meta.srcport);

	// update all dstport 
	bit_and(ct_meta.cur_dstport, tcp.dstPort, ct_meta.flow_mask);

	register_read(ct_meta.dstport, flow_xor_dstport, ct_meta.h1);
	bit_xor(ct_meta.dstport, ct_meta.dstport, ct_meta.dstport);
	register_write(flow_xor_dstport, ct_meta.h1, ct_meta.dstport);

	register_read(ct_meta.dstport, flow_xor_dstport, ct_meta.h2);
	bit_xor(ct_meta.dstport, ct_meta.dstport, ct_meta.dstport);
	register_write(flow_xor_dstport, ct_meta.h2, ct_meta.dstport);

	register_read(ct_meta.dstport, flow_xor_dstport, ct_meta.h3);
	bit_xor(ct_meta.dstport, ct_meta.dstport, ct_meta.dstport);
	register_write(flow_xor_dstport, ct_meta.h3, ct_meta.dstport);

	register_read(ct_meta.dstport, flow_xor_dstport, ct_meta.h4);
	bit_xor(ct_meta.dstport, ct_meta.dstport, ct_meta.dstport);
	register_write(flow_xor_dstport, ct_meta.h4, ct_meta.dstport);

	// update all prot
	bit_and(ct_meta.cur_prot, ipv4.protocol, ct_meta.flow_mask);

	register_read(ct_meta.prot, flow_xor_prot, ct_meta.h1);
	bit_xor(ct_meta.prot, ct_meta.prot, ct_meta.cur_prot);
	register_write(flow_xor_prot, ct_meta.h1, ct_meta.prot);

	register_read(ct_meta.prot, flow_xor_prot, ct_meta.h2);
	bit_xor(ct_meta.prot, ct_meta.prot, ct_meta.cur_prot);
	register_write(flow_xor_prot, ct_meta.h2, ct_meta.prot);

	register_read(ct_meta.prot, flow_xor_prot, ct_meta.h3);
	bit_xor(ct_meta.prot, ct_meta.prot, ct_meta.cur_prot);
	register_write(flow_xor_prot, ct_meta.h3, ct_meta.prot);

	register_read(ct_meta.prot, flow_xor_prot, ct_meta.h4);
	bit_xor(ct_meta.prot, ct_meta.prot, ct_meta.cur_prot);
	register_write(flow_xor_prot, ct_meta.h4, ct_meta.prot);

	// update all flow count
	register_read(ct_meta.flow_count, flow_count, ct_meta.h1);
	add_to_field(ct_meta.flow_count, ff_meta.new_flow);
	register_write(flow_count, ct_meta.h1, ct_meta.flow_count);

	register_read(ct_meta.flow_count, flow_count, ct_meta.h2);
	add_to_field(ct_meta.flow_count, ff_meta.new_flow);
	register_write(flow_count, ct_meta.h2, ct_meta.flow_count);

	register_read(ct_meta.flow_count, flow_count, ct_meta.h3);
	add_to_field(ct_meta.flow_count, ff_meta.new_flow);
	register_write(flow_count, ct_meta.h3, ct_meta.flow_count);

	register_read(ct_meta.flow_count, flow_count, ct_meta.h4);
	add_to_field(ct_meta.flow_count, ff_meta.new_flow);
	register_write(flow_count, ct_meta.h4, ct_meta.flow_count);

	// update all packet count
	register_read(ct_meta.packet_count, packet_count, ct_meta.h1);
	add_to_field(ct_meta.packet_count, 1);
	register_write(packet_count, ct_meta.h1, ct_meta.packet_count);

	register_read(ct_meta.packet_count, packet_count, ct_meta.h2);
	add_to_field(ct_meta.packet_count, 1);
	register_write(packet_count, ct_meta.h2, ct_meta.packet_count);

	register_read(ct_meta.packet_count, packet_count, ct_meta.h3);
	add_to_field(ct_meta.packet_count, 1);
	register_write(packet_count, ct_meta.h3, ct_meta.packet_count);

	register_read(ct_meta.packet_count, packet_count, ct_meta.h4);
	add_to_field(ct_meta.packet_count, 1);
	register_write(packet_count, ct_meta.h4, ct_meta.packet_count);
}

table flow_radar {
	actions {
		update_flow_radar;
	}
}

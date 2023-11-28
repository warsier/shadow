#include "DCFG.h"
#include "differential_privacy.h"
#include "InsBlock.h"
#include "InsRoot.h"
#include "InsMem.h"

using namespace std;

DCFG::DCFG(InsBlock *&beginBlock, InsBlock *&endBlock, const std::string &dcfg_cfg_file, const std::string &dcfg_trace_file) {
    shadow_output.open("shadow_output.out", ofstream::out);
    dcfg_output.open("dcfg_output.out", ofstream::out);

	this->dcfg_cfg_file = dcfg_cfg_file;
	this->dcfg_trace_file = dcfg_trace_file;

    dcfgMgr = DCFG_PIN_MANAGER::new_manager();
	dcfgMgr->set_cfg_collection(true);
	dcfgMgr->activate();

    dcfgData = DCFG_DATA::new_dcfg();
	string msg;
	std::vector<std::vector<int>> input, output;
	if (dcfgData->read(dcfg_cfg_file, msg) && summarizeTrace(dcfgData, "edge_log_org.txt", input) == 0) {
		DCFG_ID_VECTOR process_ids;
		int process_count = dcfgData->get_process_ids(process_ids);
		assert(process_count >= 1);
		output = obfuscate(input);

		dcfgProcInfo = dcfgData->get_process_info(process_ids[0]);

		initDCFGMap(beginBlock, endBlock);
	}
    else {
        cerr << "DCFG cfg file not existent, creating one using current run." << endl;
    }
}

void DCFG::initDCFGMap(InsBlock *&beginBlock, InsBlock *&endBlock) {
	beginBlock = new InsBlock(); 
	endBlock = new InsBlock();
	this->beginBlock = beginBlock;
	this->endBlock = endBlock;

	DCFG_ID_VECTOR bblids, edge_ids, temp_ids;
	dcfgProcInfo->get_basic_block_ids(bblids);

    // create a special "UNKNOWN" node whose BBLID is 3 in DCFG
	DCFGMap[3] = new InsBlock();

	for (DCFG_ID id: bblids) {
		DCFGMap[id] = new InsBlock();
		DCFGMap[id]->dcfgid = id;
	}

	dcfgProcInfo->get_internal_edge_ids(edge_ids);
	temp_ids.clear();
	dcfgProcInfo->get_inbound_edge_ids(temp_ids);
	edge_ids.insert(edge_ids.end(), temp_ids.begin(), temp_ids.end());
	temp_ids.clear();
	dcfgProcInfo->get_outbound_edge_ids(temp_ids);
	edge_ids.insert(edge_ids.end(), temp_ids.begin(), temp_ids.end());

	DCFG_ID begin_id = dcfgProcInfo->get_start_node_id();
	DCFG_ID end_id = dcfgProcInfo->get_end_node_id();

	for (DCFG_ID id: edge_ids) {
		DCFG_EDGE_CPTR e = dcfgProcInfo->get_edge_info(id);
		DCFG_ID src = e->get_source_node_id();
		DCFG_ID dst = e->get_target_node_id();

		UINT64 cnt = e->get_exec_count();
		// std::cout << src << " " << dst << " " << cnt << std::endl;
		InsBlock *src_block = (src == begin_id ? beginBlock : DCFGMap[src]);
		InsBlock *dst_block = (dst == end_id ? endBlock : DCFGMap[dst]);
		src_block->outEdges.insert(dst_block);
		src_block->outEdgesStack.push_back({dst_block, cnt});
		dst_block->inEdges.insert(src_block);
	}
}

void DCFG::recordBBL(DCFG *self, InsBlock *cur) {
	// InsBlock *prev = self->prevBlockinTrace;
	// cout << "cur = " << (void *) cur << endl;
	// TODO: record all traces for now
	if (self->prevBlockinTrace != nullptr) {
		// cout << (void *) prev << endl;
		if (self->prevBlockinTrace->outEdgesTrace.empty()) {
			//no out edge yet. add.
			self->prevBlockinTrace->outEdgesTrace.push_back( { cur, 1 });
		} else if (self->prevBlockinTrace->outEdgesTrace.back().first == cur) {
			//same as last one. increment count.
			self->prevBlockinTrace->outEdgesTrace.back().second++;
		} else {
			//not same as last one. add.
			self->prevBlockinTrace->outEdgesTrace.push_back( { cur, 1 });
		}
	}
	self->prevBlockinTrace = cur;
}

InsBlock *DCFG::getInsBlockByBBLAddress(ADDRINT addr) {
    DCFG_ID_VECTOR bblids;
    if (!this->exist()) return nullptr;
    dcfgProcInfo->get_basic_block_ids_by_addr(addr, bblids);
    UINT64 bblid = BBL_INVALID;
    if (bblids.size() <= 0) return nullptr;
    bblid = bblids[0];
    auto it = DCFGMap.find(bblid);

    if (it == DCFGMap.end()) return nullptr;
    return it->second;
}

void DCFG::write(const std::string &file) {
    DCFG_DATA_CPTR data = dcfgMgr->get_dcfg_data();
	string msg;
	data->write(file, msg);
}

const std::vector<std::string> EDGE_TYPE_STR{
    "ENTRY",
    "EXIT",
    "BRANCH",
    "CONDITIONAL_BRANCH",
    "UNCONDITIONAL_BRANCH",
    "DIRECT_BRANCH",
    "INDIRECT_BRANCH",
    "DIRECT_CONDITIONAL_BRANCH",
    "INDIRECT_CONDITIONAL_BRANCH",
    "DIRECT_UNCONDITIONAL_BRANCH",
    "INDIRECT_UNCONDITIONAL_BRANCH",
    "REP",
    "FALL_THROUGH",
    "CALL",
    "DIRECT_CALL",
    "INDIRECT_CALL",
    "RETURN",
    "CALL_BYPASS",
    "SYSTEM_CALL_BYPASS",
    "SYSTEM_CALL",
    "SYSTEM_RETURN",
    "CONTEXT_CHANGE",
    "CONTEXT_CHANGE_RETURN",
    "CONTEXT_CHANGE_BYPASS",
    "EXCLUDED_CODE_BYPASS",
    "UNKNOWN"
};

size_t FindExitTypeIndex(std::string target) {
    for (size_t i = 0; i < EDGE_TYPE_STR.size(); i++) {
        if (EDGE_TYPE_STR[i] == target) {
            return i;
        }
    }
    return -1;
}

// Summarize DCFG trace contents.
int DCFG::summarizeTrace(DCFG_DATA_CPTR dcfg, string logfile, std::vector<std::vector<int>> &result)
{

	std::ofstream log_ofs;
	log_ofs.open(logfile, std::ios::out | std::ios::trunc);

	// processes.
	DCFG_ID_VECTOR proc_ids;
	dcfg->get_process_ids(proc_ids);

	for (size_t pi = 0; pi < proc_ids.size(); pi++)
	{
		DCFG_ID pid = proc_ids[pi];

		// Get info for this process.
		DCFG_PROCESS_CPTR pinfo = dcfg->get_process_info(pid);
		assert(pinfo);

		// Make a new reader.
		DCFG_TRACE_READER *traceReader = DCFG_TRACE_READER::new_reader(pid);

		// threads.
		for (UINT32 tid = 0; tid <= pinfo->get_highest_thread_id(); tid++)
		{
			bool is_main = false, is_exit = false;
			// DCFG_TRACE_READER* traceReader = DCFG_TRACE_READER::new_reader(pid);
			// Open file.
			cerr << "Reading DCFG trace for PID " << pid << " and TID " << tid << " from '"
				 << this->dcfg_trace_file << "'..." << endl;
			string errMsg;
			if (!traceReader->open(this->dcfg_trace_file, tid, errMsg))
			{
				cerr << "error: " << errMsg << endl;
				delete traceReader;
				return -1;
			}

			// Header.
			// cout << "edge id,basic-block id,basic-block addr,basic-block symbol,num instrs in "
			// 		"BB"
			// 	 << endl;

			// Read until done.
			size_t nRead = 0;
			bool done = false;
			DCFG_ID_VECTOR edge_ids;
			while (!done)
			{
				if (!traceReader->get_edge_ids(edge_ids, done, errMsg))
				{
					cerr << "error: " << errMsg << endl;
					done = true;
				}
				nRead += edge_ids.size();
				for (size_t j = 0; j < edge_ids.size(); j++)
				{
					DCFG_ID edgeId = edge_ids[j];

					// Get edge.
					DCFG_EDGE_CPTR edge = pinfo->get_edge_info(edgeId);

					if (!edge)
						continue;
					if (edge->is_exit_edge_type())
					{
						cout << edgeId << ",end" << endl;
						continue;
					}

					// Get BB at target.
					DCFG_ID bbId = edge->get_target_node_id();
					DCFG_BASIC_BLOCK_CPTR bb = pinfo->get_basic_block_info(bbId);
					if (!bb)
						continue;
					const string *symbol = bb->get_symbol_name();
					// const string* filename = bb->get_source_filename();

					DCFG_ID_VECTOR ib_eids;
					bb->get_inbound_edge_ids(ib_eids);
					auto inner_loop_id = bb->get_inner_loop_id();
					auto loop_info = pinfo->get_loop_info(inner_loop_id);

					// print info.
					// cout << edgeId << ',' << bbId << ',' << (void *)bb->get_first_instr_addr()
					// 	 << ',' << '"' << (symbol ? *symbol : "unknown") << '"' << ','
					// 	 << bb->get_num_instrs() << ", [" << *(pinfo->get_edge_info(edgeId)->get_edge_type()) << "]"
					// 	 << endl;
					if (symbol)
					{
						if (*symbol == "exit")
						{
							if (edge_list.size() > 2)
								edge_list.erase(edge_list.end() - 1, edge_list.end());
							is_exit = true;
						}
					}
					if (is_main && !is_exit)
					{
						edge_list.push_back(FindExitTypeIndex(*(pinfo->get_edge_info(edgeId)->get_edge_type())));
						block_size_list.push_back(bb->get_num_instrs());
						edge_id_list.push_back(edgeId);
						block_id_list.push_back(bbId);
						if (loop_info)
						{
							auto loops = loop_info->get_iteration_count();
							loop_list.push_back(loops);
						}
						else
						{
							loop_list.push_back(0);
						}
					}
					if (symbol)
					{
						if (*symbol == "main")
							is_main = true;
					}
					// for (auto &id : ib_eids)
					// 	cout << "\t [" << id << ", " << *(pinfo->get_edge_info(id)->get_edge_type()) << "]" << std::endl;
					// if (loop_info)
					// {
					// 	auto loops = loop_info->get_iteration_count();
					// 	cout << "\t Loop info: (" << loops << ")" << std::endl;
					// }
				}
				edge_ids.clear();
			}
			cerr << "Done reading " << nRead << " edges." << endl;
		}

		log_ofs << "[";
		for (auto &edge : edge_list)
			log_ofs << edge << ",";
		log_ofs << "]\n[";
		for (auto &inst : block_size_list)
			log_ofs << inst << ",";
		log_ofs << "]\n[";
		for (auto &loop : loop_list)
			log_ofs << loop << ",";
		log_ofs << "]\n";

		log_ofs << "[";
		for (auto &edge : edge_id_list)
			log_ofs << edge << ",";
		log_ofs << "]\n";

		log_ofs << "[";
		for (auto &bb : block_id_list)
			log_ofs << bb << ",";
		log_ofs << "]\n";

		for (int i = 0; i < 5; ++i)
			result.push_back(vector<int>(0));
		for (auto &edge : edge_list)
			result[0].push_back((int)edge);
		for (auto &inst : block_size_list)
			result[1].push_back((int)inst);
		for (auto &loop : loop_list)
			result[2].push_back((int)loop);
		for (auto &edge : edge_id_list)
			result[3].push_back((int)edge);
		for (auto &bb : block_id_list)
			result[4].push_back((int)bb);

		// delete traceReader;
	}

	log_ofs.close();
	return 0;
}

// void DCFG::compressDCFG(std::set<InsBlock *> &cfg) {
// 	for (InsBlock *blk : cfg) {
// 		if (blk != this->beginBlock && blk != this->endBlock) {
// 			// if there are no instructions in this block
// 			// and this block is sequential
// 			if (blk->ins.size() == 0 && blk->inEdges.size() == 1 && blk->outEdges.size() == 1) {
// 				InsBlock *prev = *blk->inEdges.begin();
// 				InsBlock *next = *blk->outEdges.begin();
// 				// std::cout << prev->getId() << " " << blk->getId() << " " << next->getId() << std::endl;
// 				prev->replaceOutEdge(blk, next);
// 				next->inEdges.erase(blk);
// 				next->inEdges.insert(prev);
// 				blk->isUsed = false;
// 				cfg.erase(blk);
// 			}
// 		}
// 	}
// }

// bool reloadDcfgTraceBuffer() {
// 	string msg;
// 	dcfgTraceBuffer.clear();
// 	if (!dcfg_trace_done) {
// 		if (!dcfgTraceReader->get_edge_ids(dcfgTraceBuffer, dcfg_trace_done, msg)) {
// 			cerr << " error: " << msg << endl;
// 			dcfg_trace_done = true;
// 			return false;
// 		} 
// 		dcfgTraceBufferPtr = dcfgTraceBuffer.begin();
// 		return true;
// 	}
// 	return false;
// }

// UINT64 getDcfgEdgeAddress(DCFG_ID_VECTOR::iterator &edgePtr) {
// 	DCFG_EDGE_CPTR edge = dcfgProcInfo->get_edge_info(*edgePtr);
// 	if (!edge) {
// 		cerr << "error: invalid edge" << endl;
// 		return 0; 
// 	}
// 	DCFG_ID bbId = edge->get_target_node_id();
// 	DCFG_BASIC_BLOCK_CPTR bb = dcfgProcInfo->get_basic_block_info(bbId);
	
// 	if (!bb) return 0;
// 	// if (edge->is_exit_edge_type()) {
// 	// 	dcfg_output << bbId << " " << (void *)bb->get_first_instr_addr() << ",end" << endl;
// 	// 	return 0;
// 	// }
// 	return bb->get_first_instr_addr();
// }
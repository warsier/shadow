#include <map>
#include "InsBlock.h"
#include "InsBase.h"
#include "cln_utils.h"
#include <iomanip>

using namespace std;

std::vector<InsBlock*> InsBlock::blockList;
UINT64 InsBlock::_idCnt = 0;

//extern uint64_t edgeStatDirect;
//extern uint64_t edgeStatOrdered;
//extern uint64_t edgeStatRandom;
extern uint64_t edgeDynDirect;
extern uint64_t edgeDynOrdered;
extern uint64_t edgeDynRandom;

InsBlock::InsBlock() {
  blockList.push_back(this);
  this->id = _idCnt++;
}

//InsBlock::InsBlock(UINT64 id) {
//  blockList.push_back(this);
//  this->id = id;
//}


// sort outEdges by their first appearance in outEdgesTrace
void InsBlock::calcOutEdgesOrder(std::vector<InsBlock*> &order) const {
  order.clear();
  map<InsBlock *, bool> visited;
  for (InsBlock *edge : outEdges)
    visited[edge] = false;
  UINT64 visited_cnt = 0;

  // auto sum = [](std::vector<std::pair<InsBlock *, UINT64>> s)
  // {
  //   int result = 0;
  //   for (auto it : s) {
  //     result += it.second;
  //   }
  //   return result;
  // };

  // if (sum(outEdgesStack) != sum(outEdgesTrace))
  //   cout << sum(outEdgesStack) << " " << sum(outEdgesTrace) << endl;

  for (auto it : outEdgesTrace) {
    // outEdgesTrace may contain non-existent edges
    if (visited.find(it.first) != visited.end() && !visited[it.first]) {
      visited[it.first] = true;
      order.push_back(it.first);
      // cout << "visited" << endl;
      visited_cnt++;
    }
    if (visited_cnt >= outEdges.size())
      break;
  }

  // otherwise push all unvisited edges in the stack
  for (auto it : outEdgesStack) {
    if (!visited[it.first])
      order.push_back(it.first);
  }

}

bool InsBlock::isOutOrderConst(std::vector<InsBlock*> &order) const {
  size_t outBlockCnt = outEdges.size();
  //if (outEdgesStack.size() % outBlockCnt)
  //  return false; //total elements in the out stack is not a multiple of out blocks

  order.clear();
  order.resize(outBlockCnt, nullptr);

  size_t idx = 0;
  for (auto it : outEdgesStack) {
    if (order[idx] == nullptr) {
      order[idx] = it.first;
    } else if (order[idx] != it.first) {
      return false;
    }
    idx++;
    idx %= outBlockCnt;
  }
  return true;
}

map<InsBlock*, InsBlock::EdgeStat> InsBlock::calcEdgeStats() const {
  map<InsBlock*, EdgeStat> aa;
  for (auto it : outEdgesStack) {
    aa[it.first].totCnt += it.second;
    aa[it.first].entryCnt++;
  }
  for (auto &it : aa) {
    UINT64 tot = it.second.totCnt;
    it.second.avgCnt = tot / it.second.entryCnt;
    it.second.remCnt = tot % it.second.entryCnt;
  }
  return aa;
}

std::string InsBlock::printDot(UINT32 indent) const {
  if (isUsed) {
    stringstream ss;
    if (id == 0) {   //special case: start block
      ss << "\tB0 [label=\"START\",fillcolor=yellow,style=filled];\n";
    } else if (id == 1) {   //special case: end block
      ss << "\tB1 [label=\"END\",fillcolor=yellow,style=filled];\n";
    } else {
      //draw table start
      ss << "\tB" << id
          << " [shape=plain, fontname=\"Courier\", label=< <table>";
      ss << "<TR><TD balign=\"left\" border=\"0\">";
      ss << "Block: " << id;

      //draw instructions
      for (InsBase *it : ins) {
        ss << it->printDot(indent);
      }

      //draw table end
      ss << "</TD></TR> </table> >];\n";
    }

    //draw outgoing edges
    map<InsBlock*, UINT64> outBlocks;
    for (auto it : outEdgesStack) {
      outBlocks[it.first] += it.second;
    }

    for (auto it : outBlocks) {
      InsBlock *o = it.first;
      ss << "\tB" << id;   // << ":o" << cnt;
      ss << " -> B" << o->id;   // << ":i";
      ss << " [label=\"" << it.second << "\"];\n";
    }

    return ss.str();
  }
  return "";
}

UINT64 InsBlock::getId() const {
  return id;
}

void InsBlock::deleteAll() {
  for (InsBlock *blk : blockList) {
    delete blk;
  }
  blockList.clear();
}

std::string InsBlock::printDotAll(UINT32 indent) {
  stringstream ss;
  for (InsBlock *blk : blockList) {
    if (blk->isUsed && blk->id < 300) {
      ss << blk->printDot(indent);
    }
  }
  return ss.str();
}

UINT64 InsBlock::getNumBlocks() {
  return blockList.size();
}


std::string InsBlock::printEdgeInfo(UINT32 indent) const {
  stringstream ss;
  //too many edges.. for now, skip...
  ss << _tab(indent) << "//" << outEdgesStack.size() << " edges... print first few...\n";
  const size_t lst_cnt = 6;
  for (size_t i = 0; i < lst_cnt; i++) {
    ss << _tab(indent) << "//blk_" << outEdgesStack[i].first->id << " : "
        << outEdgesStack[i].second << "\n";
  }
  ss << _tab(indent) << "//...\n";
  ss << _tab(indent) << "//...\n";
  size_t sz = outEdgesStack.size();
  for (size_t i = 0; i < lst_cnt; i++) {
    ss << _tab(indent) << "//blk_" << outEdgesStack[sz - lst_cnt + i].first->id
        << " : " << outEdgesStack[sz - lst_cnt + i].second << "\n";
  }
  return ss.str();
}

std::string InsBlock::printCodeBody(UINT32 indent) const {
  stringstream out;
  out << "block" << id << ":\n";
#ifdef DEBUG
  // out << _tab(indent) << "printf(\"" << id << " \");\n";
  out << _tab(indent) << "INC_EXEC_CNT(" << id << ");\n";
  int pathcnt = 0;
#endif
  for (InsBase *base : ins) {
    out << base->printCodeBody(indent);
  }

  if (outEdges.size() == 0) {
    return out.str();
  }
  
  // simple if just one edge
  if (outEdgesStack.size() == 1) {
#ifdef DEBUG
    out << _tab(indent) << "{ INC_PATH_TAKEN(" << id << ", "
        << pathcnt << "); goto block" << outEdgesStack[0].first->id
        << "; }\n\n";
    pathcnt++;
#else
    out << _tab(indent) << "goto block" << outEdgesStack[0].first->id
        << ";\n\n";
#endif
    //if(id != 0){
    //edgeStatDirect++;
    edgeDynDirect += outEdgesStack[0].second;
    //}
    return out.str();
  }

  // small number of transitions. No need to find patterns
  if (outEdgesStack.size() < 200000) {
    out << _tab(indent) << "//Few edges. Don't bother optimizing\n";

    out << _tab(indent) << "static uint64_t out_" << id << " = 0;\n";
    out << _tab(indent) << "out_" << id << "++;\n";
    UINT64 total = 0;


    // sort outEdges
    vector<InsBlock*> outEdgesOrder;
    calcOutEdgesOrder(outEdgesOrder);
    UINT64 sz = outEdgesOrder.size();

    for (UINT64 i = 0; i < sz; i++) {
      InsBlock *edge = outEdgesOrder[i];
      UINT64 cnt = find_if(
        outEdgesStack.begin(),
        outEdgesStack.end(),
        [edge] (const std::pair<InsBlock *, UINT64> p) {return p.first == edge;}
      )->second;
      total += cnt;
      out << _tab(indent);
      if (i) {
        out << "else ";
      }
      if (i != (sz - 1)) {
        out << "if (out_" << id << " <= " << total << "LL) ";
      }
#ifdef DEBUG
    out << "{ INC_PATH_TAKEN(" << id << ", " 
        << pathcnt << "); goto block" << edge->id
        << "; }\n";
      pathcnt++;
#else
    out << "goto block" << edge->id << ";\n";
#endif
    }
    out << "\n\n";
    //edgeStatDirect++;
    edgeDynDirect += total;
    return out.str();
  }

  //check order
  vector<InsBlock*> blkOrder;
  bool isOrdered = isOutOrderConst(blkOrder);
  if (isOrdered) {
    out << _tab(indent) << "//Ordered...\n";
  }

  //print edge stats
  map<InsBlock*, EdgeStat> estat = calcEdgeStats();

  //check if remainder is zero for all
  bool isRemZero = true;
  for (auto it : estat) {
    if (it.second.remCnt) {
      isRemZero = false;
      break;
    }
  }

  //ordered, no remainder edges (use integer)
  if (isOrdered && isRemZero) {
    out << _tab(indent) << "//Remainder zero for all out blocks...\n";
    assert(estat.size() == blkOrder.size());
    UINT64 tot_cnt = 0;
    for (auto it : estat) {
      tot_cnt += it.second.avgCnt;
      edgeDynOrdered += it.second.totCnt;
    }
    out << _tab(indent) << "static uint64_t out_" << id << " = 0;\n";
    out << _tab(indent) << "out_" << id << " = (out_" << id << " == "
        << (tot_cnt) << "LL) ? 1 : (out_" << id << " + 1);\n";
    UINT64 sz = estat.size();
    tot_cnt = 0;
    for (UINT64 i = 0; i < sz; i++) {
      //get next block following the order
      InsBlock *nb = blkOrder[i];
      EdgeStat es = estat[nb];

      tot_cnt += es.avgCnt;
      out << _tab(indent);
      if (i) {
        out << "else ";
      }
      if (i != (sz - 1)) {
        out << "if (out_" << id << " <= " << tot_cnt << "LL) ";
      }
#ifdef DEBUG
      out << "{ INC_PATH_TAKEN(" << id << ", " 
          << pathcnt << "); goto block" << nb->id
          << "; }\n";
      pathcnt++;
#else
      out << "goto block" << nb->id << ";\n";
#endif
    }
    out << "\n\n";
    //edgeStatOrdered++;
    return out.str();
  }

  if (isOrdered) {
      out << _tab(indent) << "//Remainder NOT zero\n";
      assert(estat.size() == blkOrder.size());
      UINT64 tot_cnt = 0;
      UINT64 cov_cnt = 0;
      for (auto it : estat) {
        tot_cnt += it.second.avgCnt;
        cov_cnt += it.second.avgCnt * it.second.entryCnt;
        edgeDynOrdered += it.second.totCnt;
      }
      out << _tab(indent) << "static uint64_t cov_" << id << " = 0;\n";
      out << _tab(indent) << "cov_" << id << "++;\n";
      out << _tab(indent) << "if(cov_" << id << " <= " << cov_cnt << "ULL) {\n";

      out << _tab(indent+1) << "static uint64_t out_" << id << " = 0;\n";
      out << _tab(indent+1) << "out_" << id << " = (out_" << id << " == "
          << (tot_cnt) << "LL) ? 1 : (out_" << id << " + 1);\n";
      UINT64 sz = estat.size();
      for (UINT64 i = 0; i < sz; i++) {
        //get next block following the order
        InsBlock *nb = blkOrder[i];
        EdgeStat es = estat[nb];

        tot_cnt += es.avgCnt;
        out << _tab(indent+1);
        if (i) {
          out << "else ";
        }
        if (i != (sz - 1)) {
          out << "if (out_" << id << " <= " << tot_cnt << "LL) ";
        }
#ifdef DEBUG
        out << "{ INC_PATH_TAKEN(" << id << ", " 
          << pathcnt << "); goto block" << nb->id
          << "; }\n";
      pathcnt++;
#else
        out << "goto block" << nb->id << ";\n";
#endif
        
      }
      out << _tab(indent) << "}\n";

      vector<pair<InsBlock*, uint64_t>> remBlocks;

      for(uint64_t i = outEdgesStack.size() - estat.size(); i < outEdgesStack.size(); i++){
        InsBlock* blk = outEdgesStack[i].first;
        EdgeStat ee = estat[blk];
        if(ee.remCnt){
          cov_cnt += ee.remCnt;
          remBlocks.push_back({blk, cov_cnt});
        }
      }

      sz = remBlocks.size();
      for (UINT64 i = 0; i < sz; i++) {
        //get next block following the order
        out << _tab(indent) << "else ";
        if (i != (sz - 1)) {
          out << "if (cov_" << id << " <= " << remBlocks[i].second << "ULL) ";
        }
        out << "goto block" << remBlocks[i].first->id << ";\n";
      }
      out << "\n";
      //edgeStatOrdered++;
      return out.str();
    }

  //ordered, with remainder edges (use float)
  /*out << printEdgeInfo(indent);
  if (isOrdered) {
    assert(estat.size() == blkOrder.size());
    double tot_cnt = 0.0;
    for (auto it : estat) {
      tot_cnt = tot_cnt + 1.0 * it.second.totCnt / it.second.entryCnt;
    }
    out << _tab(indent) << "static double out_" << id << " = 0.0;\n";
    out.setf(ios::fixed, ios::floatfield);
    out.precision(17);
    out << _tab(indent) << "out_" << id << " = (out_" << id << " > "
        << (tot_cnt) << ") ? out_" << id << " - " << tot_cnt << " : (out_" << id << " + 1.0);\n";
    UINT64 sz = estat.size();
    tot_cnt = 0.0;
    for (UINT64 i = 0; i < sz; i++) {
      //get next block following the order
      InsBlock *nb = blkOrder[i];
      EdgeStat es = estat[nb];

      tot_cnt = tot_cnt + 1.0 * es.totCnt / es.entryCnt;
      out << _tab(indent);
      if (i) {
        out << "else ";
      }
      if (i != (sz - 1)) {
        out << "if (out_" << id << " <= " << tot_cnt << ") ";
      }
      out << "goto block" << nb->id << ";\n";
    }
    out << "\n\n";
    return out.str();
  }*/


  //unordered
  //Generic case. Use probability to jump to one of the out blocks.
  out << _tab(indent) << "//Unordered\n";

  //get last entry from edge stack
  auto lastEntry = outEdgesStack[outEdgesStack.size() - 1];

  //update estat to exclude last entry
  estat[lastEntry.first].totCnt -= lastEntry.second;

  //remove lastEntry block from estat if count becomes zero
  if (estat[lastEntry.first].totCnt == 0) {
    estat.erase(lastEntry.first);
  }

  vector<InsBlock*> tmpBlks;
  for (auto it : estat) {
    out << _tab(indent) << "static uint64_t out_" << id << "_" << it.first->id
        << " = " << it.second.totCnt << "LL;\n";
    tmpBlks.push_back(it.first);
    edgeDynRandom += it.second.totCnt;
  }
  //edgeStatRandom++;

  //calculate total
  UINT64 cc = 0;
  out << _tab(indent) << "tmpRnd = ";
  for (auto it : estat) {
    if (cc++) {
      out << " + ";
    }
    out << "out_" << id << "_" << it.first->id;
  }
  out << ";\n";

  //check if total is not zero
  out << _tab(indent) << "if (tmpRnd) {\n";

  //calc hash
  //out << _tab(indent + 1) << cln_utils::printHash();
  out << _tab(indent + 1) << "tmpRnd = bounded_rnd(tmpRnd);\n";

  //add if conditions
  for (UINT64 i = 0; i < tmpBlks.size(); i++) {
    out << _tab(indent + 1);
    if (i) {
      out << "else ";
    }
    if (i != (tmpBlks.size() - 1)) {
      out << "if (tmpRnd < (";
      for (UINT64 j = 0; j <= i; j++) {
        if (j) {
          out << " + ";
        }
        out << "out_" << id << "_" << tmpBlks[j]->id;
      }
      out << "))";
    }

    out << "{\n";
    out << _tab(indent + 2) << "out_" << id << "_" << tmpBlks[i]->id << "--;\n";
#ifdef DEBUG
    out << _tab(indent + 2) << "{ INC_PATH_TAKEN(" << id << ", " 
          << pathcnt << "); goto block" << tmpBlks[i]->id
          << "; }\n";
      pathcnt++;
#else
    out << _tab(indent + 2) << "goto block" << tmpBlks[i]->id << ";\n";
#endif
    
    out << _tab(indent + 1) << "}\n";
  }

  //close tmpRnd != 0 check
  out << _tab(indent) << "}\n";

  //add default jump (last edge)
#ifdef DEBUG
  out << _tab(indent + 2) << "{ INC_PATH_TAKEN(" << id << ", " 
          << pathcnt << "); goto block" << lastEntry.first->id
          << "; }\n";
      pathcnt++;
#else
  out << _tab(indent) << "goto block" << lastEntry.first->id << ";\n";
#endif

  out << endl << endl;
  // }
  return out.str();
}

void InsBlock::setParentLoop(InsLoop *pl) {
  for (InsBase *i : ins) {
    i->setParentLoop(pl);
  }
}

void InsBlock::updateOutEdgesStack() {
  vector<pair<InsBlock*, UINT64> > out;
  for (auto it : outEdgesStack) {
    if (out.empty()) {
      out.push_back(it);
    } else { //not the first element
      auto last = out.back();
      if (last.first == it.first) {
        //same, just change count
        out.back().second += it.second;
      } else {
        //different, insert
        out.push_back(it);
      }
    }
  }
  outEdgesStack = out;
}

void InsBlock::replaceOutEdge(InsBlock *old, InsBlock *nw) {
  if (old == nw) {
    return;   //do nothing
  }

  if (id == 33) {
    cout << "before: ";
    for (auto it : outEdgesStack)
      cout << it.first->id << " ";
    cout << endl;
  }

  for (size_t i = 0; i < outEdgesStack.size(); i++) {
    if (outEdgesStack[i].first == old) {
      outEdgesStack[i].first = nw;
    }
  }
  updateOutEdgesStack();    //update run count

  if (id == 33) {
    cout << "after: ";
    for (auto it : outEdgesStack)
      cout << it.first->id << " ";
    cout << endl;
  }

  outEdges.erase(old);
  outEdges.insert(nw);

  //fix in edges
  // old->inEdges.erase(this);
  // nw->inEdges.insert(this);
}

void InsBlock::removeOutEdge(InsBlock *oblk) {
  outEdges.erase(oblk);
  vector<pair<InsBlock*, UINT64> > out;
  //both remove and compress at the same time
  for (auto it : outEdgesStack) {
    if (it.first != oblk) {
      if (out.empty()) {
        out.push_back(it);
      } else { //not the first element
        auto last = out.back();
        if (last.first == it.first) {
          //same, just change count
          out.back().second += it.second;
        } else {
          //different, insert
          out.push_back(it);
        }
      }
    }
  }
  outEdgesStack = out;
}


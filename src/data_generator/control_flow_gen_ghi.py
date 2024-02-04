#!/usr/bin/env python
# -*- coding: utf-8 -*-
###########################
# File Name: control_flow_gen.py
# Author: Yunru Wang
# E-mail: yunruw@outlook.com
# Created Time: 2024-01-30 16:21
# Last Modified: 2024-02-04 17:57
###########################
import utils
import platform
from ghidra.util.graph import DirectedGraph
from ghidra.util.graph import Edge
from ghidra.util.graph import Vertex
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.block import CodeBlockIterator
from ghidra.program.model.block import CodeBlockReference 
from ghidra.program.model.block import CodeBlockReferenceIterator 
from ghidra.program.model.listing import CodeUnitIterator
from ghidra.program.model.listing import Function
from ghidra.program.model.listing import FunctionManager
from ghidra.program.model.listing import Listing
from ghidra.program.database.code import InstructionDB

print platform.python_version()
state = getState()
current_program = state.getCurrentProgram()


symbols = set(currentProgram.getSymbolTable().getAllSymbols(True))
symbol_iterator = currentProgram.getSymbolTable().getAllSymbols(True)
symbols = {}
for st in symbol_iterator:
    if(st not in symbols):
        symbols[st.getAddress().toString()] = [] 
        symbols[st.getAddress().toString()].append([st.getName(), st.getSymbolType()])

func_graphs = {}
basic_block_model = BasicBlockModel(current_program)
function_manager = current_program.getFunctionManager()
function_iterator = function_manager.getFunctions(True)
func_set = set()
print(symbols)
for f in function_iterator:
    print("in!!")
    if(f.isExternal() or f in func_set):
        continue
    print(f)
    func_set.add(f)
    G = DirectedGraph()
    node_dict = {}
    listing = current_program.getListing()
    print(listing)
    code_block_iterator = basic_block_model.getCodeBlocksContaining(f.getBody(), monitor)
    print(f.getBody())
    print(code_block_iterator)
    for bb in code_block_iterator:
        print('1')
        codeUnits = listing.getCodeUnits(bb, True)
        curr_addr = bb.getFirstStartAddress()
        pre_addr = curr_addr
        for code in codeUnits:
            curr_addr = code.getMinAddress()
            print(curr_addr)
            ins = utils.Instruction(str(curr_addr.toString()), utils.parseInstruction(getInstructionAt(curr_addr), symbols))
            if(str(curr_addr.toString()) not in node_dict):
                node_dict[str(curr_addr.toString())]=Vertex(ins)
            if(str(curr_addr.toString())!=str(pre_addr.toString())):
                G.add(Edge(node_dict[str(pre_addr.toString())],node_dict[str(curr_addr.toString())]))
            pre_addr = curr_addr
        dsts = bb.getDestinations(monitor)
        while(dsts.hasNext()):
            dst = dsts.next()
            if(str(dst.getDestinationAddress().toString()) not in node_dict):
                print(str(dst.getDestinationAddress().toString()))
                tins_ = getInstructionAt(dst.getDestinationAddress())
                # external func
                if(not tins_):
                    continue
                tins = utils.Instruction(str(dst.getDestinationAddress().toString()), utils.parseInstruction(tins_, symbols))
                node_dict[str(dst.getDestinationAddress().toString())]=Vertex(tins)
            G.add(Edge(node_dict[str(curr_addr.toString())], node_dict[str(dst.getDestinationAddress().toString())]))
    print('!!!!!!!!!!!!!')
    print(G.getVertices())
    print(node_dict)
    if(len(G.getVertices()) > 2):
        func_graphs[str(f.getEntryPoint().toString())] = G

print(func_graphs.keys())

config = utils.Config(output='/Users/yunruw/Documents/projects/cfg_train.txt')
with open(config.output, 'a') as w:
    for addr, graph in func_graphs.items():
        sequence = utils.randomWalk(graph, config.seq_len)
        for s in sequence:
            if len(s) < 4:
                continue
            # in original code settings, each sample will be replicate twice,
            # in case of this is a special design, we keep this
            for idx in range(len(s)):
                for i in range(1, config.win_size + 1):
                    if idx-i > 0:
                        w.write(s[idx-i]+'\t'+s[idx]+'\n')
                        print(s[idx-i]+'\t'+s[idx]+'\n')
                    if idx+i < len(s):
                        w.write(s[idx]+'\t'+s[idx+i]+'\n')
                        print(s[idx]+'\t'+s[idx+i]+'\n')

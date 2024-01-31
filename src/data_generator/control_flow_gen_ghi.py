#!/usr/bin/env python
# -*- coding: utf-8 -*-
###########################
# File Name: control_flow_gen.py
# Author: Yunru Wang
# E-mail: yunruw@outlook.com
# Created Time: 2024-01-30 16:21
# Last Modified: 2024-01-31 09:49
###########################
import utils
from ghidra.util.graph import DirectedGraph
from ghidra.util.graph import Edge
from ghidra.util.graph import Vertex
import platform


print platform.python_version()
state = getState()
# project = state.getProject()
current_program = state.getCurrentProgram()


symbols = set(currentProgram.getSymbolTable().getAllSymbols(True))
symbol_iterator = currentProgram.getSymbolTable().getAllSymbols(True)
symbols = {}
for st in symbol_iterator:
    if(st not in symbols):
        symbols[st.getAddress().toString()] = [] 
        symbols[st.getAddress().toString()].append([st.getName(), st.getSymbolType()])

# TO DO:
# 1.use networkx
# 2.use pre rather than succ
func_graphs = {}
function_manager = currentProgram.getFunctionManager()
function_iterator = function_manager.getFunctionsNoStubs(True)
for f in function_iterator:
    G = DirectedGraph()
    instructions = listing.getInstructions(f.getEntryPoint(), True)
    curr_addr = [f.getEntryPoint()]
    pre_addr = curr_addr[0]
	for instruction in instructions:
        for i in range(len(curr_addr)):
            curr_ins = getInstructionAt(curr_addr[i])
            v = utils.Instruction(str(curr_ins.getAddress().toString()),utils.parseInstruction(curr_ins, symbols))
            G.add(Vertex(v))
            if(curr_addr.toString()!=pre_addr.toString()):








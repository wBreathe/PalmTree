#!/usr/bin/env python
# -*- coding: utf-8 -*-
###########################
# File Name: helloworld.py
# Author: Yunru Wang
# E-mail: yunruw@outlook.com
# Created Time: 2024-01-30 15:31
# Last Modified: 2024-01-31 01:39
###########################
'''
from ghidra.base.project import GhidraProject
state = getState()
project = state.getProject()
program = state.getCurrentProgram()
locator = project.getProjectData().getProjectLocator()
print("type(state):           {}".format(type(state)))
print("type(project):         {}".format(type(project)))
print("type(program):         {}".format(type(program)))
print("type(locator):         {}".format(type(locator)))
print("Project Name:          {}".format(locator.getName()))
print("Files in this project: {}".format(project.getProjectData().getFileCount()))
print("Is a remote project:   {}".format(locator.isTransient()))
print("Project location:      {}".format(locator.getLocation()))
print("Project directory:     {}".format(locator.getProjectDir()))
print("Lock file:             {}".format(locator.getProjectLockFile()))
print("Marker file:           {}".format(locator.getMarkerFile()))
print("Project URL:           {}".format(locator.getURL()))
'''

# import networkx as nx
import re
import random


class Instruction():
    def __init__(self, addr, text):
        self.addr = addr
        self.text = text

def parse_instruction(ins, symbol_map):
    tokens = []
    tokens.append(str(ins.getMnemonicString()))
    op_num = ins.getNumOperands()
   
    # three factors,
    # 1.OperandType is address
    # 1.1 not in symbol_map ? - address
    # 1.2 in symbol_map
    # 1.2.1 symbol_map[1] is function - symbol
    # 1.2.2 symbol_map[1] is label
    # 1.2.2.1 getOperandRefType(i) is data - string
    # 1.2.2.2 .......... is not data then should be code - address
    for i in range(op_num):
        assert(len(ins.getOpObjects(i))==1)
        op_addr = str(ins.getOpObjects(i)[0].toString())
        if(OperandType(ins.getOperandType()).isAddress()):
            if(op_addr in symbol_map):
                assert(len(symbol_map[op_addr])==1)
                if(symbol_map[op_addr][1]=='Function'):
                    op_addr = '[ rel symbol ]'
                else:
                    assert(symbol_map[op_addr][1]=='Label')
                    if(str(ins.getOperandRefType(i).toString())=='DATA'):
                        op_addr = '[ rel string ]'
                    else:
                        op_addr = '[ rel address ]'
            else:
                op_addr = '[ rel address ]'
        else:
            pass
        tokens.append(op_addr)
    
    return ' '.join(tokens)


def random_walk(g, length):
    sequence = []
    for n in g:
        if n != -1 and 'text' in g._node[n]:
            s = []
            l = 0
            s.append(g._node[n]['text'])
            cur = n
            while l < length:
                nbs = list(g.successors(cur))
                if len(nbs):
                    # randomly select a successor
                    cur = random.choice(nbs)
                    if 'text' in g._node[cur]:
                        s.append(g._node[cur]['text'])
                        l += 1
                    else:
                        break
                else:
                    break
            sequence.append(s)
        if len(sequence) > 5000:
            print("early stop")
            return sequence[:5000]
    print(sequence)
    return sequence


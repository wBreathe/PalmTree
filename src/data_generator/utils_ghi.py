#!/usr/bin/env python
# -*- coding: utf-8 -*-
###########################
# File Name: helloworld.py
# Author: Yunru Wang
# E-mail: yunruw@outlook.com
# Created Time: 2024-01-30 15:31
# Last Modified: 2024-02-04 18:46
###########################
import re
import random
from ghidra.program.model.lang import OperandType

class Config():
    def __init__(self, output='output.data', seq_len='40', win_size=2):
        self.output = output
        self.seq_len = seq_len
        self.win_size = win_size


class Instruction():
    def __init__(self, addr, text):
        self.addr = addr
        self.text = text

def parseInstruction(ins, symbol_map):
    tokens = []
    print('in parseInstruction')
    print(ins)
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
        print(ins.getOpObjects(i))
        if(len(ins.getOpObjects(i))==1):
            # not working, example: MOV RAX,qword ptr FS:[0x28]
            # [FS,0x28]
            op_addr = str(ins.getOpObjects(i)[0].toString())
        else:
            op_addr = " ".join([str(j.toString()) for j in ins.getOpObjects(i)])
        if(OperandType.isAddress(ins.getOperandType(i))):
            if(op_addr in symbol_map):
                assert(len(symbol_map[op_addr])==1)
                print(symbol_map[op_addr])
                if(str(symbol_map[op_addr][0][1].toString())=='Function'):
                    op_addr = '[ rel   symbol ]'
                else:
                    print(type(symbol_map[op_addr][0][1]))
                    assert(str(symbol_map[op_addr][0][1].toString())=='Label')
                    if(str(ins.getOperandRefType(i).toString())=='DATA'):
                        op_addr = '[ rel   string ]'
                    else:
                        op_addr = '[ rel   address ]'
            else:
                op_addr = '[ rel   address ]'
        else:
            pass
        tokens.append(op_addr)
    
    return ' '.join(tokens)


def randomWalk(g, length):
    seq = []
    for n in g.getVertices():
        ins = n.referent()
        assert(len(ins.text)>0)
        cur_seq = []
        cur_seq.append(ins.text)
        cur_node = n
        while len(cur_seq) < length:
            succs = g.getChildren(cur_node)
            if len(succs)<= 0:
                break
            rand = random.choice(range(len(succs)))
            k = 0
            for succ in succs:
                if(k==rand):
                    cur_node = succ
                    break
                else:
                    k+=1
            cur_ins = cur_node.referent()
            assert(len(cur_ins.text)>0)
            print(cur_ins.text)
            cur_seq.append(cur_ins.text)
        # it seems that there is possiblity to have replicate sequences
        if(cur_seq not in seq):
            seq.append(cur_seq)
    return seq[:5000] if len(seq) > 5000 else seq

        

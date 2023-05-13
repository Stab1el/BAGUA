##coding=utf-8
import copy
from  primitive import *
from z3 import *
from random import *
from operation_ability import *


'''
INPUT : heap operation && cur_heap_layout
OUTPUT : heap layout:
[{'size_0':[addr1, addr2 ,addr3]},{'size_1':[addr1,addr2,addr3]...]
'''
class HeapMonitor:

    def __init__(self,cur_heap_layout, alloced_chunks):
        self.cur_hplayout = cur_heap_layout
        self.alloced_chunks = alloced_chunks

    def analyze_heap_layout(self):
        heap_layout = copy.deepcopy(self.cur_hplayout)
        hp_size_len_list = []
        for free_chain in heap_layout:
            free_chain_size = free_chain.keys()[0]
            free_chain_len = len(free_chain.values()[0])
            solver_symbol = Int("L_" + str(free_chain_size))
            chunk_addr = free_chain.values()[0]
            hp_size_len_list.append([free_chain_size, free_chain_len, solver_symbol, chunk_addr])

        sorted(hp_size_len_list, key=lambda hp_size_len_list: hp_size_len_list[0])
        return hp_size_len_list

    def modify_alloced_chunks(self):
        pass


    def add_chunk_to_chain(self,free_chain,chunk):

        cur_value = free_chain.values()[0]
        cur_value.append(chunk)
        new_free_chain = {free_chain.keys()[0]:cur_value}

        for free_chain in self.next_hplayout:
            if free_chain.keys()[0] == new_free_chain.keys()[0]:
                self.next_hplayout.remove(free_chain)
                self.next_hplayout.append(new_free_chain)
                return
        print "not found chunk"


    def del_chunk_from_chain(self,free_chain,chunk):
        cur_value = free_chain.values()[0]
        copy_cur_value = copy.deepcopy(cur_value)
        copy_cur_value.pop(0)
        new_free_chain = {free_chain.keys()[0]:copy_cur_value}

        for free_chain in self.next_hplayout:
            if free_chain.keys()[0] == new_free_chain.keys()[0]:
                if copy_cur_value == []:
                    self.next_hplayout.remove(free_chain)
                else:
                    self.next_hplayout.remove(free_chain)
                    self.next_hplayout.append(new_free_chain)
                return
        print "not found chunk"


    def __get_next_layout(self):

        m_size = self.m_ability.malloc_size
        split_size = self.m_ability.get_split_item()
        if split_size != 999999:
            last_remainder_bin = split_size - m_size
        else:
            last_remainder_bin = 999999
        malloc_chain_len = self.m_ability.count_hole_num(m_size)

        size_list = []

        ## to cur free chain in heap layout
        for free_chain in self.cur_hplayout:
            size_list.append(free_chain.keys()[0])
            ## if x == y
            if m_size == free_chain.keys()[0]:
                if malloc_chain_len  > 0:
                    self.del_chunk_from_chain(free_chain,0xffffff)
                else:
                    if last_remainder_bin == free_chain.keys()[0]:
                        self.add_chunk_to_chain(free_chain,0xffffff)
            ## if x > y
            elif m_size > free_chain.keys()[0]:
                if malloc_chain_len > 0:
                    pass
                else:
                    if last_remainder_bin == free_chain.keys()[0]:
                        self.add_chunk_to_chain(free_chain,0xffffff)
            ## if x < y
            else:
                if malloc_chain_len > 0:
                    pass
                else:
                    if split_size == free_chain.keys()[0]:
                        self.del_chunk_from_chain(free_chain,0xffffff)
                    else:
                        if last_remainder_bin == free_chain.keys()[0]:
                            self.add_chunk_to_chain(free_chain,0xffffff)


        ## maybe could add new chain
        if last_remainder_bin != 999999 and last_remainder_bin not in size_list:
            new_free_chain = {last_remainder_bin:[0xffffff]}
            self.next_hplayout.append(new_free_chain)

    def get_new_layout(self):
        self.__get_next_layout()
        return self.next_hplayout

    def count_chunk_change(self,chain):

        self.__get_next_layout()

        count_cur_num  = 0
        for free_chain in self.cur_hplayout:
            if free_chain.keys()[0] == chain:
                count_cur_num = len(free_chain.values()[0])
        count_new_num = 0
        for n_free_chain in self.next_hplayout:
            if n_free_chain.keys()[0] == chain:
                count_new_num = len(free_chain.values()[0])

        return count_new_num - count_cur_num

    def get_malloc_size_options(self):

        malloc_size_options = [100,200,400,600,800,1000,1200]

        return malloc_size_options


def analyze_heap_layout(heap_layout):
    hp_size_len_list = []
    for free_chain in heap_layout:
        free_chain_size = free_chain.keys()[0]
        free_chain_len = len(free_chain.values()[0])
        solver_symbol = Int("L_" + str(free_chain_size))
        chunk_addr = free_chain.values()[0]
        hp_size_len_list.append([free_chain_size, free_chain_len, solver_symbol, chunk_addr])

    sorted(hp_size_len_list, key=lambda hp_size_len_list: hp_size_len_list[0])
    return hp_size_len_list

def modify_alloced_chunks(alloced_chunks, chunk):
    [chunk_size, chunk_addr] = chunk
    for a_chunk in alloced_chunks:
        if chunk_addr == a_chunk[1]:
            alloced_chunks.remove(a_chunk)
            return alloced_chunks

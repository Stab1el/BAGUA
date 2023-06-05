##coding=utf-8
import copy
from heap_monitor import *
from allocator_config import *

'''
INPUT:
heap layout:
[{'size_0':[addr1, addr2 ,addr3]},{'size_1':[addr1,addr2,addr3]...]
'''
class OperationAbility:

    def __init__(self, heap_layout, cur_op, target_hole_size):
        self.heap_layout = heap_layout
        self.alloced_chunks = self.heap_layout.get_allocated_chunks()
        self.free_lists = self.heap_layout.get_free_lists()
        self.can_ms_free_lists = self.heap_layout.get_can_ms_free_chunks()
        self.target_hole_size = target_hole_size
        self.cur_op = cur_op
        self.last_remainder_bin = None
        if self.cur_op.op_type == "M":
            self.malloc_chunk_size = self.__convert_msize2ck_size()

    def get_free_chunks_by_size(self, size):

        fl_chunks = []

        for priority in range(0, len(self.free_lists[size])):
            fl = self.free_lists[size][priority]
            if fl.get_num_freed_chunks() == 0:
                continue
            fl_chunks.append(fl.chunks)
        return fl_chunks

    def __convert_msize2ck_size(self):
        return self.cur_op.malloc_size + 2*SIZE_SZ

################ For free only #####################################################

    def __to_merge_chunk(self):
        previous_chunk = None
        next_chunk = None

        free_chunk_size = self.cur_op.free_chunk_size
        free_chunk_addr = self.cur_op.free_chunk_addr

        if free_chunk_size < MS_START_SIZE:
            return previous_chunk, next_chunk

        self.can_ms_free_lists = self.heap_layout.get_can_ms_free_chunks()


        for each_size in self.can_ms_free_lists:
            fl = self.can_ms_free_lists[each_size]

            for chunk_addr in fl.chunks:
                if chunk_addr == free_chunk_addr + free_chunk_size:
                    next_chunk = [each_size, chunk_addr]
                elif chunk_addr + each_size == free_chunk_addr:
                    previous_chunk = [each_size, chunk_addr]

        if self.cur_op.free_chunk_size + self.cur_op.free_chunk_addr == self.heap_layout.top_chunk:
            next_chunk = [self.heap_layout.top_chunk, self.heap_layout.top_chunk]

        return previous_chunk, next_chunk

    def get_merged_new_chunk(self, previous_chunk, next_chunk):

        new_chunk_size = self.cur_op.free_chunk_size + 2*SIZE_SZ
        new_chunk_addr = self.cur_op.free_chunk_addr

        if previous_chunk == None and next_chunk == None:
            return None

        if previous_chunk != None:
            new_chunk_size = new_chunk_size + previous_chunk[0]
            new_chunk_addr = previous_chunk[1]

        if next_chunk != None and next_chunk[0] < self.heap_layout.top_chunk:
            new_chunk_size = new_chunk_size + next_chunk[0]

        merged_chunk = [new_chunk_size, new_chunk_addr]

        return merged_chunk

    def __find_target_chunk_position_in_ms_free_list(self, tar_chunk):
        '''
        find target position in can merge free_list
        :param tar_chunk:
        :return:
        '''
        if tar_chunk is None:
            return None

        [tar_chunk_size, tar_chunk_addr] = tar_chunk
        fl = self.can_ms_free_lists[tar_chunk_size]
        addr_lists = fl.chunks
        for each_addr_list in addr_lists:
            index = each_addr_list.index(tar_chunk_addr)
            if index is not None:
                if fl.is_FILO:
                    return len(each_addr_list) - index
                else:
                    return index + 1
        return None

    def calculate_free_effects(self,op_abi, previous_merge_chunk, next_merge_chunk, merged_chunk):

        if self.cur_op.op_type == 'F':

            effects = {}
            free_delta_chunks = []
            allocated_delta_chunks = []
            ## case 1: if no merge and increase one hole in the target chain
            if op_abi == 1 and merged_chunk == None:
                free_delta_chunks.append([self.cur_op.free_chunk_size + 2*SIZE_SZ, self.cur_op.free_chunk_addr, 1, 0, 0])
                allocated_delta_chunks.append([self.cur_op.free_chunk_size + 2*SIZE_SZ, self.cur_op.free_chunk_addr, -1, self.cur_op.malloc_target, self.cur_op.op_index])
            ## case 2: if has merge and merged chunk size = target hole size
            elif op_abi == 1 and merged_chunk[0] == self.target_hole_size:
                if previous_merge_chunk is not None:
                    free_delta_chunks.append([previous_merge_chunk[0], previous_merge_chunk[1], -1, 0, 0])
                if next_merge_chunk is not None:
                    free_delta_chunks.append([next_merge_chunk[0], next_merge_chunk[1], -1, 0, 0])
                free_delta_chunks.append([merged_chunk[0], merged_chunk[1], 1 , 0, 0])
                allocated_delta_chunks.append([self.cur_op.free_chunk_size + 2*SIZE_SZ, self.cur_op.free_chunk_addr, -1, self.cur_op.malloc_target, self.cur_op.op_index])

            ## case 3 if has merge and decreases one hole in target chain
            elif op_abi == -1:
                if previous_merge_chunk is not None:
                    free_delta_chunks.append([previous_merge_chunk[0], previous_merge_chunk[1], -1, 0, 0])
                if next_merge_chunk is not None:
                    free_delta_chunks.append([next_merge_chunk[0], next_merge_chunk[1], -1, 0, 0])

                free_delta_chunks.append([merged_chunk[0], merged_chunk[1], 1, 0, 0])
                allocated_delta_chunks.append([self.cur_op.free_chunk_size + 2*SIZE_SZ, self.cur_op.free_chunk_addr, -1, self.cur_op.malloc_target, self.cur_op.op_index])

            ## case 4 if has merge and decreases two holes in the target chain
            elif op_abi == -2:
                if self.target_hole_size == previous_merge_chunk[0] and self.target_hole_size == next_merge_chunk[0]:
                    free_delta_chunks.append([self.target_hole_size, previous_merge_chunk[1], -1, 0, 0 ])
                    free_delta_chunks.append([self.target_hole_size, next_merge_chunk[1], -1, 0, 0])
                    free_delta_chunks.append([merged_chunk[0], merged_chunk[1], 1, 0, 0])
                    allocated_delta_chunks.append([self.cur_op.free_chunk_size + 2*SIZE_SZ, self.cur_op.free_chunk_addr, -1, self.cur_op.malloc_target, self.cur_op.op_index])


            ## case 5 other unrelated effects on target chain
            elif op_abi == 0:
                if merged_chunk == None:
                    free_delta_chunks.append([self.cur_op.free_chunk_size + 2*SIZE_SZ, self.cur_op.free_chunk_addr, 1, 0, 0])
                else:
                    if previous_merge_chunk != None:
                        free_delta_chunks.append([previous_merge_chunk[0], previous_merge_chunk[1], -1, 0, 0])
                    if next_merge_chunk != None:
                        free_delta_chunks.append([next_merge_chunk[0], next_merge_chunk[1], -1, 0, 0])
                    free_delta_chunks.append([merged_chunk[0], merged_chunk[1], 1, 0, 0 ])

                allocated_delta_chunks.append([self.cur_op.free_chunk_size + 2*SIZE_SZ, self.cur_op.free_chunk_addr, -1, self.cur_op.malloc_target, self.cur_op.op_index])

            effects['A'] = allocated_delta_chunks
            effects['F'] = free_delta_chunks

            return effects

#################### For malloc only ###########################

    def get_split_item(self, m_size):
        '''
        get heap split chunk size,
        :param m_size:
        :return: heap to split chunk size, return None if no split
        '''
        t_size = 999999
        t_addr = None
        cur_each_size = 999999
        if len(self.get_free_chunks_by_size(m_size)) > 0:
            return None

        can_ms_chunks = self.heap_layout.get_can_ms_free_chunks()

        for each_size in can_ms_chunks:
            ## select the best fit chunk for split
            if each_size > m_size:
                if each_size < cur_each_size:
                    cur_each_size = each_size

        ## split and has last remainder chunk
        if cur_each_size < 999999 and cur_each_size - m_size >= MIN_CHUNK_SIZE:
            t_size = cur_each_size
            fl = can_ms_chunks[cur_each_size]
            if fl.is_FILO:
                t_addr = fl.chunks[-1]
            elif not fl.is_FILO:
                t_addr = fl.chunks[0]
            self.last_remainder_bin = [t_size - m_size, t_addr + m_size]
        ## split and no last remainder chunk
        elif cur_each_size < 999999 and cur_each_size - m_size < MIN_CHUNK_SIZE:
            t_size = cur_each_size
            fl = can_ms_chunks[cur_each_size]
            if fl.is_FILO:
                t_addr = fl.chunks[-1]
            elif not fl.is_FILO:
                t_addr = fl.chunks[0]
            # t_addr = can_ms_chunks[each_size][-1]
            self.last_remainder_bin = None
        ## no suitable chunk for split, then malloc from top chunk
        if cur_each_size == 999999 or t_addr is None:
            t_size = m_size
            t_addr = self.heap_layout.top_chunk

        return [t_size, t_addr]

    def calculate_malloc_effects(self, op_abi, m_size):
        '''
        calculate new affect matrix for malloc(m_size)
        :param op_abi: operation ability
        :param m_size: malloc chunk size
        :return: self.new_affect_matrix
        '''
        chunks_affect = {}
        delta_free_chunks = []
        delta_allocated_chunks = []
        top_chunks = []

        malloced_chunk = None

        ## find the to malloc chunk
        for priority in range(0, len(self.free_lists[m_size])):
            fl = self.free_lists[m_size][priority]
            if fl.get_num_freed_chunks() == 0:
                continue
            if fl.is_FILO:
                malloced_chunk = fl.chunks[-1]
            else:
                malloced_chunk = fl.chunks[0]
            break

        split_item = self.get_split_item(m_size)
        ## case 1: if occupy one hole from target chain
        if op_abi == -1 and split_item is None:
            delta_free_chunks.append([m_size, malloced_chunk, -1, 0, 0])
            delta_allocated_chunks.append([m_size, malloced_chunk, 1, self.cur_op.malloc_target, self.cur_op.op_index])

        ## case 2: if split one hole from target chain
        elif op_abi == -1 and split_item[0] == self.target_hole_size:
            if self.last_remainder_bin is not None:
                delta_free_chunks.append([self.last_remainder_bin[0], self.last_remainder_bin[1], 1, 0, 0])
            delta_free_chunks.append([split_item[0], split_item[1], -1, 0, 0])
            delta_allocated_chunks.append([m_size, split_item[1], 1, self.cur_op.malloc_target, self.cur_op.op_index])
        ## case 3 if split one hole and add one hole of target chain
        elif op_abi == 1 and self.last_remainder_bin[0] == self.target_hole_size:
            delta_free_chunks.append([split_item[0], split_item[1], -1, 0, 0])
            delta_free_chunks.append([self.last_remainder_bin[0], self.last_remainder_bin[1], 1, 0, 0])
            delta_allocated_chunks.append([m_size, split_item[1], 1, self.cur_op.malloc_target, self.cur_op.op_index])
        # case 4 other unrelated effects on target chain
        elif op_abi == 0:
            if split_item is None:
                delta_free_chunks.append([m_size, malloced_chunk, -1, 0, 0])
                delta_allocated_chunks.append([m_size, malloced_chunk, 1, self.cur_op.malloc_target, self.cur_op.op_index])

            elif split_item is not None and split_item[1] != self.heap_layout.top_chunk and self.last_remainder_bin is not None:
                delta_free_chunks.append([split_item[0], split_item[1], -1, 0, 0])
                delta_free_chunks.append([self.last_remainder_bin[0], self.last_remainder_bin[1], 1, 0, 0])
                delta_allocated_chunks.append([m_size, split_item[1], 1, self.cur_op.malloc_target, self.cur_op.op_index])

            elif split_item is not None and split_item[1] != self.heap_layout.top_chunk and self.last_remainder_bin is None:
                delta_free_chunks.append([split_item[0], split_item[1], -1, 0, 0])
                delta_allocated_chunks.append([split_item[0], split_item[1], 1, self.cur_op.malloc_target, self.cur_op.op_index])

            elif split_item is not None and split_item[1] == self.heap_layout.top_chunk:
                delta_allocated_chunks.append([m_size, split_item[1], 1, self.cur_op.malloc_target, self.cur_op.op_index])
                top_chunks.append([m_size, self.heap_layout.top_chunk, -1, 0, 0])

        if len(delta_free_chunks) > 0 or len(delta_allocated_chunks) > 0:
            chunks_affect['F'] = delta_free_chunks
            chunks_affect['T'] = top_chunks
            chunks_affect['A'] = delta_allocated_chunks

        return chunks_affect

################# For both malloc and free ####################################

    def collect_unsat_solvers(self, op_abi):
        '''
        call this when the op_abi is not satisfied with heap layout
        collect unsat solvers from heap layout to generate new equations to correct the satisfaction
        :param op_abi: operation ability
        :return: new_ability, new_chunk
        '''

        if self.cur_op.op_type == 'F':

            previous_merge_chunk, next_merge_chunk = self.__to_merge_chunk()

            need_fix = False
            ## if free op is not equal to target hole, and not merge the tagrget, hole ,return
            if self.cur_op.free_chunk_size != self.target_hole_size:
                if previous_merge_chunk is not None and previous_merge_chunk[0] == self.target_hole_size:
                    need_fix = True
                if next_merge_chunk is not None and next_merge_chunk[0] == self.target_hole_size:
                    need_fix = True
                if not need_fix:
                    return None

            ## if merge target hole, could not fix the heap layout, choose another ptr.
            if previous_merge_chunk is not None and previous_merge_chunk[0] == self.target_hole_size:
                return None
            if next_merge_chunk is not None and next_merge_chunk[0] == self.target_hole_size:
                return None

            ## Now we can fix this situation: the free target hole merge other hole, we fix it.
            ## may contain 2 items
            ability_list = []

            previous_merge_chunk, next_merge_chunk = self.__to_merge_chunk()

            if previous_merge_chunk is not None:
                prev_chunk_position = self.__find_target_chunk_position_in_ms_free_list(previous_merge_chunk)
                ability_list.append([0 - prev_chunk_position, previous_merge_chunk[0]])

            if next_merge_chunk is not None:
                next_chunk_position = self.__find_target_chunk_position_in_ms_free_list(next_merge_chunk)
                ability_list.append([0 - next_chunk_position, next_merge_chunk[0]])

            return ability_list


        if self.cur_op.op_type == 'M':


            ## leverage the merge to make the targer hole + 1
            if op_abi == 1:

                chunk_size_list = []
                best_fix_chunk = best_chunk_size = 99999

                for size in self.free_lists:
                    if len(self.get_free_chunks_by_size(size)) > 0:
                        chunk_size_list.append(size)

                for each_size in self.can_ms_free_lists:
                    ## correct method 1: correct split
                    fl = self.can_ms_free_lists[size]
                    if each_size + 2*SIZE_SZ != self.target_hole_size:
                        m_size = each_size + 2*SIZE_SZ - self.target_hole_size
                        if m_size != self.target_hole_size and m_size in chunk_size_list:
                            chunk_len = len(fl.chunks[0])
                            if chunk_len < best_chunk_size:
                                best_fix_chunk = m_size
                                best_chunk_size = chunk_len

                new_ability = 0 - best_chunk_size
                if best_fix_chunk == 99999:
                    return None
                return [[new_ability, best_fix_chunk]]

            elif op_abi == -1:
                # print "the target malloc chunk chain is empty, need not malloc"
                return None

            elif op_abi == 0:
                if self.cur_op.malloc_size > 0:
                    new_ability = 1
                    new_chunk = self.cur_op.malloc_size + 2*SIZE_SZ
                    return [[new_ability, new_chunk]]
            return None

    def if_op_ability_satisfied(self, op_abi):
        '''
        to judge if op_abi could be satisfied by cur heap operation and self.cur_op.malloc_size
        if could be satisfied, calculate the affect matrix of the cur op
        :param op_abi: operation ability
        :return: if_sat, affect matrix
        '''
        is_satisfied = False

        if self.cur_op.op_type == 'M':

            #### malloc size is fixed
            if self.malloc_chunk_size > 0 :

                split_item = self.get_split_item(self.malloc_chunk_size)

                if split_item is not None and split_item[1] != self.heap_layout.top_chunk:
                    last_remainder = split_item[0] - self.malloc_chunk_size
                else:
                    last_remainder = None

                if op_abi == -1:
                    ## Lx > 0 and x = y
                    if split_item is None and self.malloc_chunk_size == self.target_hole_size:
                        if len(self.get_free_chunks_by_size(self.malloc_chunk_size)) > 0:
                            is_satisfied = True

                    ## LX =0  and split_item = y
                    elif split_item is not None and split_item[0] == self.target_hole_size:
                        is_satisfied = True

                elif op_abi == 1 and last_remainder == self.target_hole_size:
                    ## LX = 0 and last_remainder = y
                    is_satisfied = True

                elif op_abi == 0:
                    if split_item is None and self.malloc_chunk_size != self.target_hole_size:
                        is_satisfied = True

                    elif split_item is not None and last_remainder != self.target_hole_size and split_item[0] != self.target_hole_size:
                        is_satisfied = True

        elif self.cur_op.op_type == 'F':

            previous_merge_chunk, next_merge_chunk = self.__to_merge_chunk()
            merged_chunk = self.get_merged_new_chunk(previous_merge_chunk, next_merge_chunk)
            if op_abi == 1:
                ## free_chunk_size == target size and not merge
                if merged_chunk == None and self.cur_op.free_chunk_size + 2*SIZE_SZ == self.target_hole_size:
                    is_satisfied = True

                ## merged_chunk_size == target_size
                elif merged_chunk != None and merged_chunk[0] == self.target_hole_size:
                    is_satisfied = True

            elif op_abi == -1:
                ## previous_chunk = target_size or next_chunk = target_size
                if previous_merge_chunk[0] == self.target_hole_size or next_merge_chunk == self.target_hole_size:
                    is_satisfied = True

            elif op_abi == -2:
                ## previous_chunk = next_chunk = target_size
                if previous_merge_chunk[0] == next_merge_chunk[0] == self.target_hole_size:
                    is_satisfied = True

            elif op_abi == 0:
                is_satisfied = True
                if previous_merge_chunk != None and previous_merge_chunk[0] == self.target_hole_size:
                    is_satisfied = False
                if next_merge_chunk is not None and next_merge_chunk[0] == self.target_hole_size:
                    is_satisfied = False
                if previous_merge_chunk is None and next_merge_chunk is None and self.cur_op.free_chunk_size + 2*SIZE_SZ == self.target_hole_size:
                    is_satisfied = False

        return is_satisfied

    def get_split_effects(self):

        chunks_affect = {}
        delta_free_chunks = []
        delta_allocated_chunks = []
        top_chunks = []

        if self.cur_op.op_type == "F":

            for each_size in self.alloced_chunks:
                for each_allocated_chunk in self.alloced_chunks[each_size]:
                    each_addr = each_allocated_chunk.addr
                    primitive_name = each_allocated_chunk.primitive_name
                    op_index = each_allocated_chunk.op_index
                    if primitive_name == self.cur_op.free_target and op_index == self.cur_op.free_malloc_index:
                        self.cur_op.free_chunk_size = each_size
                        self.cur_op.free_chunk_addr = each_addr

                        previous_merge_chunk, next_merge_chunk = self.__to_merge_chunk()
                        merged_chunk = self.get_merged_new_chunk(previous_merge_chunk, next_merge_chunk)

                        if merged_chunk is None:
                            delta_free_chunks.append([self.cur_op.free_chunk_size, self.cur_op.free_chunk_addr, 1, 0, 0])
                            delta_allocated_chunks.append([self.cur_op.free_chunk_size, self.cur_op.free_chunk_addr, -1,
                                                           self.cur_op.malloc_target, self.cur_op.op_index])
                        else:
                            delta_free_chunks.append([merged_chunk[0], merged_chunk[1], 1, 0 ,0])
                            if next_merge_chunk is not None:
                                delta_free_chunks.append([next_merge_chunk[0], next_merge_chunk[1], -1, 0, 0])
                            if previous_merge_chunk is not None:
                                delta_free_chunks.append([previous_merge_chunk[0], previous_merge_chunk[1], -1, 0, 0])
                            delta_allocated_chunks.append([self.cur_op.free_chunk_size, self.cur_op.free_chunk_addr, -1,
                                                           self.cur_op.malloc_target, self.cur_op.op_index])


                        chunks_affect['F'] = delta_free_chunks
                        chunks_affect['T'] = top_chunks
                        chunks_affect['A'] = delta_allocated_chunks

                        return chunks_affect


        if self.cur_op.op_type == "M" and self.cur_op.malloc_size > 0:
            ## calculate split bin
            split_item = self.get_split_item(self.malloc_chunk_size)
            ## calculate last remainder bin
            if split_item is not None and split_item[1] != self.heap_layout.top_chunk:
                last_remainder = split_item[0] - self.malloc_chunk_size
            else:
                last_remainder = None

            op_abi = -1

            if split_item is not None:
                delta_free_chunks.append([split_item[0], split_item[1], -1, 0, 0])
                delta_allocated_chunks.append([self.malloc_chunk_size, split_item[1], 1, self.cur_op.malloc_target, self.cur_op.op_index])
            else:
                affect_matrixs = self.calculate_malloc_effects(op_abi, self.malloc_chunk_size)
                delta_free_chunks.append(affect_matrixs["F"][0])
                delta_allocated_chunks.append(affect_matrixs["A"][0])

            if last_remainder is not None:
                delta_free_chunks.append([self.last_remainder_bin[0], self.last_remainder_bin[1], 1, 0, 0])

            if len(delta_free_chunks) > 0 or len(delta_allocated_chunks) > 0:
                chunks_affect['F'] = delta_free_chunks
                chunks_affect['T'] = top_chunks
                chunks_affect['A'] = delta_allocated_chunks

            return chunks_affect

    def get_effects(self, op_abi):
        '''
        to judge if op_abi could be satisfied by cur heap operation and self.cur_op.malloc_size
        if could be satisfied, calculate the affect matrix of the cur op
        :param op_abi: operation ability
        :return: if_sat, affect matrix
        '''
        affect_matrixs =[]

        if self.cur_op.op_type == 'M':
            #### malloc size is fixed
            if self.malloc_chunk_size > 0 :

                split_item = self.get_split_item(self.malloc_chunk_size)

                if split_item is not None and split_item[1] != self.heap_layout.top_chunk:
                    last_remainder = split_item[0] - self.malloc_chunk_size
                else:
                    last_remainder = None

                if op_abi == -1:
                    ## Lx > 0 and x = y
                    if split_item is None and self.malloc_chunk_size == self.target_hole_size:
                        if len(self.get_free_chunks_by_size(self.malloc_chunk_size)) > 0:
                            affect_matrixs = self.calculate_malloc_effects(op_abi, self.malloc_chunk_size)
                    ## LX =0  and split_item = y
                    elif split_item is not None and split_item[0] == self.target_hole_size:
                        affect_matrixs = self.calculate_malloc_effects(op_abi, self.malloc_chunk_size)

                ## LX = 0 and last_remainder = y
                elif op_abi == 1 and last_remainder == self.target_hole_size:
                    affect_matrixs = self.calculate_malloc_effects(op_abi, self.malloc_chunk_size)

                elif op_abi == 0:
                    if split_item is None and self.malloc_chunk_size != self.target_hole_size:
                        affect_matrixs = self.calculate_malloc_effects(op_abi, self.malloc_chunk_size)

                    elif split_item is not None and last_remainder != self.target_hole_size and split_item[0] != self.target_hole_size:
                        affect_matrixs = self.calculate_malloc_effects(op_abi, self.malloc_chunk_size)





        elif self.cur_op.op_type == 'F':

            previous_merge_chunk, next_merge_chunk = self.__to_merge_chunk()
            merged_chunk = self.get_merged_new_chunk(previous_merge_chunk, next_merge_chunk)

            if op_abi == 1:
                ## free_chunk_size == target size and not merge
                if merged_chunk == None and self.cur_op.free_chunk_size  + 2*SIZE_SZ == self.target_hole_size:
                    ## add abi affect matrix
                    affect_matrixs = self.calculate_free_effects(op_abi, previous_merge_chunk, next_merge_chunk,
                                                                 merged_chunk)

                ## merged_chunk_size == target_size
                elif merged_chunk != None and merged_chunk[0] == self.target_hole_size:
                    affect_matrixs = self.calculate_free_effects(op_abi, previous_merge_chunk, next_merge_chunk,
                                                                 merged_chunk)

            elif op_abi == -1:
                ## previous_chunk = target_size or next_chunk = target_size
                if previous_merge_chunk[0] == self.target_hole_size or next_merge_chunk == self.target_hole_size:
                    affect_matrixs = self.calculate_free_effects(op_abi, previous_merge_chunk, next_merge_chunk,
                                                                 merged_chunk)

            elif op_abi == -2:
                ## previous_chunk = next_chunk = target_size
                if previous_merge_chunk[0] == next_merge_chunk[0] == self.target_hole_size:
                    affect_matrixs = self.calculate_free_effects(op_abi, previous_merge_chunk, next_merge_chunk,
                                                                 merged_chunk)

            elif op_abi == 0:
                is_sat = True
                if previous_merge_chunk != None and previous_merge_chunk[0] == self.target_hole_size:
                    is_sat = False
                if next_merge_chunk is not None and next_merge_chunk[0] == self.target_hole_size:
                    is_sat = False
                if previous_merge_chunk is None and next_merge_chunk is None and self.cur_op.free_chunk_size + 2*SIZE_SZ == self.target_hole_size:
                    is_sat = False
                if is_sat:
                    affect_matrixs = self.calculate_free_effects(op_abi, previous_merge_chunk, next_merge_chunk,
                                                                 merged_chunk)

        return affect_matrixs

############################# sovler mode ##########################################################################


    def __all_malloc_size(self):
        bit = 64
        all_malloc_size = []
        if bit == 64:
            for size in range(32,2000,16):
                all_malloc_size.append(size)
        return all_malloc_size

    def __add_side_affect(self,size,affect_matrix):
        delta = 0
        for affect in affect_matrix:
            if affect[0] == size:
                delta = affect[1]
        return delta

    def __analyze_op_constraint_by_ability(self,op_abi):

        solvers = []
        affect_matrixs = []

        #### malloc_size is not fixed
        if self.cur_op.malloc_size == -1:

            malloc_size = Int("malloc_size")
            target_size = self.target_hole_size
            malloc_chain_len = Int("L_" + str(malloc_size))

            solvers = []
            if op_abi == -1:

                ## case 1: Lx > 0 and x = y
                self.calculate_malloc_effects(op_abi,self.cur_op.malloc_size)

                ## add constraint
                solver = Solver()
                solver.add(malloc_size == target_size)
                solver.add(malloc_chain_len > 0)

                solvers.append(solver)
                affect_matrixs.append(copy.deepcopy(self.new_affect_matrix))

                ## case 2 : LX =0  and split_item = y

                ## add constraint
                find_sat = False
                lower = upper = symbol =0
                for index, chain in enumerate(self.free_lists):
                    if chain[0]  == target_size and index > 0:
                        find_sat = True
                        upper = chain[0]
                        lower = self.free_lists[index-1][0]
                        symbol = chain[2]
                        break
                    elif chain[0]  == target_size and index == 0:
                        find_sat = True
                        upper = chain[0]
                        lower = 0
                        symbol = chain[2]
                        break

                if not find_sat:
                    return False

                all_malloc_size = self.__all_malloc_size()
                for m_size in all_malloc_size:
                    if m_size > lower and m_size < upper:

                        new_solver = Solver()
                        new_solver.add(symbol > 0)
                        new_solver.add(malloc_chain_len == 0)
                        new_solver.add(malloc_size == m_size)

                        self.calculate_malloc_effects(op_abi,m_size)

                        solvers.append(new_solver)
                        affect_matrixs.append(copy.deepcopy(self.new_affect_matrix))

            elif op_abi == 1:

                ##  case 3: LX = 0 and last_remainder = y
                ## add constraint

                for index,_chain in enumerate(self.free_lists):
                    m_size = _chain[0] - target_size
                    all_malloc_size = self.__all_malloc_size()
                    if m_size not in all_malloc_size:
                        continue
                    if index > 0 and m_size > self.free_lists[index -1][0]:
                        new_solver = Solver()
                        new_solver.add(malloc_chain_len == 0)
                        new_solver.add(malloc_size == m_size)
                        new_solver.add(_chain[2] > 0)

                        self.calculate_malloc_effects(op_abi, m_size)
                        solvers.append(new_solver)
                        affect_matrixs.append(copy.deepcopy(self.new_affect_matrix))
                    elif index == 0:
                        new_solver = Solver()
                        new_solver.add(malloc_chain_len == 0)
                        new_solver.add(malloc_size == m_size)
                        new_solver.add(_chain[2] > 0)

                        self.calculate_malloc_effects(op_abi,m_size)
                        solvers.append(new_solver)
                        affect_matrixs.append(copy.deepcopy(self.new_affect_matrix))



            elif op_abi == 0:
                pass

            else:
                pass

        #### malloc size is fixed
        elif self.cur_op.malloc_size > 0 :

            malloc_size = self.cur_op.malloc_size
            target_size = self.target_hole_size
            malloc_chain_len = Int("L_"+str(malloc_size))
            split_item = self.get_split_item(malloc_size)

            if split_item is not None:
                last_remainder = split_item[0] - malloc_size
            else:
                last_remainder = None

            if op_abi == -1:

                ## Lx > 0 and x = y
                if split_item is None:
                    ## abi_matrix
                    self.calculate_malloc_effects(op_abi,malloc_size)

                    ## add constraint

                    if malloc_size == target_size:
                        solver = Solver()
                        solver.add(malloc_chain_len > 0)
                        solvers.append(solver)
                        affect_matrixs.append(copy.deepcopy(self.new_affect_matrix))



                ## LX =0  and split_item = y
                elif split_item[0] == target_size:
                    ## abi_matrix
                    self.calculate_malloc_effects(op_abi, malloc_size)

                    ## add constraint
                    solver = Solver()
                    find_sat = False
                    for index, chain in enumerate(self.free_lists):
                        if chain[0] == target_size and index > 0:
                            if target_size > malloc_size > self.free_lists[index - 1][0]:
                                find_sat = True
                                solver.add(malloc_chain_len == 0)
                                solver.add(chain[2] > 0)
                                break
                        elif chain[0] == target_size and index == 0:
                            find_sat = True
                            solver.add(chain[2] > 0)

                    if find_sat:
                        solvers.append(solver)
                        affect_matrixs.append(copy.deepcopy(self.new_affect_matrix))


            elif op_abi == 1:
                ## LX = 0 and last_remainder = y
                self.calculate_malloc_effects(op_abi, malloc_size)

                ## add constraint
                solver = Solver()
                find_sat = False
                for index, chain in enumerate(self.free_lists):
                    if chain[0] == target_size + malloc_size and index > 0:
                        if malloc_size > self.free_lists[index - 1][0]:
                            find_sat = True
                            solver.add(malloc_chain_len == 0)
                            solver.add(chain[2] > 0)
                            break
                    elif chain[0] == target_size + malloc_size and index == 0:
                        find_sat = True
                        solver.add(chain[2] > 0)

                if find_sat:
                    solvers.append(solver)
                    affect_matrixs.append(copy.deepcopy(self.new_affect_matrix))




        return solvers, affect_matrixs

    def get_op_constraint_by_ability(self,op_abi):
        solvers, affects = self.__analyze_op_constraint_by_ability(op_abi)
        return solvers,affects

    def add_op_constraint_by_ability(self,op_abi,affect_matrix):
        '''
        add op_constraint and affect matrix by ability, call this func after get_op_constraint_by_ability
        :param op_abi:
        :param affect_matrix:
        :return: list solvers, list affect_matrixs
        '''
        solvers = []
        affect_matrixs = []

        ## malloc_size is fixed
        if self.cur_op.malloc_size != -1:

            malloc_size = self.cur_op.malloc_size
            target_size = self.target_hole_size
            malloc_chain_len = Int("L_" + str(malloc_size))
            split_item = self.get_split_item(malloc_size)
            last_remainder = None
            if split_item is not None:
                last_remainder = split_item - malloc_size

            if op_abi == -1:
                ## case 1: Lx > 0 and x = y
                if split_item is None:

                    self.calculate_malloc_effects(op_abi, malloc_size)
                    if malloc_size == target_size:
                        solver = Solver()
                        solver.add(malloc_chain_len + self.__add_side_affect(malloc_size, affect_matrix) > 0)
                        solvers.append(solver)
                        affect_matrixs.append(copy.deepcopy(self.new_affect_matrix))

                ## case 2: LX =0  and split_item = y
                elif split_item == self.target_hole_size:

                    self.calculate_malloc_effects(op_abi, malloc_size)
                    ## add constraint
                    solver = Solver()
                    find_sat = False
                    for index, chain in enumerate(self.free_lists):
                        if chain[0] == target_size and index > 0:
                            if target_size > malloc_size > self.free_lists[index - 1][0]:
                                find_sat = True
                                solver.add(chain[2] + self.__add_side_affect(chain[0], affect_matrix) > 0)
                                solver.add(malloc_chain_len + self.__add_side_affect(malloc_size, affect_matrix) == 0)
                            break
                        elif chain[0] == target_size and index == 0:
                            find_sat = True
                            solver.add(chain[2] +self.__add_side_affect(chain[0],affect_matrix)> 0)

                    if find_sat:
                        solvers.append(solver)
                        affect_matrixs.append(copy.deepcopy(self.new_affect_matrix))


            elif op_abi == 1:
                # case 3: LX = 0 and last_remainder = y
                self.calculate_malloc_effects(op_abi, malloc_size)

                # add constraint
                for index, chain in enumerate(self.free_lists):
                    if chain[0] == target_size + malloc_size and index > 0:
                        if malloc_size > self.free_lists[index - 1][0]:
                            solver = Solver()
                            solver.add(malloc_chain_len + self.__add_side_affect(malloc_size, affect_matrix) == 0)
                            solver.add(chain[2] + self.__add_side_affect(chain[0], affect_matrix) > 0)
                            solvers.append(solver)
                            affect_matrixs.append(copy.deepcopy(self.new_affect_matrix))
                            break


        ## malloc_size if not fixed
        elif self.cur_op.malloc_size == -1:
            pass

        return solvers, affect_matrixs


def test_single_malloc():

    # free_chain_0 = {200:[0x11111,0x22222]}
    # free_chain_1 = {600:[0x33333]}
    # free_chain_2 = {1000:[0x44444]}

    free_chain_0 = {200:[10000,20000]}
    free_chain_1 = {400:[30000,50000]}
    free_chain_2 = {600:[40000]}
    cur_heap_layout = []
    cur_heap_layout.append(free_chain_0)
    cur_heap_layout.append(free_chain_1)
    cur_heap_layout.append(free_chain_2)

    analyzed_heap_layout = analyze_heap_layout(cur_heap_layout)

    malloc_size_options = [100,200,300,400,500,600]
    alloced_chunks = [{60000, 200}, {62000, 400}]
    for each_malloc_size in malloc_size_options:

        cur_operation = Operation()
        cur_operation.op_type = 'M'
        cur_operation.malloc_size = each_malloc_size

        abi_matrix = []

        malloc_abi = OperationAbility(analyzed_heap_layout, alloced_chunks, cur_operation, abi_matrix, target_hole_size=400)
        is_sat = malloc_abi.if_op_ability_satisfied(-1)
        if is_sat:
            sat_affect_matrix = malloc_abi.get_satisfied_affect_matrix_by_ability(-1)
            print each_malloc_size, sat_affect_matrix

    # analyzed_heap_layout = malloc_abi.generate_new_heap_layout()
    #
    # print ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
    #
    # cur_operation = Operation()
    # cur_operation.op_type = 'M'
    # cur_operation.malloc_size = 400
    #
    # malloc_abi = Malloc_Ability(analyzed_heap_layout,cur_operation,abi_matrix)
    # solver = malloc_abi.add_op_constraint_by_ability(1,abi_matrix,solver)
    # abi_matrix = malloc_abi.new_affect_matrix
    #
    # print ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
    #
    #
    # cur_operation = Operation()
    # cur_operation.op_type = 'M'
    # cur_operation.malloc_size = 400
    #
    # malloc_abi = Malloc_Ability(analyzed_heap_layout,cur_operation,abi_matrix)
    # solver = malloc_abi.add_op_constraint_by_ability(1,abi_matrix,solver)
    #
    #
    # if solver.check() == sat:
    #     print solver.model()


    # malloc_abi.get_op_constraint_by_ability(1)


def main():
    test_single_malloc()

if __name__ == '__main__':
    main()


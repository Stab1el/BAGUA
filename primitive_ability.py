##coding=utf-8
from utils import *
from allocator_config import *
from run_config import *

class PrimitiveAbility:

    def __init__(self, Prim, target_hole_size, extended_capability_mode = False):

        self.primitive = Prim
        self.target_hole_size = target_hole_size
        self.prim_ability = []
        self.all_primitive = get_all_primitives_from_files(P_FILE_PATH)
        self.heap_layout = get_heap_layout_from_file(INIT_LAYOUT_PATH)
        self.extended_capability_mode = extended_capability_mode


    def get_all_abi_list_for_one_primitive(self, each_primitive, target_chunk_size, extended_capability_mode = False):
        '''
        to find all capabilities of one primitive
        '''

        all_operation_abi_lists = []
        final_all_ability_list = []
        possible_abilities_list = []

        if not extended_capability_mode:
            ## calculate the basic capability fro each heap operation
            for each_op in each_primitive.operation_list:
                if each_op.op_type == 'M':
                    if each_op.malloc_size > 0:
                        if each_op.malloc_size + 2*SIZE_SZ != target_chunk_size:
                            all_operation_abi_lists.append([0])
                        elif each_op.malloc_size + 2*SIZE_SZ == target_chunk_size:
                            all_operation_abi_lists.append([-1])
                    elif each_op.malloc_size < 0:
                        all_operation_abi_lists.append([-1, 0])

                elif each_op.op_type == 'F':
                    p_name = each_op.free_target
                    target_prim = self.all_primitive[p_name]
                    target_op = target_prim.operation_list[each_op.free_malloc_index]
                    if target_op.malloc_size > 0 and target_op.malloc_size + 2*SIZE_SZ == target_chunk_size:
                        all_operation_abi_lists.append([1])
                    elif target_op.malloc_size > 0 and target_op.malloc_size + 2*SIZE_SZ != target_chunk_size:
                        all_operation_abi_lists.append([0])
                    elif target_op.malloc_size < 0:
                        all_operation_abi_lists.append([1, 0])
            ## calculate the basic capability for the primtive
            if len(all_operation_abi_lists) > 1:
                all_ability_list = all_operation_abi_lists[0]

                for index in range(0, len(all_operation_abi_lists)-1):
                    all_ability_list = calculate_two_lists(all_ability_list,all_operation_abi_lists[index+1])

                for one_ability_chain in all_ability_list:
                    ability_chain = one_ability_chain.split(',')
                    ability_list = []
                    for _ in ability_chain:
                        ability_list.append(int(_))
                    final_all_ability_list.append(ability_list)

                for each_abi_list in final_all_ability_list:
                    sum_abi = 0
                    for each_abi in each_abi_list:
                        sum_abi += each_abi

                    if sum_abi not in possible_abilities_list:
                        possible_abilities_list.append(sum_abi)
                return possible_abilities_list

            elif len(all_operation_abi_lists) == 1:
                return all_operation_abi_lists[0]


        elif extended_capability_mode:
            ## calculate the extented capability for each heap operation
            for each_op in each_primitive.operation_list:
                if each_op.op_type == 'M':
                    if each_op.malloc_size > 0:
                        if each_op.malloc_size + 2*SIZE_SZ != target_chunk_size:
                            all_operation_abi_lists.append([0, 1, -1])
                        elif each_op.malloc_size + 2*SIZE_SZ == target_chunk_size:
                            all_operation_abi_lists.append([-1])
                    elif each_op.malloc_size < 0:
                        all_operation_abi_lists.append([-1, 0, 1])

                elif each_op.op_type == 'F':
                    p_name = each_op.free_target
                    target_prim = self.all_primitive[p_name]
                    target_op = target_prim.operation_list[each_op.free_malloc_index]
                    if target_op.malloc_size > 0 and target_op.malloc_size + 2*SIZE_SZ == target_chunk_size:
                        all_operation_abi_lists.append([1, -1, 0])
                    elif target_op.malloc_size > 0 and target_op.malloc_size + 2*SIZE_SZ != target_chunk_size:
                        all_operation_abi_lists.append([1, -1, 0])
                    elif target_op.malloc_size < 0:
                        all_operation_abi_lists.append([1, -1, 0])
            ## calculte the extended capability for the primitive
            if len(all_operation_abi_lists) > 1:
                all_ability_list = all_operation_abi_lists[0]

                for index in range(0, len(all_operation_abi_lists)-1):
                    all_ability_list = calculate_two_lists(all_ability_list,all_operation_abi_lists[index+1])

                for one_ability_chain in all_ability_list:
                    ability_chain = one_ability_chain.split(',')
                    ability_list = []
                    for _ in ability_chain:
                        ability_list.append(int(_))
                    final_all_ability_list.append(ability_list)

                for each_abi_list in final_all_ability_list:
                    sum_abi = 0
                    for each_abi in each_abi_list:
                        sum_abi += each_abi

                    if sum_abi not in possible_abilities_list:
                        possible_abilities_list.append(sum_abi)
                return possible_abilities_list

            elif len(all_operation_abi_lists) == 1:
                return all_operation_abi_lists[0]






    def find_one_primitive_ability_list(self):

        operation_ability_lists = []
        final_all_ability_list = []

        if not self.extended_capability_mode:

            for each_op in self.primitive.operation_list:
                if each_op.op_type == 'M':
                    if each_op.malloc_size > 0:
                        if each_op.malloc_size + 2*SIZE_SZ != self.target_hole_size:
                            operation_ability_lists.append([0])
                        elif each_op.malloc_size + 2*SIZE_SZ == self.target_hole_size:
                            operation_ability_lists.append([-1])
                    elif each_op.malloc_size < 0:
                        operation_ability_lists.append([-1, 0])

                elif each_op.op_type == 'F':
                    p_name = each_op.free_target
                    target_prim = self.all_primitive[p_name]
                    target_op = target_prim.operation_list[each_op.free_malloc_index]
                    if target_op.malloc_size > 0 and target_op.malloc_size + 2*SIZE_SZ== self.target_hole_size:
                        if self.find_chunk_in_heap_layout_by_op(each_op, self.heap_layout, self.all_primitive):
                            operation_ability_lists.append([1])
                        else:
                            print "can not find chunk for free, quit this equation"
                            return None
                    elif target_op.malloc_size > 0 and target_op.malloc_size + 2*SIZE_SZ!= self.target_hole_size:
                        if self.find_chunk_in_heap_layout_by_op(each_op, self.heap_layout, self.all_primitive):
                            operation_ability_lists.append([0])
                        else:
                            print "can not find chunk for free, quit this equation"
                            return None
                    elif target_op.malloc_size < 0:
                        if self.find_chunk_in_heap_layout_by_op(each_op, self.heap_layout, self.all_primitive):
                            operation_ability_lists.append([1, 0])
                        else:
                            print "can not find chunk for free, quit this equation"
                            return None

            if len(operation_ability_lists) > 1:
                all_ability_list = operation_ability_lists[0]

                for index in range(0, len(operation_ability_lists)-1):
                    all_ability_list = calculate_two_lists(all_ability_list,operation_ability_lists[index+1])

                for one_ability_chain in all_ability_list:
                    ability_chain = one_ability_chain.split(',')
                    ability_list = []
                    for _ in ability_chain:
                        ability_list.append(int(_))
                    final_all_ability_list.append(ability_list)

            elif len(operation_ability_lists) == 1:
                all_ability_list = operation_ability_lists[0]
                ability_list = []
                for _ in all_ability_list:
                    ability_list.append(int(_))
                final_all_ability_list.append(ability_list)

        elif self.extended_capability_mode:

            for each_op in self.primitive.operation_list:
                if each_op.op_type == 'M':
                    if each_op.malloc_size > 0:
                        if each_op.malloc_size + 2 * SIZE_SZ != self.target_hole_size:
                            operation_ability_lists.append([0, -1, 1])
                        elif each_op.malloc_size + 2 * SIZE_SZ == self.target_hole_size:
                            operation_ability_lists.append([-1])
                    elif each_op.malloc_size < 0:
                        operation_ability_lists.append([-1, 0, 1])

                elif each_op.op_type == 'F':
                    operation_ability_lists.append([-1, 0, 1])

            if len(operation_ability_lists) > 1:
                all_ability_list = operation_ability_lists[0]

                for index in range(0, len(operation_ability_lists) - 1):
                    all_ability_list = calculate_two_lists(all_ability_list, operation_ability_lists[index + 1])

                for one_ability_chain in all_ability_list:
                    ability_chain = one_ability_chain.split(',')
                    ability_list = []
                    for _ in ability_chain:
                        ability_list.append(int(_))
                    final_all_ability_list.append(ability_list)

            elif len(operation_ability_lists) == 1:
                all_ability_list = operation_ability_lists[0]
                ability_list = []
                for _ in all_ability_list:
                    ability_list.append(int(_))
                final_all_ability_list.append(ability_list)

        return final_all_ability_list

    def generate_ability_list(self, target_distance):

        solvable_ability_lists = []
        all_ability_lists = self.find_one_primitive_ability_list()
        ## if the ability can not be satisfied by
        if all_ability_lists is None:
            return []

        for each_ability_list in all_ability_lists:
            sum_abi = calculate_sum_of_list(each_ability_list)
            if sum_abi == target_distance:
                new_ability_list = []
                for abi in each_ability_list:
                    new_ability_list.append([self.target_hole_size, abi])
                solvable_ability_lists.append(new_ability_list)

        return solvable_ability_lists

    def find_chunk_in_heap_layout_by_op(self, op, heap_layout, all_primitives):
        return True


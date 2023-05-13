import copy
import random
import datetime
from primitive_ability import PrimitiveAbility
from utils import *
from run_config import *
from z3 import *
from allocator_config import *


class ConstraintGenerator:
    '''
    generate Constraint of ILP to get the target heap layout.
    '''
    def __init__(self, all_primitives, target_distance, target_size, heap_layout):
        self.all_primitive = all_primitives
        self.target_distance = target_distance
        self.target_size = target_size
        self.need_add_constraint = False
        self.prim_abi_list = []
        self.prim_times_list  = []
        self.unsolved_time_lists = []
        self.heap_layout = heap_layout



    def solve_primitive_equation(self, target_list, active_mode = False):
        '''
        generate and solve the primitive equation according to target_list:
        :param target_list:[[target_size, target_abi], [target_size, target_abi]]
        :return: prim_abi_list, times_list
        '''

        prim_len = len(self.all_primitive)

        all_primitive_possible_abis = []
        for index, [t_chunk_size, abi] in enumerate(target_list):
            tmp_list = []
            for prim_name in self.all_primitive:
                prim_abi = PrimitiveAbility(self.all_primitive[prim_name], t_chunk_size, active_mode)
                possible_abis = prim_abi.get_all_abi_list_for_one_primitive(self.all_primitive[prim_name], t_chunk_size, active_mode)
                tmp_list.append(possible_abis)
            all_primitive_possible_abis.append(tmp_list)

        is_solved = False
        already_key_list = []
        run_count = 0
        while not is_solved:
            ## random choose one abi for each primitive
            select_abi_list = []
            for i in range(0, len(target_list)):
                select_abi_list.append([])
                for possible_abis in all_primitive_possible_abis[i]:
                    random.seed(datetime.datetime.now())
                    abi = random.choice(possible_abis)
                    select_abi_list[i].append(abi)
            ## add constraint to solver
            solver = Solver()
            index_key = 0
            createVar = locals()

            for tg in range(0, len(target_list)):

                symbol_list = []

                for i in range(0, prim_len):
                    createVar['time_'+str(i)] = Int("time_"+str(i))
                    solver.add(createVar['time_'+str(i)] >= 0)
                    solver.add(createVar['time_' + str(i)] < 10)
                    index_key += createVar['time_'+str(i)] * pow(10, i)
                    symbol_list.append(createVar['time_'+str(i)] * select_abi_list[tg][i])

                sum = calculate_sum_of_list(symbol_list)
                solver.add(sum == target_list[tg][1])

            ## if last equation not good, add last constraint and generate a new one
            if self.need_add_constraint:
                self.add_constraint_to_solver()
                for each_time_list in self.unsolved_time_lists:
                    sum_key = 0
                    for index, each_symbol_list in enumerate(each_time_list):
                        sum_key += each_symbol_list[1]*pow(10, index)
                    solver.add(index_key != sum_key)

            ## solve the equation
            if solver.check() == sat:
                is_solved = True
                res = solver.model()
                times_list = []
                for i in range(0, prim_len):
                    times_list.append(res[createVar['time_'+str(i)]].as_long())

                self.prim_abi_list = copy.deepcopy(select_abi_list)
                self.prim_times_list = copy.deepcopy(times_list)

                return select_abi_list, times_list
            ## if cannot solve the equation for 500 times, then quit
            else:
                run_count += 1
                if run_count > 500:
                    print "sorry, equation no more"
                    return None, None


    def add_constraint_to_solver(self):

        createVar = locals()
        add_symbol_list = []
        for i, each_time in enumerate(self.prim_times_list):
            createVar['time_' + str(i)] = Int("time_" + str(i))
            add_symbol_list.append([createVar['time_' + str(i)], each_time])

        self.unsolved_time_lists.append(add_symbol_list)



    def sort_primitive_order(self, primitive_operation_list, abi_list):
        '''
        generate primtive timeline
        adjust the primitive order , to change the unlinear dig hole primitive to linear
        '''

        if len(primitive_operation_list) == 0:
            return [], []

        sum_abi_list = []
        new_primitive_operation_list = []
        new_ability_list = []
        normalize_delta_abi_list = []
        for index, each_abi_list in enumerate(abi_list):
            sum_abi = 0
            delta_abi = self.calculate_normalization_delta_distance(each_abi_list)
            normalize_delta_abi_list.append([index, delta_abi])
            for each_op_abi in each_abi_list:
                sum_abi += each_op_abi[1]
            sum_abi_list.append([index, sum_abi])

        distance_to_hole = 0 - self.heap_layout.get_distance_to_target_hole(TARGET_CHUNK_ADDR, TARGET_HOLE_SIZE)

        free_lists = self.heap_layout.get_free_lists()
        select_round_time = 0
        continue_to_find = True
        random.seed(datetime.datetime.now())


        ## find for multiple round
        while continue_to_find:
            cp_sum_abi_list = copy.deepcopy(sum_abi_list)
            new_sumbai_list = []
            accumulated_abi = 0
            cp_normalize_delta_abi_list = copy.deepcopy(normalize_delta_abi_list)

            ## add all primitive abis to new abi list
            while len(cp_sum_abi_list) > 0:
                select_index = 0
                has_checked_index_list = []
                can_add = False
                ## add one primitive abi to new abi list
                while not can_add:
                    min_delta_abi = 99
                    for [index, delta_abi] in cp_normalize_delta_abi_list:
                        if delta_abi < min_delta_abi and index not in has_checked_index_list:
                            min_delta_abi = delta_abi
                            select_index  = index
                    for [index, sum_abi] in cp_sum_abi_list:
                        if index == select_index:
                            select_abi = sum_abi
                            break
                    prim_abi = abi_list[select_index]

                    can_add =  self.can_primitive_add(accumulated_abi, prim_abi, select_abi, free_lists, distance_to_hole)

                    if can_add:
                        accumulated_abi += select_abi
                        new_sumbai_list.append([select_index, select_abi])
                        cp_sum_abi_list.remove([select_index, select_abi])
                        cp_normalize_delta_abi_list.remove([select_index, min_delta_abi])
                        break
                    else:
                        has_checked_index_list.append(select_index)
                        if len(has_checked_index_list) > len(cp_normalize_delta_abi_list):
                            print "[!] can not generate equation, break"
                            return [], []


            if len(cp_sum_abi_list) == 0:
                continue_to_find = False

            select_round_time += 1

            if select_round_time > 200:
                print "[!] not linear, can not generate equation, please fuzz again"
                return [], []


        for [index, abi] in new_sumbai_list:
            new_primitive_operation_list.append(primitive_operation_list[index])
            new_ability_list.append(abi_list[index])

        # print new_ability_list

        return new_primitive_operation_list, new_ability_list

    def calculate_normalization_delta_distance(self, abi_list):
        prim_abi_list = []
        accumulate_abi_list = []

        for each_op_abi in abi_list:
            prim_abi_list.append(each_op_abi[1])

        for i in range(0, len(prim_abi_list)):
            accumulate_abi = 0
            for j in range(0, i + 1):
                accumulate_abi += prim_abi_list[j]
            accumulate_abi_list.append(accumulate_abi)

        sum_accumulate_abi = 0

        for accu_abi in accumulate_abi_list:
            sum_accumulate_abi += accu_abi

        normaliza_prim_abi = float(sum_accumulate_abi / len(accumulate_abi_list))

        if normaliza_prim_abi < 0:
            return 0 - normaliza_prim_abi

        return normaliza_prim_abi

    def can_primitive_add(self, accumulated_abi, abi_list, abi, free_lists, distance_to_hole):

        if abi > 0 and abi + accumulated_abi + len(free_lists[self.target_size][0].chunks) <= LENGTH_LIMIT:
            cp_accumulated_abi = accumulated_abi
            can_add = True
            for each_op_abi in abi_list:
                if each_op_abi[1] > 0:
                    if each_op_abi[1] + cp_accumulated_abi + len(free_lists[self.target_size][0].chunks) > LENGTH_LIMIT:
                        can_add = False
                        break
                elif each_op_abi[1] < 0:
                    if each_op_abi[1] + cp_accumulated_abi <= distance_to_hole:
                        can_add = False
                        break
                cp_accumulated_abi += each_op_abi[1]
            if can_add:
                return True

        elif abi < 0 and abi + accumulated_abi > distance_to_hole:
            cp_accumulated_abi = accumulated_abi
            can_add = True
            for each_op_abi in abi_list:
                if each_op_abi[1] > 0:
                    if each_op_abi[1] + cp_accumulated_abi + len(free_lists[self.target_size][0].chunks) > LENGTH_LIMIT:
                        can_add = False
                        break
                elif each_op_abi[1] < 0:
                    if each_op_abi[1] + cp_accumulated_abi <= distance_to_hole:
                        can_add = False
                        break
                cp_accumulated_abi += each_op_abi[1]
            if can_add:
                return True

        return False


    ## use for generating init equation
    def generate_input_for_path_generator(self, target_hole_size):

        primitive_operation_list = []
        abi_list = []
        ## get primitive ability and  activating times
        prim_abi_list, times_list = self.solve_primitive_equation([[self.target_size, self.target_distance]])

        print prim_abi_list, times_list

        if times_list is None:
            return None, None
        ## since we have primitive ability, then we generate each op ability according to primitive ability
        for index, each_time in enumerate(times_list):
            for _ in range(0, each_time):
                prim_abi = prim_abi_list[0][index]
                p_name = 'P'+str(index)
                select_prim = self.all_primitive[p_name]
                the_prim_abi = PrimitiveAbility(select_prim, self.target_size)
                abi_all = the_prim_abi.generate_ability_list(prim_abi)
                ## if find the equation can not satisfied with heap layout
                if len(abi_all) == 0:
                    return [], []
                abi = abi_all[0]
                primitive_operation_list.append(self.all_primitive[p_name].operation_list)
                abi_list.append(abi)

        new_primitive_operation_list, new_abi_list = self.sort_primitive_order(primitive_operation_list, abi_list)
        return new_primitive_operation_list, new_abi_list

    ## use for eliminate side affect mode and for active leveraging the side affect mode
    def generate_extra_equation_by_target_ability(self, fix_hole, fix_abi, extended_mode = False):
        '''
        generate fix equation to fix the side effect
        :param fix_hole: the hole need to fix
        :param fix_abi:  + 1 or - 1
        :return: new_operation_list and times list for fix
        '''

        ## get primitive abi
        primitive_operation_list = []
        abi_list = []
        target_list = [[fix_hole, fix_abi], [self.target_size, 0]]
        prim_abi_list, times_list = self.solve_primitive_equation(target_list, extended_mode)
        print prim_abi_list, times_list

        if times_list is None:
            return None, None

        ## get each op ability by primitimve abi
        for index, each_time in enumerate(times_list):
            for _ in range(0, each_time):
                prim_abi = prim_abi_list[0][index]
                p_name = 'P'+str(index)
                select_prim = self.all_primitive[p_name]
                the_prim_abi = PrimitiveAbility(select_prim, fix_hole, extended_mode)
                abi_all = the_prim_abi.generate_ability_list(prim_abi)
                ## if find the equation can not satisfied with heap layout
                if len(abi_all) == 0:
                    return [], []
                abi = abi_all[0]
                primitive_operation_list.append(self.all_primitive[p_name].operation_list)
                abi_list.append(abi)

        ## adjust primitive order
        if len(primitive_operation_list) == 0:
            return [], []

        new_primitive_operation_list, new_abi_list = self.sort_primitive_order(primitive_operation_list, abi_list)

        return new_primitive_operation_list, new_abi_list

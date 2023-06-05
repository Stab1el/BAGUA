import copy
from operation_ability import OperationAbility
from allocator_action_utils import ComplexActorUtil
from allocator_config import *
from run_config import *
from z3 import *
from collections import Counter, OrderedDict



WATCHING_HEAP = 0


class SplitOccupy():

    def __init__(self, init_layout, all_primitives, prims_count_dependency, target_primitive, target_op_index, target_hole_size, target_chunk_addr, already_solvers):
        self.cur_layout = init_layout
        self.all_primitives = all_primitives
        self.interesting_op_list = {}
        self.target_primitive = target_primitive
        self.target_op_index = target_op_index
        self.target_hole_size = target_hole_size
        self.target_hole_addr = target_chunk_addr
        self.already_unsat_solvers = []
        self.primitive_times_limit = {}
        self.__parse_primtive_dependency(prims_count_dependency)

        self.already_solvers = already_solvers
        for each_already_solver in self.already_solvers:
            self.primitive_times_limit[each_already_solver] -= 1


    def __parse_primtive_dependency(self, prims_count_dependency):

        self.primitive_times_limit = OrderedDict()

        for each_prim in prims_count_dependency.keys():
            self.primitive_times_limit[each_prim] = prims_count_dependency[each_prim]['Max']
        self.primitive_times_limit[TARGET_PRIM_NAME] = self.primitive_times_limit[TARGET_PRIM_NAME] - 1



    def if_split_target_chunk(self, chunk_size):

        free_lists = self.cur_layout.get_free_lists()

        if len(free_lists[chunk_size]) == 0:
            return True

        return False


    def select_op_list_for_split_in_primitives(self):

        ## tag the interesting malloc op
        for each_primitive_name in self.all_primitives:
            each_primitive = self.all_primitives[each_primitive_name]
            for each_op in each_primitive.operation_list:
                if each_op.op_type == "M":
                    if each_op.malloc_size == -1:
                        each_op.interesting_for_split = 1
                    elif self.if_split_target_chunk(each_op.malloc_size + 2 * SIZE_SZ):
                        each_op.interesting_for_split = 1

        ## tag the interesting free op
        for each_primitive_name in self.all_primitives:
            each_primitive = self.all_primitives[each_primitive_name]
            for each_op in each_primitive.operation_list:
                if each_op.op_type == "F":
                    free_op = self.all_primitives[each_op.free_target].operation_list[each_op.free_malloc_index]
                    if free_op.malloc_size == -1:
                        each_op.interesting_for_split = 1


    def generate_and_solve_equation(self):

        is_solved = False
        createVar = locals()
        sum_symbol = 0
        solver = Solver()
        times_list = {}
        sizes_list = {}
        added_symbol_list = {}


        ## create equation
        for i in range(0, len(self.all_primitives)):
            pname = "P"+str(i)
            count_list = Counter(self.already_solvers)
            pname_count = count_list[pname]
            pname_limit = self.primitive_times_limit[pname]
            if pname_limit <= 0:
                continue
            createVar['time_' + str(i)] = Int("time_" + str(i))
            solver.add(createVar['time_' + str(i)] >= 0)
            solver.add(createVar['time_' + str(i)] + pname_count <= pname_limit)
            added_symbol_list['time_' + str(i)] = createVar['time_' + str(i)]

            if pname == self.target_primitive.prim_name:
                operation_list = self.all_primitives[pname].operation_list[:self.target_op_index + 1]
            else:
                operation_list = self.all_primitives[pname].operation_list

            for each_op in operation_list:
                if each_op.op_type == "M" and each_op.malloc_size == -1 and each_op.interesting_for_split == 1:

                    createVar['n_' + str(i)] = Int("n_" + str(i))
                    createVar['size_' + str(i)] = Int("size_" + str(i))
                    added_symbol_list['size_' + str(i)] = createVar['size_' + str(i)]
                    added_symbol_list['n_' + str(i)] = createVar['n_' + str(i)]

                    solver.add(createVar['n_' + str(i)] >= 0)
                    solver.add(createVar['size_' + str(i)] == createVar['n_' + str(i)] * 16)
                    solver.add(createVar['size_' + str(i)] <= MAX_CHUNK_SIZE)

                    sum_symbol += (createVar['size_' + str(i)]) * createVar['time_' + str(i)]
                elif each_op.op_type == "M" and each_op.malloc_size> 1000:
                    sum_symbol += (each_op.malloc_size + 2* SIZE_SZ) * createVar['time_' + str(i)]
        solver.add(sum_symbol == self.target_hole_size)

        if len(self.already_unsat_solvers) > 0:
            for [symbol, value] in self.already_unsat_solvers:
                if symbol in added_symbol_list:
                    solver.add(added_symbol_list[symbol]!= value)

        ## solve the equation
        if solver.check() == sat:
            is_solved = True
            res = solver.model()
            for i in range(0, len(self.all_primitives)):

                if 'time_'+str(i) in added_symbol_list and res[createVar['time_' + str(i)]].as_long() > 0:
                    times_list["P" + str(i)] = res[createVar['time_' + str(i)]].as_long()
                    if 'size_'+str(i) in added_symbol_list and res[createVar['size_' + str(i)]].as_long() > 0:
                        sizes_list["P"+str(i)] = res[createVar['size_' + str(i)]].as_long()

            return times_list, sizes_list

        else:
            print "[!]no more solver..."
            return None, None


    def generate_primitive_timeline_by_solves(self, times_list, sizes_list):
        primitive_timeline = []

        for each_prim_name in times_list:
            if times_list[each_prim_name] > 0:
                for i in range(0, times_list[each_prim_name]):
                    select_prim = copy.deepcopy(self.all_primitives[each_prim_name])
                    primitive_timeline.append(select_prim)

                    for each_op in select_prim.operation_list:
                        if each_op.op_type == "M" and each_op.malloc_size == -1:
                            each_op.malloc_size = sizes_list[each_prim_name] -  2 * SIZE_SZ
        return primitive_timeline



    def execute_primitive_list(self, primitive_list):
        cur_layout = copy.deepcopy(self.cur_layout)
        index = 0
        for each_prim in primitive_list:
            for each_op in each_prim.operation_list:
                if each_op.op_type == "M":
                    if each_op.malloc_size + 2*SIZE_SZ not in  MALLOC_SIZE_OPTIONS:
                        return  None, None
                op_abi = OperationAbility(cur_layout, each_op, TARGET_HOLE_SIZE)
                effects = op_abi.get_split_effects()
                if effects is None:
                    return None, None
                ComplexActorUtil().update_layout_by_effects(cur_layout, effects)
                index += 1

        return primitive_list, cur_layout


    def do_split_occupy(self):

        solved = False
        while not solved:
            self.select_op_list_for_split_in_primitives()
            primitive_times, malloc_sizes =  self.generate_and_solve_equation()

            if primitive_times is None:
                print "error , no more solvers"
                return None, None

            ## sorting
            primitive_timeline = self.generate_primitive_timeline_by_solves(primitive_times, malloc_sizes)
            primitive_time_list, new_layout = self.execute_primitive_list(primitive_timeline)

            if primitive_time_list is None:
                print "re-solve the equation"
                already_solver = self.add_already_unsat_solvers_to_equation(primitive_times, malloc_sizes)
                self.already_unsat_solvers.extend(already_solver)
                continue
            else:
                solved = True

        return primitive_time_list, new_layout

    def add_already_unsat_solvers_to_equation(self, primitive_times, malloc_sizes):
        already_solvers = []

        for each_malloc_size in malloc_sizes:
            if malloc_sizes[each_malloc_size] > 0:
                index = each_malloc_size[-1]
                sizes = "size_"+index
                already_solvers.append([sizes, malloc_sizes[each_malloc_size]])

        return already_solvers



## some Executors

def do_multiple_occupation_by_multiple_steps(init_layout, all_primitives, prims_count_dependency , target_primitive, target_op_index, multiple_targets):
    '''
    use this executor to occupy multiple target holes.
    return: primitives seqs
    '''
    already_solvers = []
    final_solvers = []
    cur_layout  = copy.deepcopy(init_layout)
    finish_solving = False
    if WATCHING_HEAP:
        cur_layout.dump_layout()

    while not finish_solving:

        for target_index, [each_target_addr, each_target_size] in enumerate(multiple_targets):
            sp_oc = SplitOccupy(cur_layout, all_primitives, prims_count_dependency, target_primitive, target_op_index, each_target_size, each_target_addr, already_solvers)
            primitive_time_list, new_layout = sp_oc.do_split_occupy()
            if primitive_time_list is None:
                finish_solving == False
                break

            cur_layout = copy.deepcopy(new_layout)

            if WATCHING_HEAP:
                cur_layout.dump_layout()

            # for previous_goal in range(0, target_index):
            #     chunk_addr = multiple_targets[previous_goal][0]
            #     chunk_size = multiple_targets[previous_goal][1]
            #     if not check_if_previous_chunk_merge(chunk_addr, chunk_size, cur_layout):
            #         print "[!]previous chunk merged, break"
            #         return

            for each_prim in primitive_time_list:
                already_solvers.append(each_prim.prim_name)
                final_solvers.extend(primitive_time_list)

            finish_solving = True


    return final_solvers


def get_split_effect_for_layout(original_chunk, split_chunk, prim_name, op_index):

    original_chunk_addr = original_chunk[0]
    original_chunk_size = original_chunk[1]

    split_chunk_addr = split_chunk[0]
    split_chunk_size = split_chunk[1]

    new_chunk_size =  original_chunk_size - split_chunk_size
    new_chunk_addr =  original_chunk_addr +  split_chunk_size

    new_chunk  = [new_chunk_addr, new_chunk_size]

    effect = {'A':[[split_chunk_size, split_chunk_addr, 1, prim_name, op_index]],'F':[[original_chunk_size, original_chunk_addr, -1, 0, 0], [new_chunk_size, new_chunk_addr, 1, 0, 0]]}

    return effect



def do_multiple_occupation_by_one_step(init_layout, all_primitives, prims_dependency, multiple_objects, original_large_free_chunk):
    '''
    Use this executor to occupy multiple target holes.
    return: The target primitive
    '''
    multiple_targets = multiple_objects
    cur_layout = copy.deepcopy(init_layout)
    for target_prim in all_primitives:

        copy_original_chunk = original_large_free_chunk

        final_op_list = []

        ## analyze malloc operation in each primitive
        malloc_op_list = []
        op_list = all_primitives[target_prim].operation_list
        for each_op in op_list:
            if each_op.op_type == "M":
                malloc_op = copy.deepcopy(each_op)
                malloc_op_list.append(malloc_op)
        for each_op in op_list:
            if each_op.op_type == "F":
                copy_malloc_op_list = []
                for e_op in malloc_op_list:
                    copy_malloc_op_list.append(e_op)
                for each_malloc_op in copy_malloc_op_list:
                    if each_op.op_index < each_malloc_op.op_index:
                        malloc_op_list.remove(each_malloc_op)

        if len(malloc_op_list) < len(multiple_targets):
            print "[-] can not occupy by this way, quit this method"
            return -1

        elif len(malloc_op_list) == len(multiple_targets):

            final_op_list = []

            for target_index, [each_target_addr, each_target_size] in enumerate(multiple_targets):

                cur_malloc_op = malloc_op_list[target_index]

                free_lists = cur_layout.get_free_lists()
                if len(free_lists[each_target_size]) > 0:
                    print "[-] can not occupy by this way, quit this method"
                    break
                else:

                    if cur_malloc_op.malloc_size != -1 and cur_malloc_op.malloc_size != each_target_size:
                        print "[-] can not occupy by this way, quit this method"
                        break
                    elif cur_malloc_op.malloc_size != -1 and cur_malloc_op.malloc_size == each_target_size:

                        effects = get_split_effect_for_layout(copy_original_chunk, [copy_original_chunk[0], each_target_size], target_prim, target_index)
                        ComplexActorUtil().update_layout_by_effects(cur_layout, effects)
                        copy_original_chunk = [copy_original_chunk[0] + each_target_size, copy_original_chunk[1] - each_target_size ]
                        final_op_list.append(cur_malloc_op)
                        continue

                    elif cur_malloc_op.malloc_size == -1:

                        effects = get_split_effect_for_layout(copy_original_chunk, [copy_original_chunk[0], each_target_size], target_prim, target_index)
                        ComplexActorUtil().update_layout_by_effects(cur_layout, effects)
                        copy_original_chunk = [copy_original_chunk[0] + each_target_size, copy_original_chunk[1] - each_target_size ]

                        copied_alloc_op = copy.deepcopy(cur_malloc_op)
                        copied_alloc_op.malloc_size = each_target_size
                        final_op_list.append(copied_alloc_op)

                        continue

        elif len(malloc_op_list) > len(multiple_targets):
            pass

    if len(final_op_list) > 0 :
        return final_op_list



def check_if_previous_chunk_merge(chunk_addr, chunk_size, cur_layout):
    free_lists = cur_layout.get_free_lists()
    if len(free_lists[chunk_size]) > 0:
        for each_priority in range(0, len(free_lists[chunk_size])):
            fl = free_lists[chunk_size][each_priority]
            if chunk_addr in fl.chunks:
                return True

    allocated_chunks = cur_layout.get_allocated_chunks()
    for each_ac in allocated_chunks[chunk_size]:
        if chunk_addr == each_ac.addr:
            return True
    return False





















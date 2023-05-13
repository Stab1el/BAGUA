import copy
import os
import networkx as nx
import uuid

from operation_ability import OperationAbility
from constraint_generator import ConstraintGenerator
from allocator_action_utils import ComplexActorUtil
from allocator_config import *
from primitive import *
from run_config import *
from enum import Enum

NONE_NODE = -1
UNSAT_NODE = 0
ROOT_NODE = 1
SAT_NODE = 2
MALLOC_NODE = 3
FREE_NODE = 4
WATCHING_HEAP = 0


class PathStatus(Enum):
    SUCCESS = 0
    NO_SAT_PATH = 1
    DISTANCE_VARIED = 2

class PathNode(object):

    def __init__(self, target_effect, effects, uniq_id, node_type):
        self.target_effect = target_effect
        self.effects = effects
        self.uniq_id = uniq_id
        self.action = ''
        self.node_type = node_type

    def get_full_name(self):
        pass

    def __str__(self):
        if self.node_type == UNSAT_NODE:
            return 'UNSAT'
        elif self.node_type == ROOT_NODE:
            return 'ROOT'
        elif self.node_type == SAT_NODE:
            return 'SAT'
        else:
            return self.get_full_name()


class MallocNode(PathNode):
    def __init__(self, malloc_size, target_hole_size, target_effect, effects, uniq_id, malloc_addr, node_type):
        super(MallocNode, self).__init__(target_effect, effects, uniq_id, node_type)
        self.malloc_size = malloc_size
        self.target_hole_size = target_hole_size
        self.malloc_addr = malloc_addr
        self.action = 'm'
        self.node_type = MALLOC_NODE

    def get_full_name(self):
        return 'M(0x%x)\n[%d, %d]\n%s' % (self.malloc_size, self.target_hole_size, self.target_effect, str(self.uniq_id))

class FreeNode(PathNode):
    def __init__(self, chunk_size, chunk_addr, target_hole_size, target_effect, effects, uniq_id, node_type):
        super(FreeNode, self).__init__(target_effect, effects, uniq_id, node_type)
        self.chunk_addr = chunk_addr
        self.chunk_size = chunk_size
        self.target_hole_size = target_hole_size
        self.action = 'f'
        self.node_type = FREE_NODE

    def get_full_name(self):
        return 'F(0x%x/%x)\n[%d, %d]\n%s' % (self.chunk_addr, self.chunk_size, self.target_hole_size,
                                                                                self.target_effect, str(self.uniq_id))


class PathGenerator:
    """
    Operation generator for layout.
    Parameters:
        init_layout: Initial heap layout.
        ability_lists: A list of ability, e.g. [[200,-1], [400,+1]]
        malloc_size_operations: [200, 400, 600]
        early_stop: Stop generation if find one SAT path, default is True, otherwise it may consume too much time.
    """

    def __init__(self, init_layout, ability_lists, primitive_list, all_primitives, solution_id = 0,
                                                                                early_stop=True, primitive_mode=False):
        self.init_layout = init_layout
        self.ability_lists = ability_lists
        self.malloc_size_options = MALLOC_SIZE_OPTIONS
        self.alloced_chunks = self.init_layout.get_allocated_chunks()
        self.early_stop = early_stop
        self.pritimve_mode = primitive_mode
        self.solution_id = solution_id
        self.primtive_list = primitive_list
        self.all_primitives = all_primitives
        self.target_hole_size = TARGET_HOLE_SIZE
        self.target_hole_addr = TARGET_CHUNK_ADDR

        ## construct all paths in a directed graph
        self.path_tree = nx.DiGraph()
        self.root_node = PathNode(None, None, None, ROOT_NODE)
        self.sat_node  = None
        self.path_tree.add_node(self.root_node)

        self.num_sat_paths = 0
        self.num_unsat_paths = 0

        self.primitive_path_info = {}
        self.primitive_sat_mark = False

        self.final_op_list = []
        self.new_distance = -1

        self.found_distance_varied = False
        self.layout_when_distance_varied = None
        self.newly_copied_layout = copy.deepcopy(init_layout)

    def _if_target_chunk_in_linear_chain(self, cur_heap_layout):

        cur_free_lists = cur_heap_layout.get_free_lists()
        if len(cur_free_lists[self.target_hole_size]) > 0:
            if self.target_hole_addr in cur_free_lists[self.target_hole_size][0].chunks and cur_free_lists[self.target_hole_size][0].can_ms is False:
                return True
        return False


    def _get_all_sat_operations_set(self, cur_layout, cur_operation, need_ability):
        """
        Get constraints sets for all SAT solvers.
        """
        target_hole_size = need_ability[0]
        list_delta = need_ability[1]

        sat_solvers = []
        sat_effects = []

        new_cur_operation =copy.deepcopy(cur_operation)

        self.alloced_chunks = cur_layout.get_allocated_chunks()

        ## if abi > 0, use free
        if list_delta > 0 and new_cur_operation.op_type == 'F':
            free_prim_name = new_cur_operation.free_target
            free_op = self.all_primitives[free_prim_name].operation_list[new_cur_operation.free_malloc_index]
            if free_op.malloc_size > 0:
                new_cur_operation.free_chunk_size = free_op.malloc_size
                if len(self.alloced_chunks[free_op.malloc_size + 2*SIZE_SZ]) == 0:
                    print "no allocated chunks could be freed, can not free chunk"
                else:
                    for ac in self.alloced_chunks[free_op.malloc_size + 2*SIZE_SZ]:
                        if ac.primitive_name == free_prim_name and ac.op_index == new_cur_operation.free_malloc_index:
                            new_cur_operation.free_chunk_addr = ac.addr
                            free_abi = OperationAbility(cur_layout, new_cur_operation, target_hole_size)
                            if self._if_target_chunk_in_linear_chain(cur_layout):
                                is_sat = True
                            else:
                                is_sat = free_abi.if_op_ability_satisfied(list_delta)
                            if is_sat:
                                sat_solvers.append(['F', new_cur_operation.free_chunk_size + 2*SIZE_SZ, new_cur_operation.free_chunk_addr])
                                sat_effects.append(free_abi.get_effects(list_delta))
                                break

            else:

                for each_size in self.alloced_chunks:
                    for each_allocated_chunk in self.alloced_chunks[each_size]:
                        each_addr = each_allocated_chunk.addr
                        primitive_name = each_allocated_chunk.primitive_name
                        op_index = each_allocated_chunk.op_index
                        if primitive_name == new_cur_operation.free_target and op_index == new_cur_operation.free_malloc_index:
                            new_cur_operation.free_chunk_size = each_size
                            new_cur_operation.free_chunk_addr = each_addr
                            free_abi = OperationAbility(cur_layout, new_cur_operation, target_hole_size)
                            if self._if_target_chunk_in_linear_chain(cur_layout):
                                is_sat = True
                            else:
                                is_sat = free_abi.if_op_ability_satisfied(list_delta)

                            if is_sat:
                                sat_solvers.append(['F', each_size, each_addr, new_cur_operation])
                                sat_effects.append(free_abi.get_effects(list_delta))

        ## if abi < 0, call malloc ability
        elif list_delta < 0 and new_cur_operation.op_type == 'M':

            ## if malloc size is fixed
            if new_cur_operation.malloc_size >= 0:
                malloc_abi = OperationAbility(cur_layout, new_cur_operation, target_hole_size)
                if self._if_target_chunk_in_linear_chain(cur_layout):
                    is_sat = True
                else:
                    is_sat = malloc_abi.if_op_ability_satisfied(list_delta)
                if is_sat:
                    sat_solvers.append(['M', new_cur_operation.malloc_size, None])
                    sat_effects.append(malloc_abi.get_effects(list_delta))
            ## if malloc_size is not fixed
            ## we can not get -1 by split since the tcache chain can not be splited, we can only set the malloc size equal to target size
            elif new_cur_operation.malloc_size < 0:

                new_cur_operation.malloc_size = target_hole_size - 2*SIZE_SZ
                malloc_abi = OperationAbility(cur_layout, new_cur_operation, target_hole_size)
                if self._if_target_chunk_in_linear_chain(cur_layout):
                    is_sat = True
                else:
                    is_sat = malloc_abi.if_op_ability_satisfied(list_delta)
                if is_sat:
                    sat_solvers.append(['M', new_cur_operation.malloc_size, None])
                    sat_effects.append(malloc_abi.get_effects(list_delta))

        ## if abi == 0, call free ability or malloc ability
        elif list_delta == 0:
            if new_cur_operation.op_type == 'F':

                free_prim_name  = new_cur_operation.free_target
                free_op = self.all_primitives[free_prim_name].operation_list[new_cur_operation.free_malloc_index]
                if free_op.malloc_size > 0:
                    new_cur_operation.free_chunk_size = free_op.malloc_size
                    if len(self.alloced_chunks[free_op.malloc_size + 2*SIZE_SZ]) == 0:
                        print "can not free chunk"
                        return None, None
                    else:
                         find = False
                         for ac in self.alloced_chunks[free_op.malloc_size + 2*SIZE_SZ]:
                             if ac.primitive_name == free_prim_name and ac.op_index == new_cur_operation.free_malloc_index:
                                new_cur_operation.free_chunk_addr = ac.addr
                                find = True
                                break
                         if not find:
                             print "no more chunks could be freed, fail"
                             return None, None
                         free_abi = OperationAbility(cur_layout, new_cur_operation, target_hole_size)
                         if self._if_target_chunk_in_linear_chain(cur_layout):
                             is_sat = True
                         else:
                             is_sat = free_abi.if_op_ability_satisfied(list_delta)
                    if is_sat:
                        sat_solvers.append(['F', new_cur_operation.free_chunk_size + 2*SIZE_SZ, new_cur_operation.free_chunk_addr])
                        sat_effects.append(free_abi.get_effects(list_delta))

                else:
                    for each_size in self.alloced_chunks:
                        for each_allocated_chunk in self.alloced_chunks[each_size]:
                            each_addr = each_allocated_chunk.addr
                            primitive_name = each_allocated_chunk.primitive_name
                            op_index = each_allocated_chunk.op_index
                            if primitive_name == new_cur_operation.free_target and op_index == new_cur_operation.free_malloc_index:
                                new_cur_operation.free_chunk_size = each_size
                                new_cur_operation.free_chunk_addr = each_addr
                                free_abi = OperationAbility(cur_layout, new_cur_operation, target_hole_size)
                                if self._if_target_chunk_in_linear_chain(cur_layout):
                                    is_sat = True
                                else:
                                    is_sat = free_abi.if_op_ability_satisfied(list_delta)
                            if is_sat:
                                sat_solvers.append(['F', each_size, each_addr])
                                sat_effects.append(free_abi.get_effects(list_delta))

            elif new_cur_operation.op_type == 'M':

                if new_cur_operation.malloc_size >= 0:
                    malloc_abi = OperationAbility(cur_layout, new_cur_operation, target_hole_size)
                    if self._if_target_chunk_in_linear_chain(cur_layout):
                        is_sat = True
                    else:
                        is_sat = malloc_abi.if_op_ability_satisfied(list_delta)
                    if is_sat:
                        sat_solvers.append(['M', new_cur_operation.malloc_size, None])
                        sat_effects.append(malloc_abi.get_effects(list_delta))

                elif new_cur_operation.malloc_size < 0:
                    for each_malloc_size in self.malloc_size_options:
                        new_cur_operation.malloc_size = each_malloc_size
                        malloc_abi = OperationAbility(cur_layout, new_cur_operation, target_hole_size)
                        if self._if_target_chunk_in_linear_chain(cur_layout):
                            is_sat = True
                        else:
                            is_sat = malloc_abi.if_op_ability_satisfied(list_delta)

                        if is_sat:
                            sat_solvers.append(['M', each_malloc_size, None])
                            sat_effects.append(malloc_abi.get_effects(list_delta))

        return sat_solvers, sat_effects


    def _get_one_sat_operation(self, cur_layout, cur_operation, need_ability):
        """
        Get constraints sets for all SAT solvers.
        """
        target_hole_size = need_ability[0]
        list_delta = need_ability[1]

        new_cur_operation =copy.deepcopy(cur_operation)
        self.alloced_chunks = cur_layout.get_allocated_chunks()

        sat_solver = []
        sat_effect = []
        ## if abi > 0, call free ability
        if list_delta > 0 and new_cur_operation.op_type == 'F':
            free_prim_name = new_cur_operation.free_target
            free_op = self.all_primitives[free_prim_name].operation_list[new_cur_operation.free_malloc_index]
            if free_op.malloc_size > 0:
                new_cur_operation.free_chunk_size = free_op.malloc_size
                if len(self.alloced_chunks[free_op.malloc_size + 2*SIZE_SZ]) == 0:
                    print "can not free chunk"
                else:
                    for ac in self.alloced_chunks[free_op.malloc_size + 2*SIZE_SZ]:
                        if ac.primitive_name == free_prim_name and ac.op_index == new_cur_operation.free_malloc_index:
                            new_cur_operation.free_chunk_addr = ac.addr
                            free_abi = OperationAbility(cur_layout, new_cur_operation, target_hole_size)
                            if self._if_target_chunk_in_linear_chain(cur_layout):
                                is_sat = True
                            else:
                                is_sat = free_abi.if_op_ability_satisfied(list_delta)

                            if is_sat:
                                sat_solver = ['F', new_cur_operation.free_chunk_size, new_cur_operation.free_chunk_addr]
                                sat_effect = free_abi.get_effects(list_delta)
                                break

            else:
                for each_size in self.alloced_chunks:
                    for each_allocated_chunk in self.alloced_chunks[each_size]:
                        each_addr = each_allocated_chunk.addr
                        primitive_name = each_allocated_chunk.primitive_name
                        op_index = each_allocated_chunk.op_index
                        if primitive_name == new_cur_operation.free_target and op_index == new_cur_operation.free_malloc_index:
                            new_cur_operation.free_chunk_size = each_size
                            new_cur_operation.free_chunk_addr = each_addr
                            free_abi = OperationAbility(cur_layout, new_cur_operation, target_hole_size)
                            if self._if_target_chunk_in_linear_chain(cur_layout):
                                is_sat = True
                            else:
                                is_sat = free_abi.if_op_ability_satisfied(list_delta)
                            if is_sat:
                                sat_solver = ['F', each_size, each_addr, new_cur_operation]
                                sat_effect = free_abi.get_effects(list_delta)
                                break

        ## if abi < 0, call malloc ability
        elif list_delta < 0 and new_cur_operation.op_type == 'M':

            ## if malloc size is fixed
            if new_cur_operation.malloc_size >= 0:
                malloc_abi = OperationAbility(cur_layout, new_cur_operation, target_hole_size)
                if self._if_target_chunk_in_linear_chain(cur_layout):
                    is_sat = True
                else:
                    is_sat = malloc_abi.if_op_ability_satisfied(list_delta)
                if is_sat:
                    sat_solver = ['M', new_cur_operation.malloc_size, None]
                    sat_effect = malloc_abi.get_effects(list_delta)
                    new_cur_operation.malloc_chunk_addr = sat_effect["A"][0][1]


            ## if malloc_size is not fixed
            elif new_cur_operation.malloc_size < 0:
                new_cur_operation.malloc_size =  target_hole_size - 2*SIZE_SZ
                malloc_abi = OperationAbility(cur_layout, new_cur_operation, target_hole_size)
                if self._if_target_chunk_in_linear_chain(cur_layout):
                    is_sat = True
                else:
                    is_sat = malloc_abi.if_op_ability_satisfied(list_delta)
                if is_sat:
                    sat_solver = ['M', new_cur_operation.malloc_size, None]
                    sat_effect = malloc_abi.get_effects(list_delta)
                    new_cur_operation.malloc_chunk_addr = sat_effect["A"][0][1]


        ## if abi == 0, call free ability or malloc ability
        elif list_delta == 0:
            if new_cur_operation.op_type == 'F':

                free_prim_name  = new_cur_operation.free_target
                free_op = self.all_primitives[free_prim_name].operation_list[new_cur_operation.free_malloc_index]
                if free_op.malloc_size > 0:
                    new_cur_operation.free_chunk_size = free_op.malloc_size
                    if len(self.alloced_chunks[free_op.malloc_size + 2*SIZE_SZ]) == 0:
                        print "can not free chunk"
                        return
                    else:
                         for ac in self.alloced_chunks[free_op.malloc_size + 2*SIZE_SZ]:
                             if ac.primitive_name == free_prim_name and ac.op_index == new_cur_operation.free_malloc_index:
                                new_cur_operation.free_chunk_addr = ac.addr
                                break
                         free_abi = OperationAbility(cur_layout, new_cur_operation, target_hole_size)
                         if self._if_target_chunk_in_linear_chain(cur_layout):
                             is_sat = True
                         else:
                             is_sat = free_abi.if_op_ability_satisfied(list_delta)
                    if is_sat:
                        sat_solver = ['F', new_cur_operation.free_chunk_size, new_cur_operation.free_chunk_addr]
                        sat_effect = free_abi.get_effects(list_delta)

                else:
                    for each_size in self.alloced_chunks:
                        for each_allocated_chunk in self.alloced_chunks[each_size]:
                            each_addr = each_allocated_chunk.addr
                            primitive_name = each_allocated_chunk.primitive_name
                            op_index = each_allocated_chunk.op_index
                            if primitive_name == new_cur_operation.free_target and op_index == new_cur_operation.free_malloc_index:
                                new_cur_operation.free_chunk_size = each_size
                                new_cur_operation.free_chunk_addr = each_addr
                                free_abi = OperationAbility(cur_layout, new_cur_operation, target_hole_size)
                                if self._if_target_chunk_in_linear_chain(cur_layout):
                                    is_sat = True
                                else:
                                    is_sat = free_abi.if_op_ability_satisfied(list_delta)

                            if is_sat:
                                sat_solver =['F', each_size, each_addr]
                                sat_effect = free_abi.get_effects(list_delta)

            elif new_cur_operation.op_type == 'M':

                if new_cur_operation.malloc_size >= 0:
                    malloc_abi = OperationAbility(cur_layout, new_cur_operation, target_hole_size)
                    if self._if_target_chunk_in_linear_chain(cur_layout):
                        is_sat = True
                    else:
                        is_sat = malloc_abi.if_op_ability_satisfied(list_delta)

                    if is_sat:
                        sat_solver = ['M', new_cur_operation.malloc_size, None]
                        sat_effect = malloc_abi.get_effects(list_delta)
                elif new_cur_operation.malloc_size < 0:
                    for each_malloc_size in self.malloc_size_options:
                        new_cur_operation.malloc_size = each_malloc_size
                        malloc_abi = OperationAbility(cur_layout, new_cur_operation, target_hole_size)
                        if self._if_target_chunk_in_linear_chain(cur_layout):
                            is_sat = True
                        else:
                            is_sat = malloc_abi.if_op_ability_satisfied(list_delta)
                        if is_sat:
                            sat_solver = ['M', each_malloc_size, None]
                            sat_effect = malloc_abi.get_effects(list_delta)
                            new_cur_operation.malloc_chunk_addr = sat_effect["A"][0][1]

        return sat_solver, sat_effect, new_cur_operation

    def __get_fix_extra_ability_lists(self, cur_layout, cur_operation, need_ability, active_mode = False):

        new_ability_to_fix_lists = []

        if cur_operation.op_type == 'F':
            for each_size in self.alloced_chunks:
                for each_allocated_chunk in self.alloced_chunks[each_size]:
                    each_addr = each_allocated_chunk.addr
                    primitive_name = each_allocated_chunk.primitive_name
                    op_index = each_allocated_chunk.op_index
                    if primitive_name == cur_operation.free_target and op_index == cur_operation.free_malloc_index:
                        cur_operation.free_chunk_size = each_size
                        cur_operation.free_chunk_addr = each_addr
                        target_hole_size = need_ability[0]
                        list_delta = need_ability[1]
                        malloc_abi = OperationAbility(cur_layout, cur_operation, target_hole_size)
                        new_abi_list = malloc_abi.collect_unsat_solvers(list_delta)

                        if new_abi_list is None:
                            continue

                        for [new_ability, new_target_size] in new_abi_list:
                            if new_target_size == self.target_hole_size:
                                return None, None
                            new_ability_to_fix_lists.append([new_ability, new_target_size])

        elif cur_operation.op_type == 'M':

            if cur_operation.malloc_size >= 0:
                target_hole_size = need_ability[0]
                list_delta = need_ability[1]
                malloc_abi = OperationAbility(cur_layout, cur_operation, target_hole_size)
                new_abi_list = malloc_abi.collect_unsat_solvers(list_delta)
                if new_abi_list is None:
                    return None, None
                for [new_ability, new_target_size] in new_abi_list:
                    if new_target_size == self.target_hole_size:
                        return None, None
                    new_ability_to_fix_lists.append([new_ability, new_target_size])

            elif cur_operation.malloc_size < 0:
                for each_m_size in self.malloc_size_options:
                    cur_operation.malloc_size = each_m_size
                    target_hole_size = need_ability[0]
                    list_delta = need_ability[1]
                    malloc_abi = OperationAbility(cur_layout, cur_operation, target_hole_size)
                    new_abi_list = malloc_abi.collect_unsat_solvers(list_delta)

                    if new_abi_list is None:
                        continue
                    for [new_ability, new_target_size] in new_abi_list:
                        if new_target_size == self.target_hole_size:
                            return None, None
                        new_ability_to_fix_lists.append([new_ability, new_target_size])

        if len(new_ability_to_fix_lists) == 0:
            return None, None

        target_abi = new_ability_to_fix_lists[0][0]
        for [new_abi, new_chunk_size] in new_ability_to_fix_lists:
            if abs(new_abi) <= abs(target_abi):
                target_abi = new_abi
                [f_new_ability, f_new_target_size] = [new_abi, new_chunk_size]

        # primitive_list = []
        # for each_prim in self.all_primitives:
        #     primitive_list.extend(self.all_primitives[each_prim].operation_list)

        equa_gen = ConstraintGenerator(self.all_primitives, 0, self.target_hole_size, cur_layout)
        add_primitive_op_list, add_ability_list = equa_gen.generate_extra_equation_by_target_ability(f_new_target_size, f_new_ability, active_mode)

        return add_primitive_op_list, add_ability_list

    def dump_path_tree_all(self, tree):
        """
        Dump path tree as dot file and draw it.
        """
        dot_file_name = "solution_%d.dot" % self.solution_id
        png_file_name = "solution_%d.png" % self.solution_id
        print "Now dumping path tree to %s and %s" % (dot_file_name, png_file_name)
        nx.drawing.nx_pydot.write_dot(tree, dot_file_name)
        os.system("dot -Tpng %s -o %s" % (dot_file_name, png_file_name))

    def dump_sat_path(self):
        """
        Only dump one single sat path.
        """
        if self.sat_node is None:
            print "No SAT path!"
            return

        sat_path = nx.dijkstra_path(self.path_tree, self.root_node, self.sat_node)
        sat_path_tree = nx.DiGraph()
        prev_node = None
        for each_node in sat_path:
            sat_path_tree.add_node(each_node)
            if prev_node is not None:
                sat_path_tree.add_edge(prev_node, each_node)
            prev_node = each_node


        dot_file_name = "solution_%d.dot" % self.solution_id
        png_file_name = "solution_%d.png" % self.solution_id
        print "Now dumping path tree to %s and %s" % (dot_file_name, png_file_name)
        nx.drawing.nx_pydot.write_dot(sat_path_tree, dot_file_name)
        os.system("dot -Tpng %s -o %s" % (dot_file_name, png_file_name))

        self.newly_copied_layout = copy.deepcopy(self.init_layout)
        index = 0
        if WATCHING_HEAP:
            self.init_layout.dump_layout()

        for each_node in sat_path:
            if each_node.node_type in [ROOT_NODE, SAT_NODE]:
                continue
            print "++++++++++++++++++++++++++++++++++++ step %d +++++++++++++++++++++++++++++++++++++++" % index
            ComplexActorUtil().update_layout_by_effects(self.newly_copied_layout, each_node.effects)
            index += 1

        return

    def _select_cur_node_in_path_tree(self, prev_node):
        max_len = 0xFFFFFFFF
        selected_node = None
        for each_node in nx.DiGraph.successors(self.path_tree, prev_node):
            node_abi_effect = each_node.accumulate_abi_effect
            if len(node_abi_effect) < max_len:
                selected_node = each_node
                max_len = len(node_abi_effect)

        return selected_node


    def _construct_primitive_tree_worker(self, ppt, cur_layout, ability_list, prim_op_list, ability_index, 
                                                                                            prev_path_node,
                                                                                            terminator_node):
        """
        Construct path tree for a specific primitive.
        In this function, we need to continue to find a sat path.
        """
        if self.primitive_sat_mark:
            return

        ## get all sat solvers
        need_ability = ability_list[ability_index]
        cur_operation = prim_op_list[ability_index]

        sat_solvers, sat_effects = self._get_all_sat_operations_set(cur_layout, cur_operation, need_ability)

        ## if fix path make the target distance change, then quit this fix equation.
        # for index in range(0, len(sat_effects)):
        #     for effect in sat_effects[index]['F']:
        #         if need_ability[0] != self.target_hole_size and  effect[0] == self.target_hole_size:
        #             print "[!] Cur fix affect the target hole chain while fix, can not fix "
        #             return
        #     for effect in sat_effects[index]['A']:
        #         if need_ability[0] != self.target_hole_size and effect[0] == self.target_hole_size:
        #             print "[!] Cur fix affect the target hole chain while fix, can not fix "
        #             return

        # If a path is not sat, collect the extra ability and return, please do NOT perform real fix here!
        if len(sat_solvers) == 0:
            fix_primitive, extra_ability_lists = self.__get_fix_extra_ability_lists(cur_layout,
                                                                                        cur_operation, need_ability, active_mode = False)

            if extra_ability_lists is None or len(extra_ability_lists) == 0:
                print "[!] Can not fix this equation, please use active mode.......active mode starting"
                active_fix_primitive, active_extra_ability_lists = self.__get_fix_extra_ability_lists(cur_layout,
                                                                                        cur_operation, need_ability,
                                                                                        active_mode=True)
                if active_extra_ability_lists is None:
                    self.primitive_path_info['UNSAT'].append(prev_path_node)
                else:
                    self.primitive_path_info['FIX'].append([extra_ability_lists, active_fix_primitive])
                return
            else:
                self.primitive_path_info['FIX'].append([extra_ability_lists, fix_primitive])
                return


        # collect all sat cases into path tree
        suc_nodes = []
        for index in range(0, len(sat_solvers)):
            if sat_solvers[index][0] == 'M':
                cur_malloc_size = sat_solvers[index][1]
                cur_solver = sat_solvers[index][2]
                cur_target_hole_size = need_ability[0]
                cur_target_effect = need_ability[1]
                cur_effects = sat_effects[index]
                cur_uniq_id = uuid.uuid1()
                if len(cur_effects) > 0:
                    cur_malloc_addr = cur_effects['A'][0][1]

                else:
                    cur_malloc_addr = 0

                cur_path_node = MallocNode(cur_malloc_size,
                                         cur_target_hole_size, cur_target_effect,
                                         cur_effects,
                                         cur_uniq_id, cur_malloc_addr, MALLOC_NODE)

            elif sat_solvers[index][0] == 'F':
                cur_free_chunk_size = sat_solvers[index][1]
                cur_free_chunk_addr = sat_solvers[index][2]
                cur_target_hole_size = need_ability[0]
                cur_target_effect = need_ability[1]
                cur_effects = sat_effects[index]
                cur_uniq_id = uuid.uuid1()

                cur_path_node = FreeNode(cur_free_chunk_size, cur_free_chunk_addr,
                                         cur_target_hole_size,
                                         cur_target_effect,
                                         cur_effects,
                                         cur_uniq_id, FREE_NODE)


            ppt.add_node(cur_path_node)
            ppt.add_edge(prev_path_node, cur_path_node)
            suc_nodes.append(cur_path_node)


        ability_index += 1
        if ability_index == len(ability_list):
            self.primitive_sat_mark = True
            self.primitive_path_info['SAT'] = suc_nodes
            ppt.add_node(terminator_node)
            for node in nx.DiGraph.successors(ppt, prev_path_node):
                ppt.add_edge(node, terminator_node)
            return 

        node_index = 0
        while node_index < len(suc_nodes):
            node = suc_nodes[node_index]

            # copy and update newly copied layout
            self.newly_copied_layout = copy.deepcopy(cur_layout)
            ComplexActorUtil().update_layout_by_effects(self.newly_copied_layout, node.effects)

            self._construct_primitive_tree_worker(ppt, self.newly_copied_layout, ability_list, prim_op_list, 
                                                                                           ability_index, 
                                                                                           node,
                                                                                           terminator_node)



            node_index += 1

        return


    def _construct_primitive_path(self, cur_layout, ability_list, prim_op_list, prev_node):
        """
        A wrapper for constructing primitive tree.
        """
        self.primitive_sat_mark = False
        self.primitive_path_info['SAT']   = []
        self.primitive_path_info['UNSAT'] = []
        self.primitive_path_info['FIX']   = []

        ability_index = 0
        ppt = nx.DiGraph()
        ppt.add_node(prev_node)

        terminator_node = PathNode(None, None, None, SAT_NODE)

        self._construct_primitive_tree_worker(ppt, cur_layout, ability_list, prim_op_list, ability_index, 
                                                                                            prev_node,
                                                                                            terminator_node)


        return ppt, terminator_node


    def _add_path_to_tree(self, tree, last_node, path):
        prev_node = last_node
        for each_node in path:
            tree.add_node(each_node)
            tree.add_edge(prev_node, each_node)
            prev_node = each_node
        
        return

    def _construct_path_tree_v1(self, cur_layout, ability_lists, primitive_lists, primitive_index, prev_node):
        """
        Core function code for constructing a path tree.
        """
        ## check early stop
        if self.early_stop and self.num_sat_paths != 0:
            return

        if self.found_distance_varied:
            return

        cur_prim_ability_list = ability_lists[primitive_index]
        cur_prim_op_list      = primitive_lists[primitive_index]

        ppt, sat_node = self._construct_primitive_path(cur_layout, cur_prim_ability_list, cur_prim_op_list, prev_node)
        

        # If not find sat path, and no fix, then mark as unsat path.
        if not self.primitive_sat_mark and len(self.primitive_path_info['FIX']) == 0:
            terminator_node = PathNode(None, None, None, UNSAT_NODE)
            self.path_tree.add_node(terminator_node)
            self.path_tree.add_edge(prev_node, terminator_node)
            self.num_unsat_paths += 1
            return


        # if find sat primitive path
        if self.primitive_sat_mark:
            sat_path = nx.dijkstra_path(ppt, prev_node, sat_node)
            self._add_path_to_tree(self.path_tree, prev_node, sat_path[1:-1]) # get rid of root and sat nodes

            self.add_final_op_list(sat_path[1:-1]) # add satisfied op list to final op list

            prev_node = sat_path[-2]
            primitive_index += 1

            # find one sat path and sat ALL
            if primitive_index == len(primitive_lists):

                self.newly_copied_layout = copy.deepcopy(cur_layout)
                for each_node in sat_path[1:-1]:
                    ComplexActorUtil().update_layout_by_effects(self.newly_copied_layout, each_node.effects)
                    if WATCHING_HEAP:
                        self.newly_copied_layout.dump_layout()

                terminator_node = PathNode(None, None, None, SAT_NODE)
                self.sat_node = terminator_node
                self.path_tree.add_node(terminator_node)
                self.path_tree.add_edge(prev_node, terminator_node)
                self.num_sat_paths += 1
                return
            else: # continue to construct path tree
                self.newly_copied_layout = copy.deepcopy(cur_layout)
                for each_node in sat_path[1:-1]:
                    ComplexActorUtil().update_layout_by_effects(self.newly_copied_layout, each_node.effects)
                    if WATCHING_HEAP:
                        self.newly_copied_layout.dump_layout()

                self.found_distance_varied, new_distance, final_op_list = \
                    self.compare_new_distance_after_primitive(self.newly_copied_layout, cur_layout, primitive_lists,
                                                              ability_lists, primitive_index -1)
                if self.found_distance_varied:  # if distance changed, just return ASAP!
                    self.new_distance = new_distance
                    self.final_op_list = final_op_list
                    self.layout_when_distance_varied = self.newly_copied_layout
                    return

                self._construct_path_tree_v1(self.newly_copied_layout, ability_lists, primitive_lists, primitive_index,
                                                                                                 prev_node)
                return


        # do path fix with primitive
        original_ability_lists = copy.deepcopy(ability_lists)
        original_primitive_list = copy.deepcopy(primitive_lists)
        primitive_path_fix_info = copy.deepcopy(self.primitive_path_info['FIX'])


        # print original_primitive_list

        for [extra_ability_lists, fix_primitive_op_list] in primitive_path_fix_info:
            primitive_lists = primitive_lists[:primitive_index] + fix_primitive_op_list + primitive_lists[primitive_index:]
            ability_lists = ability_lists[:primitive_index] + extra_ability_lists + ability_lists[primitive_index:]

            self._construct_path_tree_v1(cur_layout, ability_lists, primitive_lists, primitive_index, prev_node)

            primitive_lists = original_primitive_list
            ability_lists = original_ability_lists

        return


    def add_final_op_list(self, sat_path):

        for node in sat_path:
            final_op = Operation()
            if node.action == "m":
                final_op.op_type = "M"
                final_op.malloc_size = node.malloc_size
                final_op.malloc_chunk_addr = node.malloc_addr
            elif node.action == "f":
                final_op.op_type = "F"
                final_op.free_chunk_addr = node.chunk_addr
                final_op.free_chunk_size = node.chunk_size

            self.final_op_list.append(final_op)

    def do_generate_work(self):
        """
        Main interface for PathGenerator.
        """
        primitive_index = 0
        self._construct_path_tree_v1(self.init_layout, self.ability_lists, self.primtive_list, 
                                                                                    primitive_index, self.root_node)
        # print "Totally find %d SAT paths and %d *UN*SAT paths" % (self.num_sat_paths, self.num_unsat_paths)

        # self.dump_path_tree_all(self.path_tree)
        if self.num_sat_paths:
            return PathStatus.SUCCESS, []

        if self.found_distance_varied:
            return PathStatus.DISTANCE_VARIED, [self.layout_when_distance_varied, self.new_distance, self.final_op_list]

        return PathStatus.NO_SAT_PATH, []

        # dump path tree
        # self.dump_path_tree()

    def add_target_prim_to_final_op_list(self, target_hole_size, prim_name, primitive_abi_list):

        target_prim = self.all_primitives[prim_name]

        for index, cur_op in enumerate(target_prim.operation_list):
            tar_op_abi = primitive_abi_list[0][index]
            sat_solver, sat_effect, new_cur_op = self._get_one_sat_operation(self.newly_copied_layout, cur_op, [target_hole_size, tar_op_abi])
            if len(sat_solver) == 0:
                print "wrong, add target prim fail with cur heap layout"
                return None
            self.final_op_list.append(new_cur_op)
            ComplexActorUtil().update_layout_by_effects(self.newly_copied_layout, sat_effect)
            if WATCHING_HEAP:
                self.newly_copied_layout.dump_layout()
        return self.final_op_list

    def compare_new_distance_after_primitive(self, new_heap_layout, old_heap_layout, all_primitive_lists, ability_lists, primitive_index):
        # compare if cur primitive ability is matched with real delta distance
        new_distance = new_heap_layout.get_distance_to_target_hole(TARGET_CHUNK_ADDR, TARGET_HOLE_SIZE)
        old_distance = old_heap_layout.get_distance_to_target_hole(TARGET_CHUNK_ADDR, TARGET_HOLE_SIZE)
        delta_distance = new_distance - old_distance
        sum_abi = 0
        for abi in ability_lists[primitive_index]:
            sum_abi += abi[1]

        if sum_abi == delta_distance:
            return False, None, None

        if sum_abi != delta_distance:
            return True, new_distance, self.final_op_list



if __name__ == "__main__":
    print ('Use plan generator!')
    exit(0)

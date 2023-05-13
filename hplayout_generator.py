import time
import copy
from utils import *
from normal_occupation_executor import PathGenerator, PathStatus
from fuzz_target_hole import FuzzHole
from split_occupation_executor import *
from run_config import *
from primitive_ability import PrimitiveAbility
from constraint_generator import ConstraintGenerator

class HpLayoutGenerator:
    def __init__(self):
        self.all_prims = get_all_primitives_from_files(P_FILE_PATH)
        self.prims_count_dependency = get_primitives_count_dependency(COUNT_DEPENDENCY)
        self.target_prim_abi = PrimitiveAbility(self.all_prims[TARGET_PRIM_NAME], TARGET_HOLE_SIZE)
        self.target_prim_abi_list = self.target_prim_abi.find_one_primitive_ability_list()
        self.sum_abi = calculate_sum_of_list(self.target_prim_abi_list[0][:TARGET_OP_INDEX + 1])
        self.final_op_list = []
        self.init_layout = get_heap_layout_from_file(INIT_LAYOUT_PATH)


    def select_heap_layout_mode(self):
        ## selecting the occupation mode according to size of target hole and TO.
        occupy_mode = None
        free_lists = self.init_layout.get_free_lists()
        for each_size in free_lists:
            for each_priority in range(0, len(free_lists[each_size])):
                fl = free_lists[each_size][each_priority]
                for each_addr in fl.chunks:
                    if each_addr == TARGET_CHUNK_ADDR:
                        if each_size > TARGET_HOLE_SIZE:
                            print "[+] Using split mode for occupying holes!"
                            occupy_mode = "split"
                        elif each_size == TARGET_HOLE_SIZE:
                            print "[+] use normal mode occupying holes!"
                            occupy_mode = "normal"
                        elif each_size < TARGET_HOLE_SIZE:
                            print "[+] use merge mode for occupying holes!"
                            occupy_mode = "merge"

        if occupy_mode == "normal":
            self.do_normal_generate()
        elif occupy_mode == "split":
            self.do_split_generate()
        elif occupy_mode is None:
            print "[!] ERROR cannot find target chunk"


    def do_split_generate(self):

        target_prim = self.all_prims[TARGET_PRIM_NAME]
        final_op_list = do_multiple_occupation_by_one_step(self.init_layout, self.all_prims, self.prims_count_dependency, MULTI_TARGETS,
                                                           ORIGINAL_FREE_CHUNK)
        if final_op_list == -1 or len(final_op_list) == 0:
            final_primitive_list = do_multiple_occupation_by_multiple_steps(self.init_layout, self.all_prims, self.prims_count_dependency,
                                                                            target_prim, TARGET_OP_INDEX, MULTI_TARGETS)
            final_primitive_list.append(target_prim)

            if target_prim.operation_list[TARGET_OP_INDEX].malloc_size == -1:
                target_prim.operation_list[TARGET_OP_INDEX].malloc_size = TARGET_HOLE_SIZE - 2 * SIZE_SZ

            for each_prim in final_primitive_list:
                print each_prim.prim_name
                print each_prim
        else:
            for op in final_op_list:
                print op




    def do_normal_generate(self):
        '''
        using normal mode (within basic capability) for occupation
        '''
        fuzz_win = False
        init_distance = self.init_layout.get_distance_to_target_hole(TARGET_CHUNK_ADDR, TARGET_HOLE_SIZE)

        print "[+] The init distance (or number of holes to be filled) is", init_distance

        if init_distance < 8:
            fuzz_win = True
            fuzz_heap_layout = copy.deepcopy(self.init_layout)
            fuzz_op_list = []

        ## step 1: leveraging fuzzing to quickly fill some holes
        while not fuzz_win:

            print "[+] Now using fuzz mode to fill holes..."

            fuzzhole = FuzzHole()

            fuzz_op_list, fuzz_heap_layout, fuzz_distance = fuzzhole.fuzz_master()

            if fuzz_distance < (0 - self.sum_abi) or fuzz_distance < 0:
                print "[!] ERROR! fuzz fail, the target hole is occupied, fuzz again"

            if fuzz_op_list is None:
                print "[!] ERROR! fuzz fail, please fuzz again"
            else:
                fuzz_win = True

        ## step 2: heap layout accurately
        success = False
        new_layout = copy.deepcopy(fuzz_heap_layout)
        while not success:

            target_distance = 0 - (new_layout.get_distance_to_target_hole(TARGET_CHUNK_ADDR, TARGET_HOLE_SIZE)) - self.sum_abi

            print "[+] Now establishing the equation of ILP, the target distance is %d" % target_distance

            ## leverage target primitive to occupy holes directly.
            if target_distance == 0:

                pg = PathGenerator(new_layout, [[1]], [], all_primitives=self.all_prims,
                                   solution_id=0,
                                   early_stop=True,
                                   primitive_mode=True)
                pg.add_target_prim_to_final_op_list(TARGET_HOLE_SIZE, TARGET_PRIM_NAME, self.target_prim_abi_list)

                to_final_op_list = fuzz_op_list + pg.final_op_list

                final_op_list = dump_final_op_list(INIT_LAYOUT_PATH, BASE_OP_LIST_PATH, to_final_op_list)

                for op in final_op_list:
                    print op

                with open('./solution.pickle', 'wb') as f:
                    pickle.dump(final_op_list, f)
                success = True  # Win!
                break

            ## Start heap layout
            good = False
            eqg = ConstraintGenerator(self.all_prims, target_distance, TARGET_HOLE_SIZE, new_layout)
            has_equation = True

            # Get solutions for a specific target distance.
            while not good:
                primitive_operation_list, abi_list = eqg.generate_input_for_path_generator(TARGET_HOLE_SIZE)
                if abi_list is None:
                    has_equation = False
                    break

                if len(abi_list) == 0:
                    eqg.need_add_constraint = True
                    eqg.add_constraint_to_solver()
                    continue

                pg = PathGenerator(new_layout, abi_list, primitive_operation_list, all_primitives=self.all_prims,
                                   solution_id=0,
                                   early_stop=True,
                                   primitive_mode=True)
                [status, info] = pg.do_generate_work()

                if status == PathStatus.SUCCESS:

                    pg.add_target_prim_to_final_op_list(TARGET_HOLE_SIZE, TARGET_PRIM_NAME, self.target_prim_abi_list)

                    if len(self.final_op_list):
                        to_final_op_list = fuzz_op_list + self.final_op_list + pg.final_op_list
                    else:
                        to_final_op_list = fuzz_op_list + pg.final_op_list

                    if len(BASE_OP_LIST_PATH) > 0:
                       final_op_list = dump_final_op_list(INIT_LAYOUT_PATH, BASE_OP_LIST_PATH, to_final_op_list)
                    else:
                        final_op_list = dump_final_op_list(INIT_LAYOUT_PATH, "", to_final_op_list)

                    for op in final_op_list:
                        print op

                    with open('./solution.pickle', 'wb') as f:
                        pickle.dump(final_op_list, f)
                    success = True   # Win!
                    break

                elif status == PathStatus.NO_SAT_PATH:  # need to found other equations
                    eqg.need_add_constraint = True
                    eqg.add_constraint_to_solver()  # distance remains the same, but choose different coefficients
                    continue

                elif status == PathStatus.DISTANCE_VARIED:  # distance changed, need to regenerate equation
                    new_layout = info[0]
                    self.final_op_list += info[2]
                    break   # break to calculate new distance

            if not has_equation:
                print "[-] Over, Failed to find any equations!"
                break


if __name__ == "__main__":
    start_time = time.time()

    plg = HpLayoutGenerator()
    plg.select_heap_layout_mode()


    end_time = time.time()

    print (end_time - start_time)


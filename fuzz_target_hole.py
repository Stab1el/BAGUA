import copy
import difflib
import os, sys
sys.path.append('/home/usera/Heap_Layout/heap_helper')
sys.path.append('/home/usera/benchmark')
import random
from allocator_config import *
from utils import *
from run_config import *
from primitive_ability import PrimitiveAbility
import datetime
from server import *
import uuid


class FuzzHole:

    def __init__(self):
        self.all_prims = get_all_primitives_from_files(P_FILE_PATH)
        self.init_layout = get_heap_layout_from_file(INIT_LAYOUT_PATH)
        self.target_hole_size = TARGET_HOLE_SIZE
        self.target_hole_addr = TARGET_CHUNK_ADDR
        self.base_op_list_file = BASE_OP_LIST_PATH
        self.target_distance = None
        self.fuzz_op_list = []
        self.fuzz_prim_list = []
        self.target_area = []
        self.base_op_list = []
        self.__load_base_op_list()
        self.generate_c_source = True
        self.has_fixed = False
        self.seed_list = {}
        self.distance_pair_key = {}
        self.testcase_score_list = {}
        self.testcase_queue = []

    def __load_base_op_list(self):
        if not os.path.isfile(self.base_op_list_file):
            print ("Base layout operation list file at %s is not found!" % self.base_op_list_file)
            return False
        try:
            with open(self.base_op_list_file, 'rb') as f:
                self.base_op_list = pickle.load(f)
        except Exception as e:
            print ("Failed to load file at %s as pickle file" % self.base_op_list_file)
            print ("Error is " + str(e))
            return False
        return True

    def dump_layout_to_file(self, chunks, holes, layout_index):

        lf = open("fuzz_result/tmp_fuzz_layout.%d" % layout_index, 'w')
        for chunk in chunks:
            if chunk[2] == TOP_CHUNK:
                lf.write("T|0x%x|0x%x|%d|%d|%d\n" % (chunk[0], chunk[1], chunk[3], chunk[4], chunk[5]))
            else:
                lf.write("A|0x%x|0x%x|%d|%d|%d\n" % (chunk[0], chunk[1], chunk[3], chunk[4], chunk[5]))

        # correct hole orders
        tcaches = {}
        normal_free_list = {}
        unsorted_bins = []

        for hole in holes:
            addr = hole[0]
            size = hole[1]
            if hole[2] == HOLE_TCACHE_BIN:
                if size not in tcaches:
                    tcaches[size] = []
                tcaches[size].append(addr)
            elif hole[2] in [HOLE_FAST_BIN, HOLE_NORMAL_BIN]:
                if size not in normal_free_list:
                    normal_free_list[size] = []
                normal_free_list[size].append(addr)
            elif hole[2] == HOLE_UNSORTED_BIN:
                unsorted_bins.append([addr, size])
            elif hole[2] == HOLE_LAST_REMAINDER:
                lf.write("R|0x%x|0x%x|%d|%d|0\n" % (addr, size, 0, 0))

        # write tcache
        for each_size in tcaches:
            tcaches[each_size].reverse()
            for addr in tcaches[each_size]:
                lf.write("C|0x%x|0x%x|%d|%d|0\n" % (addr, each_size, 0, 0))

        # write normal free list
        for each_size in normal_free_list:
            normal_free_list[each_size].reverse()
            for addr in normal_free_list[each_size]:
                lf.write("F|0x%x|0x%x|%d|%d|0\n" % (addr, each_size, 0, 0))

        # write unsorted bin
        for [addr, size] in unsorted_bins:
            lf.write("U|0x%x|0x%x|%d|%d|0\n" % (addr, size, 0, 0))

        lf.close()

    def update_heap_layout(self, chunks, holes, fuzz_index):
        '''
        write layout info to files and get info from file
        '''

        self.dump_layout_to_file(chunks, holes, fuzz_index)
        updated_file_name = "fuzz_result/tmp_fuzz_layout.%d" % fuzz_index
        updated_heap_layout = get_heap_layout_from_file(updated_file_name)

        return updated_heap_layout, updated_file_name

    def get_holes_and_chunks(self, full_op_list, hp):

        simple_op_list = []
        global_alloc_index = 1
        global_allocs = {}
        for each_op in full_op_list:
            if each_op.op_type == 'M':
                info = each_op.malloc_size
                global_allocs[global_alloc_index] = each_op.pname + '|' + str(each_op.op_index)
                global_alloc_index += 1
            else:
                info = each_op.free_malloc_index
            simple_op_list.append([each_op.op_type, info, each_op.pnum, each_op.op_index])

        holes, chunks = hp.get_holes_for_fuzzer(simple_op_list)

        ## we could generate source code if needed
        # if self.generate_c_source:
        #     cg = CGenerator(1, full_op_list, self.target_hole_addr, self.target_hole_size)
        #     cg.do_generate()
        return holes, chunks

    def do_seed_variation(self, original_prim_list):
        '''
        we use some mutation strategy to change the  prim seqs.
        '''
        random.seed(datetime.datetime.now())
        new_prim_list = copy.deepcopy(original_prim_list)
        variation_methods_list = [1, 2, 3, 4]


        if len(original_prim_list) == 0:
            variation_method = 0
        else:
            variation_method = random.choice(variation_methods_list)

        ## add some primitives
        if variation_method == 0:
            times = random.randint(1, 10)
            for j in range(0, times):
                p_name = random.choice(list(self.all_prims.keys()))
                insert_prim = self.all_prims[p_name]
                new_prim_list.insert(j, insert_prim)

        ## add one primitive
        if variation_method == 1:
            t_prim = random.choice(new_prim_list)
            t_index = new_prim_list.index(t_prim)
            insert_prim = self.all_prims[random.choice(self.all_prims)]
            new_prim_list.insert(t_index, insert_prim)

        ## del one primitive
        elif variation_method == 2:
            del_prim = random.choice(new_prim_list)
            new_prim_list.remove(del_prim)

        ## exchange 2 primitive positions
        elif variation_method == 3:
            t_prim_1 = random.choice(new_prim_list)
            t_index_1 = new_prim_list.index(t_prim_1)
            t_prim_2 = random.choice(new_prim_list)
            t_index_2 = new_prim_list.index(t_prim_2)

            if t_index_1 != t_index_2:
                new_prim_list[t_index_1] = original_prim_list[t_index_2]
                new_prim_list[t_index_2] = original_prim_list[t_index_1]
            else:
                new_prim_list[0] = original_prim_list[t_index_2]
                new_prim_list[-1] = original_prim_list[t_index_1]

        ## splice the op_list
        t_prim = random.choice(new_prim_list)
        t_index = new_prim_list.index(t_prim)
        if t_index < len(new_prim_list)/2:
            new_prim_list = original_prim_list[:t_index] + original_prim_list[:t_index]
        else:
            new_prim_list = original_prim_list[t_index:] + original_prim_list[t_index:]

        return new_prim_list


    def calculate_testcase_score(self, testcase_uid, distance_key):
        less_similarity = 1
        if len(self.distance_pair_key) == 1:
            self.testcase_score_list[testcase_uid] = 0.5
            return

        for each_uid in self.distance_pair_key:
            each_key = self.distance_pair_key[each_uid]
            similarity = difflib.SequenceMatcher(None, each_key, distance_key).ratio()
            if similarity < less_similarity:
                less_similarity = similarity

        testcase_score = 1 - less_similarity
        self.testcase_score_list[testcase_uid] = testcase_score
        return

    def select_new_seed_from_testcase(self):
        random.seed(datetime.datetime.now())
        max_score = 0
        testcase_uid = 0
        for each_uid in self.testcase_score_list:
            score = self.testcase_score_list[each_uid]
            if score > max_score:
                testcase_uid = each_uid
        t_prim = self.seed_list[testcase_uid]
        new_prim =  self.do_seed_variation(t_prim)
        return new_prim

    def add_seed2testcase(self, prim_list):
        self.seed_list.append(prim_list)

    def fuzz_master(self):

        res = 0
        # self.init_layout.dump_layout()
        heap_layout = copy.deepcopy(self.init_layout)
        heap_file_name = INIT_LAYOUT_PATH
        hp = HoleParser()

        init_prim_list = []
        prim_uid = uuid.uuid1()
        self.seed_list[prim_uid]= copy.deepcopy(init_prim_list)

        while res == 0:
            ## init the fuzz dir
            fuzz_dir_path = "fuzz_result"

            if not os.path.exists(fuzz_dir_path):
                os.makedirs(fuzz_dir_path)

            for file in os.listdir(fuzz_dir_path):
                os.remove(fuzz_dir_path + "/" + file)

            res, updated_heap_layout, fuzz_prim_list = self.fuzz_primitive_list_by_distance(hp, heap_layout, heap_file_name, init_prim_list, prim_uid)

            if res == 0:
                self.fuzz_op_list = []
                distance_key = self.distance_pair_key[prim_uid]
                self.calculate_testcase_score(prim_uid, distance_key)
                init_prim_list =  self.select_new_seed_from_testcase()
                prim_uid = uuid.uuid1()
                self.seed_list[prim_uid] = init_prim_list

        if res == -1:
            hp.close_socket()
            return None, None, None

        if res == 1:
            hp.close_socket()
            ## judge the target_chunk index in the tcache
            free_lists = updated_heap_layout.get_free_lists()
            target_chain = free_lists[TARGET_HOLE_SIZE][0]
            target_hole_index = target_chain.chunks.index(TARGET_CHUNK_ADDR)
            fuzz_distance = LENGTH_LIMIT - target_hole_index
            fuzz_op_list  = []

            for each_prim in fuzz_prim_list:
                fuzz_op_list += each_prim.operation_list

            return fuzz_op_list, updated_heap_layout, fuzz_distance


    def fix_fuzz_side_effect(self, hp, fuzz_index, updated_heap_layout, updated_file_name):

        occupy_primitive, occupy_index = self.find_occupy_target_op(hp)

        t_op = occupy_primitive.operation_list[occupy_index]

        if t_op.op_type != "M":
            print "weried.....maybe "
            return

        self.has_fixed = True
        fix_hole_size = t_op.malloc_size + 2 * SIZE_SZ

        fix_prim = self.get_primitive_by_ability(fix_hole_size)

        tmp_op_list = copy.deepcopy(self.fuzz_op_list)
        op_len = len(self.fuzz_prim_list[-1].operation_list)
        self.fuzz_op_list = tmp_op_list[: 0 - op_len]

        for fix_prim in fix_prim:
            fix_op_list = self.execute_prim_op_list(fix_prim, updated_heap_layout, updated_file_name)
            if len(fix_op_list) == 0:
                continue
            fix_full_op_list = self.base_op_list + self.fuzz_op_list + fix_op_list
            holes, chunks = self.get_holes_and_chunks(fix_full_op_list, hp)
            updated_heap_layout, updated_file_name = self.update_heap_layout(chunks, holes, fuzz_index)
            target_distance = updated_heap_layout.get_distance_to_target_hole(self.target_hole_addr,
                                                                              self.target_hole_size)

            if target_distance > 0:
                self.fuzz_op_list += fix_op_list
                break

            return updated_heap_layout, updated_file_name

    def fuzz_primitive_list_by_distance(self, hp, heap_layout, heap_file, init_prim_list, prim_uid):

        fuzz_index = 0
        try_fuzz_times = 0
        stop_fuzz = False
        distance_key = ''
        updated_heap_layout = copy.deepcopy(heap_layout)
        updated_file_name = heap_file
        random.seed(datetime.datetime.now())
        self.fuzz_prim_list = copy.deepcopy(init_prim_list)

        for each_prim in self.fuzz_prim_list:
            new_fuzz_op_list = self.execute_prim_op_list(each_prim, updated_heap_layout, updated_file_name)
            if len(new_fuzz_op_list) == 0:
                self.fuzz_prim_list.remove(each_prim)
            else:
                self.fuzz_op_list += new_fuzz_op_list
                full_op_list = self.base_op_list + self.fuzz_op_list
                holes, chunks = self.get_holes_and_chunks(full_op_list, hp)
                updated_heap_layout, updated_file_name = self.update_heap_layout(chunks, holes, fuzz_index)
                target_distance = updated_heap_layout.get_distance_to_target_hole(self.target_hole_addr,
                                                                                  self.target_hole_size)
                distance_key += str(target_distance)

        while not stop_fuzz:

            ## step 1 : add one executed primitive....
            new_fuzz_op_list  = []
            already_use_name_list = []
            while len(new_fuzz_op_list) == 0  and len(already_use_name_list) < len(self.all_prims):
                select_prim_name = random.choice(self.all_prims.keys())
                select_prim = copy.deepcopy(self.all_prims[select_prim_name])
                already_use_name_list.append(select_prim_name)
                new_fuzz_op_list = self.execute_prim_op_list(select_prim, updated_heap_layout, updated_file_name)

            ## if all the primitive cannot be executed....
            if len(new_fuzz_op_list) == 0:
                print "can not find primitive to execute, all primitive can not be executed"
                try_op_list = copy.deepcopy(self.fuzz_op_list)
                return 0, 0, try_op_list, self.fuzz_prim_list[:-1]

            self.fuzz_prim_list.append(select_prim)
            self.fuzz_op_list += new_fuzz_op_list
            print select_prim

            full_op_list = self.base_op_list + self.fuzz_op_list

            holes, chunks = self.get_holes_and_chunks(full_op_list, hp)

            ## dump heap layout to file
            updated_heap_layout, updated_file_name = self.update_heap_layout(chunks, holes, fuzz_index)
            # updated_heap_layout.dump_layout()

            stop_fuzz = self.if_in_linear_free_list(updated_heap_layout)

            target_distance = updated_heap_layout.get_distance_to_target_hole(self.target_hole_addr, self.target_hole_size)
            distance_key +=str(target_distance)
            print target_distance

            fuzz_index += 1

            if self.if_in_dangerous_area(updated_heap_layout):

                try_fuzz_times += 1
                print "[-] The target hole drops into red zone, fuzz fail, please fuzz again."
                self.distance_pair_key[prim_uid] = distance_key
                return 0, 0, self.fuzz_prim_list[:-1]

            elif target_distance < 0:
                print "[!] The target hole is occupied, please fix it."
                try_fuzz_times += 1
                if try_fuzz_times > 50:
                    updated_heap_layout, updated_file_name = self.fix_fuzz_side_effect(hp, fuzz_index, updated_heap_layout, updated_file_name)
                else:
                    self.distance_pair_key[prim_uid] = distance_key
                    return 0, 0, self.fuzz_prim_list[:-1]

            elif self.if_in_linear_free_list(updated_heap_layout):
                return 1, updated_heap_layout, self.fuzz_prim_list

            if try_fuzz_times > 1000:
                print "[-] Fuzz too many times, fuzz fail"
                return -1, -1, [], []

    def find_occupy_target_op(self, hp):

        t_primitive = self.fuzz_prim_list[-1]
        t_prim_len = len(t_primitive.operation_list)

        for index in range(0, t_prim_len):
            full_op_list = self.base_op_list + self.fuzz_op_list[:0 - t_prim_len + index + 1]
            holes, chunks = self.get_holes_and_chunks(full_op_list, hp)
            occupied = True
            for each_hole_info in holes:
                if self.target_hole_addr == each_hole_info[0]:
                    occupied  = False
            if occupied:
                return t_primitive, index



    def get_primitive_by_ability(self, chunk_size):

        prim_list = []
        for primitive_name in self.all_prims:
            primitive = self.all_prims[primitive_name]
            prim_abi =  PrimitiveAbility(primitive, chunk_size)
            all_abis = prim_abi.get_all_abi_list_for_one_primitive(primitive, chunk_size)
            for each_abi in all_abis:
                if each_abi >= 0 and primitive not in prim_list:
                    prim_list.append(primitive)
        return prim_list

    def if_in_dangerous_area(self, heap_layout):

        free_lists = heap_layout.get_free_lists()

        if self.target_hole_addr in free_lists[self.target_hole_size][-1].chunks and free_lists[self.target_hole_size][-1].can_ms is True:
            index  = free_lists[self.target_hole_size][-1].chunks.index(self.target_hole_addr)
            if index == 0:
                return True
        return False


    def if_in_linear_free_list(self, heap_layout):

        free_lists = heap_layout.get_free_lists()

        if self.target_hole_addr in free_lists[self.target_hole_size][0].chunks and free_lists[self.target_hole_size][0].can_ms is False:
            return True

        elif self.target_hole_addr in free_lists[self.target_hole_size][-1].chunks and free_lists[self.target_hole_size][-1].can_ms is False:
            return True

        elif self.target_hole_addr in free_lists[self.target_hole_size][-1].chunks and free_lists[self.target_hole_size][-1].can_ms is True:
            return False

        print "the target hole is be occupoed, stop fuzz."

        return False


    def execute_prim_op_list(self, primitive, heap_layout, updated_file_name):

        allocated_chunks = heap_layout.get_allocated_chunks()
        op_list = []
        for t_op in primitive.operation_list:
            each_op = copy.deepcopy(t_op)
            cp_allocated_chunks = copy.deepcopy(allocated_chunks)

            if each_op.op_type == "M":
                if each_op.malloc_size < 0:
                    each_op.malloc_size = self.target_hole_size - 2*SIZE_SZ

            elif each_op.op_type == "F":
                find_malloc_op = False
                for each_size in cp_allocated_chunks:
                    for each_allocated_chunk in cp_allocated_chunks[each_size]:
                        each_addr = each_allocated_chunk.addr
                        primitive_name = each_allocated_chunk.primitive_name
                        op_index = each_allocated_chunk.op_index
                        if primitive_name == each_op.free_target and op_index == each_op.free_malloc_index:
                            each_op.free_chunk_size = each_size
                            each_op.free_chunk_addr = each_addr
                            find_malloc_op = True
                if not find_malloc_op:
                    return []
            else:
                return
            op_list.append(each_op)

        new_op_list = dump_final_op_list(updated_file_name, BASE_OP_LIST_PATH, op_list)
        primitive.operation_list = copy.deepcopy(new_op_list)
        return new_op_list








if __name__ == "__main__":
    target_area = [4,5,6,7]
    plg = FuzzHole(target_area)
    new_distance, op_list = plg.fuzz_primitive_list_by_distance()
    for op in op_list:
        print op


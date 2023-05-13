import os
import socket
import struct
import time
import subprocess
#import commands

HOST = ''
PORT = 1500
MSG_MAX_SIZE = 3
FILE_ADDR = "./input.txt"

ALLOCATED_CHUNK = 1
HOLE_TCACHE_BIN = 2
HOLE_FAST_BIN   = 3
HOLE_NORMAL_BIN = 4
HOLE_UNSORTED_BIN = 5
TOP_CHUNK = 6
HOLE_LAST_REMAINDER = 7
HOLE_INFO_SIZE = 27


class HoleParser:
    def __init__(self):
        self._target_fd = None
        self._socket_init = False
        self.dev_null_fd = None

        with open('/proc/sys/kernel/randomize_va_space', 'r') as f:
            status = f.read(1)
            if status in ['2', '1']:
                print("ERROR: You MUST turn off ASLR!!!")
                exit(0)

    def _parse_holes(self, send_buff):
        holes = []
        chunks = []
        self._target_fd.send('N')
        while True:
            cmd = ''
            while len(cmd) < MSG_MAX_SIZE:
                cmd += self._target_fd.recv(MSG_MAX_SIZE)
            
            if cmd == "111":
                self._target_fd.sendall(struct.pack("<L", len(send_buff)))
                self._target_fd.sendall(send_buff)

            elif cmd == "222":
                while 1:
                    data = self._target_fd.recv(HOLE_INFO_SIZE)
                    cur_hole_addr, cur_hole_size, cur_hole_type, cur_prim_num, cur_op_index, cur_alloc_index = struct.unpack("<QQBBBQ",data)
                    if cur_hole_addr == 0xdeadbeef:
                        break
                    cur_hole_size &= ~7
                    if cur_hole_type not in [ALLOCATED_CHUNK, TOP_CHUNK]:
                        holes.append([cur_hole_addr, cur_hole_size, cur_hole_type, cur_prim_num, cur_op_index, cur_alloc_index])
                    else:
                        chunks.append([cur_hole_addr, cur_hole_size, cur_hole_type, cur_prim_num, cur_op_index, cur_alloc_index])

            elif cmd == "000":
                break

            elif cmd == "EEE":
                print("SERVER: SIMULATOR RECEIVE ERROR\n")
                self._target_fd.send('Q')
                break
        return holes, chunks
    
    def get_data_from_file(self, file_path):
        if not os.path.isfile(file_path):
            print "Cannot find file at %s" % file_path
            return None
    
        print("SERVER: Data Loaded from:%s" % file_path)
        with open(file_path, 'r') as f:
            data_buff = f.read()
            m = map(int,data_buff.split(' '))
            print(type(m))
            send_buff = struct.pack("%ui"%len(m), *m)
    
        return send_buff
    
    
    def _init_socket(self):
        server_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_fd.bind((HOST,PORT)) 
    
        server_fd.listen(1)
        print ("SERVER: Listening port %d\n" % PORT) 
    
        self._target_fd, new_fd_addr = server_fd.accept()
        print ("SERVER: SIMULATOR knock knock!\n")
    
    
    def get_holes_for_single_file(self, file_path):

        data = self.get_data_from_file(file_path)
        
        if not self._socket_init:
            self._init_socket()
            self._socket_init = True
    
        return self._parse_holes(data)
    
    
    def get_holes_for_fuzzer(self, op_list):

        data = []
        for [op, info, pnum, op_index] in op_list:
            if op == 'M':
                data.append(1)
                data.append(info)
                data.append(pnum)
                data.append(op_index)
            elif op == 'F':
                data.append(0)
                data.append(info)
                data.append(pnum)
                data.append(op_index)
            else:
                pass

        data.append(-1)
        data.append(-1)
        data.append(-1)
        data.append(-1)

        data.append(-2)
        data.append(-2)
        data.append(-2)
        data.append(-2)

        send_buff = struct.pack("%ui" % len(data), *data)

        if not self._socket_init:
            print("not init!!!!!!!!!!!!!!!!!!!!!!!!!")
            self.dev_null_fd = open('/dev/null', 'w')
            subprocess.Popen("/home/usera/benchmark/heap_helper/client", shell=True,stdout =self.dev_null_fd,stderr= subprocess.PIPE)
            self._init_socket()
            self._socket_init = True
    
        return self._parse_holes(send_buff)


    def close_socket(self):
        self._target_fd.send('Q')
        self._target_fd.close()
        if self.dev_null_fd is not None:
            self.dev_null_fd.close()


if __name__ == "__main__":
    #hp.get_holes_for_single_file(FILE_ADDR)
    #hp.close_socket()
    hp = HoleParser()
    op_list = [['M', 12, 1, 0], ['M', 12, 1, 2], ['M', 12, 2, 0]]
    for i in range(0, 3):
        print(i)
        hp.get_holes_for_fuzzer(op_list)
    hp.close_socket()



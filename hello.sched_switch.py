#!/usr/bin/python3  
# -*- coding: utf-8 -*-
from bcc import BPF
import ctypes as ct

program = r"""
struct cmd_name_t {
   char cmd[16];
};

const char my_exe_name[ 16 ] = "hello.sched_swit";

BPF_HASH(switch_table, u32, struct cmd_name_t);

BPF_PERF_OUTPUT(output); 

        
struct data_t {
        unsigned long long pad;
        char prev_comm[16];
        int prev_pid;
        int prev_prio;
        long long prev_state;
        char next_comm[16];
        int next_pid;
        int next_prio;
        char message[12];
};

int hello(void *ctx) {
   struct data_t *data; 
   struct user_msg_t *p;
   char message[12] = "Hello World";
   u64 uid;
   u64 *p;
   u64 counter = 0;

   if( ctx != NULL)
      data = (struct data_t *) ctx;
        
   if( strncmp( data->prev_comm, my_exe_name, 16 ) == 0 ){
        bpf_trace_printk("sched_switch(): old: %s, new: %s\n",
                        data->prev_comm, data->next_comm );

        uid = data->next_pid & 0xFFFFFFFF;
        p = switch_table.lookup( &uid );

        if( p != 0 ){
            counter = *p;
        }
        counter++;
        switch_table.update( &uid, &counter );

   return 0;
}
"""

bpf_ctx = BPF( text = program )
bpf_ctx .attach_tracepoint( tp ="sched:sched_switch",
                      fn_name = "hello" )

bpf_ctx.trace_print();

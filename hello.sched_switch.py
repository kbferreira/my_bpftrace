#!/usr/bin/python3  
# -*- coding: utf-8 -*-
from bcc import BPF
import ctypes as ct

program = r"""
struct user_msg_t {
   char message[12];
};

BPF_HASH(config, u32, struct user_msg_t);

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

   if( ctx != NULL)
      data = (struct data_t *) ctx;
        
   bpf_trace_printk("sched_switch(): Hello World!");
   return 0;
}
"""

bpf_ctx = BPF( text = program )
bpf_ctx .attach_tracepoint( tp ="sched:sched_switch",
                      fn_name = "hello" )

bpf_ctx.trace_print()

#!/usr/bin/python3  
# -*- coding: utf-8 -*-
from bcc import BPF
import ctypes as ct

program = r"""
#include <linux/string.h>

struct cmd_name_t {
   char cmd[16];
};

const char my_exe_name[ 16 ] = "hello.sched_swit";

BPF_HASH(switch_table, u32, u32);


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
   char message[12] = "Hello World";
   u32 uid;
   u32 *p;
   u32 counter = 0;

   if( ctx != NULL){
      data = (struct data_t *) ctx;
   }
   bpf_trace_printk("sched_switch(): old: %s, new: %s\n",
                        data->prev_comm, data->next_comm );
   return 0;
}

int lookat_switch(void *ctx) {
   struct data_t *data; 
   u32 uid;
   u32 *p;
   u32 counter = 0;

   if( ctx != NULL){
      data = (struct data_t *) ctx;
   }

   if( strncmp( data->prev_comm, my_exe_name, 16 ) == 0 ){
        bpf_trace_printk("sched_switch(): next: %s\n",
                        data->next_comm );

        uid = data->next_pid & 0xFFFFFFFF;
        p = switch_table.lookup( &uid );

        if( p != 0 ){
            counter = *p;
        }
        counter++;
        switch_table.update( &uid, &counter );
   }

   return 0;
}

"""

bpf_ctx = BPF( text = program )
bpf_ctx.attach_tracepoint( tp ="sched:sched_switch",
                      fn_name = "lookat_switch" )

bpf_ctx.trace_print();

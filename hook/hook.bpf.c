//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// function_parameter stores information about a single parameter to a function.
typedef struct function_parameter {
    // Type of the parameter as defined by the reflect.Kind enum.
    unsigned int kind;
    // Size of the variable in bytes.
    unsigned int size;

    // Offset from stack pointer. This should only be set from the Go side.
    int offset;

    // If true, the parameter is passed in a register.
    bool in_reg;
    // The number of register pieces the parameter is passed in.
    int n_pieces;
    // If in_reg is true, this represents the registers that the parameter is passed in.
    // This is an array because the number of registers may vary and the parameter may be
    // passed in multiple registers.
    int reg_nums[6];

    // The following are filled in by the eBPF program.
    size_t daddr;   // Data address.
    char val[0x30];       // Value of the parameter.
    char deref_val[0x30]; // Dereference value of the parameter.
} function_parameter_t;

// function_parameter_list holds info about the function parameters and
// stores information on up to 6 parameters.
typedef struct function_parameter_list {
    //unsigned int goid_offset; // Offset of the goid struct member.
    //long long g_addr_offset;  // Offset of the Goroutine struct from the TLS segment.
    //int goroutine_id;

    unsigned long long int fn_addr;
    unsigned int n_parameters;          // number of parameters.
    function_parameter_t params[6];     // list of parameters.

    //unsigned int n_ret_parameters;      // number of return parameters.
    //function_parameter_t ret_params[6]; // list of return parameters.
} function_parameter_list_t;


char __license[] SEC("license") = "Dual MIT/GPL";

struct {
    __uint(max_entries, 42);
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, function_parameter_list_t);
} arg_map SEC(".maps");



SEC("uprobe/hook")
int uprobe_hook(struct pt_regs *ctx){

	// read map
	function_parameter_list_t *args;
	uint64_t key = ctx->ip;

    args = bpf_map_lookup_elem(&arg_map, &key);
    if (!args) {
		bpf_printk("args not yet ready");
        return 1;
    }
	int len = 2;
	for(int idx=0;idx<len;idx++){
		// scrape value
        bpf_printk("args %d",idx);
        bpf_printk("args:  %d",args->params[idx].in_reg);
		
	}
	bpf_printk("hello");
	return 0;
}



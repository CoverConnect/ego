//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define STRING_KIND 24

// function_parameter stores information about a single parameter to a function.
typedef struct function_parameter
{
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
    size_t daddr;         // Data address.
    char val[0x30];       // Value of the parameter.
    char deref_val[0x30]; // Dereference value of the parameter.
} function_parameter_t;

typedef struct function_context
{
    uint64_t fn_addr;
    long unsigned int r15;
    long unsigned int r14;
    long unsigned int r13;
    long unsigned int r12;
    long unsigned int bp;
    long unsigned int bx;
    long unsigned int r11;
    long unsigned int r10;
    long unsigned int r9;
    long unsigned int r8;
    long unsigned int ax;
    long unsigned int cx;
    long unsigned int dx;
    long unsigned int si;
    long unsigned int di;
    long unsigned int ip;
    long unsigned int cs;
    long unsigned int flags;
    long unsigned int sp;
    long unsigned int ss;

} function_context_t;

// function_parameter_list holds info about the function parameters and
// stores information on up to 6 parameters.
typedef struct function_parameter_list
{
    unsigned int goid_offset; // Offset of the `goid` struct member.
    long long g_addr_offset;  // Offset of the Goroutine struct from the TLS segment.
    int goroutine_id;

    unsigned long long int fn_addr;
    bool is_ret;

    unsigned int n_parameters;      // number of parameters.
    function_parameter_t params[6]; // list of parameters.

    unsigned int n_ret_parameters;      // number of return parameters.
    function_parameter_t ret_params[6]; // list of return parameters.

    function_context_t ctx;

} function_parameter_list_t;



char __license[] SEC("license") = "Dual MIT/GPL";

struct
{
    __uint(max_entries, 42);
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, function_parameter_list_t);
} context_map SEC(".maps");

#define BPF_MAX_VAR_SIZ (1 << 29)

// Ring buffer to handle communication of variable values back to userspace.
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, BPF_MAX_VAR_SIZ);
} events SEC(".maps");

SEC("uprobe/hook")
int uprobe_hook(struct pt_regs *ctx)
{

    function_parameter_list_t *tFnCtx;
    function_parameter_list_t *collectedTFnCtx;
    // function address  now we use ip for it
    uint64_t ip = ctx->ip;

    // get from go about the sp offset to read the memory
    tFnCtx = bpf_map_lookup_elem(&context_map, &ip);
    if (!tFnCtx)
    {
        bpf_printk("No trace point");
        return 1;
    }

    // prepare to send back the info
    collectedTFnCtx = bpf_ringbuf_reserve(&events, sizeof(function_parameter_list_t), 0);
    if (!collectedTFnCtx)
    {
        bpf_printk("No enough ringbuf for collectedTFnCtx");
        return 1;
    }

    // init collected

    for (int idx=0;idx<6;idx++){
        collectedTFnCtx->params[idx].in_reg = tFnCtx->params[idx].in_reg;
    }



    collectedTFnCtx->fn_addr = ip;

    // collect context
    collectedTFnCtx->ctx.r15 = ctx->r15;
    collectedTFnCtx->ctx.r14 = ctx->r14;
    collectedTFnCtx->ctx.r13 = ctx->r13;
    collectedTFnCtx->ctx.r12 = ctx->r12;

    collectedTFnCtx->ctx.bp = ctx->bp;
    collectedTFnCtx->ctx.bx = ctx->bx;

    collectedTFnCtx->ctx.r11 = ctx->r11;
    collectedTFnCtx->ctx.r10 = ctx->r10;
    collectedTFnCtx->ctx.r9 = ctx->r9;
    collectedTFnCtx->ctx.r8 = ctx->r8;

    collectedTFnCtx->ctx.ax = ctx->ax;
    collectedTFnCtx->ctx.cx = ctx->cx;
    collectedTFnCtx->ctx.dx = ctx->dx;
    collectedTFnCtx->ctx.si = ctx->si;
    collectedTFnCtx->ctx.di = ctx->di;

    collectedTFnCtx->ctx.ip = ctx->ip;
    collectedTFnCtx->ctx.cs = ctx->cs;
    collectedTFnCtx->ctx.sp = ctx->sp;
    collectedTFnCtx->ctx.ss = ctx->ss;

    bpf_ringbuf_submit(collectedTFnCtx, BPF_RB_FORCE_WAKEUP);

    return 0;
}

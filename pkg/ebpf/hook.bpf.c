//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include<bpf/bpf_core_read.h>

#define STRING_KIND 24
#define variable_num 6
// function_parameter stores information about a single parameter to a function.
typedef struct function_parameter
{
    char name[10];
    // unsigned int kind;
    //  Size of the variable in bytes.
    unsigned int size;
    // Offset from stack pointer. This should only be set from the Go side.
    int offset;
    // If true, the parameter is passed in a register.
    bool in_reg;
    // The number of register pieces the parameter is passed in.
    // int n_pieces;
    // If in_reg is true, this represents the registers that the parameter is passed in.
    // This is an array because the number of registers may vary and the parameter may be
    // passed in multiple registers.
    // int reg_nums[variable_num];

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
// stores information on up to variable_num parameters.
typedef struct function_parameter_list
{
    unsigned int goid_offset; // Offset of the `goid` struct member.
    unsigned int parent_goid_offset; // Offset of the `goid` struct member.

    long long g_addr_offset;  // Offset of the Goroutine struct from the TLS segment.
    int goroutine_id;
    int parent_goroutine_id;

    unsigned long long int fn_addr;
    bool is_ret;

    unsigned int n_parameters;                 // number of parameters.
    function_parameter_t params[variable_num]; // list of parameters.

    unsigned int n_ret_parameters;                 // number of return parameters.
    function_parameter_t ret_params[variable_num]; // list of return parameters.

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
} uprobe_events SEC(".maps");

// pipe
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, BPF_MAX_VAR_SIZ);
} uretprobe_events SEC(".maps");

__always_inline
int get_goroutine_id(function_parameter_list_t *parsed_args) {
    struct task_struct *task;
    size_t g_addr;
    __u64  goid;
    __u64  parent_goid;


    // Get the current task.
    task = (struct task_struct *)bpf_get_current_task();
    // Get the Goroutine ID which is stored in thread local storage.
    bpf_probe_read_user(&g_addr, sizeof(void *), (void*)(BPF_CORE_READ(task, thread.fsbase)+parsed_args->g_addr_offset));
    bpf_probe_read_user(&goid, sizeof(void *), (void*)(g_addr+parsed_args->goid_offset));
    bpf_probe_read_user(&parent_goid, sizeof(void *), (void*)(g_addr+parsed_args->parent_goid_offset));

    parsed_args->goroutine_id = goid;
    parsed_args->parent_goroutine_id =parent_goid;

    return 1;
}



__always_inline void collect_stack_value(function_parameter_list_t *paraList)
{

    long ret;
    for (int idx = 0; idx < variable_num; idx++)
    {
        if (paraList->params[idx].in_reg == false)
        {
            continue;
        }

        function_parameter_t *para = &paraList->params[idx];
        size_t addr = paraList->ctx.sp + para->offset;

        if (para->size > 0x30)
        {
            return;
        }

        ret = bpf_probe_read_user(&para->val, para->size, (void *)(addr));
        if (ret < 0)
        {
            bpf_printk("read memory error");
            return;
        }
        bpf_printk("read memory! idx: %d", idx);
    }
}

SEC("uprobe/hook")
int uprobe_hook(struct pt_regs *ctx)
{

    function_parameter_list_t *paraLlistTemplate;
    function_parameter_list_t *collectedParaList;
    // function address  now we use ip for it
    uint64_t ip = ctx->ip;

    // get from go about the sp offset to read the memory
    paraLlistTemplate = bpf_map_lookup_elem(&context_map, &ip);
    if (!paraLlistTemplate)
    {
        bpf_printk("No trace point");
        return 1;
    }

    // prepare to send back the info
    collectedParaList = bpf_ringbuf_reserve(&uprobe_events, sizeof(function_parameter_list_t), 0);
    if (!collectedParaList)
    {
        bpf_printk("No enough ringbuf for collectedParaList");
        return 1;
    }
    //get goid
    collectedParaList->g_addr_offset = paraLlistTemplate->g_addr_offset;
    collectedParaList->goid_offset = paraLlistTemplate->goid_offset;
    collectedParaList->parent_goid_offset = paraLlistTemplate->parent_goid_offset;

    

    if (!get_goroutine_id(collectedParaList)) {
        bpf_ringbuf_discard(paraLlistTemplate, 0);
        return 1;
    }



    // prepare collected information
    collectedParaList->n_parameters = paraLlistTemplate->n_parameters;

    // collect context
    collectedParaList->fn_addr = ip;

    collectedParaList->ctx.r15 = ctx->r15;
    collectedParaList->ctx.r14 = ctx->r14;
    collectedParaList->ctx.r13 = ctx->r13;
    collectedParaList->ctx.r12 = ctx->r12;

    collectedParaList->ctx.bp = ctx->bp;
    collectedParaList->ctx.bx = ctx->bx;

    collectedParaList->ctx.r11 = ctx->r11;
    collectedParaList->ctx.r10 = ctx->r10;
    collectedParaList->ctx.r9 = ctx->r9;
    collectedParaList->ctx.r8 = ctx->r8;

    collectedParaList->ctx.ax = ctx->ax;
    collectedParaList->ctx.cx = ctx->cx;
    collectedParaList->ctx.dx = ctx->dx;
    collectedParaList->ctx.si = ctx->si;
    collectedParaList->ctx.di = ctx->di;

    collectedParaList->ctx.ip = ctx->ip;
    collectedParaList->ctx.cs = ctx->cs;
    collectedParaList->ctx.sp = ctx->sp;
    collectedParaList->ctx.ss = ctx->ss;

    for (int idx = 0; idx < variable_num; idx++)
    {
        for (int idy = 0; idy < 10; idy++)
        {
            collectedParaList->params[idx].name[idy] = paraLlistTemplate->params[idx].name[idy];
        }

        // collectedParaList->params[idx].kind = paraLlistTemplate->params[idx].kind;
        collectedParaList->params[idx].in_reg = paraLlistTemplate->params[idx].in_reg;
        collectedParaList->params[idx].offset = paraLlistTemplate->params[idx].offset;
        collectedParaList->params[idx].size = paraLlistTemplate->params[idx].size;

        // add pieces
        /* for (int idy=0;idy<6; idy++){
             collectedParaList->params[idx].reg_nums[idy] = paraLlistTemplate->params[idx].reg_nums[idy];
         }
         */
        // collected Stack memory
        collect_stack_value(collectedParaList);
    }

    bpf_ringbuf_submit(collectedParaList, BPF_RB_FORCE_WAKEUP);

    return 0;
}

SEC("uretprobe/hook")
int uretprobe_hook(struct pt_regs *ctx)
{

    function_parameter_list_t *paraLlistTemplate;
    function_parameter_list_t *collectedParaList;
    // function address  now we use ip for it
    uint64_t ip = ctx->ip;

    // get from go about the sp offset to read the memory
    paraLlistTemplate = bpf_map_lookup_elem(&context_map, &ip);
    if (!paraLlistTemplate)
    {
        bpf_printk("No trace point");
        return 1;
    }

    // prepare to send back the info
    collectedParaList = bpf_ringbuf_reserve(&uretprobe_events, sizeof(function_parameter_list_t), 0);
    if (!collectedParaList)
    {
        bpf_printk("No enough ringbuf for collectedParaList");
        return 1;
    }
    // get goid
    collectedParaList->g_addr_offset = paraLlistTemplate->g_addr_offset;
    collectedParaList->goid_offset = paraLlistTemplate->goid_offset;
    collectedParaList->parent_goid_offset = paraLlistTemplate->parent_goid_offset;

    if (!get_goroutine_id(collectedParaList))
    {
        bpf_ringbuf_discard(paraLlistTemplate, 0);
        return 1;
    }

    // prepare collected information
    collectedParaList->n_parameters = paraLlistTemplate->n_parameters;

    // collect context
    collectedParaList->fn_addr = ip;

    collectedParaList->ctx.r15 = ctx->r15;
    collectedParaList->ctx.r14 = ctx->r14;
    collectedParaList->ctx.r13 = ctx->r13;
    collectedParaList->ctx.r12 = ctx->r12;

    collectedParaList->ctx.bp = ctx->bp;
    collectedParaList->ctx.bx = ctx->bx;

    collectedParaList->ctx.r11 = ctx->r11;
    collectedParaList->ctx.r10 = ctx->r10;
    collectedParaList->ctx.r9 = ctx->r9;
    collectedParaList->ctx.r8 = ctx->r8;

    collectedParaList->ctx.ax = ctx->ax;
    collectedParaList->ctx.cx = ctx->cx;
    collectedParaList->ctx.dx = ctx->dx;
    collectedParaList->ctx.si = ctx->si;
    collectedParaList->ctx.di = ctx->di;

    collectedParaList->ctx.ip = ctx->ip;
    collectedParaList->ctx.cs = ctx->cs;
    collectedParaList->ctx.sp = ctx->sp;
    collectedParaList->ctx.ss = ctx->ss;

    for (int idx = 0; idx < variable_num; idx++)
    {
        for (int idy = 0; idy < 10; idy++)
        {
            collectedParaList->params[idx].name[idy] = paraLlistTemplate->params[idx].name[idy];
        }

        // collectedParaList->params[idx].kind = paraLlistTemplate->params[idx].kind;
        collectedParaList->params[idx].in_reg = paraLlistTemplate->params[idx].in_reg;
        collectedParaList->params[idx].offset = paraLlistTemplate->params[idx].offset;
        collectedParaList->params[idx].size = paraLlistTemplate->params[idx].size;

        // add pieces
        /* for (int idy=0;idy<6; idy++){
             collectedParaList->params[idx].reg_nums[idy] = paraLlistTemplate->params[idx].reg_nums[idy];
         }
         */
        // collected Stack memory
        collect_stack_value(collectedParaList);
    }

    bpf_ringbuf_submit(collectedParaList, BPF_RB_FORCE_WAKEUP);

    return 0;
}

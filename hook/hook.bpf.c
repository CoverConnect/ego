// go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define STRING_KIND 24

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

char __license[] SEC("license") = "Dual MIT/GPL";

struct
{
    __uint(max_entries, 42);
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, function_context_t);
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

    function_context_t *tFnCtx;
    function_context_t *collectedTFnCtx;

    /*
        tFnCtx = bpf_map_lookup_elem(&context_map, &key);
        if (!tFnCtx)
        {
            bpf_printk("No trace point");
            return 1;
        }
    */
    collectedTFnCtx = bpf_ringbuf_reserve(&events, sizeof(function_context_t), 0);
    if (!collectedTFnCtx)
    {
        bpf_printk("No enough ringbuf for collectedTFnCtx");
        return 1;
    }

    // function address  now we use ip for it
    uint64_t ip = ctx->ip;

    collectedTFnCtx->fn_addr = ip;

    // collect context
    collectedTFnCtx->r15 = ctx->r15;
    collectedTFnCtx->r14 = ctx->r14;
    collectedTFnCtx->r13 = ctx->r13;
    collectedTFnCtx->r12 = ctx->r12;

    collectedTFnCtx->bp = ctx->bp;
    collectedTFnCtx->bx = ctx->bx;

    collectedTFnCtx->r11 = ctx->r11;
    collectedTFnCtx->r10 = ctx->r10;
    collectedTFnCtx->r9 = ctx->r9;
    collectedTFnCtx->r8 = ctx->r8;

    collectedTFnCtx->ax = ctx->ax;
    collectedTFnCtx->cx = ctx->cx;
    collectedTFnCtx->dx = ctx->dx;
    collectedTFnCtx->si = ctx->si;
    collectedTFnCtx->di = ctx->di;

    collectedTFnCtx->ip = ctx->ip;
    collectedTFnCtx->cs = ctx->cs;
    collectedTFnCtx->sp = ctx->sp;
    collectedTFnCtx->ss = ctx->ss;

    bpf_ringbuf_submit(collectedTFnCtx, BPF_RB_FORCE_WAKEUP);

    return 0;
}

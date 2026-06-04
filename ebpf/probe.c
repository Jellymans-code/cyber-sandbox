#define BPF_NO_GLOBAL_DATA
typedef unsigned int u32;

#define SEC(NAME) __attribute__((section(NAME), used))

static long (*bpf_printk)(const char *fmt, u32 fmt_size, ...) = (void *) 6;

SEC("tracepoint/syscalls/sys_enter_execve")
int detect_exec(void *ctx) {
    char msg[] = "SANDBOX ALARM: A program just tried to execute something!\n";
    bpf_printk(msg, sizeof(msg));
    return 0;
}

char _license[] SEC("license") = "GPL";

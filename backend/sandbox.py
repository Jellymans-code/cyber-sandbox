from bcc import BPF
import docker
import time
import sys

def main():

    print("Connecting to Docker engine...")
    try:
        client = docker.from_env()
    except Exception as e:
        print(f"Failed to connect to Docker: {e}")
        sys.exit(1)

    print("Booting isolated sandbox environment...")
    try:
        container =  client.containers.run(
            image = "alpine",
            command = ["sh", "-c", "sleep 3; cat /etc/passwd; sleep 3"],
            detach = True,
            network_mode = "none",
            mem_limit= "64m",
            nano_cpus = 500000000
        )
    except Exception as e:
        print(f"Failed to create container: {e}")
        sys.exit(1)
    
    print(f"Container {container.short_id} is now running")

    container.reload()
    target_pid = container.attrs['State']['Pid']

    ebpf_source_code = f"""
    #include <linux/sched.h>

    struct data_t {{
        u32 pid;
        char command[TASK_COMM_LEN];
    }};

    BPF_PERF_OUTPUT(events);

    int detect_process_execution(void *content) {{
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        
        struct data_t data = {{}};
        data.pid = pid;
        bpf_get_current_comm(&data.command, sizeof(data.command));

        events.perf_submit(content, &data, sizeof(data));
        return 0;
    }}
    """
    print("Loading eBPF monitor...")
    try:
        bpf_monitor = BPF(text = ebpf_source_code)
        bpf_monitor.attach_tracepoint(tp = "syscalls:sys_enter_execve", fn_name = "detect_process_execution")
    except Exception as e:
        print(f"Failed to load eBPF progran. Error: {e}")
        sys.exit(1)
    print("eBPF monitor is live")

    def print_event(cpu, data, size):
        event = bpf_monitor["events"].event(data)
        cmd = event.command.decode('utf-8')
        if cmd in ["sh", "sleep", "cat"]:
            print(f"[Sandbox Alert] PID: {event.pid} executed command: {cmd}")
    bpf_monitor["events"].open_perf_buffer(print_event)
    
    while container.status != "exited":
        container.reload()
        bpf_monitor.perf_buffer_poll()


    print("Cleaning up sandbox...")
    container.remove(force = True)
    print("Sandbox shut down safely")

if __name__ == "__main__":
    main()



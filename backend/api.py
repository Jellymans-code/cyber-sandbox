from fastapi import FastAPI, File, UploadFile
import uvicorn
import docker
from bcc import BPF
import time
import os

app = FastAPI(title="eBPF Sandbox API")
client = docker.from_env()

@app.get("/")
def health_check():
    return {"status": "Sandbox API is online and waiting."}

@app.post("/analyze")
async def analyze_payload(file: UploadFile = File(...)):
    print(f"\n--- New Analysis Request: {file.filename} ---")
    
    # Save the uploaded file locally
    file_path = f"/tmp/{file.filename}"
    with open(file_path, "wb") as buffer:
        buffer.write(await file.read())

    print("Booting idle sandbox...")
    container = client.containers.run(
        image="alpine",
        command=["tail", "-f", "/dev/null"],
        detach=True,
        network_mode="none",
        mem_limit="64m",
        nano_cpus=500000000,
        volumes={file_path: {'bind': f'/malware/{file.filename}', 'mode': 'ro'}}
    )
    container.reload()
    container_pid = container.attrs['State']['Pid']
    
    with open(f"/proc/{container_pid}/cgroup", "r") as f:
        cgroup_path = f.readline().split(":")[2].strip()
        if cgroup_path == "": 
            cgroup_path = "/"
            
    cgroup_id = os.stat(f"/sys/fs/cgroup{cgroup_path}").st_ino
    print(f"Locked onto Container cgroup ID: {cgroup_id}")
    
    print("Loading eBPF engine...")
    ebpf_source_code = f"""
    #include <linux/sched.h>
    
    struct data_t {{
        u32 pid;
        char command[256]; // Expanded buffer to hold full file paths
    }};
    
    BPF_PERF_OUTPUT(events);

    TRACEPOINT_PROBE(syscalls, sys_enter_execve) {{
        u64 target_cgroup = {cgroup_id};
        u64 current_cgroup = bpf_get_current_cgroup_id();

        if (current_cgroup != target_cgroup) {{
            return 0;
        }}

        u32 pid = bpf_get_current_pid_tgid() >> 32;
        struct data_t data = {{}};
        data.pid = pid;
        
        bpf_probe_read_user_str(&data.command, sizeof(data.command), args->filename);
        
        events.perf_submit(args, &data, sizeof(data));
        return 0;
    }}
    """
    bpf_monitor = BPF(text=ebpf_source_code)

    alerts = []
    def print_event(cpu, data, size):
        event = bpf_monitor["events"].event(data)
        cmd = event.command.decode('utf-8')
        
        alerts.append({"pid": event.pid, "command": cmd})
        print(f"[Alert] {cmd}")

    bpf_monitor["events"].open_perf_buffer(print_event)

    print(f"Detonating {file.filename} inside container...")
    
    # Use sh to execute the injected file
    container.exec_run(f"sh /malware/{file.filename}", detach=True)

    timeout = time.time() + 3
    while time.time() < timeout:
        bpf_monitor.perf_buffer_poll()
        time.sleep(0.1)

    print("Cleaning up...")
    container.remove(force=True)
    os.remove(file_path)

    return {
        "status": "Analysis Complete",
        "filename": file.filename,
        "threat_indicators": alerts
    }

if __name__ == "__main__":
    print("Starting eBPF API Server...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
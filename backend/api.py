from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import docker
from bcc import BPF
import time
import os
import shlex
import ctypes
import struct
from pathlib import Path
import hashlib
import math
import re
from collections import Counter

app = FastAPI(title="eBPF Sandbox API")
client = docker.from_env()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_FILE_SIZE = 5 * 1024 * 1024
MAXARG = 6
ARGLEN = 64
ARGV_BUF_SIZE = MAXARG * ARGLEN 

# Manual struct packing. BCC's ctypes generation truncates char arrays 
# at the first null byte, which breaks the argv array.
# Layout: u32 pid, u32 ppid, u64 timestamp, char command[256], char argv_buf[ARGV_BUF_SIZE]
EVENT_FORMAT = f"<IIQ256s{ARGV_BUF_SIZE}s"
EVENT_SIZE = struct.calcsize(EVENT_FORMAT)


@app.get("/")
def health_check():
    return {"status": "Sandbox API is online."}


def build_exec_command(container_path: str, raw_bytes: bytes) -> str:
    """
    Prepare execution command based on file type. 
    ELFs require a writable tmp dir to chmod +x, scripts can be piped directly to sh.
    """
    is_elf = raw_bytes[:4] == b"\x7fELF"

    if is_elf:
        return (
            f"sh -c 'cp {shlex.quote(container_path)} /tmp/sample "
            f"&& chmod +x /tmp/sample && /tmp/sample'"
        )
    else:
        return f"sh {shlex.quote(container_path)}"


def build_process_tree(alerts):
    """Convert flat process list into a parent-child relationship tree."""
    nodes = {
        a["pid"]: {
            "pid": a["pid"],
            "ppid": a["ppid"],
            "command": a["command"],
            "argv": a["argv"],
            "timestamp": a["timestamp"],
            "children": [],
        }
        for a in alerts
    }

    roots = []
    for pid, node in nodes.items():
        parent = nodes.get(node["ppid"])
        if parent and parent is not node:
            parent["children"].append(node)
        else:
            roots.append(node)

    return roots

def analyze_static(file_content: bytes) -> dict:
    """Analyze the file without executing it."""

    size = len(file_content)

    # Calculate Shannon entropy
    counts = Counter(file_content)

    entropy = 0.0

    if size > 0:
        entropy = -sum(
            (count / size) * math.log2(count / size)
            for count in counts.values()
        )

    # Detect basic file type
    if file_content.startswith(b"\x7fELF"):
        file_type = "ELF"
    elif file_content.startswith(b"MZ"):
        file_type = "PE"
    elif file_content.startswith(b"#!"):
        file_type = "Script"
    elif file_content.startswith(b"PK\x03\x04"):
        file_type = "ZIP"
    else:
        file_type = "Unknown"

    # Extract printable ASCII strings
    strings = re.findall(rb"[\x20-\x7E]{5,}", file_content)

    decoded_strings = [
        s.decode("ascii", errors="replace")
        for s in strings[:50]
    ]

    return {
        "size_bytes": size,
        "file_type": file_type,
        "entropy": round(entropy, 2),
        "is_high_entropy": entropy > 7.2,
        "extracted_strings": decoded_strings
    }

@app.post("/analyze")
async def analyze_payload(file: UploadFile = File(...)):
    print(f"[*] Analysis started: {file.filename}")

    safe_filename = Path(file.filename).name
    if not safe_filename or safe_filename in (".", ".."):
        raise HTTPException(status_code=400, detail="Invalid filename")

    file_content = await file.read()
    if len(file_content) == 0:
        raise HTTPException(status_code=400, detail="Empty file")
    if len(file_content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File too large")

    static_results = analyze_static(file_content)
    file_hash = hashlib.sha256(file_content).hexdigest()

    file_hash = hashlib.sha256(file_content).hexdigest()
    file_path = f"/tmp/{safe_filename}"
    with open(file_path, "wb") as buffer:
        buffer.write(file_content)

    container = None
    try:
        print("[*] Starting alpine sandbox...")
        container_path = f"/malware/{safe_filename}"
        container = client.containers.run(
            image="alpine",
            command=["tail", "-f", "/dev/null"],
            detach=True,
            network_mode="none",
            mem_limit="64m",
            nano_cpus=500000000,
            volumes={file_path: {'bind': container_path, 'mode': 'ro'}}
        )
        container.reload()
        container_pid = container.attrs['State']['Pid']

        with open(f"/proc/{container_pid}/cgroup", "r") as f:
            cgroup_path = f.readline().split(":")[2].strip()
            if cgroup_path == "":
                cgroup_path = "/"

        cgroup_id = os.stat(f"/sys/fs/cgroup{cgroup_path}").st_ino
        print(f"[*] Target cgroup ID: {cgroup_id}")

        print("[*] Compiling and attaching eBPF probe...")
        ebpf_source_code = f"""
        #include <linux/sched.h>

        #define MAXARG {MAXARG}
        #define ARGLEN {ARGLEN}

        struct data_t {{
            u32 pid;
            u32 ppid;
            u64 timestamp;
            char command[256];
            char argv_buf[{ARGV_BUF_SIZE}];
        }};

        BPF_PERCPU_ARRAY(data_map, struct data_t, 1);
        BPF_PERF_OUTPUT(events);

        TRACEPOINT_PROBE(syscalls, sys_enter_execve) {{
            u64 target_cgroup = {cgroup_id};
            u64 current_cgroup = bpf_get_current_cgroup_id();
            if (current_cgroup != target_cgroup) {{
                return 0;
            }}

            int zero = 0;
            struct data_t *data = data_map.lookup(&zero);
            if (!data) {{
                return 0;
            }}

            data->pid = bpf_get_current_pid_tgid() >> 32;
            data->timestamp = bpf_ktime_get_ns();
            data->ppid = 0;

            struct task_struct *task = (struct task_struct *)bpf_get_current_task();
            struct task_struct *parent = NULL;
            bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
            if (parent) {{
                bpf_probe_read_kernel(&data->ppid, sizeof(data->ppid), &parent->tgid);
            }}

            bpf_probe_read_user_str(&data->command, sizeof(data->command), args->filename);

            const char **argv = (const char **)(args->argv);

            #pragma unroll
            for (int i = 0; i < MAXARG; i++) {{
                const char *argp = NULL;
                bpf_probe_read_user(&argp, sizeof(argp), (void *)&argv[i]);
                if (argp) {{
                    bpf_probe_read_user_str(&data->argv_buf[i * ARGLEN], ARGLEN, argp);
                }} else {{
                    data->argv_buf[i * ARGLEN] = 0;
                }}
            }}

            events.perf_submit(args, data, sizeof(*data));
            return 0;
        }}
        """
        bpf_monitor = BPF(text=ebpf_source_code)
        alerts = []

        def print_event(cpu, data, size):
            raw = ctypes.string_at(data, EVENT_SIZE)
            pid, ppid, timestamp, command_raw, argv_raw = struct.unpack(EVENT_FORMAT, raw)

            cmd = command_raw.split(b'\x00', 1)[0].decode('utf-8', errors='replace')

            argv = []
            for i in range(MAXARG):
                chunk = argv_raw[i * ARGLEN:(i + 1) * ARGLEN]
                arg = chunk.split(b'\x00', 1)[0]
                if not arg:
                    break
                argv.append(arg.decode('utf-8', errors='replace'))

            alerts.append({
                "pid": pid,
                "ppid": ppid,
                "timestamp": timestamp,
                "command": cmd,
                "argv": argv,
            })
            print(f"  [+] EXEC: pid={pid} ppid={ppid} cmd={cmd} argv={argv}")

        bpf_monitor["events"].open_perf_buffer(print_event)

        exec_command = build_exec_command(container_path, file_content)
        print(f"[*] Executing payload: {safe_filename}")
        container.exec_run(exec_command, detach=True)

        timeout = time.time() + 3
        while time.time() < timeout:
            bpf_monitor.perf_buffer_poll(timeout=100)
            time.sleep(0.1)

        executed_binaries = [alert["command"].split("/")[-1] for alert in alerts]
        print("[*] Analysis complete.")
        return {
            "filename": safe_filename,
            "sha256": file_hash,
            "static_analysis": static_results,
            "processes_spawned": len(alerts),
            "commands_executed": executed_binaries,
            "process_tree": build_process_tree(alerts),
        }

    finally:
        print("[*] Cleaning up...")
        if container is not None:
            try:
                container.remove(force=True)
            except Exception as e:
                print(f"[!] Warning: container cleanup failed: {e}")
        if os.path.exists(file_path):
            os.remove(file_path)


if __name__ == "__main__":
    print("Starting eBPF API Server...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
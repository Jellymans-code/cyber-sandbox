from fastapi import FastAPI, File, UploadFile, HTTPException
import uvicorn
import docker
from bcc import BPF
import time
import os
import shlex
from pathlib import Path
import hashlib

app = FastAPI(title="eBPF Sandbox API")
client = docker.from_env()

MAX_FILE_SIZE = 5 * 1024 * 1024


@app.get("/")
def health_check():
    return {"status": "Sandbox API is online and waiting."}


def build_exec_command(container_path: str, raw_bytes: bytes) -> str:

    is_elf = raw_bytes[:4] == b"\x7fELF"

    if is_elf:
        return (
            f"sh -c 'cp {shlex.quote(container_path)} /tmp/sample "
            f"&& chmod +x /tmp/sample && /tmp/sample'"
        )
    else:
        return f"sh {shlex.quote(container_path)}"


@app.post("/analyze")
async def analyze_payload(file: UploadFile = File(...)):
    print(f"\n--- New Analysis Request: {file.filename} ---")

    safe_filename = Path(file.filename).name
    if not safe_filename or safe_filename in (".", ".."):
        raise HTTPException(status_code=400, detail="Invalid filename")

    file_content = await file.read()
    if len(file_content) == 0:
        raise HTTPException(status_code=400, detail="Empty file")
    if len(file_content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File too large")

    file_hash = hashlib.sha256(file_content).hexdigest()
    file_path = f"/tmp/{safe_filename}"
    with open(file_path, "wb") as buffer:
        buffer.write(file_content)

    container = None
    try:
        print("Booting idle sandbox...")
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
        print(f"Locked onto Container cgroup ID: {cgroup_id}")

        print("Loading eBPF engine...")
        ebpf_source_code = f"""
        #include <linux/sched.h>

        struct data_t {{
            u32 pid;
            char command[256];
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
            cmd = event.command.decode('utf-8', errors='replace')
            alerts.append({"pid": event.pid, "command": cmd})
            print(f"[Alert] {cmd}")

        bpf_monitor["events"].open_perf_buffer(print_event)

        exec_command = build_exec_command(container_path, file_content)
        print(f"Detonating {safe_filename} inside container...")
        container.exec_run(exec_command, detach=True)

        timeout = time.time() + 3
        while time.time() < timeout:
            bpf_monitor.perf_buffer_poll(timeout=100)
            time.sleep(0.1)

        executed_binaries = [alert["command"].split("/")[-1] for alert in alerts]
        return {
            "filename": safe_filename,
            "sha256": file_hash,
            "processes_spawned": len(alerts),
            "commands_executed": executed_binaries,
        }

    finally:
        print("Cleaning up...")
        if container is not None:
            try:
                container.remove(force=True)
            except Exception as e:
                print(f"Warning: container cleanup failed: {e}")
        if os.path.exists(file_path):
            os.remove(file_path)


if __name__ == "__main__":
    print("Starting eBPF API Server...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
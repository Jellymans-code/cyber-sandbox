from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.concurrency import run_in_threadpool
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
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_FILE_SIZE = 5 * 1024 * 1024
MAXARG = 6
ARGLEN = 64
ARGV_BUF_SIZE = MAXARG * ARGLEN 

EVENT_FORMAT = f"<IIQ256s{ARGV_BUF_SIZE}s"
EVENT_SIZE = struct.calcsize(EVENT_FORMAT)

# Static Analysis Regex & Rules
IPV4_REGEX = re.compile(rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
URL_REGEX = re.compile(rb'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*')
SUSPICIOUS_KEYWORDS = [b"curl", b"wget", b"chmod +x", b"/dev/tcp", b"nc -e", b"bash -i", b"base64 -d"]

@app.get("/")
def health_check():
    return {"status": "Sandbox API is online."}

def build_exec_command(container_path: str, raw_bytes: bytes) -> str:
    is_elf = raw_bytes[:4] == b"\x7fELF"
    if is_elf:
        return (
            f"sh -c 'cp {shlex.quote(container_path)} /tmp/sample "
            f"&& chmod +x /tmp/sample && /tmp/sample'"
        )
    return f"sh {shlex.quote(container_path)}"

def build_process_tree(alerts):
    events = sorted(alerts, key=lambda a: a["timestamp"])
    last_node_for_pid = {}
    roots = []

    for alert in events:
        node = {
            "pid": alert["pid"],
            "ppid": alert["ppid"],
            "command": alert["command"],
            "argv": alert["argv"],
            "timestamp": alert["timestamp"],
            "children": [],
        }

        pid, ppid = alert["pid"], alert["ppid"]

        if pid in last_node_for_pid:
            last_node_for_pid[pid]["children"].append(node)
        else:
            parent = last_node_for_pid.get(ppid)
            if parent is not None and ppid != pid:
                parent["children"].append(node)
            else:
                roots.append(node)

        last_node_for_pid[pid] = node

    return roots

def assess_risk(static_results: dict, alerts: list) -> dict:
    reasons = []
    score = 0

    if static_results["is_high_entropy"]:
        reasons.append("High file entropy — may be packed, encrypted, or obfuscated.")
        score += 2

    if static_results["suspicious_keywords"]:
        reasons.append(
            f"Suspicious string(s) found in the file: {', '.join(static_results['suspicious_keywords'])} "
            "(this only means the text appears in the file — it may be a comment, not real behavior)."
        )
        score += 1

    executed_commands = {a["command"].split("/")[-1] for a in alerts}
    network_tools = {"curl", "wget", "nc", "ncat", "telnet"}
    ran_network_tool = executed_commands & network_tools
    if ran_network_tool:
        reasons.append(f"Actually executed at runtime: {', '.join(ran_network_tool)}.")
        score += 3

    shell_execs = sum(1 for a in alerts if a["command"].split("/")[-1] in ("sh", "bash"))
    if shell_execs >= 3:
        reasons.append(f"{shell_execs} nested shell executions — a common dropper/obfuscation pattern.")
        score += 2

    if score >= 5:
        verdict = "high_risk"
    elif score >= 2:
        verdict = "suspicious"
    else:
        verdict = "low_risk"

    return {"verdict": verdict, "score": score, "reasons": reasons}

def analyze_static(file_content: bytes) -> dict:
    size = len(file_content)
    entropy = 0.0

    if size > 0:
        counts = Counter(file_content)
        entropy = -sum((count / size) * math.log2(count / size) for count in counts.values())

    if file_content.startswith(b"\x7fELF"): file_type = "ELF Executable"
    elif file_content.startswith(b"MZ"): file_type = "PE Windows Executable"
    elif file_content.startswith(b"#!"): file_type = "Shell Script"
    elif file_content.startswith(b"PK\x03\x04"): file_type = "ZIP Archive"
    else: file_type = "Unknown Data"

    # Extract strings
    raw_strings = re.findall(rb"[\x20-\x7E]{5,}", file_content)
    decoded_strings = [s.decode("ascii", errors="replace") for s in raw_strings[:50]]

    # Extract network indicators
    ips = list(set([ip.decode('ascii') for ip in IPV4_REGEX.findall(file_content)]))
    urls = list(set([url.decode('ascii') for url in URL_REGEX.findall(file_content)]))

    # Detect suspicious indicators
    detected_suspicious = []
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in file_content:
            detected_suspicious.append(keyword.decode('ascii'))

    return {
        "size_bytes": size,
        "file_type": file_type,
        "entropy": round(entropy, 2),
        "is_high_entropy": entropy > 7.2,
        "extracted_strings": decoded_strings,
        "network_indicators": {"ips": ips, "urls": urls},
        "suspicious_keywords": detected_suspicious
    }

def run_sandbox(file_content: bytes, safe_filename: str, static_results: dict) -> dict:
    file_path = f"/tmp/{safe_filename}_{int(time.time())}"
    with open(file_path, "wb") as buffer:
        buffer.write(file_content)

    container = None
    alerts = []

    try:
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
            if (bpf_get_current_cgroup_id() != target_cgroup) return 0;

            int zero = 0;
            struct data_t *data = data_map.lookup(&zero);
            if (!data) return 0;

            data->pid = bpf_get_current_pid_tgid() >> 32;
            data->timestamp = bpf_ktime_get_ns();
            data->ppid = 0;

            struct task_struct *task = (struct task_struct *)bpf_get_current_task();
            struct task_struct *parent = NULL;
            bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
            if (parent) bpf_probe_read_kernel(&data->ppid, sizeof(data->ppid), &parent->tgid);

            bpf_probe_read_user_str(&data->command, sizeof(data->command), args->filename);
            const char **argv = (const char **)(args->argv);

            #pragma unroll
            for (int i = 0; i < MAXARG; i++) {{
                const char *argp = NULL;
                bpf_probe_read_user(&argp, sizeof(argp), (void *)&argv[i]);
                if (argp) bpf_probe_read_user_str(&data->argv_buf[i * ARGLEN], ARGLEN, argp);
                else data->argv_buf[i * ARGLEN] = 0;
            }}

            events.perf_submit(args, data, sizeof(*data));
            return 0;
        }}
        """

        bpf_monitor = BPF(text=ebpf_source_code)

        def print_event(cpu, data, size):
            raw = ctypes.string_at(data, EVENT_SIZE)
            pid, ppid, timestamp, command_raw, argv_raw = struct.unpack(EVENT_FORMAT, raw)
            cmd = command_raw.split(b'\x00', 1)[0].decode('utf-8', errors='replace')

            argv = []
            for i in range(MAXARG):
                chunk = argv_raw[i * ARGLEN:(i + 1) * ARGLEN]
                arg = chunk.split(b'\x00', 1)[0]
                if not arg: break
                argv.append(arg.decode('utf-8', errors='replace'))

            alerts.append({
                "pid": pid, "ppid": ppid, "timestamp": timestamp,
                "command": cmd, "argv": argv,
            })

        bpf_monitor["events"].open_perf_buffer(print_event)

        exec_command = build_exec_command(container_path, file_content)
        container.exec_run(exec_command, detach=True)

        timeout = time.time() + 3
        while time.time() < timeout:
            bpf_monitor.perf_buffer_poll(timeout=100)
            time.sleep(0.1)

        executed_binaries = sorted(
            set(alert["command"].split("/")[-1] for alert in alerts)
        )

        return {
            "processes_observed": len({alert["pid"] for alert in alerts}),
            "commands_executed": executed_binaries,
            "process_tree": build_process_tree(alerts),
            "risk_assessment": assess_risk(static_results, alerts),
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

    finally:
        if container is not None:
            try:
                container.remove(force=True)
            except Exception:
                pass
        if os.path.exists(file_path):
            os.remove(file_path)


@app.post("/analyze")
async def analyze_payload(file: UploadFile = File(...)):
    safe_filename = Path(file.filename).name
    if not safe_filename or safe_filename in (".", ".."):
        raise HTTPException(status_code=400, detail="Invalid filename")

    file_content = await file.read()
    if len(file_content) == 0:
        raise HTTPException(status_code=400, detail="Empty file")
    if len(file_content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File too large")

    file_hash = hashlib.sha256(file_content).hexdigest()
    static_results = analyze_static(file_content)

    sandbox_results = await run_in_threadpool(run_sandbox, file_content, safe_filename, static_results)

    return {
        "filename": safe_filename,
        "sha256": file_hash,
        "static_analysis": static_results,
        **sandbox_results,
    }



if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
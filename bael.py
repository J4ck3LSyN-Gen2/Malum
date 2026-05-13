#!/usr/bin/env python3
import asyncio, ssl, argparse, random, os, logging, sys, json, socket, subprocess, ipaddress, shutil
import string, fcntl, struct, time, signal, base64, hashlib, colorama
from pathlib import Path
from collections import deque
from typing import Tuple, Optional, Deque, Dict, List, Any

try:
    from prometheus_client import start_http_server, Counter, Gauge
    HAS_METRICS = True
except ImportError:
    HAS_METRICS = False

class MockMetric:
    def labels(self, *args, **kwargs): return self
    def inc(self, *args, **kwargs): pass
    def dec(self, *args, **kwargs): pass

class BaelFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG: "\x1b[38;2;120;120;120m\x1b[1m",
        logging.INFO: "\x1b[34m\x1b[1m",
        logging.WARNING: "\x1b[33m\x1b[1m",
        logging.ERROR: "\x1b[31m",
        logging.CRITICAL: "\x1b[31m\x1b[1m"
    }
    RESET = "\x1b[0m"
    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelno, self.COLORS[logging.INFO])
        fmt = f"{self.COLORS[logging.DEBUG]}{{asctime}}{self.RESET} {color}{{levelname:<8}}{self.RESET} \x1b[32m\x1b[1m{{name}}{self.RESET} {{message}}"
        return logging.Formatter(fmt, "%Y-%m-%d %H:%M:%S", style="{").format(record)

logger = logging.getLogger("bael")
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setFormatter(BaelFormatter())
handler.setLevel(logging.INFO)
logger.addHandler(handler)

SMUGGLE_MAGIC = b"\xBA\x31\xDE\xAD"
__version__ = "0.1.7"
__author__  = "J4ck3LSyN"

class BaelLegacy:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.is_frozen = getattr(sys, 'frozen', False)
        self.temp_dir = None
        
        if self.is_frozen:
            self._deploy_bundled_keys()
            
        self.typeSvr = args.mode in ["server", "buildServer"]
        self.smuggleQueue: Deque[bytes] = deque()
        
        if getattr(args, 'data_transmit', None):
            self._loadSmuggleData(args.data_transmit, args.max_padding)
            
        self.whitelist = [ipaddress.ip_network(x.strip()) for x in args.whitelist.split(",")] if getattr(args, 'whitelist', None) else None
        
        self.sniMap: Dict[str, str] = {}
        if getattr(args, 'map', None):
            try:
                self.sniMap = json.loads(Path(args.map).read_text(encoding="utf-8"))
            except Exception as e:
                logger.error(f"SNI map fail: {e}")
                
        self.lAddr = self.parseAddr(args.listen)
        self.rAddr = self.parseAddr(args.remote) if getattr(args, 'remote', None) else None
        
        self.ssl_ctx = self._genSSLCTX() if all([getattr(args, 'cert', None), getattr(args, 'key', None), getattr(args, 'ca', None)]) else None
        
        if HAS_METRICS:
            self.CONNECTIONS_TOTAL = Counter("bael_conn_total", "Total conns", ["direction"])
            self.ACTIVE_CONNECTIONS = Gauge("bael_active_conn", "Active conns")
            self.BYTES_TRANSFERRED = Counter("bael_bytes_total", "Bytes total", ["direction"])
        else:
            self.CONNECTIONS_TOTAL = MockMetric()
            self.ACTIVE_CONNECTIONS = MockMetric()
            self.BYTES_TRANSFERRED = MockMetric()
            
        self.server: Optional[asyncio.Server] = None
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum, frame):
        self._cleanup_keys()
        sys.exit(0)

    def _cleanup_keys(self):
        if self.temp_dir and self.temp_dir.exists():
            try:
                shutil.rmtree(self.temp_dir)
                logger.info("Keys cleaned up.")
            except Exception as e:
                logger.error(f"Cleanup failed: {e}")

    def _deploy_bundled_keys(self):
        meipass = getattr(sys, '_MEIPASS', None)
        if not meipass: return
        bundled_keys = Path(meipass) / ".baelKeys"
        if not bundled_keys.exists(): return
        base_target = Path("/dev/shm") if Path("/dev/shm").exists() else Path("/tmp")
        self.temp_dir = base_target / f".bael_{''.join(random.choices(string.ascii_lowercase + string.digits, k=8))}"
        try:
            self.temp_dir.mkdir(parents=True, exist_ok=True)
            for f in bundled_keys.glob("*"): shutil.copy(f, self.temp_dir / f.name)
            self.args.cert = str(self.temp_dir / Path(self.args.cert or 'srv.crt').name)
            self.args.key = str(self.temp_dir / Path(self.args.key or 'srv.key').name)
            self.args.ca = str(self.temp_dir / Path(self.args.ca or 'ca.crt').name)
        except Exception as e: logger.error(f"Extraction failed: {e}")

    def parseAddr(self, s: str) -> Tuple[str, int]:
        if not s: raise ValueError("Empty address")
        if ":" in s and s.count(":") > 1 and "[" not in s:
            host, port = s.rsplit(":", 1)
            return host.strip("[]"), int(port)
        host, port = s.split(":", 1)
        return host, int(port)

    def _genSSLCTX(self) -> ssl.SSLContext:
        purpose = ssl.Purpose.CLIENT_AUTH if self.typeSvr else ssl.Purpose.SERVER_AUTH
        ctx = ssl.create_default_context(purpose, cafile=self.args.ca)
        ctx.load_cert_chain(certfile=self.args.cert, keyfile=self.args.key)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = False
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        if self.args.tls_profile == "chrome":
            ctx.set_ciphers("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384")
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        return ctx

    def _loadSmuggleData(self, data: str, max_pad: int):
        try:
            p = Path(data)
            raw = p.read_bytes() if p.exists() else data.encode()
            chunk_size = max(1, max_pad - 10)
            for i in range(0, len(raw), chunk_size): self.smuggleQueue.append(raw[i:i + chunk_size])
        except Exception as e: logger.error(f"Smuggle load fail: {e}")

    def _addPadding(self, data: bytes, is_encrypted_side: bool) -> bytes:
        if not (self.args.morphing and is_encrypted_side) or random.random() > self.args.morph_chance: return data
        if self.smuggleQueue:
            payload = self.smuggleQueue.popleft()
            return data + SMUGGLE_MAGIC + bytes([len(payload)]) + payload
        return data + os.urandom(random.randint(8, self.args.max_padding))

    def _extractSmuggled(self, chunk: bytes) -> Tuple[bytes, list[bytes]]:
        if SMUGGLE_MAGIC not in chunk: return chunk, []
        parts = chunk.split(SMUGGLE_MAGIC)
        clean = parts[0]
        extracted = []
        for part in parts[1:]:
            if len(part) > 0:
                length = part[0]
                if len(part) >= 1 + length:
                    extracted.append(part[1:1 + length])
                    clean += part[1 + length:]
        return clean, extracted

    async def _pump(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, direction: str, is_encrypted: bool):
        try:
            while not reader.at_eof():
                chunk = await reader.read(16384)
                if not chunk: break
                if is_encrypted:
                    chunk, smuggled = self._extractSmuggled(chunk)
                    for s in smuggled: logger.info(f"Extracted: {s.decode(errors='replace')[:50]}")
                data = self._addPadding(chunk, is_encrypted)
                writer.write(data)
                self.BYTES_TRANSFERRED.labels(direction).inc(len(data))
                if writer.transport.get_write_buffer_size() > 131072: await writer.drain()
        except Exception as e: logger.debug(f"Pump {direction} fail: {e}")
        finally:
            if not writer.is_closing(): writer.close()

    async def handle(self, local_r: asyncio.StreamReader, local_w: asyncio.StreamWriter):
        peer = local_w.get_extra_info("peername")[0]
        if self.whitelist and not any(ipaddress.ip_address(peer) in net for net in self.whitelist):
            local_w.close(); return
        target = self.rAddr
        if self.typeSvr and self.sniMap:
            ssl_obj = local_w.get_extra_info("ssl_object")
            sni = ssl_obj.server_hostname if ssl_obj else None
            if sni in self.sniMap:
                try: target = self.parseAddr(self.sniMap[sni])
                except: pass
        if not target: local_w.close(); return
        self.ACTIVE_CONNECTIONS.inc(); self.CONNECTIONS_TOTAL.labels("in" if self.typeSvr else "out").inc()
        try:
            remote_r, remote_w = await asyncio.open_connection(*target, ssl=None if self.typeSvr else self.ssl_ctx, server_hostname=self.args.sni if not self.typeSvr else None)
            await asyncio.gather(self._pump(local_r, remote_w, "to_remote", not self.typeSvr), self._pump(remote_r, local_w, "to_client", self.typeSvr), return_exceptions=True)
        except Exception as e: logger.error(f"Relay error: {e}")
        finally: self.ACTIVE_CONNECTIONS.dec()

    async def run(self):
        if HAS_METRICS: start_http_server(self.args.metrics_port)
        self.server = await asyncio.start_server(self.handle, *self.lAddr, ssl=self.ssl_ctx if self.typeSvr else None)
        async with self.server: await self.server.serve_forever()

class Bael:
    def __init__(self, config: dict):
        self.config, self.logger, self.temp_dir = config, logger, None
        self.tunFd, self.tunName = -1, config.get("tunName", "bael0")
        if getattr(sys, 'frozen', False):
            self._deploy_bundled_keys()
        self.sslContext = self.createSslContext()
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum, frame):
        self.logger.info(f"Received signal {signum}, performing cleanup...")
        self.destroyTun()
        sys.exit(0)

    def _deploy_bundled_keys(self):
        meipass = getattr(sys, '_MEIPASS', None)
        if not meipass: return
        bundled_keys = Path(meipass) / ".baelKeys"
        if not bundled_keys.exists(): return
        base_target = Path("/dev/shm") if Path("/dev/shm").exists() else Path("/tmp")
        self.temp_dir = base_target / f".bael_{''.join(random.choices(string.ascii_lowercase + string.digits, k=8))}"
        try:
            self.temp_dir.mkdir(parents=True, exist_ok=True)
            for f in bundled_keys.glob("*"): shutil.copy(f, self.temp_dir / f.name)
            is_server = self.config.get("mode") == "server"
            cert_def, key_def = ('srv.crt', 'srv.key') if is_server else ('rmt.crt', 'rmt.key')
            self.config['certFile'] = str(self.temp_dir / Path(self.config.get('certFile') or cert_def).name)
            self.config['keyFile'] = str(self.temp_dir / Path(self.config.get('keyFile') or key_def).name)
            self.config['caFile'] = str(self.temp_dir / Path(self.config.get('caFile') or 'ca.crt').name)
        except Exception as e: self.logger.error(f"Extraction failed: {e}")

    def createSslContext(self) -> ssl.SSLContext:
        purpose = ssl.Purpose.SERVER_AUTH if self.config.get("mode") == "client" else ssl.Purpose.CLIENT_AUTH
        ctx = ssl.create_default_context(purpose)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.check_hostname = False  # Critical for IP-based mTLS connections
        if self.config.get("mTLS"):
            c, k, ca = self.config.get("certFile"), self.config.get("keyFile"), self.config.get("caFile")
            if all([c, k, ca]):
                ctx.load_cert_chain(certfile=c, keyfile=k)
                ctx.load_verify_locations(cafile=ca)
                ctx.verify_mode = ssl.CERT_REQUIRED
            else: self.logger.warning("mTLS requested but certificate paths are missing.")
        return ctx

    def validatePrivileges(self):
        if os.getuid() != 0: self.logger.critical("Root required for TUN mode."); sys.exit(1)

    def setupTun(self, persist: int = 1):
        if self.tunFd != -1: return
        self.logger.info(f"Creating TUN interface: {self.tunName}")
        self.tunFd = os.open("/dev/net/tun", os.O_RDWR)
        ifr = struct.pack('16sH', bytes(self.tunName, 'utf-8'), 0x0001 | 0x1000)
        res = fcntl.ioctl(self.tunFd, 0x400454ca, ifr); self.tunName = res[:16].decode('utf-8').strip('\x00')
        fcntl.ioctl(self.tunFd, 0x400454cb, persist)
        if persist: self.setTunAddress(self.config.get("tunIp", "10.8.0.1"), self.config.get("tunMask", "255.255.255.0"))
        self.logger.info(f"TUN interface {self.tunName} is up.")

    def setTunAddress(self, ip: str, mask: str):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            ifreq = struct.pack('16sH2s4s8s', bytes(self.tunName, 'utf-8'), socket.AF_INET, b'\x00\x00', socket.inet_aton(ip), b'\x00' * 8)
            fcntl.ioctl(s.fileno(), 0x8916, ifreq)
            ifrFlags = struct.pack('16sH', bytes(self.tunName, 'utf-8'), 0x0001 | 0x0004); fcntl.ioctl(s.fileno(), 0x8914, ifrFlags)

    def destroyTun(self):
        if self.tunFd != -1:
            try: os.close(self.tunFd)
            except: pass
            self.tunFd = -1
        try:
            fd = os.open("/dev/net/tun", os.O_RDWR); ifr = struct.pack('16sH', bytes(self.tunName, 'utf-8'), 0x0001 | 0x1000)
            fcntl.ioctl(fd, 0x400454ca, ifr); fcntl.ioctl(fd, 0x400454cb, 0); os.close(fd); logger.info(f"TUN {self.tunName} removed.")
        except Exception as e:
            if "No such device" not in str(e): logger.error(f"TUN removal failed: {e}")
        if self.temp_dir and self.temp_dir.exists():
            try: shutil.rmtree(self.temp_dir); self.logger.info("Keys cleaned up.")
            except Exception as e: self.logger.error(f"Keys cleanup failed: {e}")

    def resolveDnsTxt(self, domain: str) -> str:
        try:
            tid = random.getrandbits(16); head = struct.pack('!HHHHHH', tid, 0x0100, 1, 0, 0, 0)
            q = b''.join(len(l).to_bytes(1, 'big') + l.encode() for l in domain.split('.')) + b'\x00' + struct.pack('!HH', 16, 1)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(5); s.sendto(head + q, ("8.8.8.8", 53)); data, _ = s.recvfrom(1024)
            idx = data.find(b'\xc0\x0c', len(head + q))
            if idx != -1:
                raw = data[idx + 12:idx + 12 + data[idx + 11]]
                try:
                    d = base64.b64decode(raw)
                    key = hashlib.md5(socket.gethostname().encode()).digest()
                    return bytes([d[i] ^ key[i % len(key)] for i in range(len(d))]).decode()
                except: return raw.decode()
        except Exception: return ""

    async def bridge(self, r, w, toSsl=True):
        try:
            while True:
                if toSsl:
                    data = await asyncio.get_event_loop().run_in_executor(None, os.read, self.tunFd, 2048)
                    if not data: break
                    w.write(data); await w.drain()
                else:
                    data = await r.read(2048)
                    if not data: break
                    os.write(self.tunFd, data)
        except Exception as e:
            if self.config.get("verbose"): self.logger.debug(f"Bridge error: {e}")

    async def start(self):
        self.validatePrivileges()
        target, port = self.config.get('remoteHost'), self.config.get('remotePort', 443)
        max_retries, verbose = self.config.get("maxRetries", 5), self.config.get("verbose", False)
        for attempt in range(1, max_retries + 1):
            try:
                if attempt > 1:
                    wait = self.config['retryInterval'] * (2 ** (attempt - 2)) + self.config.get('jitter', 0.2) * random.uniform(-1, 1)
                    wait = max(0.5, wait)
                    if verbose: logger.info(f"Retrying connection in {wait:.1f}s (attempt {attempt}/{max_retries})")
                    await asyncio.sleep(wait)
                if verbose: logger.info(f"Attempting connection to {target}:{port} (attempt {attempt})")
                reader, writer = await asyncio.open_connection(target, port, ssl=self.sslContext)
                self.setupTun()
                logger.info(f"mTLS L3 Tunnel Active: {target}")
                await asyncio.gather(self.bridge(reader, writer, True), self.bridge(reader, writer, False))
                return
            except Exception as e:
                logger.error(f"L3 Connection failed (attempt {attempt}/{max_retries}): {e}")
                if attempt == max_retries:
                    logger.critical("Max retries reached. Giving up.")
                    break
        self.destroyTun()

    @staticmethod
    def buildExecutable(name="bMTLSTUN0", verbose=False, bundle_keys=True):
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

class ShortHelpAction(argparse.Action):
    def __init__(self, option_strings, dest, nargs=0, **kwargs):
        super(ShortHelpAction, self).__init__(option_strings, dest, nargs=nargs, **kwargs)
    def __call__(self, parser, namespace, values, option_string=None):
        message = [
            f"\x1b[34m\x1b[1mBael v{__version__} - Minimal Help\x1b[0m",
            f"usage: {sys.argv[0]} [-h] [--mode {{server,client,tun,keygen,build,encode-dns}}] [--verbose] [--legacy] [options]",
            "",
            "Modes:",
            "  --mode tun          L3 VPN Tunnel (Requires Root)",
            "  --mode server       L4 Relay Server",
            "  --mode keygen       Generate PKI certificates",
            "  --mode build        Compile to standalone binary",
            "",
            "Use --help for full documentation and examples."
        ]
        print("\n".join(message)); parser.exit()

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Bael v0.1.7 mTLS Orchestrator", formatter_class=argparse.RawDescriptionHelpFormatter, add_help=False, epilog="""
Operational Examples:
  [+] PKI Setup: %(prog)s --mode keygen
  [+] L3 TUN Client: sudo %(prog)s --mode tun --config tun_settings.json
  [+] L4 Relay Server: %(prog)s --mode server --listen 0.0.0.0:443 --cert srv.crt --key srv.key --ca ca.crt
    """)
    core = p.add_argument_group("Core Mode Options")
    core.add_argument("-h", action=ShortHelpAction, help="Show minimal help.")
    core.add_argument("--help", action="help", help="Full documentation.")
    core.add_argument("--mode", choices=["server", "client", "tun", "keygen", "build", "encode-dns", "down"])
    core.add_argument("--verbose", action="store_true")
    core.add_argument("--legacy", action="store_true")
    net = p.add_argument_group("Network Configuration")
    net.add_argument("--listen", default="0.0.0.0:443")
    net.add_argument("--remote", metavar="ADDR:PORT")
    net.add_argument("--config", metavar="FILE")
    net.add_argument("--dns-lookup", metavar="DOMAIN")
    net.add_argument("--tun-name", default="bael0")
    stealth = p.add_argument_group("Stealth & Evasion")
    stealth.add_argument("--tls-profile", choices=["default", "chrome", "firefox"], default="chrome")
    stealth.add_argument("--sni", default="www.microsoft.com")
    stealth.add_argument("--morphing", action="store_true", default=True)
    stealth.add_argument("--morph-chance", type=float, default=0.65)
    stealth.add_argument("--max-padding", type=int, default=255)
    stealth.add_argument("--encode-str", metavar="DATA")
    stealth.add_argument("--target-hostname", metavar="NAME")
    pki = p.add_argument_group("Authentication & PKI")
    pki.add_argument("--cert")
    pki.add_argument("--key")
    pki.add_argument("--ca")
    pki.add_argument("--no-bundle", action="store_false", dest="bundle_keys", default=True)
    pki.add_argument("--whitelist", metavar="CIDR")
    pki.add_argument("--map", metavar="FILE")
    p.add_argument("--gen-config", action="store_true")
    return p

def genConfigInteractive():
    print(f"\n{colorama.Fore.CYAN}--- Bael Interactive Configuration Wizard ---{colorama.Fore.RESET}")
    try:
        config = {}
        mode = input("[?] Operation Mode (client/server) [client]: ").strip().lower() or "client"
        config['mode'] = mode
        if mode == "server":
            config['listenHost'] = input("[?] Listen Address [0.0.0.0]: ").strip() or "0.0.0.0"
            config['listenPort'] = int(input("[?] Listen Port [443]: ").strip() or 443)
        else:
            config['remoteHost'] = input("[?] Remote Peer Address: ").strip()
            config['remotePort'] = int(input("[?] Remote Peer Port [443]: ").strip() or 443)
        config['tunName'] = input("[?] TUN Interface Name [bael0]: ").strip() or "bael0"
        config['tunIp'] = input("[?] Virtual TUN IP [10.8.0.1]: ").strip() or "10.8.0.1"
        config['tunMask'] = input("[?] Virtual TUN Mask [255.255.255.0]: ").strip() or "255.255.255.0"
        config['mTLS'] = input("[?] Enable mTLS? (y/n) [y]: ").strip().lower() != 'n'
        if config['mTLS']:
            config['certFile'] = input("[?] Cert path: ").strip()
            config['keyFile'] = input("[?] Key path: ").strip()
            config['caFile'] = input("[?] CA path: ").strip()
        filename = input("[?] Save as [tun_settings.json]: ").strip() or "tun_settings.json"
        with open(filename, 'w') as f: json.dump(config, f, indent=4)
        logger.info(f"Configuration saved to {filename}")
    except KeyboardInterrupt: print("\nWizard aborted."); sys.exit(0)

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

if __name__ == "__main__":
    args = build_parser().parse_args()
    if args.verbose: handler.setLevel(logging.DEBUG); logger.info("Verbose mode enabled")
    if args.gen_config: genConfigInteractive(); sys.exit(0)
    if args.mode == "keygen": genkeys(args); sys.exit(0)
    if args.mode == "encode-dns":
        if not args.encode_str or not args.target_hostname:
            logger.error("--encode-str and --target-hostname required"); sys.exit(1)
        k = hashlib.md5(args.target_hostname.encode()).digest(); p = args.encode_str.encode()
        res = base64.b64encode(bytes([p[i] ^ k[i % len(k)] for i in range(len(p))])).decode()
        print(f"\n[+] Obfuscated DNS TXT Record:\n{res}\n"); sys.exit(0)
    if args.mode == "down":
        conf = {"tunName": getattr(args, 'tun_name', "bael0")}
        if args.config and os.path.exists(args.config):
            with open(args.config) as f: conf.update(json.load(f))
        Bael(conf).destroyTun(); sys.exit(0)
    if args.mode == "build":
        Bael.buildExecutable("bMTLSTUN0_LEGACY" if args.legacy else "bMTLSTUN0", verbose=args.verbose, bundle_keys=args.bundle_keys); sys.exit(0)
    
    if args.legacy:
        if not all([args.cert, args.key, args.ca]): logger.error("Legacy requires --cert --key --ca"); sys.exit(1)
        legacy = BaelLegacy(args)
        try: asyncio.run(legacy.run())
        except KeyboardInterrupt: pass
    else:
        conf = {"logLevel": "INFO", "maxRetries": 5, "retryInterval": 2, "jitter": 0.2, "mTLS": True, "mode": "client", "tunName": getattr(args, 'tun_name', "bael0"), "verbose": args.verbose}
        if args.config and os.path.exists(args.config):
            with open(args.config) as f: conf.update(json.load(f))
        if not args.config and args.mode in ["tun", "server"]:
            conf.update({
                "remoteHost": args.remote.split(":")[0] if args.remote else None,
                "remotePort": int(args.remote.split(":")[1]) if args.remote and ":" in args.remote else 443,
                "certFile": args.cert, "keyFile": args.key, "caFile": args.ca,
                "mode": "server" if args.mode == "server" else "client"
            })
        tool = Bael(conf)
        if args.dns_lookup:
            txt = tool.resolveDnsTxt(args.dns_lookup)
            if txt:
                try: conf.update(json.loads(txt))
                except: logger.info(f"DNS TXT: {txt}")
        
        effective_mode = args.mode or conf.get("mode")
        if effective_mode == "tun": effective_mode = conf.get("mode", "client")
        
        try:
            if effective_mode == "server":
                async def tun_server():
                    tool.validatePrivileges(); tool.setupTun()
                    async def handle_tun(r, w):
                        logger.info("Inbound L3 Tunnel verified.")
                        await asyncio.gather(tool.bridge(r, w, True), tool.bridge(r, w, False))
                    l_host = conf.get("listenHost", args.listen.split(":")[0])
                    l_port = int(conf.get("listenPort", args.listen.split(":")[1] if ":" in args.listen else 443))
                    server = await asyncio.start_server(handle_tun, l_host, l_port, ssl=tool.sslContext)
                    async with server: await server.serve_forever()
                asyncio.run(tun_server())
            else:
                asyncio.run(tool.start())
        except KeyboardInterrupt:
            logger.info("Shutdown requested. Cleaning up..."); tool.destroyTun()
        except Exception as e:
            logger.error(f"Unexpected error: {e}"); tool.destroyTun()

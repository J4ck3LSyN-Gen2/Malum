#!/usr/bin/env python3
import asyncio, ssl, argparse, random, os, logging, sys, json, socket, subprocess, ipaddress, urllib.request, string
from pathlib import Path
from collections import deque
from typing import Tuple, Optional, Deque, Dict
from prometheus_client import start_http_server, Counter, Gauge
class BaelFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG: "\x1b[38;2;120;120;120m\x1b[1m",
        logging.INFO: "\x1b[34m\x1b[1m",
        logging.WARNING: "\x1b[33m\x1b[1m",
        logging.ERROR: "\x1b[31m",
        logging.CRITICAL: "\x1b[31m\x1b[1m"}
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
__version__ = "0.0.3"
class Bael:
    def __init__(self, args:argparse.Namespace):
        # Bundle resolution for frozen binaries (PyInstaller)
        self.is_frozen = getattr(sys, 'frozen', False)
        self.bundle_dir = Path(getattr(sys, '_MEIPASS', os.getcwd()))
        self.args = args
        self.verbose = args.verbose
        # Auto-detect mode if running from a specific binary name without args
        if self.is_frozen and not args.mode:
            prog = Path(sys.executable).name.lower()
            if "server" in prog: args.mode = "server"
            elif "client" in prog: args.mode = "client"
        self.typeSvr = args.mode in ["server", "buildServer"]
        # Smuggling
        self.smuggleQueue: Deque[bytes] = deque()
        if args.data_transmit: self._loadSmuggleData(args.data_transmit,args.max_padding)
        # Whitelist
        self.whitelist = [ipaddress.ip_network(x.strip()) for x in args.whitelist.split(",")] if args.whitelist else None
        # SNI Map
        self.sniMap: Dict[str, str] = {}
        if args.map:
            try: self.sniMap = json.loads(Path(args.map).read_text(encoding="utf-8"))
            except Exception as e: logger.error(f"Failed to load SNI map: {e}")
        self.lAddr = self.parseAddr(args.listen)
        self.rAddr = self.parseAddr(args.remote) if args.remote else None
        self.sni = args.sni
        self.morphing = args.morphing
        self.morph_chance = args.morph_chance
        self.max_padding = args.max_padding
        # SOCKS5
        self.socks_mode = args.socks
        self.socks_user = args.socks_user
        self.socks_pass = args.socks_pass
        self.socks_timeout = args.socks_timeout
        # TLS Fingerprinting
        self.tls_profile = args.tls_profile
        # Dynamic PKI
        self.keysRoot = Path(".baelKeys")
        self.certs = {
            "ca": {"cn": args.ca_cn, "days": 365, "file": args.ca_name},
            "srv": {"cn": args.srv_cn, "days": 365, "file": args.srv_name},
            "rmt": {"cn": args.rmt_cn, "days": 365, "file": args.rmt_name}}
        self.OPENSSLCMDS = self._buildOpenSSLCommand()
        # If running as a binary, automatically point to internal keys if not explicitly provided
        if self.is_frozen:
            internal_keys = self.bundle_dir / ".baelKeys"
            role_file = args.srv_name if self.typeSvr else args.rmt_name
            if not args.cert: args.cert = str(internal_keys / f"{role_file}.crt")
            if not args.key: args.key = str(internal_keys / f"{role_file}.key")
            if not args.ca: args.ca = str(internal_keys / f"{args.ca_name}.crt")
        self.ssl_ctx = self._genSSLCTX() if all([args.cert, args.key, args.ca]) else None
        self.CONNECTIONS_TOTAL = Counter("bael_connections_total", "Total connections", ["direction"])
        self.ACTIVE_CONNECTIONS = Gauge("bael_active_connections", "Active connections")
        self.BYTES_TRANSFERRED = Counter("bael_bytes_transferred_total", "Bytes transferred", ["direction"])
        self.server: Optional[asyncio.Server] = None

    # ====================== Key Generation ======================
    def _get_path(self, target:str, ext:str) -> str: return str(self.keysRoot / f"{self.certs[target]['file']}.{ext}")

    def _buildOpenSSLCommand(self) -> Dict[str, list[str]]:
        ca, srv, rmt = self.certs["ca"], self.certs["srv"], self.certs["rmt"]
        return {
            "init": [f'openssl req -x509 -newkey rsa:4096 -keyout {self._get_path("ca","key")} '
                     f'-out {self._get_path("ca","crt")} -days {ca["days"]} -nodes -subj "/CN={ca["cn"]}"'],
            "srv": [
                f'openssl req -newkey rsa:4096 -keyout {self._get_path("srv","key")} '
                f'-out {self._get_path("srv","csr")} -nodes -subj "/CN={srv["cn"]}"',
                f'openssl x509 -req -in {self._get_path("srv","csr")} -CA {self._get_path("ca","crt")} '
                f'-CAkey {self._get_path("ca","key")} -CAcreateserial -out {self._get_path("srv","crt")} -days {srv["days"]}'],
            "rmt": [
                f'openssl req -newkey rsa:4096 -keyout {self._get_path("rmt","key")} '
                f'-out {self._get_path("rmt","csr")} -nodes -subj "/CN={rmt["cn"]}"',
                f'openssl x509 -req -in {self._get_path("rmt","csr")} -CA {self._get_path("ca","crt")} '
                f'-CAkey {self._get_path("ca","key")} -CAcreateserial -out {self._get_path("rmt","crt")} -days {rmt["days"]}']}

    def buildBinary(self, build_mode: str):
        """Generates fresh keys and compiles a standalone binary with the keys bundled."""
        if not self.genkeys():
            logger.error("Key generation failed, aborting build.")
            return
        # Determine the binary identity based on the build mode
        target = build_mode.replace("build", "").lower()
        bName = f"bael_{target}"
        # PyInstaller data parameter syntax: source:destination
        sep = ";" if sys.platform == "win32" else ":"
        data_param = f"{self.keysRoot}{sep}.baelKeys"
        # Optimization: Exclude heavy/unused standard modules to reduce binary size
        exclusions = ["tkinter", "unittest", "pydoc", "email", "html", "http.server", "xml", "distutils", "setuptools", "sqlite3"]
        # Obfuscation: Generate a unique 16-character encryption key for bytecode
        # Note: Requires 'pycryptodome' installed on the build machine
        oKey = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        cmd = [
            sys.executable, "-m", "PyInstaller", "--onefile", "--clean",
            "--add-data", data_param, "--name", bName, "--key", oKey]
        for mod in exclusions: cmd.extend(["--exclude-module", mod])
        if sys.platform != "win32": cmd.append("--strip") # Strip symbols to reduce size on Linux/macOS
        cmd.append("bael.py")
        logger.info(f"Building standalone {target} binary (EncKey: {oKey})...")
        try: subprocess.run(cmd, check=True)
        except Exception as e: logger.error(f"PyInstaller build failed: {e}")

    def genkeys(self) -> bool:
        self.keysRoot.mkdir(parents=True, exist_ok=True)
        logger.info(f"Generating PKI in {self.keysRoot}")
        for role, cmds in self.OPENSSLCMDS.items():
            skip = True
            for ftype in ("key", "crt", "csr"):
                if not Path(self._get_path(role if role != "init" else "ca", ftype)).exists():
                    skip = False;break
            if skip and role != "init":
                logger.info(f"{role.upper()} certificates already exist, skipping.");continue
            logger.info(f"Generating {role.upper()} certificates...")
            for cmd in cmds:
                try:
                    logger.debug(f"Running: {cmd}")
                    subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
                except subprocess.CalledProcessError as e:
                    logger.error(f"OpenSSL failed: {e.stderr.strip()}")
                    return False
        logger.info("PKI generation completed successfully.")
        return True

    # ====================== TLS Context ======================
    def _genSSLCTX(self) -> ssl.SSLContext:
        purpose = ssl.Purpose.CLIENT_AUTH if self.typeSvr else ssl.Purpose.SERVER_AUTH
        ctx = ssl.create_default_context(purpose, cafile=self.args.ca)
        ctx.load_cert_chain(certfile=self.args.cert, keyfile=self.args.key)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = False
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        # TLS Fingerprint Evasion
        if self.tls_profile == "chrome":
            ctx.set_ciphers("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
                           "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384")
            ctx.set_alpn_protocols(["h2", "http/1.1"])
        elif self.tls_profile == "firefox":
            ctx.set_ciphers("TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES256-GCM-SHA384")
            ctx.set_alpn_protocols(["h2", "http/1.1"])
        else:  # default / generic
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            ctx.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384")
        return ctx

    # ====================== Smuggling ======================
    def _loadSmuggleData(self, data:str, max_pad:int):
        try:
            p = Path(data)
            raw = p.read_bytes() if p.exists() else data.encode()
            chunk_size = max(1, max_pad - 10)
            for i in range(0, len(raw), chunk_size): self.smuggleQueue.append(raw[i:i + chunk_size])
        except Exception as e: logger.error(f"Failed to load smuggling data: {e}")

    def _addPadding(self, data:bytes, is_encrypted_side:bool) -> bytes:
        if not (self.morphing and is_encrypted_side) or random.random() > self.morph_chance: return data
        if self.smuggleQueue:
            payload = self.smuggleQueue.popleft()
            padding = SMUGGLE_MAGIC + bytes([len(payload)]) + payload
            logger.debug(f"Smuggling {len(payload)} bytes")
            return data + padding
        return data + os.urandom(random.randint(8, self.max_padding))

    def _extractSmuggled(self, chunk:bytes) -> Tuple[bytes, list[bytes]]:
        if SMUGGLE_MAGIC not in chunk: return chunk, []
        extracted = []
        parts = chunk.split(SMUGGLE_MAGIC)
        clean = parts[0]
        for part in parts[1:]:
            if len(part) > 0:
                length = part[0]
                extracted.append(part[1:1 + length])
                clean += part[1 + length:]
        return clean, extracted

    # ====================== Core Relay ======================
    async def _pump(self,reader:asyncio.StreamReader, writer:asyncio.StreamWriter,
                    direction: str, is_encrypted: bool):
        try:
            while not reader.at_eof():
                chunk = await reader.read(16384)
                if not chunk: break
                if is_encrypted:
                    chunk, smuggled = self._extractSmuggled(chunk)
                    for s in smuggled: logger.info(f"Extracted smuggled: {s.decode(errors='replace')[:200]}")
                data = self._addPadding(chunk, is_encrypted)
                writer.write(data)
                self.BYTES_TRANSFERRED.labels(direction).inc(len(data))
                if writer.transport.get_write_buffer_size() > 131072: await writer.drain()
        except Exception as e: logger.debug(f"Pump {direction}: {e}")
        finally:
            if not writer.is_closing(): writer.close()

    async def _connect_remote(self,target:Tuple[str,int]) -> Optional[Tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
        for delay in (0.3, 0.6, 1.5, 3.0, 6.0):
            try:
                if self.typeSvr: return await asyncio.open_connection(*target)
                return await asyncio.open_connection(*target, ssl=self.ssl_ctx, server_hostname=self.sni)
            except Exception: await asyncio.sleep(delay)
        logger.warning(f"Failed to connect to {target}")
        return None

    # ====================== SOCKS5 ======================
    async def _handle_socks5(self,r:asyncio.StreamReader, w:asyncio.StreamWriter) -> Optional[Tuple[str, int]]:
        try:
            ver, nmethods = await asyncio.wait_for(r.readexactly(2), self.socks_timeout)
            if ver != 0x05: return None
            methods = await r.readexactly(nmethods)
            if self.socks_user and self.socks_pass:
                if 0x02 not in methods: return None
                w.write(b"\x05\x02"); await w.drain()
                _, ulen = await asyncio.wait_for(r.readexactly(2), self.socks_timeout)
                user = (await r.readexactly(ulen)).decode()
                plen = (await r.readexactly(1))[0]
                passwd = (await r.readexactly(plen)).decode()
                if user != self.socks_user or passwd != self.socks_pass:
                    w.write(b"\x01\x01"); await w.drain(); return None
                w.write(b"\x01\x00")
            else: w.write(b"\x05\x00")
            await w.drain()
            req = await r.readexactly(4)
            if req[1] != 0x01: return None  # CONNECT only
            atyp = req[3]
            if atyp == 0x01: addr = socket.inet_ntoa(await r.readexactly(4))
            elif atyp == 0x03: addr = (await r.readexactly((await r.readexactly(1))[0])).decode()
            elif atyp == 0x04: addr = socket.inet_ntop(socket.AF_INET6, await r.readexactly(16))
            else: return None
            port = int.from_bytes(await r.readexactly(2), "big")
            w.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await w.drain()
            return addr, port
        except Exception as e:
            logger.debug(f"SOCKS5 error: {e}")
            w.close()
            return None

    # ====================== DNS TXT Discovery ======================
    async def _dns_txt_discovery(self,domain:str) -> Optional[str]:
        try:
            logger.info(f"DNS TXT discovery for {domain}")
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", "TXT", domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            if stdout:
                result = stdout.decode().strip().strip('"').strip("'")
                logger.info(f"DNS discovery resolved: {result}")
                return result
        except FileNotFoundError: logger.error("`dig` command not found. Install dnsutils / bind-tools.")
        except Exception as e: logger.error(f"DNS discovery failed: {e}")
        return None

    # ====================== Main Handler ======================
    async def handle(self, local_r: asyncio.StreamReader, local_w: asyncio.StreamWriter):
        peer = local_w.get_extra_info("peername")[0]
        if not (self.whitelist is None or any(ipaddress.ip_address(peer) in net for net in self.whitelist)):
            logger.warning(f"Rejected {peer} (not whitelisted)")
            local_w.close()
            return
        target = self.rAddr
        if not self.typeSvr and self.socks_mode:
            target = await self._handle_socks5(local_r, local_w)
            if not target: return
        if self.typeSvr and self.socks_mode:
            try:
                line = await asyncio.wait_for(local_r.readline(), self.socks_timeout)
                target = self.parseAddr(line.decode().strip())
            except Exception:
                local_w.close()
                return
        elif self.typeSvr and self.sniMap:
            ssl_obj = local_w.get_extra_info("ssl_object")
            sni = ssl_obj.server_hostname if ssl_obj else None
            if sni and sni in self.sniMap:
                target = self.parseAddr(self.sniMap[sni])
                logger.debug(f"SNI routed {sni} → {target}")
        if not target:
            local_w.close()
            return
        self.ACTIVE_CONNECTIONS.inc()
        self.CONNECTIONS_TOTAL.labels("in" if self.typeSvr else "out").inc()
        remote_pair = await self._connect_remote(target if self.typeSvr else self.rAddr)
        if not remote_pair:
            self.ACTIVE_CONNECTIONS.dec()
            local_w.close()
            return
        remote_r, remote_w = remote_pair
        if not self.typeSvr and self.socks_mode:
            remote_w.write(f"{target[0]}:{target[1]}\n".encode())
            await remote_w.drain()
        try:
            await asyncio.gather(
                self._pump(local_r, remote_w, "to_remote", is_encrypted=not self.typeSvr),
                self._pump(remote_r, local_w, "to_client", is_encrypted=self.typeSvr),
                return_exceptions=True
            )
        finally:
            self.ACTIVE_CONNECTIONS.dec()
            for w in (local_w, remote_w):
                if not w.is_closing():
                    w.close()

    @staticmethod
    def parseAddr(s: str) -> Tuple[str, int]:
        if ":" in s and s.count(":") > 1 and "[" not in s:
            host, port = s.rsplit(":", 1)
            return host.strip("[]"), int(port)
        host, port = s.split(":", 1)
        return host, int(port)

    async def run(self):
        if not self.typeSvr and self.args.dns_discovery:
            resolved = await self._dns_txt_discovery(self.args.dns_discovery)
            if resolved:
                self.rAddr = self.parseAddr(resolved)
        logger.info(f"Bael mTLS Relay v{__version__} | {self.lAddr} → {self.rAddr} | "
                   f"Mode: {'Server' if self.typeSvr else 'Client'} | Profile: {self.tls_profile}")
        start_http_server(self.args.metrics_port)
        self.server = await asyncio.start_server(
            self.handle,
            *self.lAddr,
            ssl=self.ssl_ctx if self.typeSvr else None
        )
        async with self.server:
            await self.server.serve_forever()

    async def shutdown(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info("Relay shutdown complete")


# ========================== Argument Parser ==========================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Bael mTLS Stealth Relay")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Enable verbose logging (DEBUG level).")
    p.add_argument("--mode", choices=["server", "client", "keygen", "buildClient", "buildServer", "buildMutual"],
                   help="Operation mode: 'server' (listen for clients), 'client' (connect to server), "
                        "'keygen' (generate PKI), 'buildClient' (compile client binary), "
                        "'buildServer' (compile server binary), 'buildMutual' (compile both client and server binaries).")

    p.add_argument("--listen", default="0.0.0.0:53",
                   help="Local address and port to listen on (e.g., 0.0.0.0:443).")
    p.add_argument("--remote",
                   help="Remote address and port to connect to (e.g., 1.2.3.4:443). Required for client mode.")
    p.add_argument("--map",
                   help="JSON file mapping SNI hostnames to backend targets (server mode only). "
                        "Example: {'api.example.com': '127.0.0.1:8080'}.")
    p.add_argument("--whitelist",
                   help="Comma-separated list of allowed client IPs or CIDR ranges (server mode only). "
                        "Example: '192.168.1.0/24,10.0.0.5'.")
    p.add_argument("--socks", action="store_true",
                   help="Enable SOCKS5 proxy functionality. Client listens for SOCKS5, server forwards SOCKS5.")
    p.add_argument("--socks-user", "--su",
                   help="Username for SOCKS5 authentication.")
    p.add_argument("--socks-pass", "--sp",
                   help="Password for SOCKS5 authentication.")
    p.add_argument("--socks-timeout", type=float, default=5.0,
                   help="Timeout in seconds for SOCKS5 handshake (default: 5.0).")

    p.add_argument("--dns-discovery",
                   help="Domain to query for TXT record containing remote server address (client mode only). "
                        "Example: 'relay.example.com' might resolve to '1.2.3.4:443'.")
    p.add_argument("--data-transmit",
                   help="File path or string to smuggle within the encrypted traffic padding. "
                        "Data is chunked and sent opportunistically.")

    # Certificates
    p.add_argument("--cert", "--crt",
                   help="Path to the TLS certificate file (e.g., srv.crt for server, rmt.crt for client).")
    p.add_argument("--key",
                   help="Path to the TLS private key file (e.g., srv.key for server, rmt.key for client).")
    p.add_argument("--ca",
                   help="Path to the Certificate Authority (CA) certificate file (e.g., ca.crt).")

    # TLS Fingerprint
    p.add_argument("--tls-profile", choices=["default", "chrome", "firefox"], default="chrome",
                   help="TLS fingerprint to emulate for evasion (e.g., 'chrome', 'firefox'). Default: chrome.")

    p.add_argument("--sni", default="www.microsoft.com",
                   help="Server Name Indication (SNI) to send during TLS handshake (client mode only). "
                        "Helps blend in with legitimate traffic.")

    # Morphing / Padding
    p.add_argument("--no-morph", action="store_false", dest="morphing", default=True,
                   help="Disable traffic morphing and padding for stealth.")
    p.add_argument("--morph-chance", type=float, default=0.65,
                   help="Probability (0.0-1.0) that a packet will be morphed with padding or smuggled data (default: 0.65).")
    p.add_argument("--max-padding", type=int, default=255,
                   help="Maximum number of random bytes to add as padding (default: 255).")

    p.add_argument("--metrics-port", type=int, default=9100,
                   help="Port for Prometheus metrics endpoint (default: 9100).")

    # Keygen options
    p.add_argument("--ca-cn", default="Bael-Relay",
                   help="Common Name for the Certificate Authority (CA) certificate (default: Bael-Relay).")
    p.add_argument("--srv-cn", default="Bael-Server",
                   help="Common Name for the Server certificate (default: Bael-Server).")
    p.add_argument("--rmt-cn", default="Bael-Client",
                   help="Common Name for the Remote/Client certificate (default: Bael-Client).")
    p.add_argument("--ca-name", default="ca",
                   help="Base filename for CA certificate and key (default: ca).")
    p.add_argument("--srv-name", default="srv",
                   help="Base filename for Server certificate and key (default: srv).")
    p.add_argument("--rmt-name", default="rmt",
                   help="Base filename for Remote/Client certificate and key (default: rmt).")

    return p


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()
    if not args.mode and not getattr(sys, 'frozen', False): parser.error("the following arguments are required: --mode")
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG);handler.setLevel(logging.DEBUG)
    bael = Bael(args)
    if args.mode == "keygen":
        bael.genkeys();sys.exit(0)
    if args.mode and args.mode.startswith("build"):
        bael.buildBinary(args.mode);sys.exit(0)
    if not all([args.cert, args.key, args.ca]):
        logger.error("Missing certificate arguments (--cert, --key, --ca)");sys.exit(1)
    try: asyncio.run(bael.run())
    except KeyboardInterrupt: asyncio.run(bael.shutdown())
    except Exception as e: logger.exception(f"Critical error: {e}")
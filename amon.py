import logging, socket, requests, threading, re, time, hashlib, math, random, concurrent.futures, argparse, sys, pathlib, os, tempfile, subprocess # type: ignore
try:
    from curl_cffi import requests as cf_requests  # type: ignore
    HAS_CFFI = True
    CFFI_ERROR = None
except ImportError as e:
    HAS_CFFI = False
    CFFI_ERROR = e
from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR, A, TXT, MX, QTYPE # type: ignore
__version__ = "0.1.0";__author__="J4ck3LSyN"
class amosLoggingFormatter(logging.Formatter):
    black = "\x1b[30m";red = "\x1b[31m";green = "\x1b[32m";yellow = "\x1b[33m"
    blue = "\x1b[34m";gray = "\x1b[38m";reset = "\x1b[0m";bold = "\x1b[1m"
    COLORS = {logging.DEBUG: gray+bold,logging.INFO: blue+bold,logging.WARNING: yellow+bold,logging.ERROR: red,logging.CRITICAL: red+bold,}
    def format(self, record):
        logColor = self.COLORS[record.levelno]
        fmt = "(black){asctime}(reset) (levelcolor){levelname:<8}(reset) (green){name}(reset) {message}"
        fmt = fmt.replace("(black)", self.black + self.bold).replace("(reset)", self.reset).replace("(levelcolor)", logColor).replace("(green)", self.green + self.bold)
        return logging.Formatter(fmt, "%Y-%m-%d %H:%M:%S", style="{").format(record)
customLogger = logging.getLogger("amos");customLogger.setLevel(logging.DEBUG);consoleHandler = logging.StreamHandler();consoleHandler.setFormatter(amosLoggingFormatter());consoleHandler.setLevel(logging.INFO);customLogger.addHandler(consoleHandler)
class amos:
    def customLogPipe(self,message:str,level:int=1,exc_info:bool=False,noLog:bool=False,silent:bool=False):
        """A custom logging pipe for the amos application.
        Args:
        	message (str): The message to be logged.
        	level (int, optional): The logging level. Defaults to 1 (INFO).
        	exc_info (bool, optional): If True, exception information is added to the logging message. Defaults to False.
        	noLog (bool, optional): If True, prevents the message from being logged. Defaults to False.
        	silent (bool, optional): If True, silences the log output entirely, overriding other settings. Defaults to False.
        Return:
        	None
        """
        if silent or not self.config['verbosity']: return 
        prefixMap = {1: "[*] ",3: "[!] ",'output': "[^] "};logMap = {0: self.customLogger.debug,'d': self.customLogger.debug,1: self.customLogger.info,'i': self.customLogger.info,2: self.customLogger.warning,'w': self.customLogger.warning,3: self.customLogger.error,'r': self.customLogger.error,4: self.customLogger.critical,'c': self.customLogger.critical};logFunc = logMap.get(level, self.customLogger.info)
        if not noLog: logFunc(f"{prefixMap.get(level, '')}{message}", exc_info=exc_info)
    def __init__(self,lHost:str="0.0.0.0",DOHURL:str="https://cloudflare-dns.com/dns-query",app:bool=False):
        """Initializes the amos DNS server instance.
        Args:
        	lHost (str, optional): The listening host address. Defaults to "0.0.0.0".
        	DOHURL (str, optional): The default DoH (DNS over HTTPS) upstream URL. Defaults to "https://cloudflare-dns.com/dns-query".
        	app (bool, optional): Flag to indicate if running as a full application, which initializes the 'gravity' blocklist and command-line parsers. Defaults to False.
        Return:
        	None
        """
        self.lHost, self.DOHURL, self.app, self.customLogger = lHost, DOHURL, app, customLogger
        self.DOH_POOL = ["https://cloudflare-dns.com/dns-query","https://dns.google/dns-query","https://dns.quad9.net/dns-query"]
        self.UAS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "Mozilla/5.0 (X11; Linux x86_64)"]
        self.CDN_WL = {".cloudfront.net", ".azureedge.net", ".akamai.net", ".googleusercontent.com", ".cdn.cloudflare.net"}
        self.config = {"verbosity":True, 
                       "cache":{}, 
                       "exfil_watch":True,
                       "log":{"path":pathlib.Path.cwd(),"home":".amonLogs"}}
        self.timestamp = time.time()
        self.map = self.gravity(self) if self.app else None
        self.noDeath = False
        if self.app: 
            self.customLogPipe(f"Amos Shadow-DNS initialized @ '{str(time.asctime())}'")
            if HAS_CFFI: self.customLogPipe("JA3 Spoofing Active", level=1)
            else: self.customLogPipe(f"JA3 Spoofing Inactive (curl_cffi error: {CFFI_ERROR})", level=2)
            self._initParsers()

    class gravity:
        """Gravity class for managing blocklists.
        """
        def __init__(self,AI,initRefresh:bool=True):
            """Initializes the gravity blocklist manager.
            Args:
            	AI (amos): An instance of the main `amos` class.
            	initRefresh (bool, optional): If `True`, automatically refreshes the blocklist upon initialization. Defaults to `True`.
            Return:
            	None
            """
            self.amos, self.blackList, self.sources = AI, set(), ["https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts","https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/adblock/multi.txt"]
            if initRefresh: self.refresh()
        def refresh(self):
            """Refreshes the blocklist by fetching domains from configured sources.
            Args:
            	None
            Return:
            	None
            """
            for source in self.sources:
                try:
                    resp = requests.get(source,timeout=5);doms = re.findall(r"^(?:0\.0\.0\.0|127\.0\.0\.1|\|\|)\s*([a-zA-Z0-9.-]+)", resp.text, re.M)
                    if doms: self.blackList.update(doms)
                except Exception as E: self.amos.customLogPipe(f"Gravity Fail: {str(E)}",level=2)

    def shannon(self, data):
        """Calculates the Shannon entropy of a given string.
        Args:
        	data (str): The input string to analyze.
        Return:
        	float: The calculated Shannon entropy value. Returns 0 if the data is empty.
        """
        if not data: return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x)))/len(data)
            if p_x > 0: entropy += - p_x*math.log(p_x, 2)
        return entropy

    def analyzeEntropy(self,domain:str):
        """Analyzes the Shannon entropy of domain labels to detect potential DNS tunneling or exfiltration.
        Args:
        	domain (str): The domain name to analyze.
        Return:
        	bool: `True` if suspicious keywords are found, `False` otherwise. Logs a warning if entropy is high.
        """
        if any(domain.endswith(s) for s in self.CDN_WL): return False
        labels = domain.split('.')
        for label in labels:
            if self.shannon(label) > 4.5 or len(label) > 45: self.customLogPipe(f"SUSPICIOUS ENTROPY: Potential DNS Tunneling/Exfil in {domain}", level=3)
            if any(ext in label.lower() for ext in ['v10','telemetry','metadata']): return True
        return False

    def fetchDOH(self,queryData:bytes):
        """Fetches a DNS response from an upstream DoH provider.
        Args:
        	queryData (bytes): The raw DNS query data.
        Return:
        	bytes | None: The DNS response content as bytes if successful, otherwise `None`.
        """
        h = {"accept": "application/dns-message", "content-type": "application/dns-message", "User-Agent": random.choice(self.UAS)}
        amosash = hashlib.md5(queryData).hexdigest()
        if amosash in self.config['cache']: return self.config['cache'][amosash]
        try:
            target = random.choice(self.DOH_POOL) if self.DOHURL == "https://cloudflare-dns.com/dns-query" else self.DOHURL
            if HAS_CFFI: resp = cf_requests.post(target,headers=h,data=queryData,timeout=5,impersonate="chrome")
            else:
                resp = requests.post(target,headers=h,data=queryData,timeout=5)
            if resp.status_code == 200:
                self.config['cache'][amosash] = resp.content
                return resp.content
        except Exception as E: self.customLogPipe(f"DOH Error: {str(E)}",level=3)
        return None

    def handleRequest(self,data:bytes,addr:tuple,hostSock:socket):
        """Handles an incoming DNS request. It checks against the blocklist and forwards to a DoH server if not blocked.
        Args:
        	data (bytes): The raw DNS query packet.
        	addr (tuple): The address of the client that sent the request.
        	hostSock (socket.socket): The server socket to send the response on.
        Return:
        	None
        """
        if not self.map: return None
        try:
            pq = DNSRecord.parse(data); qn = str(pq.q.name).strip(".")
            self.analyzeEntropy(qn)
            if any(domain in qn for domain in self.map.blackList):
                self.customLogPipe(f"AMON-SUNK: {qn} (Client: {addr[0]})", level=2)
                r = pq.reply(); r.add_answer(RR(qn,QTYPE.A,rdata=A("0.0.0.0"),ttl=60))
                hostSock.sendto(r.pack(),addr)
            else:
                r = self.fetchDOH(data)
                if r: hostSock.sendto(r,addr)
                self.customLogPipe(f"AMON-RESOLVE: {qn}", level=1)
        except Exception as E: self.customLogPipe(f"Handler Error: {str(E)}",level=3)

    def serve(self, port:int=53):
        """Starts the DNS server, listens for incoming requests, and handles them using a thread pool.
        Args:
        	port (int, optional): The port to listen on. Defaults to 53.
        Return:
        	None: Exits on `PermissionError` if port 53 is used without root privileges.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try: sock.bind((self.lHost, port))
        except PermissionError: exit("[!] Root required for port 53.")
        self.customLogPipe(f"AMON operational on {self.lHost}:{port}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            while True:
                data, addr = sock.recvfrom(512);executor.submit(self.handleRequest, data, addr, sock)

    def _setupFileLogging(self):
        """Sets up file logging for the application based on configuration and command-line arguments.
        Args:
        	None
        Return:
        	None
        """
        if self.args.noFileLog: return
        logPath = self.config['log']['path']
        if self.args.logDir: logPath = pathlib.Path(self.args.logDir)
        logHome = self.config['log']['home']
        baseDir = logPath / logHome
        fileName = f"amon_{int(self.timestamp)}.log"
        if self.args.logFile:
            fPath = pathlib.Path(self.args.logFile)
            if fPath.is_absolute(): fullPath = fPath
            else: fullPath = baseDir / fPath
        else: fullPath = baseDir / fileName
        try:
            fullPath.parent.mkdir(parents=True, exist_ok=True);fHandler = logging.FileHandler(str(fullPath));fFormatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S");fHandler.setFormatter(fFormatter);fHandler.setLevel(logging.DEBUG);self.customLogger.addHandler(fHandler);self.customLogPipe(f"File logging initialized at: {str(fullPath)}", level=1)
        except Exception as E: self.customLogPipe(f"Failed to setup file logging: {str(E)}", level=3)

    def _initParsers(self):
        """Initializes the command-line argument parser for the application.
        Args:
        	None
        Return:
        	None
        """
        self.baseParser = argparse.ArgumentParser(
            description="Amos Shadow-DNS",
            epilog=str("\n").join([
                "Detailed Documentation on Per-Application Target Forwarding:"
                ""
                "Amos acts as a lightweight, local DNS sinkhole similar to PI-Hole, blocking ads, trackers, and malicious domains via blacklists while forwarding legitimate queries to upstream DoH providers. It includes entropy analysis for detecting potential DNS exfiltration or tunneling."
                ""
                "The new '--wrap' functionality enables per-application DNS forwarding, allowing Amos to act as a centralized DNS filter for specific programs (e.g., browsers like Chrome or Firefox) without affecting the entire system or network. This is akin to proxychains but applied to DNS resolution: it intercepts the application's view of the DNS resolver configuration, forcing queries to route through the local Amos server."
                ""
                "Concept and Implementation:"
                "- **Mount Namespaces for Isolation**: On Linux, we leverage 'unshare -m' to create a private mount namespace for the target application. Within this namespace, we bind-mount a temporary /etc/resolv.conf file over the system's version. This temporary file sets 'nameserver 127.0.0.1' (pointing to the local Amos server) while preserving other settings like search domains or options from the original resolv.conf."
                "- **Per-Application Scope**: The change is isolated to the launched process and its children. The system-wide DNS remains unchanged, ensuring other applications or the network are unaffected."
                "- **No Root Required**: 'unshare -m' (from util-linux) runs without privileges, making it user-friendly."
                "- **Workflow**:"
                "  1. Run Amos as a DNS server in one terminal: python amos.py (or with options like -p 5353 if not root)."
                "  2. In another terminal, use '--wrap' to launch the app: python amos.py --wrap firefox."
                "  - The script creates a temp resolv.conf, binds it in the namespace, and execs the command."
                "  - DNS queries from the app (e.g., browser lookups) hit the local Amos server, which applies blocking and forwarding."
                "- **Limitations**:"
                "  - Requires 'unshare' installed (common on Linux distros)."
                "  - Works for applications using standard libc DNS resolution (getaddrinfo, etc.). Apps with hardcoded DoH (e.g., Firefox with TRR enabled) may bypass; disable such features in app settings."
                "  - If /etc/resolv.conf is a symlink (e.g., to systemd-resolved), the bind-mount still works as it overlays the path."
                "  - For system-wide use, manually edit /etc/resolv.conf or use network manager tools (not recommended for per-app focus)."
                "- **Security/Privacy Benefits**: Enables targeted ad-blocking and telemetry sinking for high-risk apps like browsers, reducing network-wide exposure. Combined with Amos's entropy checks, it helps detect anomalous DNS behavior per app."
                "- **Customization**: Adjust blacklists in gravity.sources or DOH upstream for tailored filtering."
                ""
                "This approach provides a simple, proxychains-like mechanism for DNS without needing shared libraries or hooks, ensuring compatibility and ease of use."]),formatter_class=argparse.RawDescriptionHelpFormatter,add_help=False)
        self.baseParser.add_argument("-l", "--listen", dest="lHost", default="0.0.0.0", help="Address to listen on")
        self.baseParser.add_argument("-p", "--port", dest="port", default=53, type=int, help="Port to listen on")
        self.baseParser.add_argument("-h",'--help', action='store_true', help="Show help")
        self.baseParser.add_argument("-v",'--verbose', action='store_true', help="Enable verbose output")
        self.baseParser.add_argument("-d","--doh", dest="doh", type=str, default=None, help="DOH upstream URL")
        self.baseParser.add_argument("--log-file", dest="logFile", type=str, help="Custom log file name/path")
        self.baseParser.add_argument("--log-dir", dest="logDir", type=str, help="Custom log directory")
        self.baseParser.add_argument("--no-log", dest="noFileLog", action="store_true", help="Disable file logging")
        self.baseParser.add_argument("--wrap", nargs=argparse.REMAINDER, help="Wrap the following command to use the local Amos DNS server (e.g., --wrap firefox)")
        self.args = self.baseParser.parse_args()

    def run(self):
        """Main execution function. Parses arguments, sets up logging, and either starts the server or wraps a command.
        Args:
        	None
        Return:
        	None
        """
        if self.args.help:
            self.baseParser.print_help();sys.exit(1)
        if self.args.verbose: self.config['verbosity'] = True
        self._setupFileLogging()
        if self.args.lHost: self.lHost = self.args.lHost
        if self.args.doh: self.DOHURL = self.args.doh
        port = int(self.args.port) if self.args.port else 53
        if self.args.wrap:
            if not self.args.wrap:
                self.customLogPipe("No command provided to wrap.", level=3);sys.exit(1)
            try:
                with open('/etc/resolv.conf', 'r') as f: lines = f.readlines()
            except Exception as e:
                self.customLogPipe(f"Failed to read /etc/resolv.conf: {str(e)}", level=3);sys.exit(1)
            nl = [l for l in lines if not l.strip().startswith('nameserver')];nl = ['nameserver 127.0.0.1\n'] + nl
            try:
                fd, temp_path = tempfile.mkstemp(text=True)
                with os.fdopen(fd, 'w') as tmp: tmp.writelines(nl)
            except Exception as e:
                self.customLogPipe(f"Failed to create temp resolv.conf: {str(e)}", level=3);sys.exit(1)
            command = ' '.join([arg.replace("'", "\\'").replace('"', '\\"') for arg in self.args.wrap]);usCMD = ['unshare', '-m', '/bin/sh', '-c', f"mount --bind '{temp_path}' /etc/resolv.conf && exec {command}"]
            try:
                self.customLogPipe(f"Wrapping command: {' '.join(self.args.wrap)} with custom DNS.", level=1);subprocess.check_call(usCMD)
            except Exception as e: self.customLogPipe(f"Failed to execute unshare: {str(e)}", level=3)
            finally:
                try: os.unlink(temp_path)
                except Exception: pass
        else:
            try: self.serve(port=port)
            except KeyboardInterrupt: self.customLogPipe(f"Received Keyboard Interrupt, Terminating...");self.exit(1)
            except Exception as E: self.customLogPipe(f"Fatal Error: {str(E)}", level=3);self.exit(1)

    def exit(self,exitCode:int=0):
        """Exits the application with a given exit code, unless `noDeath` flag is set.
        Args:
        	exitCode (int, optional): The exit code to use. Defaults to 0.
        Return:
        	int: The exit code.
        """
        self.customLogPipe(f"Attempted Termination ({str(exitCode)}):{str(self.noDeath)} @ {str(time.asctime())}",level=2)
        if not self.noDeath: sys.exit(exitCode)
        else: self.customLogPipe(f"Termination failed due to noDeath flag!",level=2)
        return exitCode

if __name__ == "__main__":
    amosInst = amos(app=True)
    amosInst.run()
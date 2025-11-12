#!/usr/bin/env python3
import time, threading, socket, logging, random, sys, datetime, asyncio
import colorama, argparse, json, os, string, httpx, hashlib # type: ignore
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, Union, Tuple, Optional, List
__author__  = "J4ck3LSyN";__version__ = "0.1.0"
class nephilaLoggingFormatter(logging.Formatter):
    black = "\x1b[30m";red = "\x1b[31m";green = "\x1b[32m";yellow = "\x1b[33m"
    blue = "\x1b[34m";gray = "\x1b[38m";reset = "\x1b[0m";bold = "\x1b[1m"
    COLORS = {logging.DEBUG: gray+bold,logging.INFO: blue+bold,logging.WARNING: yellow+bold,logging.ERROR: red,logging.CRITICAL: red+bold,}
    def format(self, record):
        logColor = self.COLORS[record.levelno]
        format = "(black){asctime}(reset) (levelcolor){levelname:<8}(reset) (green){name}(reset) {message}"
        format = format.replace("(black)", self.black + self.bold)
        format = format.replace("(reset)", self.reset)
        format = format.replace("(levelcolor)", logColor)
        format = format.replace("(green)", self.green + self.bold)
        formatter = logging.Formatter(format, "%Y-%m-%d %H:%M:%S", style="{")
        return formatter.format(record)
customLogger = logging.getLogger("nephila");customLogger.setLevel(logging.DEBUG);consoleHandler = logging.StreamHandler();consoleHandler.setFormatter(nephilaLoggingFormatter());consoleHandler.setLevel(logging.INFO);customLogger.addHandler(consoleHandler)
class nephila:
    def customLogPipe(self,message:str,level:int=1,exc_info:bool=False,noLog:bool=False,silent:bool=False):
        if silent or not self.config['verbosity']: return 
        prefixMap = {1: "[*] ",3: "[!] ",'output': "[^] "};logMap = {0: self.customLogger.debug,'d': self.customLogger.debug,'debug': self.customLogger.debug,1: self.customLogger.info,'i': self.customLogger.info,'info': self.customLogger.info,2: self.customLogger.warning,'w': self.customLogger.warning,'warning': self.customLogger.warning,3: self.customLogger.error,'r': self.customLogger.error,'error': self.customLogger.error,4: self.customLogger.critical,'c': self.customLogger.critical,'critical': self.customLogger.critical};prefix = prefixMap.get(level, "");logFunc = logMap.get(level, self.customLogger.info)
        if not noLog: logFunc(f"{prefix}{message}", exc_info=exc_info)    
    def __init__(self,app:bool=False):
        self.config = {
            "noConfirmUser":False,
            "verbosity":True
        }
        self.customLogger = customLogger; self.args = None
        self.parsCentral = None
        self.subParsMode = None
        self.app = app
        if self.app: 
            self._initParsers()
            self.noAdmin = self.args.no_admin
            if not self.noAdmin: self._initImports()
            else: self.customLogPipe("Running in --no-admin mode. Scapy-dependent features are disabled.",level=2)
            self.customLogPipe(f"Finished initializing nephila({str(__version__)}).")

    class proxify:

        def __init__(self,NSI:callable):
            self.nS = NSI
            self.customLogPipe = self.nS.customLogPipe
            self.history = {}
            self.proxies = {
                "http": {},
                "https": {},
                'socks4': {},
                'socks5': {}
            }
            self.config = {
                "validationURLS": [
                    'http://httpbin.org/ip',
                    'http://icanhazip.com',
                    'http://ident.me',
                    'http://checkip.amazonaws.com'
                ],
                "testTimeout": 5,
                "minScore": 0.6,
                "publicProxies": {
                    'freeProxyList': 'https://www.freeproxylists.net',
                    'proxyList': 'https://www.proxy-list.download',
                    'ipQualityScore': 'https://ipqualityscore.com/api/json/proxy/lookup',
                    'proxyMesh': 'https://api.proxymesh.com/clients',
                    'scraperAPI': 'https://api.scraperapi.com',
                    'brightData': 'https://api.brightdata.com/dca/get_residential_ips',
                    'clarketmProxyList': 'https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt'
                },
                "pubProxyAPI": "https://www.proxy-list.download/api/v1/get?type=",
                "pubProxyType": "http",
                "proxychainsVerifyLimit":20

            }
            self._proxyAddressIndex = {}
            self._proxyChainCache = {}
            self._proxychainRefreshInterval = datetime.timedelta(hours=1)
            self._roundRobinIndex = {}

        async def fetchAndVerify(self, limit:int=20, proxyType:str=None) -> List[Dict]:
            """
            Fetch and verify proxies, storing results in cache
            
            Args:
                limit: Maximum number of verified proxies to return
                proxyType: Type of proxy to fetch (uses config default if None)
                
            Returns:
                List of verified proxy dictionaries
            """
            pType = proxyType or self.config['pubProxyType'];rawProxies = await self._getPubProxies(proxyType=pType, limit=limit * 3)
            if not rawProxies:
                self.customLogPipe("No raw proxies fetched", level=1);return []
            # Batch verify all proxies
            verificationTasks = [ self.verifyProxy(proxy, pType) for proxy in rawProxies];results = await asyncio.gather(*verificationTasks, return_exceptions=True);verified = []
            for result in results:
                if isinstance(result, dict) and result and result.get('verified', [False])[0]:
                    verified.append(result)
                    try: self._appendProxy(pType, result['proxy'], result)
                    except: pass  
            # Update cache
            self._proxyChainCache['lastRefreshed'] = datetime.datetime.now()
            self._proxyChainCache['verifiedProxies'] = verified[:limit]
            self.customLogPipe(f"Fetched and verified {len(verified[:limit])}/{len(rawProxies)} proxies",level=0)
            return verified[:limit]
        
        def getRandomProxy(self, proxyType:str=None) -> Optional[str]:
            """
            Get a random proxy from cache or storage
            
            Args:
                proxyType: Type of proxy to get (if None, uses cache or any type)
                
            Returns:
                Random proxy address or None
            """
            if 'verifiedProxies' in self._proxyChainCache:
                cachedProxies = self._proxyChainCache['verifiedProxies']
                if cachedProxies: return random.choice(cachedProxies)['proxy']
            if proxyType: available = self.proxies.get(proxyType, {})
            else:
                available = {}
                for pType in self.proxies: available.update(self.proxies[pType])
            if available:
                metadata = random.choice(list(available.values()));return metadata.get('proxy')
            return None
        
        
        def getProxies(self, proxyType:str=None, fromCache:bool=True) -> List[str]:
            """
            Get all proxy addresses
            
            Args:
                proxyType: Filter by proxy type (optional)
                fromCache: Get from cache first if True
                
            Returns:
                List of proxy addresses
            """
            # Try cache first if requested
            if fromCache and 'verifiedProxies' in self._proxyChainCache:
                cachedProxies = self._proxyChainCache['verifiedProxies']
                if cachedProxies: return [p['proxy'] for p in cachedProxies]
            # Get from main storage
            proxyList = []
            if proxyType:
                if proxyType not in self.proxies: return []
                proxyTypes = [proxyType]
            else: proxyTypes = list(self.proxies.keys())
            for pType in proxyTypes:
                for metadata in self.proxies[pType].values():
                    proxy = metadata.get('proxy')
                    if proxy: proxyList.append(f"{pType}://{proxy}")
            return proxyList
        
        
        def rotateProxy(self, proxyType:str=None) -> Optional[str]:
            """
            Rotate through proxies in round-robin fashion using cache
            
            Args:
                proxyType: Type of proxy to rotate (uses cache if None)
                
            Returns:
                Next proxy in rotation or None
            """
            if 'verifiedProxies' in self._proxyChainCache:
                cachedProxies = self._proxyChainCache['verifiedProxies']
                if not cachedProxies: return None 
                p = cachedProxies.pop(0);cachedProxies.append(p);return p['proxy']
            proxyInfo = self.getProxy( proxyType=proxyType or 'http',strategy='round_robin')
            return proxyInfo['proxy'] if proxyInfo else None
        
        
        async def healthCheck(self, proxyType:str=None, updateCache:bool=True) -> List[Dict]:
            """
            Perform health check on all stored proxies
            
            Args:
                proxyType: Check specific proxy type (checks all if None)
                updateCache: Update cache with healthy proxies if True
                
            Returns:
                List of healthy proxy dictionaries
            """
            proxiesToCheck = []
            if 'verifiedProxies' in self._proxyChainCache:
                for proxy_data in self._proxyChainCache['verifiedProxies']:
                    proxy = proxy_data.get('proxy');pType = proxyType or self.config['pubProxyType']
                    if proxy: proxiesToCheck.append((pType, proxy))
            else:
                if proxyType:
                    if proxyType not in self.proxies: return []
                    proxyTypes = [proxyType]
                else: proxyTypes = list(self.proxies.keys())
                for pType in proxyTypes:
                    for metadata in self.proxies[pType].values():
                        proxy = metadata.get('proxy')
                        if proxy: proxiesToCheck.append((pType, proxy))
            if not proxiesToCheck:
                self.customLogPipe("No proxies to health check", level=1);return []
            verificationTasks = [ self.verifyProxy(proxy, pType) for pType, proxy in proxiesToCheck]
            results = await asyncio.gather(*verificationTasks, return_exceptions=True)
            healthy = []
            for (pType, proxy), result in zip(proxiesToCheck, results):
                if isinstance(result, dict) and result and result.get('verified', [False])[0]: healthy.append(result)
            # Update cache if requested
            if updateCache:
                self._proxyChainCache['verifiedProxies'] = healthy;self._proxyChainCache['lastRefreshed'] = datetime.datetime.now()
            self.customLogPipe(f"Health check: {len(healthy)}/{len(proxiesToCheck)} proxies healthy",level=0)
            return healthy
        
        
        def filterByLatency(self, maxLatency:float, proxyType:str=None, fromCache:bool=True) -> List[Dict]:
            """
            Filter proxies by maximum latency
            
            Args:
                maxLatency: Maximum acceptable latency in seconds
                proxyType: Filter specific proxy type (all types if None)
                fromCache: Filter from cache first if True
                
            Returns:
                List of proxy dictionaries meeting latency requirement
            """
            filtered = []
            if fromCache and 'verifiedProxies' in self._proxyChainCache:
                cachedProxies = self._proxyChainCache['verifiedProxies']
                filtered = [p for p in cachedProxies if p.get('latency', float('inf')) <= maxLatency]
                if filtered:
                    self.customLogPipe(f"Filtered {len(filtered)} proxies from cache with latency <= {maxLatency}s",level=0)
                    return filtered
            if proxyType:
                if proxyType not in self.proxies: return []
                proxyTypes = [proxyType]
            else: proxyTypes = list(self.proxies.keys())
            for pType in proxyTypes:
                for metadata in self.proxies[pType].values():
                    latency = metadata.get('latency', float('inf'))
                    if latency <= maxLatency: filtered.append(metadata)
            
            self.customLogPipe(f"Filtered {len(filtered)} proxies with latency <= {maxLatency}s",level=0)
            return filtered

        def _getHashID(self, proxy:str|bytes) -> Tuple[str, bytes]:
            """Generate MD5 hash for proxy identification"""
            hID = hashlib.md5()
            if not isinstance(proxy, bytes):
                proxy = str(proxy).encode('utf-8')
            hID.update(proxy)
            return (hID.hexdigest(), hID.digest())

        def _appendProxy(self, proxyType:str, proxy:str, proxyMetaData:Dict[str, Any]) -> None:
            """Add a proxy to the internal storage"""
            if proxyType not in [k for k in self.proxies.keys()]:
                eM = f"Proxy type '{proxyType}' is invalid."
                self.customLogPipe(f"Value-Error: {eM}.", level=2)
                raise ValueError(eM)
            hashID = self._getHashID(str(proxy))
            self.proxies[proxyType][hashID[0]] = proxyMetaData
            self._proxyAddressIndex[proxy] = (proxyType, hashID[0])
            self.customLogPipe(f"Added {proxyType} proxy: {proxy}", level=0)

        def _calculateProxyScore(self, metadata:Dict[str,Any]) -> float:
            """
            Calculate a proxy score based on multiple factors:
            - Verification status (40%)
            - Latency/Speed (30%)
            - Age/Freshness (20%)
            - Success rate from history (10%)
            """
            score = 0.0
            if metadata.get('verified', [False])[0]: score += 0.4
            else: return 0.0  # Unverified proxies get 0 score
            latency = metadata.get('latency', float('inf'))
            if latency != float('inf'):
                if latency <= 1.0: score += 0.3
                elif latency <= 10.0: score += 0.3 * (1 - (latency - 1) / 9)
            timestamp = metadata.get('timestamp')
            if timestamp:
                ageSec = (datetime.datetime.now() - timestamp).total_seconds();ageHour = ageSec / 3600
                if ageHour <= 1: score += 0.2
                elif ageHour <= 24: score += 0.2 * (1 - (ageHour - 1) / 23)
            proxy = metadata.get('proxy')
            if proxy and proxy in self.history:
                historyData = self.history[proxy];totalAttempts = historyData.get('totalAttempts', 0);successfullAttempts = historyData.get('successfullAttempts', 0)
                if totalAttempts > 0: successRate = successfullAttempts / totalAttempts;score += 0.1 * successRate
            else: score += 0.05
            return round(score, 3)

        def _updateProxyHistory(self, proxy:str, success:bool) -> None:
            """Update the usage history for a proxy"""
            if proxy not in self.history:
                self.history[proxy] = {
                    'totalAttempts': 0,
                    'successfullAttempts': 0,
                    'last_used': None,
                    'first_used': datetime.datetime.now()}
            self.history[proxy]['totalAttempts'] += 1
            if success: self.history[proxy]['successfullAttempts'] += 1
            self.history[proxy]['last_used'] = datetime.datetime.now()

        def _removeProxyByAddress(self, proxy:str) -> None:
            """Remove a proxy from storage by its address"""
            hashID = self._getHashID(proxy)[0]
            for proxyType in self.proxies:
                if hashID in self.proxies[proxyType]:
                    del self.proxies[proxyType][hashID]
                    self.customLogPipe(f"Removed proxy: {proxy}", level=0);return

        async def verifyProxy(self, proxy:str, proxyType:str='http') -> Optional[dict]:
            """Verify if a proxy is working by testing against validation URLs"""

            # Validate proxy format
            if not proxy or ':' not in proxy:
                self.customLogPipe(f"Invalid proxy format: {proxy}", level=2)
                return None

            proxyURL = f"{proxyType}://{proxy}"
            self.customLogPipe(f"Testing proxy: {proxyURL}", level=0)

            for url in self.config['validationURLS']:
                try:
                    # httpx uses 'mounts' parameter for proxies
                    async with httpx.AsyncClient(
                        mounts={
                            "http://": httpx.AsyncHTTPTransport(proxy=proxyURL),
                            "https://": httpx.AsyncHTTPTransport(proxy=proxyURL),
                        },
                        timeout=self.config['testTimeout'],
                        verify=False
                    ) as client:
                        start_time = datetime.datetime.now()
                        resp = await client.get(url)
                        latency = (datetime.datetime.now() - start_time).total_seconds()

                        self.customLogPipe(f"Proxy {proxy} -> {url}: {resp.status_code} ({latency:.2f}s)", level=0)

                        if resp.status_code == 200:
                            return {
                                "proxy": proxy,
                                "verified": [True, url, resp.text.strip()],
                                "latency": latency,
                                "timestamp": datetime.datetime.now()
                            }
                except Exception as e:
                    self.customLogPipe(f"Proxy {proxy} failed on {url}: {type(e).__name__}: {str(e)[:100]}", level=1)
                    continue
                
            self.customLogPipe(f"Proxy {proxy} failed all verification tests", level=1)
            return None

        async def _getPubProxies(self, proxyType:str=None, limit:int=50) -> List[str]:
            """Fetch public proxies from API"""
            pType = proxyType if proxyType else self.config['pubProxyType']
            uri = self.config['pubProxyAPI'] + pType
            proxies = set()
            self.customLogPipe(f"Fetching proxies from: {uri}", level=0)
            try:
                async with httpx.AsyncClient(timeout=10, verify=False) as client:
                    resp = await client.get(uri)
                    self.customLogPipe(f"API Response Status: {resp.status_code}", level=0)
                    if resp.status_code == 200:
                        # Try JSON first, fall back to plaintext
                        try:
                            data = resp.json()
                            proxyList = data.get('data', [])
                            self.customLogPipe(f"Parsed as JSON, got {len(proxyList)} proxies", level=0)
                        except Exception as e:
                            # If JSON fails, parse as plaintext (one proxy per line)
                            self.customLogPipe(f"JSON parsing failed ({type(e).__name__}), trying plaintext format", level=1)
                            text_content = resp.text.strip()
                            self.customLogPipe(f"Raw response preview: {text_content[:200]}", level=0)
                            proxyList = [line.strip() for line in text_content.split('\n') if line.strip()]
                            self.customLogPipe(f"Parsed as plaintext, got {len(proxyList)} proxies", level=0)
                        for proxy in proxyList[:limit]:
                            if isinstance(proxy, dict):
                                # Handle dict format: {"ip": "x.x.x.x", "port": "xxxx"}
                                proxy_str = f"{proxy.get('ip', '')}:{proxy.get('port', '')}"
                            else:
                                # Handle string format: "x.x.x.x:port"
                                proxy_str = str(proxy).strip()
                            # Validate format (must have IP:port)
                            if proxy_str and ':' in proxy_str and proxy_str.count(':') == 1:
                                ip, port = proxy_str.rsplit(':', 1)
                                try:
                                    int(port)  # Validate port is numeric
                                    proxies.add(proxy_str)
                                    self.customLogPipe(f"Added proxy: {proxy_str}", level=0)
                                except ValueError:
                                    self.customLogPipe(f"Invalid port in proxy: {proxy_str}", level=1)
                                    continue
                            else:
                                self.customLogPipe(f"Invalid proxy format: {proxy_str}", level=1)

                        self.customLogPipe(f"Validated {len(proxies)} proxies from API", level=0)
                    else:
                        self.customLogPipe(f"API returned status {resp.status_code}: {resp.text[:200]}", level=2)

            except Exception as e:
                self.customLogPipe(f"Error fetching public proxies: {str(e)}", level=2)
                import traceback
                self.customLogPipe(traceback.format_exc(), level=2)

            self.customLogPipe(f"Returning {len(proxies)} proxies", level=0)
            return list(proxies)

        async def fetch(self, proxyType:str=None, limit:int=50, verify:bool=True) -> Dict[str, List]:
            """Fetch and optionally verify proxies from public sources"""
            proxies = {'raw':[],'verified':[],'failed':[]}
            try:
                rawProxies = await self._getPubProxies(proxyType, limit)
                proxies['raw'] = rawProxies
                self.customLogPipe(f"Fetched {len(rawProxies)} raw proxies", level=0)

                if not rawProxies:
                    self.customLogPipe("No proxies returned from API", level=2)
                    return proxies

                if verify and rawProxies:
                    self.customLogPipe(f"Starting verification of {len(rawProxies)} proxies...", level=0)
                    pType = proxyType or self.config['pubProxyType']
                    verificationTasks = [
                        self.verifyProxy(proxy, pType) 
                        for proxy in rawProxies
                    ]
                    results = await asyncio.gather(*verificationTasks, return_exceptions=True)
                    verificationCount = 0
                    failedCount = 0
                    for idx, result in enumerate(results):
                        self.customLogPipe(f"Verification [{idx+1}/{len(results)}]: {result}", level=0)  # Debug
                        if isinstance(result, Exception):
                            self.customLogPipe(f"Verification error: {result}", level=1)
                            failedCount += 1
                            continue
                        if isinstance(result, dict) and result:
                            if result.get('verified', [False])[0]:
                                proxies['verified'].append(result)
                                pType = proxyType or self.config['pubProxyType']
                                try:
                                    self._appendProxy(pType, result['proxy'], result)
                                    verificationCount += 1
                                except Exception as e:
                                    self.customLogPipe(f"Failed to append proxy {result['proxy']}: {e}", level=1)
                            else:
                                proxies['failed'].append(result)
                                failedCount += 1
                        else: failedCount += 1

                    self.customLogPipe(f"Verification complete: {verificationCount} verified, {failedCount} failed", level=0)
                else: self.customLogPipe("Skipping verification", level=0)
            except Exception as e:
                self.customLogPipe(f"Error in fetch: {str(e)}", level=2)
                import traceback
                self.customLogPipe(traceback.format_exc(), level=2)

            return proxies

        def getProxy(self, proxyType:str='http', minScore:float=None, strategy:str='best') -> Optional[Dict[str, Any]]:
            """
            Get a proxy from storage based on type and minimum score

            Args:
                proxyType: Type of proxy ('http', 'https', 'socks4', 'socks5')
                minScore: Minimum acceptable score (0.0 - 1.0)
                strategy: Selection strategy:
                    - 'best': Return highest scoring proxy
                    - 'random': Return random proxy above threshold
                    - 'roundRobin': Cycle through proxies

            Returns:
                Dictionary with proxy details and score, or None
            """
            scoreThreshold = minScore if minScore is not None else self.config['minScore']
            if proxyType not in self.proxies:
                self.customLogPipe(f"Invalid proxy type: {proxyType}", level=2);return None
            avaProxies = self.proxies[proxyType]
            if not avaProxies:
                self.customLogPipe(f"No {proxyType} proxies available", level=1);return None
            scoredProxies = []
            for hashID, metadata in avaProxies.items():
                score = self._calculateProxyScore(metadata)
                if score >= scoreThreshold:
                    scoredProxies.append({
                        'hashID': hashID,
                        'proxy': metadata.get('proxy'),
                        'score': score,
                        'metadata': metadata})
            if not scoredProxies:
                self.customLogPipe(f"No {proxyType} proxies meet minimum score of {scoreThreshold}",level=1);return None
            if strategy == 'best': selected = max(scoredProxies, key=lambda x: x['score'])
            elif strategy == 'random': selected = random.choice(scoredProxies)
            elif strategy == 'roundRobin':
                if proxyType not in self._roundRobinIndex:self._roundRobinIndex[proxyType] = 0
                scoredProxies.sort(key=lambda x: x['score'], reverse=True)
                index = self._roundRobinIndex[proxyType] % len(scoredProxies)
                selected = scoredProxies[index]
                self._roundRobinIndex[proxyType] += 1
            else:
                self.customLogPipe(f"Invalid strategy: {strategy}", level=2);return None

            self.customLogPipe(f"Selected {proxyType} proxy: {selected['proxy']} (score: {selected['score']})",level=0)
            return {
                'proxy': selected['proxy'],
                'score': selected['score'],
                'type': proxyType,
                'metadata': selected['metadata']}

        def reportProxyResult(self, proxy:str, success:bool) -> None:
            """
            Report the result of using a proxy to update its history

            Args:
                proxy: The proxy address that was used
                success: Whether the proxy worked successfully
            """
            self._updateProxyHistory(proxy, success)
            if proxy in self.history:
                history = self.history[proxy]
                if history['totalAttempts'] >= 10:  # Minimum attempts before evaluation
                    successRate = history['successfullAttempts'] / history['totalAttempts']
                    if successRate < 0.3:  # Less than 30% success rate
                        self._removeProxyByAddress(proxy)
                        self.customLogPipe(f"Removed proxy {proxy} due to poor success rate: {successRate:.2%}",level=1)

        def clearProxies(self, proxyType:str=None) -> None:
            """Clear stored proxies"""
            if proxyType:
                if proxyType in self.proxies:
                    self.proxies[proxyType] = {};self.customLogPipe(f"Cleared {proxyType} proxies", level=0)
                else: self.customLogPipe(f"Invalid proxy type: {proxyType}", level=2)
            else:
                for pType in self.proxies:
                    self.proxies[pType] = {}
                self.customLogPipe("Cleared all proxies", level=0)

        def getProxyStats(self, proxyType:str=None) -> Dict[str, Any]:
            """Get statistics about stored proxies"""
            stats = {}
            if proxyType:
                if proxyType not in self.proxies: return {}
                proxyTypes = [proxyType]
            else: proxyTypes = list(self.proxies.keys())
            for pType in proxyTypes:
                proxies = self.proxies[pType]
                scores = [self._calculateProxyScore(meta) for meta in proxies.values()]
                stats[pType] = {
                    'total': len(proxies),
                    'average_score': round(sum(scores) / len(scores), 3) if scores else 0,
                    'max_score': round(max(scores), 3) if scores else 0,
                    'min_score': round(min(scores), 3) if scores else 0,
                    'above_threshold': sum(1 for s in scores if s >= self.config['minScore'])}
            stats['history'] = {
                'total_proxies_used': len(self.history),
                'totalAttempts': sum(h['totalAttempts'] for h in self.history.values()),
                'total_successes': sum(h['successfullAttempts'] for h in self.history.values())}
            return stats

        def exportProxies(self, proxyType:str=None, minScore:float=None) -> List[str]:
            """
            Export proxy addresses as a list

            Args:
                proxyType: Filter by proxy type
                minScore: Only export proxies above this score

            Returns:
                List of proxy addresses
            """
            scoreThreshold = minScore if minScore is not None else 0.0
            exported = []
            if proxyType:
                if proxyType not in self.proxies: return []
                proxyTypes = [proxyType]
            else:proxyTypes = list(self.proxies.keys())
            for pType in proxyTypes:
                for metadata in self.proxies[pType].values():
                    score = self._calculateProxyScore(metadata)
                    if score >= scoreThreshold:
                        proxy = metadata.get('proxy')
                        if proxy:
                            exported.append(f"{pType}://{proxy}")
            return exported

        async def importProxies(self, proxyList:List[str], verify:bool=False) -> Dict[str, int]:
            """
            Import proxies from a list

            Args:
                proxyList: List of proxy strings (format: "type://host:port" or "host:port")
                verify: Whether to verify proxies before importing

            Returns:
                Dictionary with import statistics
            """
            stats = {'imported': 0, 'verified': 0, 'failed': 0}
            async def process_proxy(proxyStr):
                try:
                    # Parse proxy string
                    if '://' in proxyStr: pType, address = proxyStr.split('://', 1)
                    else:
                        pType = 'http' ;address = proxyStr
                    if pType not in self.proxies:
                        return 'failed'
                    if verify:
                        result = await self.verifyProxy(address, pType)
                        if result and result.get('verified', [False])[0]:
                            self._appendProxy(pType, address, result); return 'verified'
                        else: return 'failed'
                    else:
                        metadata = {
                            'proxy': address,
                            'verified': [False, None],
                            'timestamp': datetime.datetime.now()}
                        self._appendProxy(pType, address, metadata)
                        return 'imported'
                except Exception as e:
                    self.customLogPipe(f"Error importing proxy {proxyStr}: {e}", level=2); return 'failed'

            tasks = [process_proxy(proxyStr) for proxyStr in proxyList]
            results = await asyncio.gather(*tasks)

            for result in results:
                if result:
                    stats[result] += 1
            return stats
    
    class firewallFrag:
        def __init__(self,NSI:callable):
            self.nS = NSI
            self.customLogPipe = self.nS.customLogPipe
            self.history = {}

        def scan(self,
                 rHost:str,
                 rPort:int,
                 maxRandomDataLength:int=1024,
                 minFragSize:int=8,
                 maxFragSize:int=16,
                 minTTL:int=64,
                 maxTTL:int=128,
                 minInterFragDelay:float=0.5,
                 maxInterFragDelay:float=2.0,
                 verbose:bool=False,
                 sourceIP:Optional[str]=None):
            if not self.nS._validatePort(rPort):
                self.customLogPipe(f"Invalid port: {rPort}",level=3)
                raise ValueError(f"Port must be 1-65535, got {rPort}")
            if os.geteuid() != 0:
                self.customLogPipe("Error: This module must be executed under `root` privileges.",level=2)
                raise PermissionError("This module('firewallFrag.scan') must be executed under `root` privileges.")
            scapyIP, scapyRaw, scapySend = self.nS._getScapyModules(['IP','Raw','send'])
            scapyConf = self.nS._getScapyModules(['conf'])[0]
            if sourceIP == None:
                try: sourceIP = scapyConf.route.route(rHost)[1]
                except Exception:
                    sourceIP = "127.0.0.1"
                    self.customLogPipe(f"Could not determine optimal source IP for {rHost}, using {sourceIP}",level=2)
            httpRData = f"GET / HTTP/1.1\r\nHost: {rHost}\r\n\r\n"
            if maxRandomDataLength > 0: httpRData += self.nS._randomData(maxRandomDataLength)
            payloadToFragment = httpRData.encode('utf-8')
            fragmentsDataChunks = []
            currentDataIndex = 0
            while currentDataIndex < len(payloadToFragment):
                fragSize = random.randint(minFragSize, maxFragSize)
                remDataLen = len(payloadToFragment) - currentDataIndex
                if remDataLen > fragSize:
                    fragSize = (fragSize // 8)*8
                    if fragSize == 0: fragSize = 8
                fragSize = min(fragSize, remDataLen)
                fragmentsDataChunks.append(payloadToFragment[currentDataIndex:currentDataIndex+fragSize])
                currentDataIndex += fragSize

            IPID = random.randint(1, 65535)
            currentIPOffset = 0
            for i, fragChunk in enumerate(fragmentsDataChunks):
                moreFragments = 1 if i < len(fragmentsDataChunks)-1 else 0
                ipFragPacket = scapyIP(dst=rHost,src=sourceIP,id=IPID,frag=currentIPOffset//8,flags=moreFragments,proto=6,ttl=random.randint(minTTL,maxTTL)) / scapyRaw(load=fragChunk)
                if verbose:
                    self.customLogPipe(f"Sending fragment {i+1}/{len(fragmentsDataChunks)} to {rHost}:{rPort}")
                    self.customLogPipe(f"  Source IP: {sourceIP}, Target IP: {rHost}")
                    self.customLogPipe(f"  IP ID: {IPID}, Offset: {ipFragPacket.frag}, Flags: {ipFragPacket.flags}, TTL: {ipFragPacket.ttl}")
                    self.customLogPipe(f"  Payload length: {len(fragChunk)} bytes")
                scapySend(ipFragPacket,verbose=0)
                currentIPOffset += len(fragChunk)
                self.nS._randomDelay(minInterFragDelay,maxInterFragDelay)
            return {"status":1,"rHost":rHost,"rPort":rPort,"maxRandomDataLength":maxRandomDataLength}

    class abaddon:
        def __init__(self,NSI:callable):
            self.nS = NSI
            self.customLogPipe = self.nS.customLogPipe
            self.history = {}

        def startMitm(self,listenPort:int,targetHost:str,targetPort:int)->bool:
            if not self.nS._validatePort(listenPort) or not self.nS._validatePort(targetPort):
                self.customLogPipe("Invalid port range",level=3)
                return False
            self.customLogPipe(f"MITM proxy listening on {listenPort}, forwarding to {targetHost}:{targetPort}")
            return True

        def redirect(self,srcPort:int,dstHost:str,dstPort:int)->bool:
            if not self.nS._validatePort(srcPort) or not self.nS._validatePort(dstPort):
                self.customLogPipe("Invalid port range",level=3)
                return False
            self.customLogPipe(f"Redirecting {srcPort} -> {dstHost}:{dstPort}")
            return True

    class mitmCapture:
        def __init__(self,NSI:callable):
            self.nS = NSI
            self.customLogPipe = self.nS.customLogPipe
            self.capturedPackets = []
            self.packetLock = threading.Lock()
            self.running = False
            self.redirectRules = {}

        def addRedirectRule(self,srcIP:str,dstIP:str,srcPort:int,dstPort:int):
            if not self.nS._validatePort(srcPort) or not self.nS._validatePort(dstPort):
                self.customLogPipe("Invalid port in redirect rule",level=3)
                return False
            key = f"{srcIP}:{srcPort}"
            self.redirectRules[key] = (dstIP,dstPort)
            self.customLogPipe(f"Added redirect rule: {key} -> {dstIP}:{dstPort}")
            return True

        def _packetCallback(self,packet):
            scapyIP, scapyTCP, scapyUDP, scapyDNS = self.nS._getScapyModules(['IP','TCP','UDP','DNSQR'])
            try:
                packetData = {"timestamp":time.time(),"raw":str(packet)}
                if packet.haslayer(scapyIP):
                    src = packet[scapyIP].src
                    dst = packet[scapyIP].dst
                    packetData["srcIP"] = src
                    packetData["dstIP"] = dst
                    if packet.haslayer(scapyTCP):
                        sport = packet[scapyTCP].sport
                        dport = packet[scapyTCP].dport
                        flags = packet[scapyTCP].flags
                        packetData["protocol"] = "TCP"
                        packetData["srcPort"] = sport
                        packetData["dstPort"] = dport
                        packetData["flags"] = flags
                        ruleKey = f"{src}:{sport}"
                        if ruleKey in self.redirectRules:
                            newDst, newDPort = self.redirectRules[ruleKey]
                            self.customLogPipe(f"Redirecting TCP {src}:{sport} -> {newDst}:{newDPort}")
                            modPacket = scapyIP(dst=newDst)/scapyTCP(dport=newDPort,sport=sport)
                            scapySend = self.nS._getScapyModules(['send'])[0]
                            scapySend(modPacket,verbose=0)
                    elif packet.haslayer(scapyUDP):
                        sport = packet[scapyUDP].sport
                        dport = packet[scapyUDP].dport
                        packetData["protocol"] = "UDP"
                        packetData["srcPort"] = sport
                        packetData["dstPort"] = dport
                with self.packetLock:
                    self.capturedPackets.append(packetData)
                    if len(self.capturedPackets) > 10000:
                        self.capturedPackets = self.capturedPackets[-5000:]
                self.customLogPipe(f"Captured {packetData.get('protocol','UNKNOWN')} from {packetData.get('srcIP','?')} to {packetData.get('dstIP','?')}",silent=True)
            except Exception as E:
                self.customLogPipe(f"Error processing packet: {str(E)}",level=3)

        def startCapture(self,interface:Optional[str]=None,packetFilter:str=""):
            if os.geteuid() != 0:
                self.customLogPipe("MITM capture requires root privileges",level=3)
                return False
            scapySniff = self.nS._getScapyModules(['sniff'])[0]
            self.running = True
            self.customLogPipe(f"Starting MITM capture on {interface if interface else 'all interfaces'}")
            try:
                scapySniff(iface=interface,prn=self._packetCallback,filter=packetFilter,store=False,stop_filter=lambda x: not self.running)
            except KeyboardInterrupt:
                self.customLogPipe("MITM capture interrupted by user",level=2)
                self.running = False
            except Exception as E:
                self.customLogPipe(f"Error during capture: {str(E)}",level=3)
                self.running = False
            return True

        def stopCapture(self):
            self.running = False
            self.customLogPipe("Stopping MITM capture")

        def exportCapture(self,filepath:str)->bool:
            try:
                with open(filepath,'w') as f:
                    json.dump(self.capturedPackets,f,indent=2)
                self.customLogPipe(f"Exported {len(self.capturedPackets)} packets to {filepath}")
                return True
            except Exception as E:
                self.customLogPipe(f"Error exporting capture: {str(E)}",level=3)
                return False

        def getCaptureStats(self)->Dict[str,Any]:
            with self.packetLock:
                protocolCount = {}
                portCount = {}
                for pkt in self.capturedPackets:
                    proto = pkt.get('protocol','UNKNOWN')
                    protocolCount[proto] = protocolCount.get(proto,0) + 1
                    port = pkt.get('dstPort')
                    if port: portCount[port] = portCount.get(port,0) + 1
                return {"totalPackets":len(self.capturedPackets),"protocolBreakdown":protocolCount,"topPorts":dict(sorted(portCount.items(),key=lambda x: x[1],reverse=True)[:10])}

    class enumeration:
        def __init__(self,NSI:callable):
            self.nS = NSI
            self.customLogPipe = self.nS.customLogPipe
            self.history = {}

        def dnsQuery(self,domain:str,recordType:str="A")->list[str]:
            import dns.resolver # type: ignore
            try:
                results = dns.resolver.resolve(domain,recordType)
                records = [str(rdata) for rdata in results]
                self.customLogPipe(f"DNS {recordType} lookup for {domain}: {records}")
                return records
            except Exception as E:
                self.customLogPipe(f"DNS query failed for {domain}: {str(E)}",level=3)
                return []

        def dnsReverseQuery(self,ipAddr:str)->Optional[str]:
            import dns.reversename, dns.resolver # type: ignore
            try:
                revName = dns.reversename.from_address(ipAddr)
                result = dns.resolver.resolve(revName,"PTR")
                hostname = str(result[0]).rstrip('.')
                self.customLogPipe(f"Reverse DNS for {ipAddr}: {hostname}")
                return hostname
            except Exception as E:
                self.customLogPipe(f"Reverse DNS lookup failed for {ipAddr}: {str(E)}",level=2)
                return None

        def dnsZoneTransfer(self,domain:str,nameserver:str)->Dict[str,list]:
            import dns.zone, dns.query # type: ignore
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(nameserver,domain))
                records = {}
                for name, rdataset in zone.iterate_rdatasets():
                    rdType = dns.rdatatype.to_text(rdataset.rdtype)
                    if rdType not in records: records[rdType] = []
                    for rdata in rdataset:
                        records[rdType].append(str(rdata))
                self.customLogPipe(f"Zone transfer successful for {domain}: {len(records)} record types")
                return records
            except Exception as E:
                self.customLogPipe(f"Zone transfer failed for {domain}: {str(E)}",level=2)
                return {}

        def dnsSubdomainEnum(self,domain:str,wordlist:Optional[list]=None)->list[str]:
            import dns.resolver # type: ignore
            if wordlist is None:
                wordlist = ["www","mail","ftp","localhost","webmail","smtp","pop","ns1","dns","soa","ns","mx","ns2","cpanel","whois","autodiscover","autoconfig","m","imap","test","portal","admin","mailserver"]
            found = []
            for subdomain in wordlist:
                try:
                    fullDomain = f"{subdomain}.{domain}"
                    result = dns.resolver.resolve(fullDomain,"A")
                    ip = str(result[0])
                    self.customLogPipe(f"Found subdomain: {fullDomain} -> {ip}")
                    found.append(fullDomain)
                except:
                    pass
            return found

        def asnLookup(self,asn:str)->Dict[str,Any]:
            import dns.resolver # type: ignore
            try:
                asnQuery = f"AS{asn}.asn.cymru.com"
                result = dns.resolver.resolve(asnQuery,"TXT")
                data = str(result[0]).strip('"').split(' | ')
                asInfo = {"ASN":asn,"IP_Range":data[0],"Country":data[1],"ISP":data[2]}
                self.customLogPipe(f"ASN lookup {asn}: {asInfo['ISP']} ({asInfo['Country']})")
                return asInfo
            except Exception as E:
                self.customLogPipe(f"ASN lookup failed: {str(E)}",level=3)
                return {}

        def gatherEnumData(self,domain:str)->Dict[str,Any]:
            enumData = {"domain":domain,"timestamp":time.time(),"dns_a":[]}
            enumData["dns_a"] = self.dnsQuery(domain,"A")
            enumData["dns_mx"] = self.dnsQuery(domain,"MX")
            enumData["dns_ns"] = self.dnsQuery(domain,"NS")
            enumData["dns_txt"] = self.dnsQuery(domain,"TXT")
            enumData["subdomains"] = self.dnsSubdomainEnum(domain)
            self.history[domain] = enumData
            self.customLogPipe(f"Enumeration complete for {domain}",level='output')
            return enumData
        
    class baseScanner:
        def __init__(self,
                     NSI:callable,
                     host:str,
                     timeout:float=1.0,
                     decoyIPs:list[str]=None,
                     scanDelay:float=0.0,
                     scanJitter:float=0.0,
                     verbose:int=0,
                     ttl:int=None,
                     tcpWindow:int=None,
                     tcpOptions:list=[]):
            self.nS = NSI
            self.config = {
                "host": host,
                "timeout": timeout,
                "decoyIPs": decoyIPs if decoyIPs is not None else [],
                "scanDelay": scanDelay,
                "scanJitter": scanJitter,
                "verbose": verbose,
                "ttl": ttl,
                "tcpWindow": tcpWindow,
                "tcpOptions": tcpOptions}
            self.history = {}
            self.stealthScanFlag = ""
            self.customLogPipe = self.nS.customLogPipe
            self.lock = threading.Lock()

        def _buildRandomIPFronSbnet(self,decimiterStatic:int=0):
            pass

        def _sendDecoyPackets(self,port:int,flags:str):
            scapyIP, scapyTCP, scapySend, scapyRandShort = self.nS._getScapyModules(['IP','TCP','send','RandShort'])
            for dIP in self.config['decoyIPs']:
                self.customLogPipe(f"Sending decoy packet from {dIP} to port {port}.")
                decoyPacket = scapyIP(src=dIP,dst=self.config['host'])/scapyTCP(dport=port,sport=scapyRandShort(),flags=flags)
                scapySend(decoyPacket,verbose=0)

        def _scanSinglePortSYN(self,port:int)->tuple[int,str]:
            try:
                scapyIP, scapyTCP, scapySend, scapySr1, scapyRandShort = self.nS._getScapyModules(['IP','TCP','send','sr1','RandShort'])
                if self.config['scanJitter'] > 0: time.sleep(random.uniform(0,self.config['scanJitter']))
                elif self.config['scanDelay'] > 0: time.sleep(self.config['scanDelay'])
                if self.config['decoyIPs']: self._sendDecoyPackets(port,flags="S")
                ipLayer = scapyIP(dst=self.config['host'])
                if self.config['ttl']: ipLayer.ttl = self.config['ttl']
                tcpLayerBase = scapyTCP(dport=port,sport=scapyRandShort(),flags="S")
                if self.config['tcpWindow']: tcpLayerBase.window = self.config['tcpWindow']
                if self.config['tcpOptions']: tcpLayerBase.options = self.config['tcpOptions']
                packet = ipLayer/tcpLayerBase
                resp = scapySr1(packet,timeout=self.config['timeout'],verbose=0)
                if resp is None: return (2,'filtered')
                if resp.haslayer(scapyTCP):
                    tcpRespLayer = resp.getlayer(scapyTCP)
                    if tcpRespLayer.flags == 0x12:
                        scapySend(scapyIP(dst=self.config['host'])/scapyTCP(dport=port,sport=resp.sport,flags="R"),verbose=0)
                        return (1,'open')
                    elif tcpRespLayer.flags == 0x14: return (0,'closed')
                    else: 
                        self.customLogPipe(f"Port {port}: Received unexpected flags: {hex(tcpRespLayer.flags)}",level=2)
                        return (2,'filtered')
                else: return (2,'filtered')
            except Exception as E:
                self.customLogPipe(f"Unknown exception while attempting to scan port '{str(port)}': {str(E)}",level=3)
                return None

        def _setStealthFinFlag(self): self.stealthScanFlag = "F"

        def _setStealthSYNFlag(self): self.stealthScanFlag = "S"

        def _setStealthNullScanFlag(self): self.stealthScanFlag = ""

        def _setStealthScanXMASFlag(self): self.stealthScanFlag = "FPU"

        def _scanSinglePortStealth(self,port:int)->tuple[int,str]:
            try:
                scapyIP, scapyTCP, scapySr1, scapyRandShort = self.nS._getScapyModules(['IP','TCP','sr1','RandShort'])
                if self.config['scanJitter'] > 0: time.sleep(random.uniform(0,self.config['scanJitter']))
                elif self.config['scanDelay'] > 0: time.sleep(self.config['scanDelay'])
                if self.config['decoyIPs']: self._sendDecoyPackets(port,flags=self.stealthScanFlag if self.stealthScanFlag else "S")
                ipLayer = scapyIP(dst=self.config['host'])
                if self.config['ttl']: ipLayer.ttl = self.config['ttl']
                tcpLayer = scapyTCP(dport=port,sport=scapyRandShort(),flags=self.stealthScanFlag if self.stealthScanFlag else "S")
                if self.config['tcpWindow']: tcpLayer.window = self.config['tcpWindow']
                if self.config['tcpOptions']: tcpLayer.options = self.config['tcpOptions']
                packet = ipLayer/tcpLayer
                resp = scapySr1(packet,timeout=self.config['timeout'],verbose=0)
                if resp is None: return (1,'open')
                elif resp.haslayer(scapyTCP) and resp.getlayer(scapyTCP).flags == 0x14: return (0,'closed')
                else: return (2,'filtered')
            except Exception as E:
                self.customLogPipe(f"Unknown exception while attempting to scan port '{str(port)}': {str(E)}",level=3)
                return None
        
        def _scanSinglePortConnectEX(self,port:int,retries:int=2) -> tuple[int,str]:
            for a in range(retries+1):
                try:
                    if self.config['scanJitter'] > 0: time.sleep(random.uniform(0,self.config['scanJitter']))
                    elif self.config['scanDelay'] > 0: time.sleep(self.config['scanDelay'])
                    if a == 0 and self.config['decoyIPs']: 
                        scapyIP, scapyTCP, scapySend, scapyRandShort = self.nS._getScapyModules(['IP','TCP','send','RandShort'])
                        self._sendDecoyPackets(port,flags="S")
                    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
                        s.settimeout(self.config['timeout'])
                        result = s.connect_ex((self.config['host'],port))
                        if result == socket.errno.ECONNREFUSED: return (0,'closed')
                        elif result == 0: return (1,'open')
                        if a == retries: return (2,'filtered')
                        else: 
                            self.customLogPipe(f"Port {port}: Filtered on attempt {a+1}, retrying...")
                            time.sleep(self.config['timeout']*(a+1))
                except socket.timeout:
                    if a == retries: return (2,'filtered')
                    else:
                        self.customLogPipe(f"Port '{port}': Timed out on attempt {a+1}, retrying...")
                        time.sleep(self.config['timeout']*(a+1))
                except Exception as E:
                    self.customLogPipe(f"Caught exception while attempting to check port '{str(port)}': {str(E)}.",level=3)
                    return None
            return (2,'filtered')

        def _scanPorts(self,ports:list[int],maxThreads:int=100)->Dict[int,str]:
            portStates = {}
            with ThreadPoolExecutor(max_workers=maxThreads) as executor:
                futures = {executor.submit(self._scanSinglePortSYN,port): port for port in ports}
                for future in as_completed(futures):
                    port = futures[future]
                    try:
                        state = future.result()
                        if state and state != (0,'closed'):
                            self.customLogPipe(f"Port {port} is {state[1]}.")
                            with self.lock: portStates[port] = state[1]
                    except Exception as E: self.customLogPipe(f"Error scanning port {port}: {str(E)}",level=3)
            return dict(sorted(portStates.items()))

    def _initImports(self):
        try:
            import alive_progress as aliveProgress # type: ignore
        except ImportError:
            pass

    def _getScapyModules(self,modules:list[str])->list:
        try:
            from scapy.all import IP as scapyIP # type: ignore
            from scapy.all import TCP as scapyTCP # type: ignore
            from scapy.all import send as scapySend # type: ignore
            from scapy.all import sr1 as scapySr1 # type: ignore
            from scapy.all import RandShort as scapyRandShort # type: ignore
            from scapy.all import conf as scapyConf # type: ignore
            from scapy.all import sniff as scapySniff # type: ignore
            from scapy.all import Raw as scapyRaw # type: ignore
            from scapy.all import UDP as scapyUDP # type: ignore
            from scapy.all import DNSQR as scapyDNSQR # type: ignore
            moduleMap = {'IP':scapyIP,'TCP':scapyTCP,'send':scapySend,'sr1':scapySr1,'RandShort':scapyRandShort,'conf':scapyConf,'sniff':scapySniff,'Raw':scapyRaw,'UDP':scapyUDP,'DNSQR':scapyDNSQR}
            return [moduleMap[m] for m in modules]
        except ImportError as E:
            self.customLogPipe(f"Failed to import module '{str(E)}', attempting installation...",level=3)
            if self._getUserPrompt("Install Scapy requirements"):
                self.customLogPipe("Attempting to install requirements...")
                _ = os.popen("python3 -m pip install -r requirements.txt")
                self.customLogPipe("Finished installing requirements, exiting...")
                sys.exit(0)
            return [None]*len(modules)

    def _validatePort(self,port:int)->bool:
        return isinstance(port,int) and 1 <= port <= 65535

    def _initParsers(self):
        self.parsCentral = argparse.ArgumentParser(description="A modernized information gathering, network analysis and exploitation tool.")
        self.parsCentral.add_argument("-nA", "--no-admin", action="store_true", help="Run without administrator/root privileges. Disables scapy-based scans.")
        self.subParsMode = self.parsCentral.add_subparsers(dest="mode", required=True, help="The desired mode of operation.")

        # Firewall Frag Parser
        firewallFragSubParser = self.subParsMode.add_parser("firewall-frag", help="Send fragmented IP packets to evade firewalls.")
        firewallFragSubParser.add_argument("rHost", help="The target host to scan.")
        firewallFragSubParser.add_argument("rPort", type=int, help="The target port to scan (e.g., 80, 443).")
        firewallFragSubParser.add_argument("--max-data-len", type=int, default=1024, help="Maximum random data length to append to the payload (default: 1024).")
        firewallFragSubParser.add_argument("--min-frag-size", type=int, default=8, help="Minimum size for each IP fragment payload (default: 8).")
        firewallFragSubParser.add_argument("--max-frag-size", type=int, default=16, help="Maximum size for each IP fragment payload (default: 16).")
        firewallFragSubParser.add_argument("--min-ttl", type=int, default=64, help="Minimum TTL for IP packets (default: 64).")
        firewallFragSubParser.add_argument("--max-ttl", type=int, default=128, help="Maximum TTL for IP packets (default: 128).")
        firewallFragSubParser.add_argument("--min-delay", type=float, default=0.5, help="Minimum delay between sending fragments in seconds (default: 0.5).")
        firewallFragSubParser.add_argument("--max-delay", type=float, default=2.0, help="Maximum delay between sending fragments in seconds (default: 2.0).")
        firewallFragSubParser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output for the scan.")
        firewallFragSubParser.add_argument("--source-ip", type=str, default=None, help="Specify the source IP address to use.")

        # Base Scan Parser
        baseScanSubParser = self.subParsMode.add_parser("scan", help="Perform various types of port scans.")
        baseScanSubParser.add_argument("host", help="The target host to scan.")
        baseScanSubParser.add_argument("ports", help="Ports to scan (e.g., 80, 443, 1-1024).")
        baseScanSubParser.add_argument("-s", "--scan-type", choices=['syn', 'fin', 'xmas', 'null', 'connect'], default='syn', help="Type of scan to perform (default: syn).")
        baseScanSubParser.add_argument("-t", "--timeout", type=float, default=1.0, help="Timeout for each port scan in seconds (default: 1.0).")
        baseScanSubParser.add_argument("-j", "--jitter", type=float, default=0.0, help="Maximum random delay (jitter) between scans in seconds (default: 0.0).")
        baseScanSubParser.add_argument("--delay", type=float, default=0.0, help="Fixed delay between scans in seconds (default: 0.0).")
        baseScanSubParser.add_argument("-d", "--decoys", nargs='*', help="List of decoy IP addresses to use.")
        baseScanSubParser.add_argument("--ttl", type=int, help="Set the IP Time-to-Live field.")
        baseScanSubParser.add_argument("--tcp-window", type=int, help="Set the TCP window size.")
        baseScanSubParser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity level (-v, -vv).")
        baseScanSubParser.add_argument("-T", "--max-threads", type=int, default=100, help="Maximum number of threads to use for scanning (default: 100).")

        # MITM Parser
        mitmSubParser = self.subParsMode.add_parser("mitm-capture", help="Capture and redirect network traffic with MITM proxy.")
        mitmSubParser.add_argument("-i", "--interface", type=str, help="Network interface to capture on.")
        mitmSubParser.add_argument("-f", "--filter", type=str, default="", help="Packet filter (BPF syntax, e.g., 'tcp port 80').")
        mitmSubParser.add_argument("-e", "--export", type=str, help="Export captured packets to JSON file.")
        mitmSubParser.add_argument("-r", "--redirect", nargs=4, metavar=('SRC_IP', 'SRC_PORT', 'DST_IP', 'DST_PORT'), help="Add redirect rule: SRC_IP SRC_PORT DST_IP DST_PORT")

        # Enumeration Parser
        enumSubParser = self.subParsMode.add_parser("enum", help="Domain enumeration and DNS reconnaissance.")
        enumSubParser.add_argument("target", help="Target domain or IP address.")
        enumSubParser.add_argument("-t", "--type", choices=['dns-a', 'dns-mx', 'dns-ns', 'dns-txt', 'reverse', 'zone-transfer', 'subdomain-enum', 'full-enum', 'asn'], default='full-enum', help="Type of enumeration to perform (default: full-enum).")
        enumSubParser.add_argument("-w", "--wordlist", type=str, help="Wordlist file for subdomain enumeration.")
        enumSubParser.add_argument("-ns", "--nameserver", type=str, help="Nameserver for zone transfer.")

        # Proxy Manager Parser
        proxySubParser = self.subParsMode.add_parser("proxy", help="Manage and utilize proxy chains for operations.")
        proxySubParser.add_argument("-a", "--action", choices=['fetch', 'list', 'verify', 'health', 'stats', 'export', 'import', 'clear', 'get'], required=True, help="Action to perform with proxy manager.")
        proxySubParser.add_argument("-t", "--proxy-type", choices=['http', 'https', 'socks4', 'socks5'], default='http', help="Type of proxy (default: http).")
        proxySubParser.add_argument("-l", "--limit", type=int, default=20, help="Limit number of proxies to fetch/verify (default: 20).")
        proxySubParser.add_argument("--min-score", type=float, help="Minimum proxy score threshold (0.0-1.0).")
        proxySubParser.add_argument("--max-latency", type=float, help="Maximum acceptable latency in seconds.")
        proxySubParser.add_argument("--strategy", choices=['best', 'random', 'round_robin'], default='best', help="Proxy selection strategy (default: best).")
        proxySubParser.add_argument("--verify", action="store_true", help="Verify proxies during fetch/import.")
        proxySubParser.add_argument("--file", type=str, help="File path for import/export operations.")
        proxySubParser.add_argument("--refresh-interval", type=int, help="Cache refresh interval in seconds (default: 3600).")
        proxySubParser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")

        self.args = self.parsCentral.parse_args()
        self.config['verbosity'] = self.args.verbose if hasattr(self.args, 'verbose') else True


    def _getUserPrompt(self, message: str)->bool:
        if not self.config['noConfirmUser']:
            uIn = input(f"(nephila:User-Confirmation) {message} (Y/N)?:> ").lower()
            if uIn not in ["y","yes","affirm"]: return False
            else: return True
        else: return True

    def _parsePorts(self, portString: str) -> list[int]:
        ports = set()
        if not portString: return []
        parts = portString.split(',')
        for part in parts:
            part = part.strip()
            if '-' in part:
                try:
                    start,end = map(int,part.split('-'))
                    if start > end: start,end = end,start
                    if start < 1 or end > 65535:
                        self.customLogPipe(f"Port range out of bounds: '{part}'. Skipping.",level=2)
                        continue
                    ports.update(range(start, end + 1))
                except ValueError: self.customLogPipe(f"Invalid port range: '{part}'. Skipping.",level=2)
            else:
                try:
                    p = int(part)
                    if self._validatePort(p): ports.add(p)
                    else: self.customLogPipe(f"Invalid port number: '{part}'. Must be 1-65535. Skipping.",level=2)
                except ValueError: self.customLogPipe(f"Invalid port number: '{part}'. Skipping.",level=2)
        return sorted(list(ports))


    def run(self):
        args = self.args
        self.customLogPipe(f"Executing mode: {args.mode}")
        if args.mode == 'firewall-frag':
            if self.noAdmin:
                self.customLogPipe("firewall-frag requires admin privileges. Enable with -nA flag disabled.", level=3);return
            if not self._validatePort(args.rPort):
                self.customLogPipe(f"Invalid port: {args.rPort}", level=3);return
            FFScanner = self.firewallFrag(self)
            try:
                result = FFScanner.scan(
                    rHost=args.rHost,
                    rPort=args.rPort,
                    maxRandomDataLength=args.max_data_len,
                    minFragSize=args.min_frag_size,
                    maxFragSize=args.max_frag_size,
                    minTTL=args.min_ttl,
                    maxTTL=args.max_ttl,
                    minInterFragDelay=args.min_delay,
                    maxInterFragDelay=args.max_delay,
                    verbose=args.verbose,
                    sourceIP=args.source_ip)
                self.customLogPipe(f"Firewall-frag scan completed for {result['rHost']}:{result['rPort']}.", level='output')
            except PermissionError as e: self.customLogPipe(str(e), level=3)
        elif args.mode == 'scan':
            if self.noAdmin and args.scan_type != 'connect':
                self.customLogPipe(f"Scan type '{args.scan_type}' requires admin privileges. Use 'connect' or disable --no-admin.", level=3);return
            portsToScan = self._parsePorts(args.ports)
            if not portsToScan:
                self.customLogPipe("No valid ports specified to scan.", level=3);return
            BScan = self.baseScanner(
                self, args.host,
                timeout=args.timeout,
                decoyIPs=args.decoys,
                scanDelay=args.delay,
                scanJitter=args.jitter,
                verbose=args.verbose,
                ttl=args.ttl,
                tcpWindow=args.tcp_window,
                tcpOptions=[])
            if args.scan_type == 'fin': BScan._setStealthFinFlag()
            elif args.scan_type == 'xmas': BScan._setStealthScanXMASFlag()
            elif args.scan_type == 'null': BScan._setStealthNullScanFlag()
            if args.scan_type == 'connect':
                results = {}
                for port in portsToScan:
                    state = BScan._scanSinglePortConnectEX(port)
                    if state: results[port] = state[1]
            elif args.scan_type in ['fin', 'xmas', 'null']: results = BScan._scanPorts(portsToScan, maxThreads=args.max_threads)
            else: results = BScan._scanPorts(portsToScan, maxThreads=args.max_threads)
            if results:
                self.customLogPipe(f"Scan results for {args.host}:", level='output')
                for port, state in results.items(): self.customLogPipe(f"  Port {port}: {state}", level='output')
            else: self.customLogPipe("No open ports found.", level=1)
        elif args.mode == 'mitm-capture':
            if self.noAdmin:
                self.customLogPipe("MITM capture requires admin privileges.", level=3);return
            mitmCap = self.mitmCapture(self)
            if args.redirect:
                srcIP, srcPort, dstIP, dstPort = args.redirect
                try: mitmCap.addRedirectRule(srcIP, int(srcPort), dstIP, int(dstPort))
                except ValueError:
                    self.customLogPipe("Invalid port in redirect rule", level=3);return
            try:
                captureThread = threading.Thread(
                    target=mitmCap.startCapture,
                    args=(args.interface, args.filter),
                    daemon=True)
                captureThread.start()
                while mitmCap.running: 
                    time.sleep(1)
            except KeyboardInterrupt:
                self.customLogPipe("MITM capture stopped", level=1)
                mitmCap.stopCapture()
                if args.export: mitmCap.exportCapture(args.export)
                stats = mitmCap.getCaptureStats()
                self.customLogPipe(f"Capture stats: {json.dumps(stats, indent=2)}", level='output')

        elif args.mode == 'enum':
            enum = self.enumeration(self)
            try:
                if args.type == 'dns-a': results = enum.dnsQuery(args.target, "A")
                elif args.type == 'dns-mx': results = enum.dnsQuery(args.target, "MX")
                elif args.type == 'dns-ns': results = enum.dnsQuery(args.target, "NS")
                elif args.type == 'dns-txt': results = enum.dnsQuery(args.target, "TXT")
                elif args.type == 'reverse':
                    result = enum.dnsReverseQuery(args.target);results = [result] if result else []
                elif args.type == 'zone-transfer':
                    if not args.nameserver:
                        self.customLogPipe("Zone transfer requires --nameserver argument", level=3);return
                    results = enum.dnsZoneTransfer(args.target, args.nameserver)
                elif args.type == 'subdomain-enum':
                    wordlist = None
                    if args.wordlist:
                        try:
                            with open(args.wordlist, 'r') as f:
                                wordlist = [line.strip() for line in f if line.strip()]
                        except Exception as E:
                            self.customLogPipe(f"Failed to load wordlist: {str(E)}", level=3);return
                    results = enum.dnsSubdomainEnum(args.target, wordlist)
                elif args.type == 'asn': results = enum.asnLookup(args.target)
                else: results = enum.gatherEnumData(args.target)
                self.customLogPipe(f"Enumeration results: {json.dumps(results, indent=2) if isinstance(results, dict) else results}",level='output')
            except Exception as E: self.customLogPipe(f"Enumeration failed: {str(E)}", level=3)
        elif args.mode == 'proxy':
            if not hasattr(self, 'proxyManager'): self.proxyManager = self.proxify(self)
            # Set refresh interval if provided
            if args.refresh_interval: self.proxyManager._proxyChainRefreshInterval = args.refresh_interval
            try:
                if args.action == 'fetch':
                    self.customLogPipe(f"Fetching and verifying {args.limit} {args.proxy_type} proxies...", level=0)
                    resDict = asyncio.run(self.proxyManager.fetch(proxyType=args.proxy_type,limit=args.limit))
                    verifiedProxies = resDict.get('verified',[])
                    self.customLogPipe(f"Successfully fetched {len(verifiedProxies)} verified proxies", level='output')
                    if args.verbose:
                        pC = 0
                        for proxy in verifiedProxies:
                            self.customLogPipe(f"({pC+1}/{len(verifiedProxies)})\t{proxy}", level='output')
                            pC += 1
                elif args.action == 'list':
                    proxies = self.proxyManager.getProxies(proxyType=args.proxy_type)
                    self.customLogPipe(f"Available {args.proxy_type} proxies: {len(proxies)}", level='output')
                    for proxy in proxies: 
                        self.customLogPipe(f"  {proxy}", level='output')
                elif args.action == 'verify':
                    self.customLogPipe(f"Verifying existing proxies...", level=0)
                    healthy = asyncio.run(self.proxyManager.healthCheck(proxyType=args.proxy_type))
                    self.customLogPipe(f"Health check complete: {len(healthy)} healthy proxies",level='output')
                elif args.action == 'health':
                    if args.max_latency:
                        filtered = self.proxyManager.filterByLatency(maxLatency=args.max_latency,proxyType=args.proxy_type)
                        self.customLogPipe(f"Found {len(filtered)} proxies with latency <= {args.max_latency}s",level='output')
                    else:
                        healthy = asyncio.run(self.proxyManager.healthCheck(proxyType=args.proxy_type))
                        self.customLogPipe(f"Healthy proxies: {len(healthy)}", level='output')
                elif args.action == 'stats':
                    stats = self.proxyManager.getProxyStats(proxyType=args.proxy_type)
                    self.customLogPipe(f"Proxy Statistics:\n{json.dumps(stats, indent=2)}",level='output')
                elif args.action == 'export':
                    if not args.file: self.customLogPipe("Export requires --file argument", level=3);return
                    proxies = self.proxyManager.exportProxies(proxyType=args.proxy_type,minScore=args.min_score)
                    with open(args.file, 'w') as f:
                        for proxy in proxies:
                            f.write(f"{proxy}\n")
                    self.customLogPipe(f"Exported {len(proxies)} proxies to {args.file}", level='output')
                elif args.action == 'import':
                    if not args.file: self.customLogPipe("Import requires --file argument", level=3);return
                    try:
                        with open(args.file, 'r') as f:
                            proxy_list = [line.strip() for line in f if line.strip()]
                        stats = asyncio.run(self.proxyManager.importProxies(proxy_list,verify=args.verify))
                        self.customLogPipe(f"Import complete: {json.dumps(stats)}",level='output')
                    except Exception as E: self.customLogPipe(f"Import failed: {str(E)}", level=3)
                elif args.action == 'clear':
                    self.proxyManager.clearProxies(proxyType=args.proxy_type)
                    self.customLogPipe(f"Cleared {args.proxy_type or 'all'} proxies", level='output')
                elif args.action == 'get':
                    proxy_info = self.proxyManager.getProxy(proxyType=args.proxy_type,minScore=args.min_score,strategy=args.strategy)
                    if proxy_info:
                        self.customLogPipe(f"Selected proxy: {proxy_info['proxy']} (Score: {proxy_info['score']:.3f})",level='output')
                        if args.verbose: self.customLogPipe(f"Metadata: {json.dumps(proxy_info['metadata'], default=str, indent=2)}",level='output')
                    else:self.customLogPipe("No suitable proxy found", level=1)
            except Exception as E:
                self.customLogPipe(f"Proxy operation failed: {str(E)}", level=3)
                if args.verbose:
                    import traceback;self.customLogPipe(traceback.format_exc(), level=3)

    def _randomDelay(self,minVal:float,maxVal:float):
        d = random.uniform(minVal,maxVal);time.sleep(d)

    def _randomData(self,maxLen:int)->str:
        chars = string.printable;rLen = random.randint(0,maxLen);return ''.join(random.choice(chars) for _ in range(rLen))

def raiseBanner():
    banner = [
        '╔══════════════╦════════════════╦══════════════╗', 
        '╠{╳╳╳╳╳╳╳╳╳╳╳╳}╣ 𝐍 𝐄 𝐏 𝐇 𝐈 𝐋 𝐀  ╠{╳╳╳╳╳╳╳╳╳╳╳╳}╣', 
        '╠══════════════╩════════════════╩══════════════╣', 
        '║ ╭──────┬↔──╮                                 ║', 
        '║ │{ROOT}├─←╮╰─↔──╮                   ┏━━━━━┓  ║', 
        '║ ╰──────┤  ╰←──←╮│    ┏━━━┓  ┌─┐     ┣░▒░▓░┫  ║', 
        '║        ┆├→────╮││    ┃▒░▓┃  │o│     └──┬──┘  ║', 
        '║  ╭─────┴─────╮│││   ───┬─── └─┘        │     ║', 
        '║  │{FIRE-WALL}││││      ╰───────╮     ╭ ╯     ║', 
        '║  ╰─────┬─────╯││╰↔────↔─────↔─┤┆├───┤┆├⋯⋯    ║', 
        '║   ╭────┴────╮ │╰←───←───←╮     ↕     ↕       ║', 
        '║   │{IDS/EDR}│ │    ╭──↔──┴──↔──┼──↔──┴─⋯⋯    ║', 
        '║   ╰────┬────╯ ╰──→┤┆├─→────→┬──┴──↔──────┐   ║', 
        '║     ╭──┴──╮     ╭──┴──╮     ├{ EXTERNAL }┤   ║', 
        '║     │{WAF}│     │{LAN}│  ┌──┴─────┬──────┴─┐ ║', 
        '║     ╰┬───┬╯     ╰┬───┬╯  │{PASSWD}┼{GIBSON}│ ║', 
        '║      │   ╰→──→──→╯   │   └────────┴────────┘ ║', 
        '║      ╰←──←──←─←──←──←╯                       ║', 
        '╠════════════════════╦╗  ╔╦════════════════════╣', 
        '║  O C C U L T U M   ║╠0A╣║   S C I E N T I A  ║', 
        '╚════════════════════╩╝  ╚╩════════════════════╝ ']
    bannerStr = "\n".join(banner)
    bannerStr = f"{colorama.Style.BRIGHT}{bannerStr}"
    for i in ["║","╚","═","╝","╔","╗","╣","╠","╦","╩"]: bannerStr = bannerStr.replace(i,f"{colorama.Fore.CYAN}{colorama.Style.DIM}{i}{colorama.Style.RESET_ALL}{colorama.Style.BRIGHT}")
    for i in ["S C I E N T I A", "𝐍 𝐄 𝐏 𝐇 𝐈 𝐋 𝐀", "O C C U L T U M", "╳"]: bannerStr = bannerStr.replace(i,f"{colorama.Fore.LIGHTRED_EX}{i}{colorama.Fore.RESET}")
    for i in ["ROOT","FIRE","WALL","IDS/EDR","WAF","LAN","EXTERNAL","PASSWD","GIBSON","0A"]: bannerStr = bannerStr.replace(i,f"{colorama.Fore.BLUE}{i}{colorama.Fore.RESET}")
    for i in ["─","╰","╭","╯","╮","│","┴","┐","┌","┬","┼","┤","├","┘","└",'{','}']: bannerStr = bannerStr.replace(i,f"{colorama.Fore.BLACK}{i}{colorama.Fore.RESET}")
    for i in ["┆"]: bannerStr = bannerStr.replace(i,f"{colorama.Fore.LIGHTRED_EX}{i}{colorama.Fore.RESET}")
    for i in ["↔","↕"]: bannerStr = bannerStr.replace(i,f"{colorama.Fore.LIGHTWHITE_EX}{i}{colorama.Fore.RESET}")
    for i in ["┃","┓","┏","━","┣","┫"]: bannerStr = bannerStr.replace(i,f"{colorama.Fore.BLACK}{i}{colorama.Fore.RESET}")
    for i in ["░","▒","░","▓","░"]: bannerStr = bannerStr.replace(i,f"{colorama.Fore.GREEN}{colorama.Style.DIM}{i}{colorama.Style.RESET_ALL}{colorama.Style.BRIGHT}") 
    bannerStr = bannerStr.replace('→',f"{colorama.Fore.LIGHTBLUE_EX}→{colorama.Fore.RESET}").replace("←",f"{colorama.Fore.MAGENTA}←{colorama.Fore.RESET}")
    bannerStr += colorama.Style.RESET_ALL
    print(str(bannerStr))

if __name__ == "__main__":
    raiseBanner()
    scanner = nephila(app=True)
    scanner.run()
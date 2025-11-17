import time,json,re,hashlib,base64,urllib.parse,colorama,itertools,argparse # type: ignore
import logging,yaml,os,pickle,mimetypes,socket,ssl,requests,sqlite3,configparser # type: ignore
import difflib,random,string,sys,traceback,shutil,threading,shlex
import selenium.webdriver as webdriver # type: ignore
from bs4 import BeautifulSoup # type: ignore 
from typing import List,Dict,Any,Optional,Callable
from pathlib import Path
from datetime import datetime
from fake_useragent import UserAgent # type: ignore
from collections import defaultdict 
from dataclasses import dataclass,asdict,field
from concurrent.futures import ThreadPoolExecutor,as_completed
from selenium.webdriver.common.by import By # type: ignore
from selenium.webdriver.support import expected_conditions as EC # type: ignore
from selenium.webdriver.common.proxy import Proxy,ProxyType # type: ignore
from selenium.common.exceptions import TimeoutException,NoSuchElementException # type: ignore
from selenium.webdriver.common.action_chains import ActionChains # type: ignore
from selenium.webdriver.common.keys import Keys # type: ignore
from selenium.webdriver.support.ui import WebDriverWait # type: ignore 

class AndrasLoggingFormatter(logging.Formatter):
    black = "\x1b[30m"
    red = "\x1b[31m"
    green = "\x1b[32m"
    yellow = "\x1b[33m"
    blue = "\x1b[34m"
    gray = "\x1b[38m"
    reset = "\x1b[0m"
    bold = "\x1b[1m"
    COLORS = {logging.DEBUG: gray + bold, logging.INFO: blue + bold, logging.WARNING: yellow + bold, logging.ERROR: red, logging.CRITICAL: red + bold}
    def format(self,record):
        logColor = self.COLORS[record.levelno]
        fmt = "(black){asctime}(reset) (levelcolor){levelname:<8}(reset) (green){name}(reset) {message}"
        fmt = fmt.replace("(black)", self.black + self.bold).replace("(reset)", self.reset).replace("(levelcolor)", logColor).replace("(green)", self.green + self.bold)
        formatter = logging.Formatter(fmt, "%Y-%m-%d %H:%M:%S", style="{")
        return formatter.format(record)

customLogger = logging.getLogger("andras")
customLogger.setLevel(logging.DEBUG)
consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(AndrasLoggingFormatter())
consoleHandler.setLevel(logging.INFO)
customLogger.addHandler(consoleHandler)

__version__ = "0.0.3"
__author__  = "J4ck3LSyN"

class Andras:
    def customLogPipe(self,message:str,level:int=1,excInfo:bool=False,noLog:bool=False,silent:bool=False):
        if silent or not self.config['verbosity']:
            return
        prefixMap = {1: "[*] ", 3: "[!] ", 'output': "[^] "}
        logMap = {
            0: self.customLogger.debug, 'd': self.customLogger.debug, 'debug': self.customLogger.debug,
            1: self.customLogger.info, 'i': self.customLogger.info, 'info': self.customLogger.info,
            2: self.customLogger.warning, 'w': self.customLogger.warning, 'warning': self.customLogger.warning,
            3: self.customLogger.error, 'r': self.customLogger.error, 'error': self.customLogger.error,
            4: self.customLogger.critical, 'c': self.customLogger.critical, 'critical': self.customLogger.critical
        }
        prefix = prefixMap.get(level, "")
        logFunc = logMap.get(level, self.customLogger.info)
        if not noLog:
            logFunc(f"{prefix}{message}", exc_info=excInfo)
    def __init__(self,
                 app:bool=False,
                 silent=False,
                 browser:str=None,
                 useHome:bool=False,
                 basePath:Path=None,
                 cacheName:str=None):
        self.app = app
        self.silent = silent
        self.customLogger = customLogger
        self.browser=browser if browser else 'firefox'
        self.cacheName=cacheName if cacheName else '.andras'
        self.base=str(os.path.join(basePath,self.cacheName)) if basePath else (str(os.path.join(os.getcwd(),self.cacheName)) if not useHome else str(os.path.join(Path.home(),self.cacheName)))
        self.args=None
        Path(self.base).mkdir(parents=True,exist_ok=True)
        self.config={
            "verbosity":not self.silent,
            'cookies':{},
            "userAgents":{
                "useCacheStatus":True,
                "cacheExpiry":86400,
                "type":str(self.browser)
                },
            "scanners":{
                "headerSecurity":{
                    "securityHeaders":{
                        'X-Frame-Options':'Clickjacking protection',
                        'X-Content-Type-Options':'MIME-sniffing protection',
                        'Strict-Transport-Security':'HTTPS enforcement',
                        'X-XSS-Protection':'XSS filter',
                        'Content-Security-Policy':'Content injection protection',
                        'Referrer-Policy':'Referrer leakage protection',
                        'Permissions-Policy':'Feature policy'}
                        },
            "crawler":{},
            "spider":{}}}
        self.customLogPipe(f"Configured base path to '{str(self.base)}'.",level='d')
        self.cacheInstance = self.Cache(self)
        self.driverInstance = self.Driver(self)
        # The driver instance is now a class that holds the driver, not the driver itself.
        # The actual selenium driver object will be at self.driverInstance.driver
        # However, your existing code seems to pass around the main Andras instance and access `driverInstance`
        # which is later replaced by the actual driver. I will keep this pattern for now but it's worth noting.
        self.browserInstance = self.Browser(self)
        self.userAgentInstance = self.UserAgent(self)
        self.xInteractInstance = self.XInteract(self)
        self.duckInteractInstance = self.DuckInteract(self)
        if self.app:
            self.customLogPipe(f"*--- Initializing App ---*")
            self._raiseBanner()
            self._initParsers()

    # *--- Data Classes ---*
    @dataclass
    class UserAgentsInternalDefault:
        userAgentsIndex:Dict[str,List[str]] = field(default_factory=lambda: {
            "chrome": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 11.6; rv:95.0) Gecko/20100101 Firefox/95.0",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        ],
            "edge": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.0.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.0.0",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.0.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.0.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.0.0",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.0.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Edg/116.0.0.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Edg/116.0.0.0",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Edg/116.0.0.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edg/115.0.0.0",
        ],
            "firefox": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
                "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
                "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:119.0) Gecko/20100101 Firefox/119.0",
                "Mozilla/5.0 (X11; Linux x86_64; rv:119.0) Gecko/20100101 Firefox/119.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:118.0) Gecko/20100101 Firefox/118.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:118.0) Gecko/20100101 Firefox/118.0",
                "Mozilla/5.0 (X11; Linux x86_64; rv:118.0) Gecko/20100101 Firefox/118.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:117.0) Gecko/20100101 Firefox/117.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:117.0) Gecko/20100101 Firefox/117.0",
                "Mozilla/5.0 (X11; Linux x86_64; rv:117.0) Gecko/20100101 Firefox/117.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:116.0) Gecko/20100101 Firefox/116.0",
        ],
            "openAI": [
                "Mozilla/5.0 (compatible; GPTBot/1.0; +https://openai.com/gptbot)",
                "Mozilla/5.0 (compatible; OpenAI-SearchBot/1.0; +https://openai.com/searchbot)",
                "Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com)",
                "Mozilla/5.0 (compatible; OpenAI; +https://openai.com/gpt)",
                "Mozilla/5.0 (compatible; OpenAI-API/1.0; +https://platform.openai.com)",
                "Mozilla/5.0 (compatible; OpenAI-Research/1.0; +https://research.openai.com)",
                "Mozilla/5.0 (compatible; ChatGPT-User-Agent/1.0; +https://openai.com/chatgpt)",
                "Mozilla/5.0 (compatible; OpenAI-Browsing/1.0; +https://openai.com)",
                "Mozilla/5.0 (compatible; OpenAI-WebCrawler/1.0; +https://openai.com)",
                "Mozilla/5.0 (compatible; OpenAI-Integration/1.0; +https://openai.com)",
                "Mozilla/5.0 (compatible; OpenAI-Bot/1.0; +https://openai.com)",
                "Mozilla/5.0 (compatible; OpenAI-Assistant/1.0; +https://openai.com)",
                "Mozilla/5.0 (compatible; OpenAI-Plugin/1.0; +https://openai.com/plugins)",
                "Mozilla/5.0 (compatible; OpenAI-Fetch/1.0; +https://openai.com)",
                "Mozilla/5.0 (compatible; GPT-4/1.0; +https://openai.com/gpt4)",
                "Mozilla/5.0 (compatible; OpenAI/2.0; +https://openai.com)",
        ],
            "gemma": [
                "Mozilla/5.0 (compatible; Gemini/1.0; +https://ai.google)",
                "Mozilla/5.0 (compatible; Google-Gemini/1.0; +https://google.com/gemini)",
                "Mozilla/5.0 (compatible; Gemma-Bot/1.0; +https://google.com/gemma)",
                "Mozilla/5.0 (compatible; Google-AI/1.0; +https://ai.google)",
                "Mozilla/5.0 (compatible; Bard/1.0; +https://google.com/bard)",
                "Mozilla/5.0 (compatible; GoogleBot-Gemini/1.0; +https://google.com)",
                "Mozilla/5.0 (compatible; Gemini-Integration/1.0; +https://ai.google)",
                "Mozilla/5.0 (compatible; GooglePaLM/1.0; +https://google.com)",
                "Mozilla/5.0 (compatible; Google-LaMDA/1.0; +https://google.com)",
                "Mozilla/5.0 (compatible; Gemma/2.0; +https://google.com/gemma)",
                "Mozilla/5.0 (compatible; Google-AI-Studio/1.0; +https://aistudio.google.com)",
                "Mozilla/5.0 (compatible; Gemini-API/1.0; +https://google.com)",
                "Mozilla/5.0 (compatible; Google-Generative-AI/1.0; +https://google.com)",
                "Mozilla/5.0 (compatible; GoogleAI-Bot/1.0; +https://ai.google)",
                "Mozilla/5.0 (compatible; Gemma-Chat/1.0; +https://google.com)",
                "Mozilla/5.0 (compatible; Google-MedLM/1.0; +https://google.com)",
        ],
            "safari": [
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
                "Mozilla/5.0 (Macintosh; PPC Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Safari/605.1.15",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Safari/605.1.15",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Safari/605.1.15",
        ],
            "opera": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 OPR/104.0.0.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 OPR/104.0.0.0",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 OPR/104.0.0.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 OPR/103.0.0.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 OPR/103.0.0.0",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 OPR/103.0.0.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 OPR/102.0.0.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 OPR/102.0.0.0",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 OPR/102.0.0.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 OPR/101.0.0.0",
        ],
            "brave": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Brave/1.72",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Brave/1.71",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Brave/1.72",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Brave/1.71",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Brave/1.72",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Brave/1.71",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Brave/1.70",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Brave/1.70",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Brave/1.70",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Brave/1.69",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Brave/1.69",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Brave/1.69",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Brave/1.68",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Brave/1.68",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Brave/1.68",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Brave/1.67",
        ],
            "vivaldi": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vivaldi/7.0.3495.13",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Vivaldi/6.6.3404.32",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vivaldi/7.0.3495.13",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Vivaldi/6.6.3404.32",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vivaldi/7.0.3495.13",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Vivaldi/6.6.3404.32",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Vivaldi/6.5.3347.46",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Vivaldi/6.5.3347.46",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Vivaldi/6.5.3347.46",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Vivaldi/6.4.3297.42",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Vivaldi/6.4.3297.42",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Vivaldi/6.4.3297.42",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Vivaldi/6.3.3245.48",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Vivaldi/6.3.3245.48",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Vivaldi/6.3.3245.48",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Vivaldi/6.2.3188.25",
        ],
            "comet": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Comet/1.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Comet/1.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Comet/1.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Comet/1.0",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Comet/1.0",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Comet/1.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Comet/1.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Comet/1.0",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Comet/1.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Comet/1.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Comet/1.0",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Comet/1.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Comet/1.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Comet/1.0",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Comet/1.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Comet/1.0",
        ],
            "mobile": [
                "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
                "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
                "Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
                "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
                "Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
                "Mozilla/5.0 (Linux; Android 14; SM-S910B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
                "Mozilla/5.0 (Linux; Android 13; SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
                "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
                "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
                "Mozilla/5.0 (Linux; Android 14; OnePlus 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
                "Mozilla/5.0 (Linux; Android 13; Xiaomi 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
                "Mozilla/5.0 (Linux; Android 12; OPPO Find X5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Mobile Safari/537.36",
                "Mozilla/5.0 (Linux; Android 14; Motorola Edge 50) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        ]})

        userAgentFallbacks:Dict[str,str] = field(default_factory=lambda: {
            "safari": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "opera":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
            "chrome":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "gemma":"Mozilla/5.0 (compatible; Google-Gemini/1.0; +https://google.com/gemini)",
            "edge":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Edg/116.0.0.0",
            "openAI":"Mozilla/5.0 (compatible; OpenAI-SearchBot/1.0; +https://openai.com/searchbot)",
            "firefox":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "brave":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Brave/1.72",
            "vivaldi":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Vivaldi/6.3.3245.48",
            "comet":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Comet/1.0",
            "mobile":"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
        })


    @dataclass
    class scanInfo:
        # Scoped domains
        domains:List[str]|str=None
        # 'vulnsite.com' // [ 'vunsite.com', 'app.vulnsite.com', 'vulnsite-admin.com' ]
        # Further scope (if None than all of domains)
        scope:Dict[str,Dict[str,List[str]]]=field(default_factory=lambda: {}) 
        # { 'vulnsite.com':[ 'vulnsite.com', 'api.vulnsite.com', 'app.vulnsite.site' ] }
        # { 'vulnsite-admin.com':[ ... ] }
        # Allow outside-scope operations 
        allowScopeEscape:bool=False # Allows for the scanner to reach outside of the scoped domains.
        scopeExclusion:List[str]=field(default_factory=list) # Exclusivly exlude from scope (even if its isnide of the domain, skip all that match)
        # [ 'admin.vulnsite.com',... ]
        # Discoveries
        ## Fuzz
        fuzzSubdomains:List[str]=field(default_factory=list) # Fuzzed sub-domains
        ## [ '{subdomain}.{domain}.com',... ]
        fuzzEndpoints:Dict[str,List[str]]=field(default_factory=lambda: {}) # Fuzzed endpoints
        ## { 'http://{subdomain}.{domain}.com':[ '/search?q=123' ],... }
        fuzzFullPaths:List[str]=field(default_factory=list)
        ## [ 'http://{subdomain}.{domain}.com/search?q=123',... ]
        


    # *--- Static Methods ---*
    class ActHuman:
        @staticmethod
        def humanDelay(minSec=1, maxSec=3):
            time.sleep(random.uniform(minSec, maxSec))
        @staticmethod
        def humanType(element,text,typoChance=0.1):
            for char in text:
                element.send_keys(char)
                time.sleep(random.uniform(0.05, 0.25))
                if random.random() < typoChance:
                    element.send_keys(random.choice('abcdefghijklmnopqrstuvwxyz'))
                    time.sleep(random.uniform(0.1, 0.3))
                    element.send_keys(Keys.BACKSPACE)
        @staticmethod
        def humanClick(driver,element):
            actions = ActionChains(driver)
            offsetX = random.randint(-5, 5)
            offsetY = random.randint(-5, 5)
            actions.move_to_element_with_offset(element, offsetX, offsetY).perform()
            time.sleep(random.uniform(0.3, 0.8))
            element.click()
        @staticmethod
        def humanScroll(driver, scrolls=None, direction='down'):
            if scrolls is None:
                scrolls = random.randint(1, 4)
            for _ in range(scrolls):
                scroll_height = driver.execute_script("return document.body.scrollHeight")
                if direction == 'down':
                    amount = random.randint(100, 400)
                else: # 'up'
                    amount = -random.randint(100, 400)
                driver.execute_script(f"window.scrollBy(0, {amount});")
                time.sleep(random.uniform(0.2, 0.8))
        @staticmethod
        def randomMouseMovement(driver):
            actions = ActionChains(driver)
            body = driver.find_element(By.TAG_NAME, 'body')
            for _ in range(random.randint(2, 5)):
                actions.move_to_element_with_offset(body, random.randint(-100, 100), random.randint(-100, 100)).perform()
                time.sleep(random.uniform(0.1, 0.3))

    class WaitHelper:
        @staticmethod
        def waitForPageLoad(driver, timeout=30):
            wait = WebDriverWait(driver, timeout)
            wait.until(lambda d: d.execute_script("return document.readyState") == "complete")
            try: wait.until(lambda d: d.execute_script("return typeof jQuery!=='undefined'&&jQuery.active==0"))
            except: pass
            try: wait.until(lambda d: d.execute_script("return typeof angular!=='undefined'&&window.getAllAngularTestabilities().findIndex(x=>!x.isStable())===-1"))
            except: pass
            for selector in [(By.CLASS_NAME, "loading"), (By.CLASS_NAME, "spinner"), (By.ID, "loading"), (By.XPATH, "//*[contains(@class,'loader')]")]:
                try: wait.until(EC.invisibility_of_element_located(selector))
                except: pass
        @staticmethod
        def waitForInputReady(driver,locator,timeout=10):
            wait = WebDriverWait(driver, timeout)
            element = wait.until(EC.presence_of_element_located(locator))
            wait.until(EC.visibility_of(element))
            wait.until(lambda d: element.is_enabled())
            wait.until(lambda d: element.get_attribute("readonly") != "true")
            return element
        @staticmethod
        def waitForAnyElement(driver,locators,timeout=10):
            wait = WebDriverWait(driver, timeout)
            for locator in locators:
                try:
                    return wait.until(EC.presence_of_element_located(locator))
                except TimeoutException:
                    continue
            raise TimeoutException("None of the elements found")

    class BrowserPaths:
        @staticmethod
        def getChromeProfilePath()->Path:
            paths={'win32':Path(os.environ.get('LOCALAPPDATA',''))/'Google/Chrome/User Data','darwin':Path.home()/'Library/Application Support/Google/Chrome'};return paths.get(sys.platform,Path.home()/'.config/google-chrome')
        @staticmethod
        def getFirefoxProfilePath()->Path:
            paths={'win32':Path(os.environ.get('APPDATA',''))/'Mozilla/Firefox/Profiles','darwin':Path.home()/'Library/Application Support/Firefox/Profiles'};return paths.get(sys.platform,Path.home()/'.mozilla/firefox')
        @staticmethod
        def getEdgeProfilePath()->Path:
            paths={'win32':Path(os.environ.get('LOCALAPPDATA',''))/'Microsoft/Edge/User Data','darwin':Path.home()/'Library/Application Support/Microsoft Edge'};return paths.get(sys.platform,Path.home()/'.config/microsoft-edge')
        @staticmethod
        def getBraveProfilePath()->Path:
            paths={'win32':Path(os.environ.get('LOCALAPPDATA',''))/'BraveSoftware/Brave-Browser/User Data','darwin':Path.home()/'Library/Application Support/BraveSoftware/Brave-Browser'};return paths.get(sys.platform,Path.home()/'.config/BraveSoftware/Brave-Browser')
    
    # *--- Built-In Interactables ---*
    class XInteract:
        def __init__(self, ai: callable):
            self.andras = ai
            self.baseUrl = 'https://x.com'
            self.searchResults = []
            self.driver = self.andras.driverInstance
            self.sessionMetadata = {
                'authenticated': False,
                'username': None,
                'userID': None,
                'auth_token': None,
                'cookies': {},
                'headers': {},
                'login_time': None,
                'session_duration': 0,
                '2fa_detected': False,
                '2fa_method': None,
                'user_agent': None}
            self.andras.customLogPipe("Initialized X(twitter) interaction.")
    
        def _setMetadata(self, key: str, value: Any):
            """Safely set metadata for the current session"""
            if key in self.sessionMetadata:
                self.sessionMetadata[key] = value
                self.andras.customLogPipe(f"Session metadata updated: {key} = {value}", level='d')
            else: self.andras.customLogPipe(f"Unknown metadata key: {key}", level=2)
    
        def _getMetadata(self, key: str = None) -> Any:
            """Retrieve session metadata"""
            if key: return self.sessionMetadata.get(key)
            return self.sessionMetadata
    
        def _exportSessionInfo(self, filepath: str = None) -> str:
            """Export session information and browser data for manual cookie extraction"""
            if not filepath: filepath = Path(self.andras.base) / f"x_session_{int(time.time())}.json"
            sessionInfo = {
                'metadata': self.sessionMetadata.copy(),
                'extraction_guide': self._getExtractionGuide(),
                'current_cookies': self.driver.get_cookies() if self.driver else [],
                'localStorage': self._getLocalStorage() if self.driver else {},
                'session_storage': self._getSessionStorage() if self.driver else {},
            }
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(sessionInfo, f, indent=2, ensure_ascii=False)
            self.andras.customLogPipe(f"Session info exported to {filepath}")
            return str(filepath)
    
        def _getExtractionGuide(self) -> Dict[str, Any]:
            """Provide manual extraction guide for different OS"""
            guide = {
                'windows': {
                    'chrome': {
                        'location': '%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Network\\Cookies',
                        'instructions': [
                            '1. Close Chrome completely',
                            '2. Navigate to: C:\\Users\\[YourUsername]\\AppData\\Local\\Google\\Chrome\\User Data\\Default',
                            '3. Copy the "Cookies" file (SQLite database)',
                            '4. Use a SQLite viewer or Python sqlite3 to extract cookies',
                            '5. Look for cookies with domain=".twitter.com" or ".x.com"'
                        ],
                        'python_extraction': '''
    >> import sqlite3
    >> import json
    >> 
    >> conn = sqlite3.connect('Cookies')
    >> cursor = conn.cursor()
    >> cursor.execute("SELECT name, value, domain FROM cookies WHERE domain LIKE '%.x.com%' OR domain LIKE '%.twitter.com%'")
    >> cookies = {row[0]: row[1] for row in cursor.fetchall()}
    >> json.dump(cookies, open('x_cookies.json', 'w'))
    >> conn.close()
                        '''
                    },
                    'firefox': {
                        'location': '%APPDATA%\\Mozilla\\Firefox\\Profiles\\[profile]\\cookies.sqlite',
                        'instructions': [
                            '1. Close Firefox completely',
                            '2. Navigate to: C:\\Users\\[YourUsername]\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles',
                            '3. Open the profile folder (usually contains random characters)',
                            '4. Copy "cookies.sqlite" file',
                            '5. Use sqlite3 to extract cookies',
                            '6. Look for entries with host like ".x.com" or ".twitter.com"'
                        ],
                        'python_extraction': '''
    >> import sqlite3
    >> import json
    >> 
    >> conn = sqlite3.connect('cookies.sqlite')
    >> cursor = conn.cursor()
    >> cursor.execute("SELECT name, value, host FROM moz_cookies WHERE host LIKE '%.x.com%' OR host LIKE '%.twitter.com%'")
    >> cookies = {row[0]: row[1] for row in cursor.fetchall()}
    >> json.dump(cookies, open('x_cookies.json', 'w'))
    >> conn.close()
                        '''
                    }
                },
                'linux': {
                    'chrome': {
                        'location': '~/.config/google-chrome/Default/Network/Cookies',
                        'instructions': [
                            '1. Close Chrome completely',
                            '2. Navigate to: ~/.config/google-chrome/Default/',
                            '3. Copy the "Cookies" file (SQLite database)',
                            '4. Use sqlite3 to extract cookies',
                            '5. Look for cookies with domain=".x.com" or ".twitter.com"'
                        ],
                        'python_extraction': '''
    >> import sqlite3
    >> import json
    >> import os
    >> 
    >> cookies_file = os.path.expanduser('~/.config/google-chrome/Default/Cookies')
    >> conn = sqlite3.connect(cookies_file)
    >> cursor = conn.cursor()
    >> cursor.execute("SELECT name, value, domain FROM cookies WHERE domain LIKE '%.x.com%' OR domain LIKE '%.twitter.com%'")
    >> cookies = {row[0]: row[1] for row in cursor.fetchall()}
    >> json.dump(cookies, open('x_cookies.json', 'w'))
    >> conn.close()
                        '''
                    },
                    'firefox': {
                        'location': '~/.mozilla/firefox/[profile]/cookies.sqlite',
                        'instructions': [
                            '1. Close Firefox completely',
                            '2. Navigate to: ~/.mozilla/firefox/',
                            '3. Open the profile folder (usually contains random characters)',
                            '4. Copy "cookies.sqlite" file',
                            '5. Use sqlite3 to extract cookies',
                            '6. Look for entries with host like ".x.com" or ".twitter.com"'
                        ],
                        'python_extraction': '''
    >> import sqlite3
    >> import json
    >> import os
    >> 
    >> cookies_file = os.path.expanduser('~/.mozilla/firefox/[profile]/cookies.sqlite')
    >> conn = sqlite3.connect(cookies_file)
    >> cursor = conn.cursor()
    >> cursor.execute("SELECT name, value, host FROM moz_cookies WHERE host LIKE '%.x.com%' OR host LIKE '%.twitter.com%'")
    >> cookies = {row[0]: row[1] for row in cursor.fetchall()}
    >> json.dump(cookies, open('x_cookies.json', 'w'))
    >> conn.close()
                        '''
                    }
                }
            }
            return guide
    
        def _getLocalStorage(self) -> Dict[str, str]:
            """Extract local storage data"""
            try:
                localStorage = self.driver.execute_script("return window.localStorage;") or {}
                return dict(localStorage)
            except: return {}
    
        def _getSessionStorage(self) -> Dict[str, str]:
            """Extract session storage data"""
            try:
                session_storage = self.driver.execute_script("return window.sessionStorage;") or {}
                return dict(session_storage)
            except: return {}
    
        def _2FADetect(self) -> bool:
            """Detect if 2FA challenge is present"""
            try:
                indicators = [
                    (By.XPATH, "//span[contains(text(), 'Enter verification code')]"),
                    (By.XPATH, "//span[contains(text(), 'Verification code')]"),
                    (By.XPATH, "//span[contains(text(), 'Enter your code')]"),
                    (By.CSS_SELECTOR, "input[placeholder*='code']"),
                    (By.CSS_SELECTOR, "input[aria-label*='verification']"),
                    (By.XPATH, "//span[contains(text(), 'two-factor')]")]
                for by, value in indicators:
                    try:
                        self.driver.find_element(by, value)
                        return True
                    except NoSuchElementException: continue
                return False
            except Exception as e:
                self.andras.customLogPipe(f"Error detecting 2FA: {e}", level='d')
                return False
    
        def _2FAIDMethod(self) -> str:
            """Identify the 2FA method being used"""
            try:
                if self.driver.find_element(By.XPATH, "//span[contains(text(), 'authentication app')]"): return 'authenticator_app'
                elif self.driver.find_element(By.XPATH, "//span[contains(text(), 'text message')]"): return 'sms'
                elif self.driver.find_element(By.XPATH, "//span[contains(text(), 'security key')]"): return 'security_key'
                elif self.driver.find_element(By.XPATH, "//span[contains(text(), 'backup code')]"): return 'backup_code'
            except: pass
            return 'unknown'
    
        def login(self, username: str, password: str, code2FA: str = None) -> bool:
            """
            Login to X/Twitter with credentials and optional 2FA code
            
            Args:
                username: Username or email
                password: Password
                code2FA: Optional 2FA code (if required)
            
            Returns:
                bool: Success status
            """
            if not self.driver: self.driver = self.andras.browserInstance.start(headless=False, stealth=True)
            try:
                self.andras.customLogPipe(f"Attempting X login for {username}...", level=1)
                self._setMetadata('login_time', datetime.now().isoformat())
                self._setMetadata('user_agent', self.driver.execute_script("return navigator.userAgent"))
                # Navigate to login
                self.driver.get(f'{self.baseUrl}/login')
                self.andras.WaitHelper.waitForPageLoad(self.driver)
                self.andras.actHuman.humanDelay(1, 2)
                # Username/Email field
                self.andras.customLogPipe("Entering credentials...", level='d')
                usernameField = self.andras.WaitHelper.waitForAnyElement(
                    self.driver,
                    [
                        (By.NAME, 'text'),
                        (By.CSS_SELECTOR, 'input[name="text"]'),
                        (By.CSS_SELECTOR, 'input[autocomplete="username"]'),
                        (By.XPATH, '//input[@autocomplete="username"]')
                    ],
                    timeout=15)
                if not usernameField: raise Exception("Username field not found")
                self.andras.ActHuman.humanType(usernameField, username)
                self.andras.ActHuman.humanDelay(1, 2)
                # Next button
                nextBtn = self.driver.find_element(By.XPATH, "//span[text()='Next']/.. | //button[.//span[text()='Next']]")
                self.andras.ActHuman.humanClick(self.driver, nextBtn)
                self.andras.ActHuman.humanDelay(2, 3)
                # Password field
                passwordField = self.andras.WaitHelper.waitForAnyElement(
                    self.driver,
                    [
                        (By.NAME, 'password'),
                        (By.CSS_SELECTOR, 'input[type="password"]'),
                        (By.XPATH, '//input[@type="password"]')
                    ],
                    timeout=15)
                if not passwordField: raise Exception("Password field not found")
                self.andras.ActHuman.humanType(passwordField, password)
                self.andras.ActHuman.humanDelay(1, 2)
                # Login button
                loginBtn = self.driver.find_element(
                    By.XPATH,
                    "//span[text()='Log in']/.. | //button[.//span[text()='Log in']]")
                self.andras.ActHuman.humanClick(self.driver, loginBtn)
                self.andras.ActHuman.humanDelay(3, 5)
                # Check for 2FA
                if self._2FADetect():
                    self._setMetadata('2fa_detected', True)
                    self._setMetadata('2fa_method', self._2FAIDMethod())
                    self.andras.customLogPipe(
                        f"2FA DETECTED - Method: {self.sessionMetadata['2fa_method']}",
                        level=2)
                    if code2FA:
                        self.andras.customLogPipe("Entering 2FA code...", level=1)
                        cideField = self.andras.WaitHelper.waitForAnyElement(
                            self.driver,
                            [
                                (By.CSS_SELECTOR, 'input[placeholder*="code"]'),
                                (By.CSS_SELECTOR, 'input[aria-label*="verification"]'),
                                (By.NAME, 'verification_code'),
                            ],
                            timeout=10)
                        if cideField:
                            self.andras.ActHuman.humanType(cideField, code2FA)
                            self.andras.ActHuman.humanDelay(1, 2)
                            # Submit 2FA
                            submitButton = self.driver.find_element(
                                By.XPATH,
                                "//span[text()='Next']/.. | //button[.//span[text()='Next']]")
                            self.andras.ActHuman.humanClick(self.driver, submitButton)
                            self.andras.ActHuman.humanDelay(3, 5)
                        else:
                            self.andras.customLogPipe("2FA code field not found", level=3)
                            return False
                    else:
                        self.andras.customLogPipe(
                            "2FA required but no code provided. Manual intervention needed.",
                            level=3)
                        self._exportSessionInfo()
                        return False
                # Verify login success
                self.andras.WaitHelper.waitForPageLoad(self.driver)
                time.sleep(2)
                currentURL = self.driver.currentURL
                loginSuccess = any(path in currentURL for path in ['/home', '/compose', '/explore'])
                if loginSuccess:
                    # Extract session data
                    self._setMetadata('authenticated', True)
                    self._setMetadata('username', username)
                    self._setMetadata('cookies', {c['name']: c['value'] for c in self.driver.get_cookies()})
                    # Try to extract user ID
                    try:
                        userID = self.driver.execute_script(
                            "return window.__INITIAL_STATE__?.entities?.users?.[0]?.id || null")
                        if userID: self._setMetadata('userID', userID)
                    except: pass
                    self.andras.customLogPipe(f"✓ Successfully logged in as {username}", level=1)
                    self._exportSessionInfo()
                    return True
                else:
                    self.andras.customLogPipe(f"Login appeared successful but URL verification failed. Current URL: {currentURL}", level=2)
                    return False
            except Exception as e:
                self.andras.customLogPipe(f"X login failed: {e}", level=3, excInfo=True)
                return False
    
        def postMessage(self, message: str, mediaPath: str = None) -> Dict[str, Any]:
            """
            Post a message/tweet to X
            
            Args:
                message: The tweet text
                mediaPath: Optional path to media file
            
            Returns:
                dict: Post result with metadata
            """
            result = {
                'success': False,
                'message': message,
                'media': mediaPath,
                'timestamp': datetime.now().isoformat(),
                'error': None,
                'post_id': None}
            
            try:
                if not self.sessionMetadata['authenticated']:
                    result['error'] = 'Not authenticated'
                    self.andras.customLogPipe("Cannot post without authentication", level=3)
                    return result
                self.driver.get(f'{self.baseUrl}/compose/tweet')
                self.andras.WaitHelper.waitForPageLoad(self.driver)
                self.andras.ActHuman.humanDelay(2, 3)
                # Find text area
                textArea = self.andras.WaitHelper.waitForAnyElement(
                    self.driver,
                    [
                        (By.CSS_SELECTOR, 'div[contenteditable="true"]'),
                        (By.CSS_SELECTOR, 'div[role="textbox"]'),
                        (By.CSS_SELECTOR, 'div.DraftEditor-root'),
                        (By.XPATH, '//div[@contenteditable="true"]')
                    ],
                    timeout=15)
                if not textArea: raise Exception("Tweet text area not found")
                textArea.click()
                self.andras.ActHuman.humanDelay(0.5, 1)
                # Type message with human-like behavior
                self.andras.ActHuman.humanType(textArea, message)
                # Handle media if provided
                if mediaPath and os.path.exists(mediaPath):
                    try:
                        fileInputs = self.driver.find_elements(By.CSS_SELECTOR, 'input[type="file"]')
                        if fileInputs:
                            fileInputs[0].send_keys(os.path.abspath(mediaPath))
                            self.andras.ActHuman.humanDelay(2, 4)
                            result['media'] = os.path.basename(mediaPath)
                    except Exception as e: self.andras.customLogPipe(f"Media upload failed: {e}", level=2)
                # Click post button
                postBtn = self.andras.WaitHelper.waitForAnyElement(
                    self.driver,
                    [
                        (By.XPATH, "//span[text()='Post']/.."),
                        (By.CSS_SELECTOR, 'div[data-testid="tweetButtonInline"]'),
                        (By.XPATH, '//button[.//span[text()="Post"]]'),
                    ],
                    timeout=10)
                if postBtn:
                    self.andras.ActHuman.humanClick(self.driver, postBtn)
                    self.andras.ActHuman.humanDelay(2, 4)
                    result['success'] = True
                    self.andras.customLogPipe(f"Posted: {message[:50]}...", level=1)
                else: raise Exception("Post button not found")
            except Exception as e:
                result['error'] = str(e)
                self.andras.customLogPipe(f"Post failed: {e}", level=3)
            return result
    
        def searchPosts(self, keywords: List[str], maxResults: int = 50, includeReplies: bool = False) -> Dict[str, Any]:
            """
            Search for posts on X
            
            Args:
                keywords: List of search keywords
                maxResults: Maximum number of results per keyword
                includeReplies: Include replies in results
            
            Returns:
                dict: Search results with metadata
            """
            searchResult = {
                'timestamp': datetime.now().isoformat(),
                'keywords': keywords,
                'total_results': 0,
                'results_by_keyword': {},
                'errors': []}
            for keyword in keywords:
                keywordResults = []
                try:
                    self.andras.customLogPipe(f"Searching for: {keyword}", level=1)
                    searchUrl = f'{self.baseUrl}/search?q={urllib.parse.quote(keyword)}&src=typed_query'
                    if not includeReplies: searchUrl += '&f=live'
                    self.driver.get(searchUrl)
                    self.andras.WaitHelper.waitForPageLoad(self.driver)
                    self.andras.ActHuman.humanDelay(2, 3)
                    lastHeight = self.driver.execute_script("return document.body.scrollHeight")
                    while len(keywordResults) < maxResults:
                        posts = self.driver.find_elements(By.CSS_SELECTOR, 'article[data-testid="tweet"]')
                        for post in posts:
                            if len(keywordResults) >= maxResults: break
                            try:
                                postData = self._extractPostData(post)
                                if postData and postData not in keywordResults:
                                    keywordResults.append(postData)
                            except Exception as e:
                                self.andras.customLogPipe(f"Error extracting post: {e}", level='d')
                                continue
                        self.andras.ActHuman.humanScroll(self.driver)
                        time.sleep(2)
                        newHeight = self.driver.execute_script("return document.body.scrollHeight")
                        if newHeight == lastHeight: break
                        lastHeight = newHeight
                    searchResult['results_by_keyword'][keyword] = keywordResults
                    searchResult['total_results'] += len(keywordResults)
                    self.andras.customLogPipe(f"Found {len(keywordResults)} posts for '{keyword}'", level=1)
                except Exception as e:
                    error_msg = f"Search error for '{keyword}': {e}"
                    searchResult['errors'].append(error_msg)
                    self.andras.customLogPipe(error_msg, level=2)
            self.searchResults = searchResult
            return searchResult
    
        def _extractPostData(self, postElement) -> Dict[str, Any]:
            """
            Extract comprehensive data from a post element
            
            Returns:
                dict: Structured post data
            """
            try:
                post_data = {
                    'username': None,
                    'handle': None,
                    'userID': None,
                    'text': None,
                    'timestamp': None,
                    'is_retweet': False,
                    'is_reply': False,
                    'stats': {
                        'replies': 0,
                        'retweets': 0,
                        'likes': 0,
                        'views': 0,
                        'bookmarks': 0,
                    },
                    'images': [],
                    'videos': [],
                    'urls': [],
                    'hashtags': [],
                    'mentions': [],
                    'quoted_tweet': None,
                    'post_url': None,
                    'post_id': None}
                # Extract username and handle
                try:
                    username = postElement.find_element(By.CSS_SELECTOR, 'span[dir="ltr"] > span').text
                    post_data['username'] = username
                except: pass
                try:
                    handle_element = postElement.find_element(
                        By.CSS_SELECTOR,
                        'a[role="link"][href*="/"]')
                    handle = handle_element.get_attribute('href').split('/')[-1]
                    post_data['handle'] = handle
                except: pass
                # Extract text
                try:
                    textElements = postElement.find_elements(By.CSS_SELECTOR, 'div[lang]')
                    text = ' '.join([el.text for el in textElements]) if textElements else ''
                    post_data['text'] = text
                except: pass
                # Extract timestamp and post ID
                try:
                    timeElement = postElement.find_element(By.TAG_NAME, 'time')
                    timestamp = timeElement.get_attribute('datetime')
                    post_data['timestamp'] = timestamp
                    
                    # Try to extract post ID from URL
                    url_element = timeElement.find_element(By.XPATH, '..')
                    post_url = url_element.get_attribute('href')
                    if post_url:
                        post_data['post_url'] = f"{self.baseUrl}{post_url}" if post_url.startswith('/') else post_url
                        post_id = post_url.split('/')[-1]
                        post_data['post_id'] = post_id
                except: pass
                # Extract stats
                stat_types = ['reply', 'retweet', 'like', 'views', 'bookmark']
                for statType in stat_types:
                    try:
                        stat_element = postElement.find_element(
                            By.CSS_SELECTOR,
                            f'div[data-testid="{statType}"]')
                        stat_text = stat_element.text
                        stat_value = 0
                        if stat_text:
                            if stat_text.endswith('K'): stat_value = int(float(stat_text[:-1]) * 1000)
                            elif stat_text.endswith('M'): stat_value = int(float(stat_text[:-1]) * 1000000)
                            elif stat_text.isdigit(): stat_value = int(stat_text)
                        post_data['stats'][statType] = stat_value
                    except: pass
                # Extract media
                try:
                    images = [img.get_attribute('src') for img in postElement.find_elements(By.CSS_SELECTOR, 'img[alt="Image"]')]
                    post_data['images'] = images
                except: pass
                try:
                    videos = postElement.find_elements(By.CSS_SELECTOR, 'video')
                    post_data['videos'] = [v.get_attribute('src') for v in videos]
                except: pass
                # Extract URLs, hashtags, mentions
                if post_data['text']:
                    post_data['hashtags'] = list(set(re.findall(r'#\w+', post_data['text'])))
                    post_data['mentions'] = list(set(re.findall(r'@\w+', post_data['text'])))
                    post_data['urls'] = list(set(re.findall(r'https?://\S+', post_data['text'])))
                # Check if retweet
                try:
                    postElement.find_element(By.XPATH, ".//span[contains(text(), 'Reposted')]")
                    post_data['is_retweet'] = True
                except: pass
                # Check if reply
                try:
                    postElement.find_element(By.XPATH, ".//span[contains(text(), 'Replying to')]")
                    post_data['is_reply'] = True
                except: pass 
                return post_data
            except Exception as e:
                self.andras.customLogPipe(f"Error extracting post data: {e}", level='d')
                return None
    
        def exportResults(self, filepath: str = None, format: str = 'json') -> str:
            """
            Export search results to file
            
            Args:
                filepath: Output file path
                format: Output format ('json', 'csv')
            
            Returns:
                str: Path to exported file
            """
            if not filepath: filepath = Path(self.andras.base) / f'x_search_{int(time.time())}.{format}'
            filepath = Path(filepath)
            filepath.parent.mkdir(parents=True, exist_ok=True)
            try:
                if format == 'json':
                    with open(filepath, 'w', encoding='utf-8') as f:
                        json.dump(self.searchResults, f, indent=2, ensure_ascii=False)      
                elif format == 'csv':
                    import csv
                    all_posts = []
                    if isinstance(self.searchResults, dict) and 'results_by_keyword' in self.searchResults:
                        for posts in self.searchResults['results_by_keyword'].values():
                            all_posts.extend(posts)
                    else: all_posts = self.searchResults
                    if all_posts:
                        with open(filepath, 'w', newline='', encoding='utf-8') as f:
                            fieldnames = list(all_posts[0].keys())
                            writer = csv.DictWriter(f, fieldnames=fieldnames)
                            writer.writeheader()
                            for post in all_posts:
                                # Convert complex fields to JSON strings
                                row = {k: json.dumps(v) if isinstance(v, (dict, list)) else v for k, v in post.items()}
                                writer.writerow(row)
                self.andras.customLogPipe(
                    f"Exported {self.searchResults.get('total_results', len(self.searchResults))} results to {filepath}",
                    level=1)
                return str(filepath)        
            except Exception as e:
                self.andras.customLogPipe(f"Export failed: {e}", level=3)
                return None
    
        def getSessionMetadata(self) -> Dict[str, Any]:
            """Get current session metadata"""
            return self._getMetadata()
    
        def setSessionMetadata(self, key: str, value: Any):
            """Set session metadata"""
            return self._setMetadata(key, value)

    class DuckInteract:
        def __init__(self, ai: callable):
            self.andras = ai
            self.baseUrl = 'https://duckduckgo.com'
            self.chatUrl = 'https://duck.ai/'
            self.searchResults = []
            self.chat_history = []
            self.chat_session_metadata = {
                'session_start': None,
                'model': None,
                'total_messages': 0,
                'total_tokens_used': 0,
                'conversation_id': None}
            self.andras.customLogPipe("Initialized DuckDuckGo interaction.")

        def search(self, query: str, pages: int = 1) -> List[Dict[str, Any]]:
            """Search DuckDuckGo and return results"""
            if not self.andras.driverInstance: self.andras.browserInstance.start(headless=False, stealth=True)
            results = []
            try:
                self.andras.customLogPipe(f"Searching DuckDuckGo for: {query}", level=1)
                self.andras.driverInstance.get(self.baseUrl)
                self.andras.ActHuman.humanDelay(1, 2)
                searchBox = self.andras.WaitHelper.waitForAnyElement(
                    self.andras.driverInstance,
                    [
                        (By.ID, 'searchbox_input'),
                        (By.NAME, 'q'),
                        (By.CSS_SELECTOR, 'input[type="text"]'),
                        (By.XPATH, '//input[@type="text"][@name="q"]')
                    ],
                    timeout=15)
                if not searchBox: raise Exception("Search box not found")
                self.andras.ActHuman.humanType(searchBox, query)
                self.andras.ActHuman.humanDelay(0.5, 1)
                searchBox.send_keys(Keys.RETURN)
                self.andras.WaitHelper.waitForPageLoad(self.andras.driverInstance)
                self.andras.ActHuman.humanDelay(2, 3)
                for page in range(pages):
                    self.andras.customLogPipe(f"Extracting page {page + 1}/{pages}", level='d')
                    pageResults = self._extractDuckResults()
                    results.extend(pageResults)
                    if page < pages - 1:
                        try:
                            moreBtn = self.andras.driverInstance.find_element(
                                By.CSS_SELECTOR,
                                'button.result--more__btn, a.result--more__btn'
                            )
                            self.andras.ActHuman.humanClick(self.andras.driverInstance, moreBtn)
                            self.andras.WaitHelper.waitForPageLoad(self.andras.driverInstance)
                            self.andras.ActHuman.humanDelay(2, 3)
                        except:
                            self.andras.driverInstance.execute_script("window.scrollTo(0,document.body.scrollHeight)")
                            time.sleep(2)
                            try:
                                moreBtn = self.andras.driverInstance.find_element(
                                    By.CSS_SELECTOR,
                                    'button.result--more__btn'
                                )
                                self.andras.ActHuman.humanClick(self.andras.driverInstance, moreBtn)
                                self.andras.ActHuman.humanDelay(2, 3)
                            except:
                                self.andras.customLogPipe("No more pages available", level='d')
                                break
                            
                self.andras.customLogPipe(f"Found {len(results)} total results", level=1)
            except Exception as e: self.andras.customLogPipe(f"DuckDuckGo search error: {e}", level=3, excInfo=True)
            self.searchResults = results
            return results

        def _extractDuckResults(self) -> List[Dict[str, Any]]:
            """Extract search results from DuckDuckGo page"""
            results = []
            try:
                WebDriverWait(self.andras.driverInstance, 10).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, 'div[data-testid="result"]')))
                resultDivs = self.andras.driverInstance.find_elements(
                    By.CSS_SELECTOR,
                    'div[data-testid="result"]')
                for idx, div in enumerate(resultDivs):
                    try:
                        titleElement = div.find_element(By.CSS_SELECTOR, 'a[data-testid="result-title-a"]')
                        title = titleElement.text if titleElement else ''
                        url = titleElement.get_attribute('href') if titleElement else ''

                        snippetElement = div.find_element(By.CSS_SELECTOR, 'div[data-testid="result-snippet"]')
                        snippet = snippetElement.text if snippetElement else ''

                        if url and 'duckduckgo.com' not in url:
                            results.append({
                                'title': title,
                                'url': url,
                                'snippet': snippet,
                                'position': len(results) + 1,
                                'timestamp': datetime.now().isoformat(),
                                'source': 'duckduckgo'})
                    except Exception as e:
                        self.andras.customLogPipe(f"Error extracting result {idx}: {e}", level='d')
                        continue
                    
                # Check for instant answer
                instantAnswer = None
                try:
                    iaElement = self.andras.driverInstance.find_element(
                        By.CSS_SELECTOR,
                        'div.module--about, div.module--definitions')
                    instantAnswer = {
                        'type': 'instant_answer',
                        'content': iaElement.text,
                        'position': 0,
                        'timestamp': datetime.now().isoformat()}
                except: pass
                if instantAnswer: results.insert(0, instantAnswer)
            except Exception as e: self.andras.customLogPipe(f"Duck result extraction error: {e}", level=2)
            return results

        def _handleAntiBotPopup(self) -> bool:
            """
            Handle and dismiss DuckDuckGo anti-bot popup/verification

            Returns:
                bool: True if popup was handled, False otherwise
            """
            try:
                self.andras.customLogPipe("Checking for anti-bot popup...", level='d')
                # Common popup selectors
                popupSelectors = [
                    (By.XPATH, "//button[contains(text(), 'Okay')]"),
                    (By.XPATH, "//button[contains(text(), 'OK')]"),
                    (By.CSS_SELECTOR, 'button[aria-label*="Okay"]'),
                    (By.CSS_SELECTOR, 'button[aria-label*="OK"]'),
                    (By.CSS_SELECTOR, 'div.modal button'),
                    (By.XPATH, "//span[contains(text(), 'Okay')]/.."),
                    (By.XPATH, "//span[contains(text(), 'OK')]/.."),
                ]
                for by, value in popupSelectors:
                    try:
                        okBtn = self.andras.driverInstance.find_element(by, value)
                        if okBtn.is_displayed():
                            self.andras.customLogPipe("Found and clicking anti-bot popup button", level='d')
                            self.andras.ActHuman.humanClick(self.andras.driverInstance, okBtn)
                            self.andras.ActHuman.humanDelay(1, 2)
                            return True
                    except NoSuchElementException: continue
                return False
            except Exception as e:
                self.andras.customLogPipe(f"Error handling anti-bot popup: {e}", level='d')
                return False

        def duckChat(self, prompt: str, model: str = 'claude-3-haiku', 
                     waitForResponse: bool = True, timeout: int = 120) -> Dict[str, Any]:
            """
            Send a prompt to DuckDuckGo AI Chat and get response

            Args:
                prompt: The question/prompt to send
                model: AI model to use
                waitForResponse: Whether to wait for response
                timeout: Maximum time to wait for response (seconds)

            Returns:
                dict: Response with metadata
            """
            if not self.andras.driverInstance: self.andras.browserInstance.start(headless=False, stealth=True)
            response = {
                'success': False,
                'prompt': prompt,
                'model': model,
                'timestamp': datetime.now().isoformat(),
                'response': None,
                'code_blocks': [],
                'sources': [],
                'error': None,
                'response_time': 0,
                'stop_reason': None}
            startTime = time.time()
            try:
                self.andras.customLogPipe(f"Navigating to DuckDuckGo Chat with model: {model}", level=1)
                self.andras.driverInstance.get(self.chatUrl)
                self.andras.WaitHelper.waitForPageLoad(self.andras.driverInstance)
                self.andras.ActHuman.humanDelay(2, 3)
                # Handle anti-bot popup
                popupHandled = self._handleAntiBotPopup()
                if popupHandled: self.andras.ActHuman.humanDelay(1, 2)
                # Try to dismiss "Get Started" button if present
                try:
                    getStartedBtn = self.andras.driverInstance.find_element(
                        By.XPATH,
                        "//button[contains(text(), 'Get Started')] | //button[contains(text(), 'Start chat')]")
                    if getStartedBtn.is_displayed():
                        self.andras.ActHuman.humanClick(self.andras.driverInstance, getStartedBtn)
                        self.andras.ActHuman.humanDelay(2, 3)
                except: pass
                # Select model if available
                try:
                    self.andras.customLogPipe(f"Attempting to select model: {model}", level='d')
                    modelSelector = self.andras.WaitHelper.waitForAnyElement(
                        self.andras.driverInstance,
                        [
                            (By.CSS_SELECTOR, 'button[aria-label*="model"]'),
                            (By.CSS_SELECTOR, 'div.model-selector'),
                            (By.CSS_SELECTOR, 'button[class*="model"]'),
                            (By.XPATH, "//button[contains(text(), 'Model')]"),
                        ],
                        timeout=5)
                    if modelSelector:
                        self.andras.ActHuman.humanClick(self.andras.driverInstance, modelSelector)
                        self.andras.ActHuman.humanDelay(1, 2)
                        modelOptions = {
                            'claude-3-haiku': ['Claude 3 Haiku', 'Claude Haiku', 'Haiku'],
                            'gpt-3.5': ['GPT-3.5', 'GPT 3.5'],
                            'gpt-4': ['GPT-4', 'GPT 4'],
                            'llama': ['Llama', 'Llama 2'],
                            'mixtral': ['Mixtral', 'Mixtral 8x7B']}
                        if model in modelOptions:
                            for modelName in modelOptions[model]:
                                try:
                                    modelBtn = self.andras.driverInstance.find_element(
                                        By.XPATH,
                                        f"//button[contains(text(), '{modelName}')] | //div[contains(text(), '{modelName}')]"
                                    )
                                    self.andras.ActHuman.humanClick(self.andras.driverInstance, modelBtn)
                                    self.andras.ActHuman.humanDelay(1, 2)
                                    self.andras.customLogPipe(f"Selected model: {modelName}", level='d')
                                    break
                                except: continue
                except: self.andras.customLogPipe("Could not select model, using default", level='d')
                # Find and interact with chat input
                self.andras.customLogPipe("Finding chat input field...", level='d')
                textArea = self.andras.WaitHelper.waitForAnyElement(
                    self.andras.driverInstance,
                    [
                        (By.CSS_SELECTOR, 'textarea[placeholder*="Ask"]'),
                        (By.CSS_SELECTOR, 'textarea.chat-input'),
                        (By.CSS_SELECTOR, 'div[contenteditable="true"]'),
                        (By.XPATH, "//textarea[@placeholder]"),
                        (By.CSS_SELECTOR, 'input[type="text"][placeholder*="Ask"]'),
                    ],
                    timeout=15)
                if not textArea: raise Exception("Chat input field not found")
                # Click on the text area to focus it
                self.andras.ActHuman.humanClick(self.andras.driverInstance, textArea)
                self.andras.ActHuman.humanDelay(0.5, 1)
                # Type the prompt with human-like behavior
                self.andras.customLogPipe(f"Typing prompt: {prompt[:50]}...", level='d')
                self.andras.ActHuman.humanType(textArea, prompt)
                self.andras.ActHuman.humanDelay(0.5, 1)
                # Find and click submit button
                submitBtn = self.andras.WaitHelper.waitForAnyElement(
                    self.andras.driverInstance,
                    [
                        (By.CSS_SELECTOR, 'button[type="submit"]'),
                        (By.CSS_SELECTOR, 'button[aria-label*="Send"]'),
                        (By.CSS_SELECTOR, 'button[aria-label*="submit"]'),
                        (By.XPATH, "//button[@type='submit']"),
                        (By.CSS_SELECTOR, 'button[class*="submit"]'),
                    ],
                    timeout=10)
                if not submitBtn: raise Exception("Submit button not found")
                self.andras.customLogPipe("Submitting prompt...", level='d')
                self.andras.ActHuman.humanClick(self.andras.driverInstance, submitBtn)
                self.andras.ActHuman.humanDelay(1, 2)
                if waitForResponse:
                    response['response'], response['code_blocks'], response['sources'] = self._waitForChatResponse(
                        timeout=timeout)
                response['response_time'] = time.time() - startTime
                response['success'] = True
                self.andras.customLogPipe(
                    f"Chat response received ({response['response_time']:.2f}s)",
                    level=1)
            except Exception as e:
                response['error'] = str(e)
                response['response_time'] = time.time() - startTime
                self.andras.customLogPipe(f"DuckChat error: {e}", level=3, excInfo=True)
            # Add to conversation history
            self.chat_history.append(response)
            self.chat_session_metadata['total_messages'] += 1
            return response

        def _waitForChatResponse(self, timeout: int = 120) -> tuple:
            """
            Wait for AI response and extract data

            Args:
                timeout: Maximum time to wait

            Returns:
                tuple: (response_text, code_blocks, sources)
            """
            self.andras.customLogPipe(f"Waiting for response (timeout: {timeout}s)...", level='d')
            startTime = time.time()
            response_text = None
            code_blocks = []
            sources = []
            try:
                # Wait for response to appear
                last_response_count = 0
                stable_checks = 0
                stable_threshold = 3  # Number of checks to confirm response is complete
                while time.time() - startTime < timeout:
                    try:
                        # Look for chat messages
                        responseElements = self.andras.driverInstance.find_elements(
                            By.CSS_SELECTOR,
                            'div[data-testid="chat-message-content"], div.chat-response, div[class*="message"]')
                        # Check for loading indicators
                        loadingIndicators = self.andras.driverInstance.find_elements(
                            By.CSS_SELECTOR,
                            'div.loading, div.typing-indicator, div[class*="loading"], span[class*="spinner"]')
                        loading_active = any(
                            ind.is_displayed() for ind in loadingIndicators 
                            if ind.value_of_css_property('display') != 'none')
                        if responseElements and not loading_active:
                            current_count = len(responseElements)
                            if current_count == last_response_count:
                                stable_checks += 1
                                if stable_checks >= stable_threshold:
                                    # Response is stable, extract it
                                    response_text = self._extractChatResponse(responseElements[-1])
                                    code_blocks = self._extractCodeBlocks(responseElements[-1])
                                    sources = self._extractSources(responseElements[-1])
                                    break
                            else:
                                stable_checks = 0
                                last_response_count = current_count
                        time.sleep(1)
                    except Exception as e:
                        self.andras.customLogPipe(f"Error during response wait: {e}", level='d')
                        time.sleep(1)
                elapsed = time.time() - startTime
                if elapsed >= timeout: self.andras.customLogPipe(f"Response wait timeout after {elapsed:.2f}s", level=2)
            except Exception as e: self.andras.customLogPipe(f"Error waiting for chat response: {e}", level=3)

            return response_text, code_blocks, sources

        def _extractChatResponse(self, responseElement) -> str:
            """Extract text from response element"""
            try:
                # Try multiple selectors for text content
                text_selectors = [
                    'div[data-testid="chat-message-content"]',
                    'p',
                    'span',
                    'div[class*="content"]']
                for selector in text_selectors:
                    try:
                        textElements = responseElement.find_elements(By.CSS_SELECTOR, selector)
                        if textElements:
                            text = ' '.join([el.text for el in textElements if el.text.strip()])
                            if text: return text
                    except: continue
                # Fallback to full text
                return responseElement.text
            except Exception as e:
                self.andras.customLogPipe(f"Error extracting response text: {e}", level='d')
                return ""

        def _extractCodeBlocks(self, responseElement) -> List[str]:
            """Extract code blocks from response"""
            code_blocks = []
            try:
                codeElements = responseElement.find_elements(By.CSS_SELECTOR, 'pre, code, div[class*="code"]')
                for code in codeElements:
                    code_text = code.text.strip()
                    if code_text: code_blocks.append(code_text)
            except Exception as e: self.andras.customLogPipe(f"Error extracting code blocks: {e}", level='d')
            return code_blocks

        def _extractSources(self, responseElement) -> List[Dict[str, str]]:
            """Extract sources/citations from response"""
            sources = []
            try:
                sourceElements = responseElement.find_elements(
                    By.CSS_SELECTOR,
                    'a[href], div[class*="source"], div[class*="citation"]')
                for source in sourceElements[:5]:  # Limit to first 5
                    try:
                        href = source.get_attribute('href')
                        text = source.text.strip()
                        if href and text:
                            sources.append({
                                'text': text,
                                'url': href,
                                'timestamp': datetime.now().isoformat()})
                    except: continue
            except Exception as e:
                self.andras.customLogPipe(f"Error extracting sources: {e}", level='d')
            return sources

        def chatConversation(self, prompts: List[str], model: str = 'claude-3-haiku',
                            delay_between: tuple = (2, 4)) -> Dict[str, Any]:
            """
            Have a multi-turn conversation

            Args:
                prompts: List of prompts
                model: AI model to use
                delay_between: Delay range between messages (min, max)

            Returns:
                dict: Conversation summary with all responses
            """
            self.chat_session_metadata['session_start'] = datetime.now().isoformat()
            self.chat_session_metadata['model'] = model
            self.chat_history = []
            conversation = {
                'session_metadata': self.chat_session_metadata.copy(),
                'messages': [],
                'total_prompts': len(prompts),
                'successful_responses': 0,
                'failed_responses': 0,
                'total_time': 0,}

            startTime = time.time()
            try:
                for idx, prompt in enumerate(prompts):
                    self.andras.customLogPipe(
                        f"Sending message {idx + 1}/{len(prompts)}",
                        level=1)
                    response = self.duckChat(prompt, model, waitForResponse=True)
                    conversation['messages'].append(response)
                    if response['success']: conversation['successful_responses'] += 1
                    else: conversation['failed_responses'] += 1
                    # Delay between messages
                    if idx < len(prompts) - 1:
                        delay = random.uniform(delay_between[0], delay_between[1])
                        self.andras.customLogPipe(f"Waiting {delay:.2f}s before next message...", level='d')
                        time.sleep(delay)
                conversation['total_time'] = time.time() - startTime
                self.andras.customLogPipe(
                    f"Conversation complete. {conversation['successful_responses']}/{conversation['total_prompts']} successful",
                    level=1)
            except Exception as e: self.andras.customLogPipe(f"Conversation error: {e}", level=3, excInfo=True)
            self.chat_history.append(conversation)
            return conversation

        def constructDork(self, query: str, site: str = None, filetype: str = None,
                         intitle: str = None, region: str = None) -> str:
            """Construct a DuckDuckGo dork query"""
            dork = query
            if site: dork += f' site:{site}'
            if filetype: dork += f' filetype:{filetype}'
            if intitle: dork += f' intitle:{intitle}'
            if region: dork += f' region:{region}'
            return dork

        def exportResults(self, filepath: str = None, format: str = 'json') -> str:
            """
            Export search or chat results

            Args:
                filepath: Output file path
                format: 'json' or 'csv'

            Returns:
                str: Path to exported file
            """
            if not filepath:
                if self.chat_history: filepath = Path(self.andras.base) / f'duck_chat_{int(time.time())}.{format}'
                else: filepath = Path(self.andras.base) / f'duck_search_{int(time.time())}.{format}'
            filepath = Path(filepath)
            filepath.parent.mkdir(parents=True, exist_ok=True)
            try:
                if format == 'json':
                    data = self.chat_history if self.chat_history else self.searchResults
                    with open(filepath, 'w', encoding='utf-8') as f:
                        json.dump(data, f, indent=2, ensure_ascii=False)
                elif format == 'csv':
                    import csv
                    data = self.chat_history if self.chat_history else self.searchResults
                    if data:
                        with open(filepath, 'w', newline='', encoding='utf-8') as f:
                            fieldnames = list(data[0].keys())
                            writer = csv.DictWriter(f, fieldnames=fieldnames)
                            writer.writeheader()
                            for row in data:
                                # Convert complex fields to JSON strings
                                cleaned_row = {
                                    k: json.dumps(v) if isinstance(v, (dict, list)) else v
                                    for k, v in row.items()}
                                writer.writerow(cleaned_row)
                count = len(self.chat_history) if self.chat_history else len(self.searchResults)
                self.andras.customLogPipe(f"Exported {count} results to {filepath}", level=1)
                return str(filepath)
            except Exception as e:
                self.andras.customLogPipe(f"Export failed: {e}", level=3)
                return None

        def getChatHistory(self) -> List[Dict[str, Any]]:
            """Get chat conversation history"""
            return self.chat_history

        def getSessionMetadata(self) -> Dict[str, Any]:
            """Get current chat session metadata"""
            return self.chat_session_metadata
    
    # *--- Browser ---*
    class Replay:
        def __init__(self,ai:callable,driver:callable=None):
            self.andras = ai
            self.driver = driver if driver else self.andras.driverInstance
            self.recordedActions:List[Dict[str,Any]]=[]
        def _getXPath(self,element)->Optional[str]:
            if not self.driver:
                return None
            script = """function getXPath(e){if(e.id!=='')return`//*[@id="${e.id}"]`;if(e===document.body)return'/html/body';let ix=0;const s=e.parentNode.childNodes;for(let i=0;i<s.length;i++){const sib=s[i];if(sib===e)return`${getXPath(e.parentNode)}/${e.tagName.toLowerCase()}[${(ix+1)}]`;if(sib.nodeType===1&&sib.tagName===e.tagName)ix++;}return null;}return getXPath(arguments[0]);"""
            try:
                return self.driver.execute_script(script, element)
            except Exception as e:
                self.andras.customLogPipe(f"Could not generate XPath: {e}", level=3)
                return None
        def recordAction(self,actionType:str,**kwargs):
            self.recordedActions.append({'type': actionType, 'timestamp': datetime.now().isoformat(), **kwargs})
            self.andras.customLogPipe(f"Recorded: {actionType}", level=0)
        def recordNav(self,url:str):
            self.recordAction('navigate', url=url)
        def recordClick(self,element):
            xpath = self._getXPath(element)
            if xpath:
                self.recordAction('click', xpath=xpath)
        def recordInput(self,element,value:str):
            xpath = self._getXPath(element)
            if xpath:
                self.recordAction('input', xpath=xpath, value=value)
        def replay(self,delay:float=0.5):
            if not self.driver:
                self.andras.customLogPipe("Driver not available", level=3)
                return
            for action in self.recordedActions:
                try:
                    if action['type'] == 'navigate':
                        self.driver.get(action['url'])
                    elif action['type'] == 'click':
                        WebDriverWait(self.driver, 10).until(EC.element_to_be_clickable((By.XPATH, action['xpath']))).click()
                    elif action['type'] == 'input':
                        elem = WebDriverWait(self.driver, 10).until(EC.presence_of_element_located((By.XPATH, action['xpath'])))
                        elem.clear()
                        elem.send_keys(action['value'])
                    time.sleep(delay)
                except Exception as e:
                    self.andras.customLogPipe(f"Replay error: {e}", level=3)

    class Mouse:
        def __init__(self, ai: callable):
            self.andras = ai
            self.verbose = False
            self.usePrint = False
            self.records = defaultdict(list)
            self.isRecord = False
            self.recording_start_time = None
            self.event_listener_cleanupScript = None

        def _log(self, message: str, level: int = 1):
            """Internal logging helper."""
            if self.verbose: self.andras.customLogPipe(message, level=level)
            if self.usePrint: print(message)

        def setRecord(self, eventType: str, data: Any):
            """Adds a new record to the records dictionary."""
            if not isinstance(eventType, str):
                self._log(f"Invalid event type: {eventType}. Must be string.", level=3)
                return
            record = {
                'timestamp': datetime.now().isoformat(),
                'data': data}
            self.records[eventType].append(record)
            self._log(f"Record added to '{eventType}': {str(data)[:100]}", level='d')

        def clearRecords(self, eventType: str = None) -> bool:
            """
            Clear recorded events

            Args:
                eventType: Specific event type to clear, or None for all

            Returns:
                bool: Success status
            """
            try:
                if eventType:
                    if eventType in self.records:
                        count = len(self.records[eventType])
                        del self.records[eventType]
                        self._log(f"Cleared {count} records for event type '{eventType}'", level='d')
                    else:
                        self._log(f"Event type '{eventType}' not found", level=2)
                else:
                    total_count = sum(len(v) for v in self.records.values())
                    self.records.clear()
                    self._log(f"Cleared all {total_count} records", level='d')
                return True
            except Exception as e:
                self._log(f"Failed to clear records: {e}", level=3)
                return False

        def getRecords(self, eventType: str = None) -> Dict[str, Any] | List[Dict[str, Any]]:
            """
            Retrieve records

            Args:
                eventType: Specific event type to retrieve

            Returns:
                dict or list of records
            """
            if eventType: return self.records.get(eventType, [])
            return dict(self.records)

        def getRecordStats(self) -> Dict[str, Any]:
            """Get statistics about recorded events"""
            stats = {
                'total_events': sum(len(v) for v in self.records.values()),
                'eventTypes': list(self.records.keys()),
                'events_by_type': {k: len(v) for k, v in self.records.items()},
                'is_recording': self.isRecord}
            return stats

        def exportRecords(self, filepath: str = None) -> bool:
            """
            Exports the recorded mouse events to a JSON file.

            Args:
                filepath: Path to export file

            Returns:
                bool: Success status
            """
            if not filepath: filepath = Path(self.andras.base) / f'mouse_records_{int(time.time())}.json'
            filepath = Path(filepath)
            try:
                filepath.parent.mkdir(parents=True, exist_ok=True)
                export_data = {
                    'export_timestamp': datetime.now().isoformat(),
                    'total_events': sum(len(v) for v in self.records.values()),
                    'records': dict(self.records)}
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, indent=4, ensure_ascii=False)
                self._log(f"Successfully exported {export_data['total_events']} records to {filepath}", level=1)
                return True
            except Exception as e:
                self._log(f"Failed to export records: {e}", level=3)
                return False

        def importRecords(self, filepath: str) -> bool:
            """
            Imports mouse event records from a JSON file, merging with existing records.

            Args:
                filepath: Path to import file

            Returns:
                bool: Success status
            """
            if not Path(filepath).exists():
                self._log(f"File not found: {filepath}", level=3)
                return False
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                # Handle both old and new format
                if isinstance(data, dict) and 'records' in data: importedRecords = data['records']
                else: importedRecords = data
                importedCount = 0
                for eventType, events in importedRecords.items():
                    if isinstance(events, list):
                        self.records[eventType].extend(events)
                        importedCount += len(events)
                self._log(f"Successfully imported {importedCount} records from {filepath}", level=1)
                return True
            except json.JSONDecodeError as e:
                self._log(f"Invalid JSON in {filepath}: {e}", level=3)
                return False
            except Exception as e:
                self._log(f"Failed to import records: {e}", level=3)
                return False

        def getLinkAtCursor(self) -> Optional[str]:
            """
            Retrieves the href of the link currently under the mouse cursor.
            Requires the recording script to be injected.

            Returns:
                str: URL of link under cursor, or None
            """
            if not self.andras.driverInstance:
                self._log("Browser not active.", level=3)
                return None
            try:
                link = self.andras.driverInstance.execute_script(
                    "return window._andras_mouse_state ? window._andras_mouse_state.hoveredLink : null;")
                if link:
                    self._log(f"Link at cursor: {link}", level='d')
                    self.setRecord('getLinkAtCursor', {'url': link, 'timestamp': datetime.now().isoformat()})
                else: self._log("No link at cursor", level='d')
                return link
            except Exception as e:
                self._log(f"Could not get link at cursor: {e}", level=2)
                return None

        def _injectRecordingScript(self) -> bool:
            """Inject mouse event listening script into the page"""
            if not self.andras.driverInstance:
                self._log("Browser not active.", level=3)
                return False
            try:
                # Enhanced script with better element tracking
                script = """
                window._andras_mouse_events = [];
                window._andras_mouse_state = { 
                    hoveredLink: null, 
                    hoveredElement: null,
                    lastMovement: null
                };

                function getElementDetails(elem) {
                    if (!elem) return null;
                    try {
                        const rect = elem.getBoundingClientRect();
                        return {
                            tagName: elem.tagName,
                            id: elem.id || '',
                            className: elem.className || '',
                            text: (elem.innerText || elem.textContent || '').substring(0, 100),
                            href: elem.href || (elem.closest('a') ? elem.closest('a').href : null),
                            x: Math.round(rect.x),
                            y: Math.round(rect.y),
                            width: Math.round(rect.width),
                            height: Math.round(rect.height)
                        };
                    } catch (e) {
                        return null;
                    }
                }

                function andrasMouseEventHandler(e) {
                    try {
                        const details = getElementDetails(e.target);
                        const eventData = {
                            type: e.type,
                            x: e.clientX,
                            y: e.clientY,
                            pageX: e.pageX,
                            pageY: e.pageY,
                            screenX: e.screenX,
                            screenY: e.screenY,
                            timestamp: new Date().toISOString(),
                            element: details,
                            button: e.button || 0,
                            buttons: e.buttons || 0
                        };

                        window._andras_mouse_events.push(eventData);

                        // Update state for mousemove
                        if (e.type === 'mousemove') {
                            window._andras_mouse_state.hoveredLink = details ? details.href : null;
                            window._andras_mouse_state.hoveredElement = details;
                            window._andras_mouse_state.lastMovement = {
                                x: e.clientX,
                                y: e.clientY,
                                timestamp: new Date().toISOString()
                            };
                        }
                    } catch (err) {
                        console.error('Error in andrasMouseEventHandler:', err);
                    }
                }

                // Store reference for cleanup
                window._andrasMouseEventHandler = andrasMouseEventHandler;

                document.addEventListener('click', andrasMouseEventHandler, true);
                document.addEventListener('mousemove', andrasMouseEventHandler, true);
                document.addEventListener('mousedown', andrasMouseEventHandler, true);
                document.addEventListener('mouseup', andrasMouseEventHandler, true);
                document.addEventListener('dblclick', andrasMouseEventHandler, true);

                return true;
                """
                self.andras.driverInstance.execute_script(script)
                self._log("Mouse event listeners injected successfully.", level='d')
                return True
            except Exception as e:
                self._log(f"Failed to inject recording script: {e}", level=3)
                return False

        def _removeRecordingScript(self) -> bool:
            """Remove mouse event listeners from the page"""
            if not self.andras.driverInstance: return False
            try:
                cleanupScript = """
                try {
                    if (window._andrasMouseEventHandler) {
                        document.removeEventListener('click', window._andrasMouseEventHandler, true);
                        document.removeEventListener('mousemove', window._andrasMouseEventHandler, true);
                        document.removeEventListener('mousedown', window._andrasMouseEventHandler, true);
                        document.removeEventListener('mouseup', window._andrasMouseEventHandler, true);
                        document.removeEventListener('dblclick', window._andrasMouseEventHandler, true);
                    }
                    delete window._andras_mouse_events;
                    delete window._andras_mouse_state;
                    delete window._andrasMouseEventHandler;
                    return true;
                } catch (e) {
                    return false;
                }
                """
                result = self.andras.driverInstance.execute_script(cleanupScript)
                if result: self._log("Mouse event listeners removed successfully.", level='d')
                else: self._log("Failed to remove some event listeners.", level=2)
                return result
            except Exception as e:
                self._log(f"Error during cleanup: {e}", level=2)
                return False

        def record(self, duration: int = 10, poll_interval: float = 0.5) -> Dict[str, Any]:
            """
            Records mouse movements and clicks for a specified duration.
            Injects a JS listener to capture events.

            Args:
                duration: Recording duration in seconds
                poll_interval: How often to poll for events (seconds)

            Returns:
                dict: Recording summary
            """
            if not self.andras.driverInstance:
                self._log("Browser not active. Cannot start recording.", level=3)
                return {'success': False, 'error': 'Browser not active', 'events_recorded': 0}
            if self.isRecord:
                self._log("Already recording. Stop current recording first.", level=2)
                return {'success': False, 'error': 'Already recording', 'events_recorded': 0}
            if duration <= 0:
                self._log("Duration must be greater than 0", level=3)
                return {'success': False, 'error': 'Invalid duration', 'events_recorded': 0}
            recordingSummary = {
                'success': False,
                'start_time': datetime.now().isoformat(),
                'end_time': None,
                'duration': duration,
                'events_recorded': 0,
                'events_by_type': {},
                'error': None}
            try:
                self._log(f"Starting mouse recording for {duration} seconds...", level=1)
                self.isRecord = True
                self.recording_start_time = time.time()
                # Inject listener script
                if not self._injectRecordingScript():
                    raise Exception("Failed to inject recording script")
                end_time = time.time() + duration
                try:
                    while time.time() < end_time:
                        time.sleep(poll_interval)
                        try:
                            # Retrieve and clear events from browser
                            events = self.andras.driverInstance.execute_script(
                                "const events = window._andras_mouse_events; window._andras_mouse_events = []; return events;")
                            if events and isinstance(events, list):
                                self._log(f"Retrieved {len(events)} mouse events.", level='d')
                                for event in events:
                                    if isinstance(event, dict):
                                        eventType = event.get('type', 'unknown')
                                        self.setRecord(eventType, event)
                                        # Update summary
                                        if eventType not in recordingSummary['events_by_type']: recordingSummary['events_by_type'][eventType] = 0
                                        recordingSummary['events_by_type'][eventType] += 1
                                        recordingSummary['events_recorded'] += 1
                        except Exception as e:
                            self._log(f"Error polling events: {e}", level='d')
                            continue
                except KeyboardInterrupt:
                    self._log("Recording stopped by user.", level=2)
                recordingSummary['success'] = True

            except Exception as e:
                self._log(f"An error occurred during recording: {e}", level=3, excInfo=True)
                recordingSummary['error'] = str(e)
            finally:
                self.isRecord = False
                recordingSummary['end_time'] = datetime.now().isoformat()
                # Clean up the listeners
                try: self._removeRecordingScript()
                except Exception as e: self._log(f"Error during cleanup: {e}", level='d')
                self._log(
                    f"Mouse recording finished. "
                    f"Recorded {recordingSummary['events_recorded']} events.",
                    level=1)
            return recordingSummary

        def playback(self, eventType: str = None, speed: float = 1.0) -> Dict[str, Any]:
            """
            Playback recorded mouse events

            Args:
                eventType: Specific event type to playback, or None for all
                speed: Playback speed multiplier

            Returns:
                dict: Playback summary
            """
            if not self.andras.driverInstance:
                self._log("Browser not active.", level=3)
                return {'success': False, 'error': 'Browser not active'}
            if not self.records:
                self._log("No records to playback.", level=2)
                return {'success': False, 'error': 'No records'}
            playbackSummary = {
                'success': False,
                'start_time': datetime.now().isoformat(),
                'end_time': None,
                'events_played': 0,
                'error': None}
            try:
                self._log(f"Starting playback with speed: {speed}x", level=1)
                eventsToPlay = []
                if eventType: eventsToPlay = self.records.get(eventType, [])
                else:
                    for event_list in self.records.values():
                        eventsToPlay.extend(event_list)
                if not eventsToPlay: raise Exception("No events to playback")
                # Sort by timestamp
                eventsToPlay = sorted(eventsToPlay, key=lambda x: x.get('timestamp', ''))
                last_time = None
                for record in eventsToPlay:
                    try:
                        data = record.get('data', {})
                        timestamp = record.get('timestamp', '')
                        # Calculate delay
                        if last_time and timestamp:
                            try:
                                last_dt = datetime.fromisoformat(last_time)
                                curr_dt = datetime.fromisoformat(timestamp)
                                delay = (curr_dt - last_dt).total_seconds() / speed
                                if delay > 0: time.sleep(min(delay, 1.0))  # Cap at 1 second
                            except: pass
                        last_time = timestamp
                        # Playback event
                        if data.get('type') == 'click':
                            x = data.get('x', 0)
                            y = data.get('y', 0)
                            self.andras.ActHuman.humanClick(
                                self.andras.driverInstance,
                                self.andras.driverInstance.find_element(By.TAG_NAME, 'body'))
                            self._log(f"Playback click at ({x}, {y})", level='d')
                        elif data.get('type') == 'mousemove':
                            x = data.get('x', 0)
                            y = data.get('y', 0)
                            actions = ActionChains(self.andras.driverInstance)
                            actions.move_by_offset(x, y).perform()
                            self._log(f"Playback move to ({x}, {y})", level='d')
                        playbackSummary['events_played'] += 1
                    except Exception as e:
                        self._log(f"Error during playback: {e}", level='d')
                        continue
                playbackSummary['success'] = True
            except Exception as e:
                self._log(f"Playback failed: {e}", level=3)
                playbackSummary['error'] = str(e)
            finally: playbackSummary['end_time'] = datetime.now().isoformat()
            return playbackSummary

    class Cache:
        
        def __init__(self,ai:callable):
            self.andras    = ai
            self.base      = self.andras.base
            self.andras.customLogPipe("Initialized Cache Instance...")

        def get(self, key:str,expiry:int=86400) -> Optional[Any]:
            """Retrieves an item from the cache if it exists and is not expired."""
            cacheFile = Path(self.base) / f"{key}.json"
            if cacheFile.exists() and not self.isExpired(cacheFile, expiry):
                try:
                    self.andras.customLogPipe(f"Loading from cache file {cacheFile}...")
                    with open(cacheFile, 'r', encoding='utf-8') as f:
                        return json.load(f)
                except (json.JSONDecodeError, IOError) as E: self.andras.customLogPipe(f"Failed to read cache file {cacheFile}: {E}", level=3)
            return None

        def set(self,key:str,data:Any):
            """Saves an item to the cache."""
            cacheFile = Path(self.base) / f"{key}.json"
            try:
                self.andras.customLogPipe(f"Saving to cache file {cacheFile}...")
                with open(cacheFile, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=4)
            except (TypeError, IOError) as e: self.andras.customLogPipe(f"Failed to write to cache file {cacheFile}: {e}", level=3)

        def isExpired(self, filepath: Path, expiry: int) -> bool:
            """Checks if a cached file has expired."""
            return (time.time() - filepath.stat().st_mtime) > expiry
         
    class UserAgent:

        def __init__(self,ai:callable):
            self.andras      = ai
            self.defaults    = self.andras.UserAgentsInternalDefault()
            self.cache       = self.andras.cacheInstance
            self.agents      = {} # Storage for loaded user-agent lists
            self.remoteSrc   = {
                # NOTE: This can be expanded to fetch user agents from remote sources.
                # The 'type' key will determine how the raw data is parsed.
                # Example:
                # "bot": [{'type': 'json', 'url': 'https://raw.githubusercontent.com/monperrus/crawler-user-agents/master/crawler-user-agents.json'},...]
                "mobile":{'type': 'json', 'url':"https://raw.githubusercontent.com/microlinkhq/top-user-agents/refs/heads/master/src/mobile.json"} # List 
            }
            self.andras.customLogPipe("Initialized UserAgent Instance...")

        def fetch(self,browser:str,source:Dict[str, str]):
            """
            Fetches user agents from a remote source, utilizing the cache. If a valid
            cache exists, it's returned. Otherwise, it fetches, parses, caches, and
            returns the user agents.

            Returns:
                List[str]: A list of user agent strings, or an empty list on failure.
            """
            if not source or not ('type' in source and 'url' in source): 
                self.andras.customLogPipe(f"Invalid remote source for {browser}: {source}, skipping(Returning `[]`)", level=3)
                return []

            cacheKey = f"user_agents_{browser}_{hashlib.md5(source['url'].encode()).hexdigest()}"
            cachedData = self.cache.get(cacheKey, self.andras.config['userAgents']['cacheExpiry'])
            if cachedData:
                self.andras.customLogPipe(f"Loaded user agents for '{browser}' from cache.")
                return cachedData
            self.andras.customLogPipe(f"Fetching remote user agents for '{browser}' from {source['url']}...")
            try:
                dataRaw = requests.get(source['url'], timeout=10)
                dataRaw.raise_for_status()
                data = []
                if source['type'] == 'json':
                    jsonData = dataRaw.json()
                    if isinstance(jsonData, list): data = jsonData
                    elif isinstance(jsonData, dict): data = list(jsonData.values())
                    else: raise ValueError(f"Unknown JSON data structure from {source['url']}: {type(jsonData)}")
                elif source['type'] == 'txt': data = [line for line in dataRaw.text.split('\n') if line.strip()]
                if data:
                    self.cache.set(cacheKey, data)
                    self.andras.customLogPipe(f"Successfully fetched and cached {len(data)} user agents for '{browser}'.")
                return data
            except (requests.exceptions.RequestException, json.JSONDecodeError, ValueError) as e:
                self.andras.customLogPipe(f"Failed to fetch or parse user agents for '{browser}' from {source['url']}: {e}", level=3)
                return []

        def getFallBack(self,browser:str=None):
            """Returns a fallback user-agent string for a given browser type."""
            browser = browser.lower() if browser else self.andras.config['userAgents']['type']
            return self.defaults.userAgentFallbacks.get(browser, self.defaults.userAgentFallbacks['firefox'])
            

        def random(self,browser:str=None):
            """Returns a random user-agent string for a given browser type from the internal list."""
            browser = browser.lower() if browser else self.andras.config['userAgents']['type']
            # Prioritize remotely fetched agents if available
            agentList = self.agents.get(browser)
            # Fallback to internal defaults if no remote list is loaded
            if not agentList: agentList = self.defaults.userAgentsIndex.get(browser)
            if agentList: return random.choice(agentList)
            # Final fallback
            return self.getFallBack(browser)

        def load(self, fetchRemote: bool = False):
            """
            Loads user agents into memory.
            It prioritizes loading from the internal defaults first.
            If fetchRemote is True, it will then attempt to fetch from remote sources,
            which will either come from cache or a network request.
            """
            # 1. Load all internal default user agents first
            self.andras.customLogPipe("Loading default user agents into memory...")
            self.agents = self.defaults.userAgentsIndex.copy()

            # 2. If requested, fetch remote lists, which will check cache first.
            if fetchRemote:
                for browser, source in self.remoteSrc.items():
                    self.andras.customLogPipe(f"Fetching remote user agents for '{browser}'...")
                    remote_agents = self.fetch(browser, source)
                    if remote_agents:
                        # Combine and de-duplicate, giving preference to remote agents
                        self.agents[browser] = list(dict.fromkeys(remote_agents + self.agents.get(browser, [])))

    class Driver:
        def __init__(self, ai: callable):
            self.andras = ai
            # In the new structure, UserAgent is instantiated on Andras, not Driver.
            # We will create an instance of the new UserAgent class.
            # This seems to be a refactoring from the old structure.
            # In andrasPre.py, it was `self.andras.userAgents`.
            # In the new structure, it seems you want to instantiate it here.
            # Let's assume you'll instantiate it on the Andras object later.
            # For now, we'll create it directly.
            self.userAgents = self.andras.UserAgent(self.andras)
            self.driver = None
        
        def setup(self,
                  browser:str='chrome',
                  headless:bool=False,
                  stealth:bool=False,
                  proxy:str=None,
                  userAgent:str=None,
                  windowSize:str=None):
            """Sets up and configures the WebDriver instance."""
            # Determine browser type from Andras config if not specified
            browser = browser if browser else self.andras.browser
            # Get a user agent if one isn't provided
            userAgent = userAgent if userAgent else self.userAgents.random(browser=browser)
            # Window size configuration
            sizeMap = {'small': (800, 600), 'normal': (1366, 768), 'large': (1920, 1080)}
            width, height = sizeMap.get(windowSize, (random.choice([1366, 1920, 1440]), random.choice([768, 1080, 900])))
            if browser.lower() == 'firefox':
                options = webdriver.FirefoxOptions()
                options.set_preference('dom.webdriver.enabled', False)
                options.set_preference('useAutomationExtension', False)
                options.set_preference('general.useragent.override', str(userAgent))
                if headless:
                    options.add_argument('--headless')
                self.driver = webdriver.Firefox(options=options)
            elif browser.lower() == 'chrome':
                options = webdriver.ChromeOptions()
                if stealth:
                    options.add_argument('--disable-blink-features=AutomationControlled')
                    options.add_experimental_option("excludeSwitches", ["enable-automation"])
                    options.add_experimental_option('useAutomationExtension', False)
                options.add_argument('--disable-dev-shm-usage')
                options.add_argument('--no-sandbox')
                options.add_argument(f'user-agent={userAgent}')
                if proxy: options.add_argument(f'--proxy-server={proxy}')
                if headless: options.add_argument('--headless=new')
                self.driver = webdriver.Chrome(options=options)
            if windowSize == 'full': self.driver.maximize_window()
            else: self.driver.set_window_size(width, height)
            self.andras.driverInstance = self.driver
            return self.driver

    class Browser:
        def __init__(self, ai: callable):
            self.andras = ai
            self.driver = None
            self.wait = None
            self.actions = None
            self.last_url = None
            self.monitor_thread = None
            self.monitoring = False

        def _logNavigation(self, url: str):
            """Logs navigation events to the console."""
            self.andras.customLogPipe(f"Navigated to {url}", level=1)

        def start(self,browser:str='chrome',headless:bool=False,stealth:bool=True,proxy:str=None,userAgent:str=None,windowSize:str=None):
            driverInstance = self.andras.Driver(self.andras)
            self.driver = driverInstance.setup(browser=browser, headless=headless, stealth=stealth, proxy=proxy, userAgent=userAgent, windowSize=windowSize)
            self.wait = WebDriverWait(self.driver, 10)
            self.actions = ActionChains(self.driver)
            self.andras.driverInstance = self.driver
            # Start monitoring for URL changes
            self.monitoring = True
            self.monitor_thread = threading.Thread(target=self._urlMonitor, daemon=True)
            self.monitor_thread.start()
            self.andras.customLogPipe("URL monitor started.", level='d')

        def stop(self):
            if self.driver:
                self.monitoring = False
                if self.monitor_thread and self.monitor_thread.is_alive():
                    self.monitor_thread.join(timeout=1) # Wait briefly for the thread to exit
                self.driver.quit()
                self.driver = None
                self.andras.driverInstance = None

        def _urlMonitor(self):
            """A background thread to monitor and log URL changes."""
            while self.monitoring and self.driver:
                try:
                    current_url = self.driver.current_url
                    if current_url != self.last_url:
                        self._logNavigation(current_url)
                        self.last_url = current_url
                except Exception:
                    # This can happen if the browser is closed unexpectedly.
                    # The loop will exit on the next check of `self.monitoring`.
                    break
                time.sleep(1) # Check every second

        def navigateTo(self,url:str):
            if self.driver: 
                self.driver.get(url)
                # The monitor will pick up this change, so no need to log here.
                return True
            return False
        
        def findElement(self,by,value,timeout=10):
            if not self.driver: return None
            try: return WebDriverWait(self.driver, timeout).until(EC.presence_of_element_located((by, value)))
            except: return None
        
        def findElements(self,by,value):
            return self.driver.find_elements(by, value) if self.driver else []
        
        def screenshot(self,filepath:str):
            if self.driver: self.driver.save_screenshot(filepath)

    # *--- Console ---*
    class InlineConsole:
        def __init__(self, ai: callable):
            self.andras = ai
            self.driver = None
            self.running = True
            self.history = []
            self.commands = {
                'help': self.cmdLet_help,
                'screenshot': self.cmdLet_screenshot,
                'navigate': self.cmdLet_navigate,
                'currentURL': self.cmdLet_currentURL,
                'title': self.cmdLet_title,
                'execute': self.cmdLet_execute,
                'find': self.cmdLet_find,
                'click': self.cmdLet_click,
                'type': self.cmdLet_type,
                'scroll': self.cmdLet_scroll,
                'wait': self.cmdLet_wait,
                'cookies': self.cmdLet_cookies,
                'source': self.cmdLet_source,
                'delay': self.cmdLet_delay,
                'clear': self.cmdLet_clear,
                'history': self.cmdLet_history,
                'exit': self.cmdLet_exit,
                'quit': self.cmdLet_exit,
                'x.login': self.cmdLet_x_login,
                'x.post': self.cmdLet_x_post,
                'x.search': self.cmdLet_x_search,
                'ddg.search': self.cmdLet_ddg_search,
                'ddg.chat': self.cmdLet_ddg_chat,
                'profiles.list': self.cmdLet_profiles_list,
            }

        def _require_driver(func):
            """Decorator to ensure a driver instance is available."""
            def wrapper(self, *args, **kwargs):
                if not self.driver:
                    print("[!] Browser not active. Cannot execute command.")
                    return
                return func(self, *args, **kwargs)
            wrapper.__doc__ = func.__doc__
            return wrapper

        def _validate_args(min_args: int = 0, max_args: Optional[int] = None, usage: str = ""):
            """Decorator to validate the number of arguments for a command."""
            def decorator(func):
                def wrapper(self, args):
                    if not (min_args <= len(args) and (max_args is None or len(args) <= max_args)):
                        command_name = func.__name__.replace('cmdLet_', '').replace('_', '.')
                        print(f"[!] Invalid arguments for '{command_name}'.")
                        if usage:
                            print(f"    Usage: {usage}")
                        return
                    return func(self, args)
                wrapper.__doc__ = func.__doc__
                return wrapper
            return decorator

        def cmdLet_help(self, args):
            """Display available commands"""
            print("\n--- Andras Console Commands ---")
            for cmd, func in self.commands.items():
                doc = func.__doc__ or "No description"
                print(f"  {cmd:<20} - {doc}")
            print("\nNote: For commands with spaces in arguments, wrap them in quotes.")
            print()

        def cmdLet_history(self, args):
            """Show command history"""
            print("\n--- Command History ---")
            if not self.history:
                print("No commands in history.")
            for i, cmd in enumerate(self.history):
                print(f"  {i}: {cmd}")
            print()

        @_require_driver
        @_validate_args(max_args=1, usage="screenshot [filepath]")
        def cmdLet_screenshot(self, args):
            """Take a screenshot: screenshot [filepath]"""
            if not self.driver:
                print("[!] Browser not active")
                return
            filepath = args[0] if args else "screenshot.png"
            try:
                self.driver.save_screenshot(filepath)
                print(f"[*] Screenshot saved to {filepath}")
            except Exception as e:
                print(f"[!] Error: {e}")

        @_require_driver
        @_validate_args(min_args=1, max_args=1, usage="navigate <url>")
        def cmdLet_navigate(self, args):
            """Navigate to URL: navigate <url>"""
            if not self.driver:
                print("[!] Browser not active")
                return
            if not args:
                print("[!] URL required")
                return
            try:
                url = args[0]
                self.driver.get(url)
                print(f"[*] Navigated to {url}")
            except Exception as e:
                print(f"[!] Error: {e}")

        @_require_driver
        def cmdLet_currentURL(self, args):
            """Get current URL"""
            if not self.driver:
                print("[!] Browser not active")
                return
            try:
                print(f"[*] Current URL: {self.driver.currentURL}")
            except Exception as e:
                print(f"[!] Error: {e}")

        @_require_driver
        def cmdLet_title(self, args):
            """Get page title"""
            if not self.driver:
                print("[!] Browser not active")
                return
            try:
                print(f"[*] Page title: {self.driver.title}")
            except Exception as e:
                print(f"[!] Error: {e}")

        @_require_driver
        @_validate_args(min_args=1, usage="execute <javascript_code>")
        def cmdLet_execute(self, args):
            """Execute JavaScript: execute <js_code>"""
            if not self.driver:
                print("[!] Browser not active")
                return
            if not args:
                print("[!] JavaScript code required")
                return
            try:
                js_code = ' '.join(args)
                result = self.driver.execute_script(js_code)
                print(f"[*] Result: {result}")
            except Exception as e:
                print(f"[!] Error: {e}")

        @_require_driver
        @_validate_args(min_args=2, usage="find <by> <value>")
        def cmdLet_find(self, args):
            """Find elements: find <by> <value>"""
            if not self.driver:
                print("[!] Browser not active")
                return
            if len(args) < 2:
                print("[!] Usage: find <by> <value>")
                print("[!] by options: id, name, class, css, xpath, tag")
                return
            try:
                by_type = args[0].lower()
                by_map = {
                    'id': By.ID,
                    'name': By.NAME,
                    'class': By.CLASS_NAME,
                    'css': By.CSS_SELECTOR,
                    'xpath': By.XPATH,
                    'tag': By.TAG_NAME,
                }
                if by_type not in by_map:
                    print(f"[!] Unknown locator type: {by_type}")
                    print("[!] by options: id, name, class, css, xpath, tag")
                    return

                value = ' '.join(args[1:])
                elements = self.driver.find_elements(by_map[by_type], value)
                print(f"[*] Found {len(elements)} element(s)")
                for idx, elem in enumerate(elements[:5]):  # Show first 5
                    print(f"  [{idx}] Tag: {elem.tag_name}, Text: {elem.text[:50]}")
            except Exception as e:
                print(f"[!] Error: {e}")

        @_require_driver
        @_validate_args(min_args=2, usage="click <by> <value>")
        def cmdLet_click(self, args):
            """Click element: click <by> <value>"""
            if not self.driver:
                print("[!] Browser not active")
                return
            if len(args) < 2:
                print("[!] Usage: click <by> <value>")
                return
            try:
                by_type = args[0].lower()
                by_map = {
                    'id': By.ID,
                    'name': By.NAME,
                    'class': By.CLASS_NAME,
                    'css': By.CSS_SELECTOR,
                    'xpath': By.XPATH,
                }
                if by_type not in by_map:
                    print(f"[!] Unknown locator type: {by_type}")
                    return

                value = ' '.join(args[1:])
                element = WebDriverWait(self.driver, 10).until(
                    EC.element_to_be_clickable((by_map[by_type], value))
                )
                element.click()
                print(f"[*] Clicked element")
            except Exception as e:
                print(f"[!] Error: {e}")

        @_require_driver
        @_validate_args(min_args=3, usage="type <by> <element_value> <text_to_type>")
        def cmdLet_type(self, args):
            """Type text: type <by> <value> <text>"""
            if not self.driver:
                print("[!] Browser not active")
                return
            if len(args) < 3:
                print("[!] Usage: type <by> <element_value> <text_to_type>")
                return
            try:
                by_type = args[0].lower()
                by_map = {
                    'id': By.ID,
                    'name': By.NAME,
                    'class': By.CLASS_NAME,
                    'css': By.CSS_SELECTOR,
                    'xpath': By.XPATH,
                }
                if by_type not in by_map:
                    print(f"[!] Unknown locator type: {by_type}")
                    return

                element_value = args[1]
                text = ' '.join(args[2:])
                element = WebDriverWait(self.driver, 10).until(
                    EC.presence_of_element_located((by_map[by_type], element_value))
                )
                element.clear()
                element.send_keys(text)
                print(f"[*] Typed '{text}' into element")
            except Exception as e:
                print(f"[!] Error: {e}")

        @_require_driver
        @_validate_args(min_args=1, max_args=2, usage="scroll <down|up> [amount]")
        def cmdLet_scroll(self, args):
            """Scroll page: scroll <direction> [amount]"""
            if not self.driver:
                print("[!] Browser not active")
                return
            if not args:
                print("[!] Usage: scroll <down|up> [amount]")
                return
            try:
                direction = args[0].lower()
                amount = int(args[1]) if len(args) > 1 else 300

                if direction == 'down':
                    self.driver.execute_script(f"window.scrollBy(0, {amount});")
                elif direction == 'up':
                    self.driver.execute_script(f"window.scrollBy(0, -{amount});")
                else:
                    print("[!] Direction must be 'down' or 'up'")
                    return
                print(f"[*] Scrolled {direction} by {amount}px")
            except Exception as e:
                print(f"[!] Error: {e}")

        @_validate_args(min_args=1, max_args=1, usage="wait <seconds>")
        def cmdLet_wait(self, args):
            """Wait for seconds: wait <seconds>"""
            if not args:
                print("[!] Usage: wait <seconds>")
                return
            try:
                seconds = float(args[0])
                print(f"[*] Waiting {seconds} seconds...")
                time.sleep(seconds)
                print(f"[*] Done waiting")
            except Exception as e:
                print(f"[!] Error: {e}")

        @_require_driver
        @_validate_args(min_args=1, usage="cookies <list|clear|save|load> [file]")
        def cmdLet_cookies(self, args):
            """Manage cookies: cookies <list|clear|save [file]|load [file]>"""
            if not self.driver:
                print("[!] Browser not active")
                return
            if not args:
                print("[!] Usage: cookies <list|clear|save|load> [file]")
                return

            action = args[0].lower()
            try:
                if action == 'list':
                    cookies = self.driver.get_cookies()
                    if not cookies:
                        print("[*] No cookies found")
                        return
                    for idx, cookie in enumerate(cookies[:10]):
                        print(f"  [{idx}] {cookie.get('name')} = {cookie.get('value')[:30]}")
                    if len(cookies) > 10:
                        print(f"  ... and {len(cookies) - 10} more")

                elif action == 'clear':
                    self.driver.delete_all_cookies()
                    print("[*] All cookies cleared")

                elif action == 'save':
                    filename = args[1] if len(args) > 1 else "cookies.pkl"
                    with open(filename, 'wb') as f:
                        pickle.dump(self.driver.get_cookies(), f)
                    print(f"[*] Cookies saved to {filename}")

                elif action == 'load':
                    filename = args[1] if len(args) > 1 else "cookies.pkl"
                    with open(filename, 'rb') as f:
                        cookies = pickle.load(f)
                        for cookie in cookies:
                            self.driver.add_cookie(cookie)
                    print(f"[*] Cookies loaded from {filename}")
                else:
                    print(f"[!] Unknown action: {action}")
            except Exception as e:
                print(f"[!] Error: {e}")

        @_require_driver
        @_validate_args(max_args=1, usage="source [save_to_file]")
        def cmdLet_source(self, args):
            """Get page source: source [save_to_file]"""
            if not self.driver:
                print("[!] Browser not active")
                return
            try:
                source = self.driver.page_source
                if args:
                    with open(args[0], 'w', encoding='utf-8') as f:
                        f.write(source)
                    print(f"[*] Source saved to {args[0]}")
                else:
                    print(f"[*] Source length: {len(source)} characters")
                    print(source[:500] + "..." if len(source) > 500 else source)
            except Exception as e:
                print(f"[!] Error: {e}")

        @_validate_args(max_args=2, usage="delay [min_seconds] [max_seconds]")
        def cmdLet_delay(self, args):
            """Human-like delay: delay [min] [max]"""
            if not args:
                print("[!] Usage: delay [min_seconds] [max_seconds]")
                return
            try:
                min_sec = float(args[0]) if args else 1
                max_sec = float(args[1]) if len(args) > 1 else 3
                delay = random.uniform(min_sec, max_sec)
                print(f"[*] Delaying {delay:.2f} seconds...")
                time.sleep(delay)
                print(f"[*] Done")
            except Exception as e:
                print(f"[!] Error: {e}")

        def cmdLet_clear(self, args):
            """Clear console screen"""
            os.system('cls' if sys.platform == 'win32' else 'clear')

        def cmdLet_exit(self, args):
            """Exit console"""
            print("[*] Exiting console...")
            self.running = False

        @_require_driver
        @_validate_args(min_args=2, max_args=3, usage="x.login <username> <password> [2fa_code]")
        def cmdLet_x_login(self, args):
            """Login to X: x.login <username> <password> [2fa_code]"""
            if len(args) < 2:
                print("[!] Usage: x.login <username> <password> [2fa_code]")
                return
            username = args[0]
            password = args[1]
            code2FA = args[2] if len(args) > 2 else None
            self.andras.xInteractInstance.login(username, password, code2FA)

        @_require_driver
        def cmdLet_x_post(self, args):
            """Post to X: x.post <message> [--media /path/to/media]"""
            if not args:
                print("[!] Usage: x.post <message> [--media /path/to/media]")
                return
            
            message = ' '.join(args)
            # Re-join args to handle potential spaces in file paths if not quoted
            full_input = ' '.join(args)
            media_path = None
            if '--media' in message:
                parts = message.split('--media')
                message = parts[0].strip()
                media_path = parts[1].strip()

            message = full_input
            if '--media' in full_input:
                # Use shlex to properly split, respecting quotes
                try:
                    post_args = shlex.split(full_input)
                    media_index = post_args.index('--media')
                    message = ' '.join(post_args[:media_index])
                    media_path = post_args[media_index + 1]
                except (ValueError, IndexError):
                    print("[!] Invalid format for --media. Usage: x.post \"your message\" --media \"/path/to/file\"")
                    return
            self.andras.xInteractInstance.postMessage(message, media_path)

        @_require_driver
        @_validate_args(min_args=1, usage="x.search <keyword1> [keyword2] ...")
        def cmdLet_x_search(self, args):
            """Search on X: x.search <keyword1> [keyword2] ..."""
            if not args:
                print("[!] Usage: x.search <keyword1> [keyword2] ...")
                return
            self.andras.xInteractInstance.searchPosts(args)
            print(f"[*] Search complete. Found {self.andras.xInteractInstance.searchResults.get('total_results', 0)} results.")
            print("[*] Use 'x.export' to save results.")

        @_require_driver
        @_validate_args(min_args=1, usage="ddg.search <query>")
        def cmdLet_ddg_search(self, args):
            """Search DuckDuckGo: ddg.search <query>"""
            if not args:
                print("[!] Usage: ddg.search <query>")
                return
            query = ' '.join(args)
            self.andras.duckInteractInstance.search(query)
            print(f"[*] Search complete. Found {len(self.andras.duckInteractInstance.searchResults)} results.")

        @_require_driver
        @_validate_args(min_args=1, usage="ddg.chat <prompt>")
        def cmdLet_ddg_chat(self, args):
            """Chat with DuckDuckGo AI: ddg.chat <prompt>"""
            if not args:
                print("[!] Usage: ddg.chat <prompt>")
                return
            prompt = ' '.join(args)
            response = self.andras.duckInteractInstance.duckChat(prompt)
            if response and response.get('success'):
                print("\n--- DDG AI Response ---")
                print(response.get('response'))
                print("-----------------------\n")
            else:
                print(f"[!] DDG Chat failed: {response.get('error')}")

        @_validate_args(max_args=0, usage="profiles.list")
        def cmdLet_profiles_list(self, args):
            """List available browser profiles for supported browsers."""
            print("\n--- Available Browser Profiles ---")
            
            profile_finders = {
                'Chrome': self.andras.BrowserPaths.getChromeProfilePath,
                'Firefox': self.andras.BrowserPaths.getFirefoxProfilePath,
                'Edge': self.andras.BrowserPaths.getEdgeProfilePath,
                'Brave': self.andras.BrowserPaths.getBraveProfilePath,
            }

            for browser, finder in profile_finders.items():
                try:
                    base_path = finder()
                    print(f"\n[*] {browser} profiles (from: {base_path}):")
                    if not base_path.exists():
                        print("    Profile directory not found.")
                        continue

                    profiles_found = False
                    if browser == 'Firefox':
                        ini_path = base_path / 'profiles.ini'
                        if ini_path.exists():
                            config = configparser.ConfigParser()
                            config.read(ini_path)
                            for section in config.sections():
                                if section.startswith('Profile'):
                                    name = config[section].get('Name', 'Unknown')
                                    path = config[section].get('Path', 'Unknown')
                                    print(f"    - {name} (directory: {path})")
                                    profiles_found = True
                    else: # For Chromium-based browsers
                        for p in base_path.iterdir():
                            if p.is_dir() and (p / 'Preferences').exists():
                                print(f"    - {p.name}")
                                profiles_found = True

                    if not profiles_found:
                        print("    No profiles found.")
                except Exception as e:
                    print(f"    Error finding {browser} profiles: {e}")
            print()

        def start(self):
            """Start the interactive console"""
            if not self.andras.driverInstance:
                self.andras.customLogPipe("Browser not started. Please start the browser before using the console.", level=3)
                return

            self.driver = self.andras.driverInstance

            # Mute verbosity during console
            old_verbosity = self.andras.config['verbosity']
            self.andras.config['verbosity'] = False

            print("\n" + "="*60)
            print("--- Andras Interactive Console ---")
            print("Type 'help' for available commands")
            print("="*60 + "\n")

            try:
                while self.running:
                    try:
                        userInput = input("andras> ").strip()
                        if not userInput: continue
                        self.history.append(userInput)
                        # Parse command and arguments
                        parts = userInput.split()
                        parts = shlex.split(userInput)
                        command = parts[0].lower()
                        args = parts[1:] if len(parts) > 1 else []
                        if command in self.commands: self.commands[command](args)
                        else: print(f"[!] Unknown command: {command}. Type 'help' for commands.")

                    except KeyboardInterrupt:
                        print("\n[*] Interrupted. Type 'exit' to quit.")
                    except Exception as e:
                        print(f"[!] Error: {e}")

            finally:
                # Restore verbosity
                self.andras.config['verbosity'] = old_verbosity
                print("\n" + "="*60)
                print("Console closed")
                print("="*60 + "\n")
    
    def _initParsers(self):
        """Initializes argument parsers for the application."""
        
        # Custom action for the short help message
        class ShortHelpAction(argparse.Action):
            def __init__(self, option_strings, dest, nargs=0, **kwargs):
                super(ShortHelpAction, self).__init__(option_strings, dest, nargs=nargs, **kwargs)

            def __call__(self, parser, namespace, values, option_string=None):
                print("Usage: andras.py -u <url> [options]")
                print("\nCommon Options:")
                print("  -u, --url <url>         URL to navigate to.")
                print("  -b, --browser <browser>   Browser to use (chrome, firefox). Default: chrome.")
                print("  -hL, --headless         Run in headless mode.")
                print("  -c, --console           Open interactive console.")
                print("  --x-search <keywords>   Search on X/Twitter.")
                print("  --ddg-search <query>    Search on DuckDuckGo.")
                print("\nUse --help for the full list of options.")
                parser.exit()

        central = argparse.ArgumentParser(
            description="An attempt at a headless browser automation framework.", add_help=False)
        central.add_argument('-h', action=ShortHelpAction, help='Show a short help message and exit.')
        central.add_argument('--help', action='help', default=argparse.SUPPRESS, help='Show this help message and exit.')
        central.add_argument('-b','--browser',
                             help='Browser to use. Default: chrome',
                             default='chrome',
                             choices=['chrome','firefox'])
        central.add_argument('-u','--url',
                             help='URL to navigate to. Default: None',
                             default=None,
                             type=str)
        central.add_argument('-hL','--headless',
                             help='Run in headless mode. Default: False',
                             action='store_true')
        central.add_argument('-nS','--no-stealth',
                             help='Disable stealth mode. Default: False',
                             action='store_true')
        # User Agents
        central.add_argument('-uaS','--set-user-agent',
                             help='User agent to use. Default: random',
                             default=None,
                             type=str)
        central.add_argument('-uaL','--load-user-agents',
                             help='Load user agents from remote sources. Default: False',
                             action='store_true')
        central.add_argument('-ual','--list-user-agents',
                             help='List all user agents. Default: False',
                             action='store_true')
        central.add_argument('-uaR','--random-user-agent',
                             help="Get a random user agent. Default: False",
                             action='store_true')
        central.add_argument('-uaRT','--random-user-agent-by-type',
                             help="Get a random user agent by type.",
                             type=str,
                             default=None)
        # Proxy
        central.add_argument('-p','--proxy',
                             help='Proxy to use. Default: None',
                             default=None,
                             type=str)
        # Cookies
        central.add_argument('-cL','--cookies-load',
                             help='Load cookies from a file. Default: None',
                             default=None,
                             type=str)
        central.add_argument('-cS','--cookies-save',
                             help='Save cookies to a file. Default: None',
                             default=None,
                             type=str)
        # Extractions
        central.add_argument('-eC','--extract-cookies',
                             help="Extract cookies from the browser.",
                             choices=['chrome','firefox'],
                             default=None,
                             type=str)
        central.add_argument('-eP','--extract-profile',
                             help="Profile name to extract from.",
                             default="default",
                             type=str)
        central.add_argument('-eS','--extract-storage',
                             help="Storage name to extract from.",
                             default="default",
                             type=str)
        # Injections 
        central.add_argument('-iEC',"--inject-extracted-cookies",
                             help="Injects extracted cookies from previous sessions into the new session. (Default: False)",
                             action='store_true')
        # Cache
        central.add_argument('-lC','--list-cache',
                             help="Lists all cached files.",
                             action='store_true')
        # Window
        central.add_argument('-wS','--window-size',
                             help="Window size to use. Default: normal",
                             default='normal',
                             choices=['small','normal','large','full'])
        central.add_argument('-wF','--keep-open',
                             help="Keep the browser open after the script finishes.",
                             action='store_true')
        central.add_argument('-wW','--wait-for-close',
                             help="Wait for the user to close the browser window.",
                             action='store_true')
        # Console
        central.add_argument('-c','--console',
                             help="Opens an interactive console in a separate window.",
                             action='store_true')
        # X/Twitter Interaction
        x_group = central.add_argument_group('X/Twitter Interaction')
        x_group.add_argument('--x-login', 
                            help='Login to X. Usage: --x-login <user> <pass> [2fa_code]',
                            nargs='+') 
        x_group.add_argument('--x-post', 
                             help='Post a message to X.',
                             type=str)
        x_group.add_argument('--x-post-media', 
                             help='Path to media file for the post.',
                             type=str)
        x_grop = x_group.add_argument('--x-search', 
                                      help='Search for keywords on X.',
                                      nargs='+')
        x_group.add_argument('--x-search-limit', 
                             help='Maximum number of results for X search.',
                             default=50, 
                             type=int) 
        x_group.add_argument('--x-no-replies', 
                             help='Exclude replies from X search results.',
                             action='store_true')
        x_group.add_argument('--x-export', 
                             help='Export X search results to a file (e.g., results.json or results.csv).',
                             type=str)
        # DuckDuckGo Interaction
        ddg_group = central.add_argument_group('DuckDuckGo Interaction')
        ddg_group.add_argument('--ddg-search',
                               help='Search DuckDuckGo.',
                               type=str)
        ddg_group.add_argument('--ddg-search-pages', 
                               help='Number of pages to scrape for DDG search.',
                               default=1, 
                               type=int)
        ddg_group.add_argument('--ddg-chat', 
                               help='Send a prompt to DuckDuckGo AI Chat.',
                               type=str)
        ddg_group.add_argument('--ddg-chat-model', 
                               help='Model to use for DDG Chat.',
                               default='claude-3-haiku', 
                               type=str)
        ddg_group.add_argument('--ddg-export', 
                               help='Export DDG search/chat results to a file.',
                               type=str)
        # Post-Operation
        central.add_argument('--clear-cache',
                             help="Clears the cache.",
                             action='store_true')
        central.add_argument('--clear-cookies',
                             help="Clears the cookies.",
                             action='store_true')
        # Process
        self.args = central.parse_args()
        self.customLogPipe(f"Parsed arguments: '{' '.join(sys.argv[1:])}' ...")
        return self.args

    def _execBrowserPreOps(self, args) -> tuple:
        """Handles operations that occur before the browser is started."""
        browser = args.browser if args.browser else self.browser
        userAgent = None
        # User-Agent handling
        if args.load_user_agents: self.userAgentInstance.load(fetchRemote=True)
        else: self.userAgentInstance.load(fetchRemote=False)
        self.customLogPipe("Loaded user agents...")
        # List user-agents if true
        if args.list_user_agents:
            self.customLogPipe("Listing all loaded user agents...")
            for browser_type, agents in self.userAgentInstance.agents.items():
                print(f"\n--- {browser_type.upper()} ---")
                aC = 0
                for agent in agents:
                    print(f"({aC}) - {agent}")
                    aC += 1
        # Determine which user agent to use
        if args.random_user_agent and not (args.set_user_agent or args.random_user_agent_by_type):
            userAgent = self.userAgentInstance.random()
            self.customLogPipe(f"Using random user-agent: {userAgent[:10]}... (truncated)")
        elif args.random_user_agent_by_type and not args.set_user_agent:
            userAgent = self.userAgentInstance.random(browser=args.random_user_agent_by_type)
            self.customLogPipe(f"Using random user-agent for {args.random_user_agent_by_type}: {userAgent[:10]}... (truncated)")
        elif args.set_user_agent:
            userAgent = args.set_user_agent
            self.customLogPipe(f"Using custom user-agent: {userAgent[:10]}... (truncated)")
        else:
            userAgent = self.userAgentInstance.random(browser=browser)
            self.customLogPipe(f"Using random user-agent: {userAgent} (Default)")
        self.customLogPipe(f"Final User-Agent: {str(json.dumps({
            "browser":browser,
            "user-agent":userAgent},indent=2))}", level='d')
        return browser, userAgent

    def _handle_cookie_injection(self, args):
        """Loads and injects cookies if specified."""
        if not args.cookies_load:
            return
        try:
            with open(args.cookies_load, 'rb') as f:
                cookies = pickle.load(f)
                for cookie in cookies:
                    self.driverInstance.add_cookie(cookie)
            self.customLogPipe(f"Loaded and injected cookies from {args.cookies_load}")
            self.driverInstance.refresh()
        except Exception as e:
            self.customLogPipe(f"Failed to load or inject cookies: {e}", level=3)

    def _handle_x_operations(self, args):
        """Handles all X/Twitter related command-line operations."""
        if args.x_login:
            user = args.x_login[0]
            passwd = args.x_login[1] if len(args.x_login) > 1 else None
            code2fa = args.x_login[2] if len(args.x_login) > 2 else None
            if not passwd:
                from getpass import getpass
                passwd = getpass(f"Enter password for {user}: ")
            self.xInteractInstance.login(user, passwd, code2fa)
        
        if args.x_post:
            self.xInteractInstance.postMessage(args.x_post, args.x_post_media)
        
        if args.x_search:
            self.xInteractInstance.searchPosts(args.x_search, args.x_search_limit, not args.x_no_replies)
            if args.x_export:
                self.xInteractInstance.exportResults(args.x_export, format=Path(args.x_export).suffix[1:])

    def _handle_ddg_operations(self, args):
        """Handles all DuckDuckGo related command-line operations."""
        if args.ddg_search:
            self.duckInteractInstance.search(args.ddg_search, args.ddg_search_pages)
        if args.ddg_chat:
            self.duckInteractInstance.duckChat(args.ddg_chat, model=args.ddg_chat_model)
        if args.ddg_export and (args.ddg_search or args.ddg_chat):
            self.duckInteractInstance.exportResults(args.ddg_export, format=Path(args.ddg_export).suffix[1:])

    def _execBrowserOps(self, args, browser, userAgent):
        """Handles operations that require an active browser session."""
        # Determine if any browser-dependent action is requested
        browser_action_required = any([
            args.url, args.console, args.x_login, args.x_post, 
            args.x_search, args.ddg_search, args.ddg_chat])

        if args.wait_for_close and args.headless:
            self.customLogPipe("Cannot use --wait-for-close with --headless mode. This would cause an indefinite hang.", level=3)
            sys.exit(1)

        if not browser_action_required: return
        self.customLogPipe("Starting browser for operation...")
        self.browserInstance.start(
            browser=browser,
            headless=args.headless,
            stealth=not args.no_stealth,
            proxy=args.proxy,
            userAgent=userAgent,
            windowSize=args.window_size)
        
        # --- Initial Browser Setup ---
        if args.url:
            self.customLogPipe(f"Navigating to {args.url}")
            self.browserInstance.navigateTo(args.url)
        
        self._handle_cookie_injection(args)

        # --- Main Operations ---
        self._handle_x_operations(args)
        self._handle_ddg_operations(args)

        # --- Interactive Console (runs last) ---
        if args.console:
            console = self.InlineConsole(self)
            console.start()

    def _execBrowserPostOps(self, args):
        """Handles cleanup and final operations after browser tasks are complete."""
        # --- Post-Browser Operations ---
        if self.driverInstance:
            # Save cookies if requested
            if args.cookies_save:
                try:
                    with open(args.cookies_save, 'wb') as f:
                        pickle.dump(self.driverInstance.get_cookies(), f)
                    self.customLogPipe(f"Saved cookies to {args.cookies_save}")
                except Exception as e:
                    self.customLogPipe(f"Failed to save cookies: {e}", level=3)
            # Decide whether to close the browser
            if args.wait_for_close:
                self.customLogPipe("Browser session will remain open until manually closed by the user...")
                try:
                    # This loop will run as long as the browser is open.
                    # Accessing window_handles will raise an exception when the browser is closed.
                    while self.driverInstance.window_handles:
                        time.sleep(1)
                except Exception:
                    self.customLogPipe("Browser closed by user. Exiting.")
                finally:
                    self.browserInstance.stop()
            elif not args.keep_open:
                self.customLogPipe("Closing browser session...")
                self.browserInstance.stop()
            else: # This handles --keep-open
                self.customLogPipe("Browser session will remain open as requested by --keep-open.")

    def _raiseBanner(self):
        """"""
        colorama.init()
        banner = [
            '╔══════════════╦════════════════╦══════════════╗', 
            '╠{╳╳╳╳╳╳╳╳╳╳╳╳}╣   𝐀 𝐍 𝐃 𝐑 𝐀 𝐒  ╠{╳╳╳╳╳╳╳╳╳╳╳╳}╣', 
            '╠══════════════╩════════════════╩══════════════╣', 
            '║ ╭─┬─╮╭─────────┬──────────┬──────────┬─────╮ ║', 
            '║ ├ R ┼├{EMULATE}┼{IDENTIFY}┼{VALIDATE}┼{PWN}│ ║', 
            '║ │ O │╰─────────┼──────────┴──────────┼─────╯ ║', 
            '║ │ O │╭──────┬──┴─┬───────┬──────┬────┼─────╮ ║', 
            '║ ├ T ┼┼{PHISH│POST│SCRAPE┌┘INFECT│LEAK│ROOT}│ ║', 
            '║ ╰┬┼─╯╰──────┴────┴──────┼┬──────┴────┼─────╯ ║', 
            '║  ↕╰→───→───→───→───→───→┼├{INTERCEPT}┼╮  .   ║', 
            '║  ╰↔──↔───↔───↔───↔───↔─╮↓╰───────────╯↓  ┊   ║', 
            '║         ┌─────┐        ╰↔───────┬─────╯  ┆   ║', 
            '║  ┌──────┼{WAF}┼──────┐          ↕ ┌────┬─┴──┐║', 
            '║  │{BOTIDENTIFICATION}├───{┄}───┤┆ ├{GIB┼SON}┤║', 
            '║  └┬──────────────────┘╭↔───────↔╯ └────┬────┘║', 
            '║  ┌┼┬──↔──────↔─────┬─↔┘  ┌─┬─────┬─────┴──┐  ║', 
            '║  │W├───→──────→───┤┆├────┼C┼{SQL}┼{INJECT}┴┐ ║', 
            '║  │W│  ┌──────┐ ┌───┴───┐ ├M┼{API}┼{EXPLOIT}┤ ║', 
            '║  │W├─↔┼{PROD}┼←┼{ADMIN}┼─┼S┼{LFI}┼{PERSIST}┤ ║', 
            '║  └┴┘  └──────┘ └───────┘ └─┴─────┴─────────┘ ║', 
            '╠════════════════════╦╗  ╔╦════════════════════╣', 
            '║  "𝐇 𝐎 𝐌 𝐈 𝐂 𝐈 𝐃 𝐀" ║╠0E╣║ "𝐁 𝐄 𝐋 𝐋 𝐀 𝐓 𝐎 𝐑"  ║', 
            '╚════════════════════╩╝  ╚╩════════════════════╝']
        bannerStr = "\n".join(banner)
        bannerStr = f"{colorama.Style.BRIGHT}{bannerStr}"
        for i in ["║","╚","═","╝","╔","╗","╣","╠","╦","╩","{","}"]: bannerStr = bannerStr.replace(i,f"{colorama.Fore.CYAN}{colorama.Style.DIM}{i}{colorama.Style.RESET_ALL}{colorama.Style.BRIGHT}")
        for i in ["𝐇 𝐎 𝐌 𝐈 𝐂 𝐈 𝐃 𝐀","𝐁 𝐄 𝐋 𝐋 𝐀 𝐓 𝐎 𝐑","𝐀 𝐍 𝐃 𝐑 𝐀 𝐒","╳"]: bannerStr = bannerStr.replace(i,f"{colorama.Fore.LIGHTRED_EX}{i}{colorama.Fore.RESET}")
        for i in ["PROD","ADMIN","SQL","INJECT","API","EXPLOIT","GIBSON","PERSIST","LFI","GIB","SON"]: bannerStr = bannerStr.replace(i,f"{colorama.Fore.LIGHTYELLOW_EX}{i}{colorama.Fore.RESET}")
        for i in ["╰","┘","┴","┤","│","├","┬","┼","├","┬","╮","─","╭","┌","┐","└","╯","┆","┊","."]: bannerStr = bannerStr.replace(i,f"{colorama.Fore.BLUE}{i}{colorama.Fore.RESET}")
        for i in ["WAF","BOTIDENTIFICATION"]: bannerStr = bannerStr.replace(i,f"{colorama.Fore.LIGHTRED_EX}{i}{colorama.Fore.RESET}")
        for i in ["EMULATE","IDENTIFY","VALIDATE","PWN","PHISH","POST","INFECT","LEAK","ROOT","SCRAPE"]: bannerStr = bannerStr.replace(i,f"{colorama.Fore.LIGHTMAGENTA_EX}{i}{colorama.Fore.RESET}") 
        bannerStr = bannerStr.replace("INTERCEPT",f"{colorama.Fore.LIGHTBLUE_EX}INTERCEPT{colorama.Fore.RESET}")
        bannerStr = bannerStr.replace("0E",f"{colorama.Fore.LIGHTGREEN_EX}0E{colorama.Fore.RESET}")
        # for i in []:bannerStr=bannerStr
        bannerStr += colorama.Style.RESET_ALL
        print(str(bannerStr))
    
    def run(self):
        """Main execution flow for Andras."""
        args = self.args
        browser, userAgent = self._execBrowserPreOps(args)
        self._execBrowserOps(args, browser, userAgent)
        self._execBrowserPostOps(args)
        # List cache if requested
        if args.list_cache:
            self.customLogPipe("Listing cached files...")
            cache_dir = Path(self.base)
            if cache_dir.exists():
                cached_files = list(cache_dir.glob('*.json'))
                if cached_files:
                    for idx, cache_file in enumerate(cached_files):
                        print(f"({idx}) - {cache_file.name}")
                else: self.customLogPipe("No cached files found.", level=1)
            else: self.customLogPipe("Cache directory does not exist.", level=1)
        # Cache clearing
        if args.clear_cache:
            self.customLogPipe("Clearing cache...")
            if os.path.exists(self.base):
                shutil.rmtree(self.base)
                Path(self.base).mkdir(parents=True, exist_ok=True)
                self.customLogPipe("Cache cleared successfully.")
        # Cookie clearing
        if args.clear_cookies:
            self.customLogPipe("Clearing cookies...")
            cookies_file = Path(self.base) / 'cookies.pkl'
            if cookies_file.exists():
                cookies_file.unlink()
                self.customLogPipe("Cookies cleared successfully.")
            else:
                self.customLogPipe("No cookies file found to clear.", level=1)
        self.customLogPipe("Andras run finished.")


if __name__ == "__main__":
    AI = Andras(app=True)
    AI.run()
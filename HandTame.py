#!/usr/bin/python3
import logging
import requests
import sys
import os
import time
import base64
from dotenv import load_dotenv
from googlesearch import search
import socket
import dns.resolver
import re
import nmap
import subprocess
import os
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import colorama
from colorama import Fore, Back, Style, init
import csv


load_dotenv()
def load_config_from_env():
    return {
        "google_api_key": os.getenv("GOOGLE_API_KEY"),
        "urlscan_api_key": os.getenv("URLSCAN_API_KEY"),
        "vt_api_key": os.getenv("VT_API_KEY"),
        "otx_api_key": os.getenv("OTX_API_KEY"),
        "builtwith_api_key": os.getenv("BUILTWITH_API_KEY"),
        "whoisjson_api_key": os.getenv("WHOISJSON_API_KEY"),
        "discord_webhook": os.getenv("DISCORD_WEBHOOK"),
        "telegram_bot_token": os.getenv("TELEGRAM_BOT_TOKEN"),
        "telegram_chat_id": os.getenv("TELEGRAM_CHAT_ID")
    }

# Initialize colorama
init(autoreset=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

class PassiveRecon:
    def __init__(self, target: str):
        self.target = target
        self.results = {}
        config = load_config_from_env()
        self.google_api_key = config.get("google_api_key")
        self.urlscan_api_key = config.get("urlscan_api_key")
        self.vt_api_key = config.get("vt_api_key")
        self.whoisjson_api_key = config.get("whoisjson_api_key")
        self.otx_api_key = config.get("otx_api_key")
        self.bultiwith_api_key = config.get("bultiwith_api_key ")
    
    """Malware detection"""
    def malicious_link_checker(self):
        # 1. URLhaus
        try:
            resp = requests.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                json={"url": self.target},
                timeout=30
            )
            if resp.json().get("query_status") == "ok":
                logger.warning(f"Malicious detected by URLhaus: {self.target}")
                sys.exit(1)
        except Exception as e:
            logger.error(f"Error in malicious_link_checker with URLhaus: {e}")
        
        # 2. AlienVault OTX
        try:
            resp = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/url/{self.target}/general",
                timeout=30
            )
            if resp.json().get("pulse_info", {}).get("pulses"):
                logger.warning(f"Malicious detected by AlienVault OTX: {self.target}")
                sys.exit(1)
        except Exception as e:
            logger.error(f"Error in malicious_link_checker with AlienVault OTX: {e}")
        
        # 3. Google Safe Browsing
        if self.google_api_key:
            try:
                payload = {
                    "client": {"clientId": "recon-tool", "clientVersion": "1.0.0"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": self.target}]
                    }
                }
                resp = requests.post(
                    f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.google_api_key}",
                    json=payload,
                    timeout=30
                )
                if "matches" in resp.json():
                    logger.warning(f"Malicious detected by Google Safe Browsing: {self.target}")
                    sys.exit(1)
            except Exception as e:
                logger.error(f"Error in malicious_link_checker with Google Safe Browsing: {e}")
        
        # 4. urlscan.io
        if self.urlscan_api_key:
            try:
                resp = requests.post(
                    "https://urlscan.io/api/v1/scan/",
                    json={"url": self.target, "visibility": "public"},
                    headers={"API-Key": self.urlscan_api_key},
                    timeout=30
                )
                uuid = resp.json().get("uuid")
                if uuid:
                    for _ in range(6):
                        time.sleep(10)
                        resp = requests.get(f"https://urlscan.io/api/v1/result/{uuid}/", timeout=30)
                        if resp.status_code == 200:
                            if resp.json().get("verdicts", {}).get("overall", {}).get("malicious"):
                                logger.warning(f"Malicious detected by urlscan.io: {self.target}")
                                sys.exit(1)
                            break
            except Exception as e:
                logger.error(f"Error in malicious_link_checker with urlscan.io: {e}")
        
        # 5. VirusTotal
        if self.vt_api_key:
            try:
                url_id = base64.urlsafe_b64encode(self.target.encode()).decode().strip("=")
                resp = requests.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers={"x-apikey": self.vt_api_key},
                    timeout=30
                )
                if resp.status_code == 200:
                    stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    if stats.get("malicious", 0) > 0:
                        logger.warning(f"Malicious detected by VirusTotal: {self.target}")
                        sys.exit(1)
            except Exception as e:
                logger.error(f"Error in malicious_link_checker with VirusTotal: {e}")
        
        return {"malicious": False, "source": None}
    
    """OSINT(Google dorking)"""
    def dork(self):
        dork_list = [
            # Admin panels and login pages
            f"inurl:admin site:{self.target}",
            f"inurl:login site:{self.target}",
            f"inurl:wp-admin site:{self.target}",
            f"inurl:cpanel site:{self.target}",
            f"intitle:\"admin panel\" site:{self.target}",
            f"intitle:\"login\" site:{self.target}",
            # Sensitive files and configs
            f"filetype:env \"DB_PASSWORD\" site:{self.target}",
            f"filetype:sql \"password\" site:{self.target}",
            f"filetype:conf \"root\" site:{self.target}",
            f"filetype:log \"password\" site:{self.target}",
            f"filetype:ini \"password\" site:{self.target}",
            f"filetype:json \"api_key\" site:{self.target}",
            # Open directories
            f"intitle:\"index of\" \"parent directory\" site:{self.target}",
            f"intitle:\"Index of /\" site:{self.target}",
            f"intitle:\"directory listing\" site:{self.target}",
            # Debug and error info
            f"intext:\"SQL syntax\" intext:\"error\" site:{self.target}",
            f"intext:\"Warning\" intext:\"mysql\" site:{self.target}",
            f"intext:\"debug\" intext:\"password\" site:{self.target}",
            # Backup and archive files
            f"filetype:bak site:{self.target}",
            f"filetype:backup site:{self.target}",
            f"filetype:old site:{self.target}",
            f"filetype:sql site:{self.target}",
            # APIs and services
            f"inurl:/api/ site:{self.target}",
            f"inurl:/swagger site:{self.target}",
            f"inurl:/docs site:{self.target}",
            # Technology detection
            f"\"X-Powered-By\" site:{self.target}",
            f"\"Server:\" site:{self.target}",
            f"\"wp-content\" site:{self.target}",
            f"\"laravel\" site:{self.target}"
        ]
        
        all_dork_results = []

        for q in dork_list:
            try:
                for url in search(q, num_results=10, advanced=True, timeout=5):
                    all_dork_results.append(url)
            except Exception as e:
                logger.error(f"Error in dork for query '{q}': {e}")
            continue
        self.results["dork"] = all_dork_results
    
    """Subdomain detection"""
    def passive_subdomain_finder(self):
        all_subdomains = set()
        
        # crt.sh
        try:
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            response = requests.get(url, timeout=30)
            data = response.json()
            
            for item in data:
                name = item.get('name_value', '')
                if name:
                    for sub in name.split('\n'):
                        sub = sub.strip()
                        if sub.endswith(self.target):
                            all_subdomains.add(sub)
        except Exception as e:
            logger.error(f"Error in passive_subdomain_finder with crt.sh: {e}")
        
        # AlienVault OTX
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.target}/passive_dns"
            response = requests.get(url, timeout=30)
            data = response.json()
            
            for item in data.get('passive_dns', []):
                hostname = item.get('hostname', '')
                if hostname and hostname.endswith(self.target):
                    all_subdomains.add(hostname)
        except Exception as e:
            logger.error(f"Error in passive_subdomain_finder with AlienVault OTX: {e}")
        
        # WhoisJSON 
        try:
            url = f"https://whoisjson.com/api/v1/subdomains?domain={self.target}"
            headers = {"Authorization": f"Token {self.whoisjson_api_key}"}
            response = requests.get(url, headers=headers, timeout=30)
            data = response.json()
        
            for sub in data.get('subdomains', []):
                full_sub = f"{sub}.{self.target}"
                all_subdomains.add(full_sub)
        except Exception as e:
            logger.error(f"Error in passive_subdomain_finder with WhoisJSON: {e}")
        
        # VirusTotal
        if hasattr(self, 'vt_api_key') and self.vt_api_key:
            try:
                url = f"https://www.virustotal.com/api/v3/domains/{self.target}"
                headers = {"x-apikey": self.vt_api_key}
                response = requests.get(url, headers=headers, timeout=30)
                data = response.json()
                
                for sub in data.get('data', {}).get('attributes', {}).get('subdomains', []):
                    all_subdomains.add(sub)
            except Exception as e:
                logger.error(f"Error in passive_subdomain_finder with VirusTotal: {e}")
        
        # urlscan.io
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{self.target}"
            response = requests.get(url, timeout=30)
            data = response.json()
            
            for result in data.get('results', []):
                page_domain = result.get('page', {}).get('domain', '')
                if page_domain and page_domain.endswith(self.target):
                    all_subdomains.add(page_domain)
        except Exception as e:
            logger.error(f"Error in passive_subdomain_finder with urlscan.io: {e}")
        
        # Wayback Machine
        try:
            url = f"https://web.archive.org/cdx/search/cdx?url=*.{self.target}/*&output=json&fl=original"
            response = requests.get(url, timeout=60)
            data = response.json()
            
            for item in data[1:]:
                url_str = item[0]
                if self.target in url_str:
                    parts = url_str.split('/')[2] if len(url_str.split('/')) > 2 else ''
                    if parts and parts.endswith(self.target):
                        all_subdomains.add(parts)
        except Exception as e:
            logger.error(f"Error in passive_subdomain_finder with Wayback Machine: {e}")
        
        self.results["all_subdomains"] = list(all_subdomains)
    
    """Technology detection"""
    def passive_technology_detection(self):
        all_tech = {}
        
        # 1. BuiltWith API (need API key)
        if hasattr(self, 'builtwith_api_key') and self.builtwith_api_key:
            try:
                url = f"https://api.builtwith.com/free1/api.json?KEY={self.builtwith_api_key}&LOOKUP={self.target}"
                response = requests.get(url, timeout=30)
                data = response.json()
                
                for tech in data.get('groups', []):
                    for item in tech.get('technologies', []):
                        name = item.get('name')
                        if name:
                            all_tech[name] = item.get('categories', [])
            except Exception as e:
                logger.error(f"Error in BuiltWith API: {e}")
        
        # 2. Wappalyzer via crawl.dev (public endpoint)
        try:
            url = f"https://crawl.dev/api/wappalyzer?url=https://{self.target}"
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                all_tech['wappalyzer'] = data.get('technologies', {})
        except Exception as e:
            logger.error(f"Error in Wappalyzer API: {e}")
        
        # 3. WhatWeb via CertSpotter (SSL certificates)
        try:
            url = f"https://api.certspotter.com/v1/issuances?domain={self.target}&include_subdomains=true"
            response = requests.get(url, timeout=30)
            data = response.json()
            
            for cert in data:
                if 'common_name' in cert:
                    cn = cert['common_name']
                    if 'nginx' in cn.lower():
                        all_tech['server'] = 'nginx'
                    elif 'apache' in cn.lower():
                        all_tech['server'] = 'apache'
                    elif 'cloudflare' in cn.lower():
                        all_tech['cdn'] = 'Cloudflare'
        except Exception as e:
            logger.error(f"Error in WhatWeb API: {e}")
        
        # 4. DNS TXT records for technology hints
        try:
            answers = dns.resolver.resolve(self.target, 'TXT')
            for answer in answers:
                txt = str(answer).lower()
                if 'google-site-verification' in txt:
                    all_tech['google_verified'] = True
                if 'facebook-domain-verification' in txt:
                    all_tech['facebook_verified'] = True
        except Exception as e:
            logger.error(f"Error in DNS TXT records: {e}")
        
        self.results["passive_technology"] = all_tech
    
    """Archive detection"""
    def archive_detection(self):
        all_archives = []
        
        try:
            url = f"https://web.archive.org/cdx/search/cdx?url={self.target}/*&output=json&fl=original,timestamp,statuscode"
            response = requests.get(url, timeout=30)
            data = response.json()

            if response.status_code != 200:
                logger.error(f"Error in archive_detection with status code")
            
            for item in data[1:]:
                original_url = item[0]
                timestamp = item[1]
                statuscode = item[2] if len(item) > 2 else None

                if statuscode and statuscode != '200':
                    continue


                all_archives.append({
                     "url": original_url,
                     "timestamp": timestamp,
                     "status": statuscode
                 })
                
        except Exception as e:
            logger.error(f"Error in archive_detection: {e}")
        
        self.results["all_archives"] = all_archives

    
    """Endpoint discovery"""
    def passive_endpoint_discovery(self):
        all_endpoints = set()
        
        # 1. Get URLs from Wayback Machine (already in archive_detection)
        archive_urls = self.results.get("all_archives", [])
        
        # 2. Get URLs from AlienVault OTX
        if hasattr(self, 'otx_api_key') and self.otx_api_key:
            try:
                url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.target}/url_list"
                headers = {"X-OTX-API-KEY": self.otx_api_key}
                response = requests.get(url, headers=headers, timeout=30)
                data = response.json()
                
                for item in data.get('url_list', []):
                    endpoint = item.get('url', '')
                    if endpoint:
                        all_endpoints.add(endpoint)
            except Exception as e:
                logger.error(f"Error in BuiltWith AlienVault OTX API: {e}")
        
        # 3. Get URLs from URLScan.io
        if hasattr(self, 'urlscan_api_key') and self.urlscan_api_key:
            try:
                url = f"https://urlscan.io/api/v1/search/?q=domain:{self.target}"
                response = requests.get(url, timeout=30)
                data = response.json()
                
                for result in data.get('results', []):
                    task_url = result.get('task', {}).get('url', '')
                    if task_url:
                        all_endpoints.add(task_url)
            except Exception as e:
                logger.error(f"Error in BuiltWith AlienVault OTX API: {e}")
        
        # 4. Extract endpoints from URLs (parse path only)
        new_paths = set()
        for full_url in all_endpoints:
            if self.target in full_url:
                parts = full_url.split('/')
                if len(parts) > 3:
                    path = '/' + '/'.join(parts[3:])
                    if len(path) > 1:
                        new_paths.add(path)
    
        all_endpoints.update(new_paths)
        self.results["passive_endpoints"] = list(all_endpoints)
        self.results["endpoints"] = list(all_endpoints)
    
    """Orgin IP detection"""
    def origin_ip_detection(self):
        ips = set()
        
        # Get A records
        try:
            answers = dns.resolver.resolve(self.target, 'A')
            for answer in answers:
                ips.add(str(answer))
        except Exception as e:
            logger.error(f"Error in origin_ip_detection with A records: {e}")
        
        # Get MX records
        try:
            answers = dns.resolver.resolve(self.target, 'MX')
            for answer in answers:
                mx_host = str(answer.exchange).rstrip('.')
                try:
                    mx_ips = dns.resolver.resolve(mx_host, 'A')
                    for ip in mx_ips:
                        ips.add(str(ip))
                except Exception as e:
                    logger.error(f"Error in origin_ip_detection with MX records: {e}")
        except Exception as e:
            logger.error(f"Error in origin_ip_detection with MX records: {e}")
        
        # Check CDN
        cdn = set()
        origin_ip = set()
        
        for ip in ips:
            is_cdn = False
            # Cloudflare ranges
            if ip.startswith('104.16.') or ip.startswith('104.17.') or ip.startswith('172.64.'):
                cdn.add("Cloudflare")
                is_cdn = True
            # Cloudfront ranges
            elif ip.startswith('13.32.') or ip.startswith('13.33.') or ip.startswith('13.34.'):
                cdn.add("Cloudfront")
                is_cdn = True
            # Fastly ranges
            elif ip.startswith('151.101.'):
                cdn.add("Fastly")
                is_cdn = True
            else:
                if is_cdn == False:
                    origin_ip.add(ip)
        
        self.results["origin_ip"] = {
        "ip": origin_ip,
        "cdn": cdn,
        "all_ips": list(ips)
         }
        
        return self.results


class ActiveRecon:
    def __init__(self, target: str, os_detection: bool = True, nse: bool = True, custom_nse: bool = False, ports: str = "-", max_workers: int = 10):
        self.nm = nmap.PortScanner()
        self.wordlist_path = None
        self.target = target
        self.os_detection = os_detection
        self.nse = nse
        self.custom_nse = custom_nse
        self.ports = ports
        self.max_workers = max_workers
        self.results = {}
    
    def nmap_scaning(self):
        results = {"os_detection": {}, "nse_vuln": {}, "custom_nse_vuln": {}}
        
        if self.os_detection:
            try:
                print(f"[*] Nmap scanning ports: {self.ports}")
                self.nm.scan(self.target, arguments=f"-sV -O -p{self.ports}")
                for host in self.nm.all_hosts:
                    host_data = {
                        "hostname": self.nm[host].hostname(),
                        "state": self.nm[host].state(),
                        "os": self.nm[host].get('osmatch', [{}])[0].get('name', 'Unknown'),
                        "ports": []
                    }
                    for proto in self.nm[host].all_protocols():
                        for port in self.nm[host][proto].keys():
                            port_info = {
                                "port": port,
                                "protocol": proto,
                                "state": self.nm[host][proto][port]['state'],
                                "service": self.nm[host][proto][port].get('name', 'unknown'),
                                "version": self.nm[host][proto][port].get('version', '')
                            }
                            host_data["ports"].append(port_info)
                    results["os_detection"][host] = host_data
                    logger.info(f"Host {host}: {len(host_data['ports'])} ports found")
            except Exception as e:
                logger.error(f"Error in OS detection: {e}")
        
        if self.nse:
            try:
                self.nm.scan(self.target, arguments=f"--script vuln -sV -p{self.ports}")
                nse_results = []
                for host in self.nm.all_hosts:
                    for proto in self.nm[host].all_protocols():
                        for port in self.nm[host][proto].keys():
                            script_output = self.nm[host][proto][port].get('script', {})
                            if script_output:
                                nse_results.append({
                                    "host": host, "port": port, "protocol": proto, "vulnerabilities": script_output
                                })
                                logger.warning(f"Potential vulnerability on {host}:{port}")
                results["nse_vuln"]["findings"] = nse_results
            except Exception as e:
                logger.error(f"Error in NSE scan: {e}")
        
        if self.custom_nse:
            try:
                with open("custom_nse_script.lua", "r") as f:
                    lua_script = f.read()
                self.nm.scan(self.target, arguments=f"--script {lua_script} -p{self.ports}")
                custom_results = []
                for host in self.nm.all_hosts:
                    for proto in self.nm[host].all_protocols():
                        for port in self.nm[host][proto].keys():
                            script_output = self.nm[host][proto][port].get('script', {})
                            if script_output:
                                custom_results.append({
                                    "host": host, "port": port, "protocol": proto, "vulnerabilities": script_output
                                })
                                logger.warning(f"Custom NSE found on {host}:{port}")
                results["custom_nse_vuln"]["findings"] = custom_results
            except FileNotFoundError:
                logger.error("custom_nse_script.lua not found")
            except Exception as e:
                logger.error(f"Error in custom NSE scan: {e}")
        
        self.results["nmap_results"] = results
    
    def directory_detection(self):    
        tools_available = {"dirb": False, "gobuster": False}
        
        try:
            subprocess.run(["dirb", "-h"], capture_output=True, timeout=5)
            tools_available["dirb"] = True
        except:
            logger.warning("dirb not found. Install with: apt install dirb")
        
        try:
            subprocess.run(["gobuster", "--help"], capture_output=True, timeout=5)
            tools_available["gobuster"] = True
        except:
            logger.warning("gobuster not found. Install with: apt install gobuster")
        
        if not any(tools_available.values()):
            logger.error("No directory busting tools available")
            return
        
        wordlist_path = self.wordlist_path or "/usr/share/wordlists/dirb/common.txt"
        
        if not os.path.exists(wordlist_path):
            logger.info(f"Downloading wordlist to {wordlist_path}")
            try:
                os.makedirs(os.path.dirname(wordlist_path), exist_ok=True)
                url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
                response = requests.get(url, timeout=30)
                response.raise_for_status()
                with open(wordlist_path, "w") as f:
                    f.write(response.text)
                logger.info("Wordlist downloaded successfully")
            except Exception as e:
                logger.error(f"Failed to download wordlist: {e}")
                return
        
        def calculate_priority(path):
            score = 0
            path_lower = path.lower()
            high_patterns = [".php", ".asp", ".aspx", ".jsp", ".do", "/admin", "/login", 
                            "/wp-admin", "/dashboard", "password", "forgot", "reset", 
                            "config", ".env", ".sql", ".bak", ".old", ".backup"]
            for pattern in high_patterns:
                if pattern in path_lower:
                    score += 50
            medium_patterns = ["/api", "/v1", "/v2", "/upload", "/download", "/files", 
                              "/data", "/ajax", "/includes", "/modules", "/components"]
            for pattern in medium_patterns:
                if pattern in path_lower:
                    score += 20
            return score
        
        all_results = []
        
        if tools_available["dirb"]:
            try:
                logger.info(f"Running dirb on {self.target}")
                cmd = ["dirb", f"https://{self.target}", wordlist_path, "-r", "-z", "10", "-S"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                for line in result.stdout.split('\n'):
                    if '+' in line and ('http' in line or 'CODE:' in line):
                        parts = line.split()
                        url = None
                        status = 0
                        for part in parts:
                            if part.startswith('http'):
                                url = part
                            elif part.isdigit():
                                status = int(part)
                        if url and status:
                            path = url.replace(f"https://{self.target}", "")
                            all_results.append({
                                "tool": "dirb", "path": path or "/", "status": status,
                                "priority": calculate_priority(path)
                            })
            except Exception as e:
                logger.error(f"Error running dirb: {e}")
        
        if tools_available["gobuster"]:
            try:
                logger.info(f"Running gobuster on {self.target}")
                cmd = ["gobuster", "dir", "-u", f"https://{self.target}", "-w", wordlist_path, 
                       "-t", "30", "-q", "-b", "404"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                for line in result.stdout.split('\n'):
                    if 'Status:' in line:
                        parts = line.split()
                        url = None
                        status = 0
                        for part in parts:
                            if part.startswith('http'):
                                url = part
                            elif part.isdigit():
                                status = int(part)
                        if url and status:
                            path = url.replace(f"https://{self.target}", "")
                            all_results.append({
                                "tool": "gobuster", "path": path or "/", "status": status,
                                "priority": calculate_priority(path)
                            })
            except Exception as e:
                logger.error(f"Error running gobuster: {e}")
        
        unique = {}
        for item in all_results:
            path = item["path"]
            if path not in unique or item["priority"] > unique[path]["priority"]:
                unique[path] = item
        
        final_results = sorted(unique.values(), key=lambda x: x["priority"], reverse=True)
        logger.info(f"Directory scan complete: {len(final_results)} directories found")
        for item in final_results[:10]:
            logger.info(f"  [{item['status']}] {item['path']} (priority: {item['priority']})")
        
        self.results["directories"] = final_results
    
    def active_subdomain_finder(self):        
        results = {
            "subfinder_passive": [], "subfinder_active": [], "chaos": [],
            "resolved": [], "all_subdomains": [], "unique_subdomains": [], "stats": {}
        }
        
        tools_status = {"subfinder": False, "chaos": False, "shuffledns": False, "puredns": False, "massdns": False}
        
        def check_tool(tool_name, install_cmd):
            try:
                subprocess.run([tool_name, "-h"], capture_output=True, timeout=5)
                return True
            except FileNotFoundError:
                logger.warning(f"{tool_name} not found. Installing...")
                try:
                    subprocess.run(install_cmd, shell=True, timeout=120)
                    logger.info(f"{tool_name} installed successfully")
                    return True
                except Exception as e:
                    logger.error(f"Failed to install {tool_name}: {e}")
                    return False
            except:
                return False
        
        install_commands = {
            "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "chaos": "go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest",
            "shuffledns": "go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest",
            "puredns": "go install -v github.com/d3mondev/puredns/v2@latest",
            "massdns": "sudo apt install massdns -y"
        }
        
        for tool in tools_status:
            tools_status[tool] = check_tool(tool, install_commands[tool])
        
        def run_subfinder_passive():
            subs = []
            try:
                cmd = ["subfinder", "-d", self.target, "-all", "-silent", "-oJ"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                for line in result.stdout.split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            subdomain = data.get('host', '')
                            if subdomain:
                                subs.append({"subdomain": subdomain, "tool": "subfinder"})
                        except:
                            pass
            except Exception as e:
                logger.error(f"Error in subfinder passive: {e}")
            return subs
        
        def run_subfinder_active():
            subs = []
            try:
                cmd = ["subfinder", "-d", self.target, "-recursive", "-silent", "-oJ"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                for line in result.stdout.split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            subdomain = data.get('host', '')
                            if subdomain:
                                subs.append({"subdomain": subdomain, "tool": "subfinder"})
                        except:
                            pass
            except Exception as e:
                logger.error(f"Error in subfinder active: {e}")
            return subs
        
        def run_chaos():
            subs = []
            if hasattr(self, 'chaos_api_key') and self.chaos_api_key:
                try:
                    cmd = ["chaos", "-d", self.target, "-silent", "-key", self.chaos_api_key]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                    for line in result.stdout.split('\n'):
                        if line.strip():
                            subs.append({"subdomain": line.strip(), "tool": "chaos"})
                except Exception as e:
                    logger.error(f"Error in chaos: {e}")
            return subs
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = []
            if tools_status["subfinder"]:
                futures.append(executor.submit(run_subfinder_passive))
                futures.append(executor.submit(run_subfinder_active))
            if tools_status["chaos"]:
                futures.append(executor.submit(run_chaos))
            
            all_results = []
            for future in as_completed(futures):
                all_results.extend(future.result())
        
        for item in all_results:
            if item['tool'] == 'subfinder':
                if len(str(item)) > 100:  
                    results["subfinder_active"].append(item)
                else:
                    results["subfinder_passive"].append(item)
            elif item['tool'] == 'chaos':
                results["chaos"].append(item)
        
        all_subs = set()
        for item in results["subfinder_passive"]:
            all_subs.add(item["subdomain"])
        for item in results["subfinder_active"]:
            all_subs.add(item["subdomain"])
        for item in results["chaos"]:
            all_subs.add(item["subdomain"])
        
        results["all_subdomains"] = list(all_subs)
        logger.info(f"Total unique subdomains collected: {len(all_subs)}")
        
        if all_subs and (tools_status["puredns"] or tools_status["massdns"]):
            temp_subs_file = f"/tmp/subdomains_{self.target.replace('.', '_')}.txt"
            with open(temp_subs_file, "w") as f:
                f.write("\n".join(all_subs))
            
            resolved_subs = set()
            
            if tools_status["puredns"]:
                try:
                    logger.info(f"Resolving with puredns")
                    cmd = ["puredns", "resolve", temp_subs_file, "-q", "-w", temp_subs_file + "_resolved.txt"]
                    subprocess.run(cmd, timeout=300)
                    if os.path.exists(temp_subs_file + "_resolved.txt"):
                        with open(temp_subs_file + "_resolved.txt", "r") as f:
                            for line in f:
                                parts = line.strip().split()
                                if len(parts) >= 2:
                                    resolved_subs.add(parts[0])
                except Exception as e:
                    logger.error(f"Error in puredns: {e}")
            
            if not resolved_subs and tools_status["massdns"]:
                try:
                    logger.info(f"Resolving with massdns")
                    cmd = ["massdns", "-t", "A", "-o", "S", "-w", temp_subs_file + "_massdns.txt", temp_subs_file]
                    subprocess.run(cmd, timeout=300)
                    if os.path.exists(temp_subs_file + "_massdns.txt"):
                        with open(temp_subs_file + "_massdns.txt", "r") as f:
                            for line in f:
                                if " A " in line:
                                    subdomain = line.split()[0].rstrip('.')
                                    resolved_subs.add(subdomain)
                except Exception as e:
                    logger.error(f"Error in massdns: {e}")
            
            for f in [temp_subs_file, temp_subs_file + "_resolved.txt", temp_subs_file + "_massdns.txt"]:
                if os.path.exists(f):
                    os.remove(f)
            
            for sub in resolved_subs:
                results["resolved"].append({"subdomain": sub, "status": "resolved"})
            logger.info(f"Resolved subdomains: {len(results['resolved'])}")
        
        def calculate_priority(subdomain):
            score = 0
            sub_lower = subdomain.lower()
            high_patterns = ["admin", "login", "dashboard", "api", "vpn", "mail", "database", "jenkins", "gitlab"]
            medium_patterns = ["www", "web", "app", "auth", "portal", "cdn", "static"]
            for pattern in high_patterns:
                if pattern in sub_lower:
                    score += 10
            for pattern in medium_patterns:
                if pattern in sub_lower:
                    score += 5
            return score
        
        all_combined = {}
        for sub in results["all_subdomains"]:
            priority = calculate_priority(sub)
            all_combined[sub] = {
                "subdomain": sub, "priority": priority,
                "resolved": sub in [r["subdomain"] for r in results["resolved"]]
            }
        
        sorted_subs = sorted(all_combined.values(), key=lambda x: (x["resolved"], x["priority"]), reverse=True)
        results["unique_subdomains"] = sorted_subs
        results["stats"]["total_found"] = len(all_subs)
        results["stats"]["resolved_count"] = len(results["resolved"])
        
        logger.info("=" * 50)
        logger.info(f"Subdomain enumeration completed for {self.target}")
        logger.info(f"  Total found: {results['stats']['total_found']}")
        logger.info(f"  Resolved: {results['stats']['resolved_count']}")
        logger.info("=" * 50)
        
        self.results["active_subdomains"] = results
    
    def active_technology_detection(self):
        all_tech = {}
        try:
            url = f"https://{self.target}"
            response = requests.get(url, timeout=30)
            headers = response.headers
            
            if headers.get('Server'):
                all_tech['server'] = headers.get('Server')
            if headers.get('X-Powered-By'):
                all_tech['powered_by'] = headers.get('X-Powered-By')
            
            for cookie in response.cookies:
                if 'wp' in cookie.name.lower():
                    all_tech['cms'] = 'WordPress'
                elif 'laravel' in cookie.name.lower():
                    all_tech['framework'] = 'Laravel'
            
            html = response.text.lower()
            if 'wp-content' in html:
                all_tech['cms'] = 'WordPress'
            elif 'laravel' in html:
                all_tech['framework'] = 'Laravel'
            elif 'react' in html or '_next' in html:
                all_tech['frontend'] = 'React/Next.js'
            elif 'vue' in html:
                all_tech['frontend'] = 'Vue.js'
        except Exception as e:
            logger.error(f"Error in technology_detection: {e}")
        
        self.results["technology"] = all_tech
    
    def active_endpoint_discovery(self):      
        all_endpoints = set()
        subdomains = self.results.get("active_subdomains", {}).get("all_subdomains", [])[:100]
        
        def scan_subdomain(sub):
            endpoints = set()
            try:
                url = f"https://{sub}"
                response = requests.get(url, timeout=30)
                html = response.text
                
                links = re.findall(r'href=["\'](/(?:[^"\']+))["\']', html)
                for link in links:
                    if link and not link.startswith('http') and len(link) > 1:
                        endpoints.add(link)
                
                forms = re.findall(r'action=["\']([^"\']+)["\']', html)
                for form in forms:
                    if form and not form.startswith('http') and len(form) > 1:
                        endpoints.add(form)
                
                js_files = re.findall(r'src=["\']([^"\']+\.js)["\']', html)
                for js_file in js_files:
                    if not js_file.startswith("http"):
                        js_file = f"https://{sub}{js_file}"
                    try:
                        js_response = requests.get(js_file, timeout=30)
                        endpoints_in_js = re.findall(r'["\'](/(?:[a-zA-Z0-9_\-/]+))["\']', js_response.text)
                        for ep in endpoints_in_js:
                            if len(ep) > 1 and ep not in ['/', '//']:
                                endpoints.add(ep)
                        time.sleep(0.1)
                    except:
                        pass
            except Exception as e:
                logger.error(f"Error scanning {sub}: {e}")
            return endpoints
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(scan_subdomain, sub): sub for sub in subdomains[:self.max_workers * 5]}
            
            for future in as_completed(futures):
                sub = futures[future]
                try:
                    endpoints = future.result()
                    all_endpoints.update(endpoints)
                    logger.debug(f"Found {len(endpoints)} endpoints on {sub}")
                except Exception as e:
                    logger.error(f"Failed to scan {sub}: {e}")
        
        self.results["endpoints"] = list(all_endpoints)
        return self.results
    


def main():
    banner = f"""
{Fore.CYAN}
                                                                                                                                          ░░                                        
                                                                                                                            ▒▒▓▓▓▓▓▓▒▒▓▓▓▓▒▒▓▓░░                                    
                                                                                                                        ░░▓▓▓▓▓▓▓▓████▓▓▓▓▒▒▒▒▓▓░░                                  
                                                                                                                      ▒▒▓▓▒▒▒▒▒▒▒▒▓▓██▓▓██▒▒▓▓▓▓▓▓                                  
                                                                                                                    ░░    ▒▒▒▒▒▒▒▒▒▒▓▓████▒▒▓▓▒▒▓▓▓▓                                
                                                                                                                      ░░▒▒▒▒▒▒▒▒▒▒▓▓██▒▒▒▒▒▒▒▒▒▒▓▓▓▓░░                              
                                                                                                                              ░░▓▓████▒▒▒▒▓▓▓▓▒▒▓▓██▓▓                              
                                                                                                                                  ▓▓▓▓▓▓▒▒▒▒▒▒▓▓██████                              
                                                                                                                                  ░░▓▓▓▓▒▒░░▒▒▒▒▓▓████░░                            
                                                                                                                                    ▒▒▓▓▓▓░░▒▒▓▓▓▓████▓▓                            
                                                                                                                                    ▓▓▒▒▒▒░░▓▓▓▓████████░░                          
                                                                                                                                  ▒▒▓▓▒▒▒▒▒▒▒▒▓▓▓▓██▓▓████▒▒                        
                                                                                                                                  ▓▓▓▓▓▓▓▓▓▓▓▓▒▒▓▓▓▓▓▓████▓▓▓▓                      
                                                                                                    ░░░░░░░░                ▓▓████▓▓▓▓██▓▓██▓▓▓▓▓▓▓▓████████▓▓▒▒                    
                                                                                                ░░▒▒▒▒▓▓▓▓▓▓░░            ▓▓▓▓▓▓▒▒▒▒▓▓▓▓██████▓▓▒▒▒▒▓▓████▒▒▒▒▒▒░░                  
                                                                                              ░░▒▒▓▓▒▒▓▓▓▓▓▓▓▓            ░░▓▓▒▒▒▒▓▓▓▓██████▓▓██▓▓████████▒▒▓▓▓▓▓▓                  
                                                                                              ▒▒▒▒▒▒▒▒▓▓▒▒▒▒▓▓░░          ██▒▒▓▓▓▓██▓▓██████▓▓▓▓████████████████▓▓▒▒                
                                                                                            ░░▒▒▒▒████▓▓▓▓▓▓▓▓░░          ██▒▒████████████████████████████████████▓▓                
                                                                                          ▒▒▒▒▒▒▓▓▓▓▓▓▒▒▒▒▒▒▓▓▒▒          ▓▓▒▒▓▓████████████████████████████▓▓██▓▓▓▓                
                                                                                        ▒▒▓▓▓▓▓▓▓▓▓▓░░▒▒░░░░▒▒░░          ░░██▓▓██████████████████████████████████▓▓░░              
                                                                                      ▒▒▓▓████▓▓▓▓▓▓▒▒▒▒░░░░▒▒              ██▓▓▓▓██▒▒████████████████████████▓▓██▓▓▓▓              
                                                                                    ▓▓▓▓▓▓▓▓████████▓▓▓▓░░▒▒▒▒              ▓▓██▓▓▓▓▒▒██████████████▒▒▓▓██████▓▓████▓▓              
                                                                                ░░▒▒▓▓▓▓▓▓▓▓▓▓██████████▒▒▒▒▒▒                ████▓▓████▓▓██████████▓▓▓▓██▓▓████▓▓██▓▓▓▓            
                                                                              ▒▒▓▓▒▒▓▓▓▓▓▓▓▓▓▓██████████▓▓▓▓                  ▒▒██████▓▓▓▓▓▓████████▓▓██▓▓▓▓▓▓██████▓▓▓▓            
                                                                        ▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██████▓▓▒▒                    ▒▒▓▓██████▒▒████████████▓▓▓▓████████▓▓▓▓            
                                                                    ▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓                          ░░▒▒▓▓▓▓██████████████▓▓██████████▓▓            
                                                                ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██████▓▓▓▓▓▓▓▓▓▓▓▓▓▓                              ▓▓████▓▓██████▓▓████████████████░░          
                                                            ░░██▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██▓▓██▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓                                ▓▓██▓▓▓▓██▓▓██████▓▓██████████▒▒          
                                                          ▒▒▓▓██████▓▓▓▓▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██▓▓▓▓▓▓▓▓▓▓▓▓▓▓                                  ░░▓▓████▓▓██▓▓▓▓██████████▓▓▓▓          
                                                      ░░████▓▓████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒                                    ▓▓▓▓░░██████████▓▓██████████          
                                                    ▒▒██▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓                                      ▓▓▓▓░░▒▒████████▓▓██▓▓▒▒████          
                                                ░░████▓▓▓▓▓▓▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒                                      ▒▒▓▓    ▒▒██████▓▓████▓▓████▒▒        
                                              ▒▒▓▓██▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▓▓▓▓▓▓▒▒▓▓▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░                                      ▒▒▒▒      ██████▓▓██████████▓▓░░      
                                        ░░▓▓▓▓██▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▒▒▒▒                                        ▓▓        ▒▒██▒▒▒▒██████████▓▓▓▓▒▒    
                                    ░░▓▓▓▓████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▓▓▓▓▓▓▒▒▒▒▒▒▓▓▓▓▒▒▒▒▒▒▒▒                                      ▓▓        ░░▒▒▓▓▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
                                ░░▓▓▓▓██████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▓▓▓▓▓▓▒▒▒▒▒▒▓▓░░                                    ░░▒▒░░      ▓▓▒▒▓▓▓▓▓▓▓▓▓▓▒▒▒▒▓▓▓▓▓▓▓▓▒▒▒▒
                              ▒▒▓▓████████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▓▓▓▓▒▒▒▒▒▒▒▒▒▒░░                                      ▓▓▒▒░░▓▓▓▓▓▓▓▓▓▓▒▒▒▒▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓
                            ▓▓▓▓██████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▓▓▓▓▒▒▒▒▒▒▓▓░░                                        ░░▓▓▒▒▒▒▓▓▓▓▒▒▒▒▓▓▒▒▒▒▒▒▓▓▓▓▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓
                          ▒▒▓▓██████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▓▓▒▒▓▓▓▓▓▓▒▒▒▒▓▓                                          ░░▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒    
                        ▒▒▓▓██████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▓▓▓▓▓▓▓▓▓▓▓▓▒▒                                            ▒▒▓▓▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░██████████████▓▓    
                  ░░▒▒▒▒▓▓██████▓▓████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░                                              ░░▒▒▒▒▒▒▓▓▓▓▓▓▓▓░░          ▓▓██████████████    
                      ▒▒██▓▓████████▓▓██▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░                                                ▒▒▓▓▓▓▓▓▓▓▓▓▓▓                  ██████████████    
                        ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██████████▓▓▓▓▓▓▒▒                                              ▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓                    ▓▓▓▓██████████▒▒  
                      ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██▓▓▓▓▓▓▓▓██▓▓▓▓██████████████████▓▓▓▓▒▒                                            ░░▓▓▓▓▓▓▓▓▓▓▓▓▓▓██                        ████████████▒▒  
                    ▓▓████▓▓▓▓▓▓▓▓████▓▓▓▓▓▓██████▓▓▓▓██████████▓▓▓▓██▓▓▓▓▒▒                                            ▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓                            ▒▒▒▒░░██▓▓    
                ▒▒▓▓▒▒▓▓▓▓████▓▓▓▓██████████████▓▓▒▒  ░░░░  ▓▓██▓▓████▓▓▓▓                                          ░░▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░                                            
            ░░▒▒▒▒▓▓▓▓████▓▓████████████▓▓██▓▓▒▒            ████████▓▓▓▓                                          ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░                                                
        ░░▒▒▓▓▓▓▓▓██▓▓██▓▓████████▓▓██▓▓░░                ▓▓████▓▓▓▓▓▓▒▒                                      ░░▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░                                                  
    ░░▒▒▓▓▓▓▓▓▓▓▒▒▒▒▓▓▓▓████████████                    ░░████▒▒▒▒▓▓▓▓▒▒                                    ░░▓▓▓▓▓▓▓▓▒▒░░░░░░    ░░                                                
  ▓▓▓▓▓▓▒▒░░  ░░▒▒▓▓████████▓▓████                      ░░▓▓▓▓░░  ░░▒▒░░                                  ░░▒▒░░░░░░░░░░  ░░    ▒▒░░                                                
▒▒▒▒░░      ░░▓▓██▓▓▓▓████▓▓▓▓▓▓                          ▓▓██▒▒  ░░░░▒▒                                ░░░░▓▓▓▓▒▒▒▒▒▒░░░░  ▒▒  ▒▒▒▒                                                
          ░░▓▓██▓▓██████▓▓████                            ▒▒▓▓        ▒▒▓▓▒▒                          ░░▒▒░░  ░░▒▒▒▒▒▒░░    ░░░░░░                                                  
        ░░▓▓▓▓████████▓▓██▓▓                                ▓▓▒▒          ▓▓▓▓░░            ░░░░░░░░░░░░▒▒░░▒▒▒▒░░░░░░  ░░░░▒▒                                                      
      ▒▒▓▓████████▓▓▓▓██▓▓                                    ▓▓            ▒▒▓▓░░      ░░░░░░░░░░░░  ░░  ░░▒▒░░░░▒▒▒▒░░▒▒░░░░░░░░                                                  
    ▒▒▓▓▓▓████▓▓▓▓████░░                                      ▒▒▒▒              ▒▒▒▒  ░░░░▒▒░░▒▒░░░░░░░░  ░░▒▒░░░░░░░░      ░░░░▒▒                                                  
░░▓▓▓▓▓▓████▒▒▓▓██░░                                            ▓▓              ▒▒▒▒▒▒▒▒▒▒░░▒▒░░░░░░░░░░▒▒░░░░░░░░                                                                  
▓▓▓▓▓▓██▓▓▒▒██▒▒                                                ░░▓▓          ░░▒▒░░▒▒░░▓▓▒▒░░░░░░░░▒▒░░▒▒░░░░░░░░                                                                  
▓▓▒▒▓▓▒▒░░                                                        ▓▓▒▒      ▒▒▒▒▒▒▒▒░░▒▒▓▓░░░░░░░░▒▒░░░░░░░░░░                                                                      

{Style.RESET_ALL}   
"""
    print(banner)
    target = input(f"{Fore.CYAN}[?] {Fore.WHITE}Enter target domain: {Fore.YELLOW}").strip()
    if not target:
        print(f"{Fore.RED}[-] No target provided{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.CYAN}[+] Configuration (press Enter for default/no){Style.RESET_ALL}\n")
    
    # Output options
    show_terminal = input(f"{Fore.WHITE}Show full results in terminal? (y/N): {Fore.YELLOW}").strip().lower() == 'y'
    save_json = input(f"{Fore.WHITE}Save results to JSON file? (y/N): {Fore.YELLOW}").strip().lower() == 'y'
    
    # Output format options
    print(f"\n{Fore.CYAN}[+] Output formats:{Style.RESET_ALL}")
    output_html = input(f"{Fore.WHITE}Generate HTML report? (y/N): {Fore.YELLOW}").strip().lower() == 'y'
    output_csv = input(f"{Fore.WHITE}Generate CSV report? (y/N): {Fore.YELLOW}").strip().lower() == 'y'
    output_markdown = input(f"{Fore.WHITE}Generate Markdown report? (y/N): {Fore.YELLOW}").strip().lower() == 'y'
    
    # Notifications
    discord_webhook = input(f"{Fore.WHITE}Discord webhook URL (or press Enter): {Fore.YELLOW}").strip()
    tg_bot = input(f"{Fore.WHITE}Telegram bot token (or press Enter): {Fore.YELLOW}").strip()
    tg_chat = input(f"{Fore.WHITE}Telegram chat ID (or press Enter): {Fore.YELLOW}").strip()
    
    # Nmap options
    print(f"\n{Fore.CYAN}[+] Nmap options:{Style.RESET_ALL}\n")
    os_detection = input(f"{Fore.WHITE}Run OS detection (-O)? (Y/n): {Fore.YELLOW}").strip().lower() != 'n'
    
    ports = input(f"{Fore.WHITE}Ports to scan (e.g., 80,443,8080 or press Enter for all ports): {Fore.YELLOW}").strip()
    if not ports:
        ports = "-"
    
    nse_vuln = input(f"{Fore.WHITE}Run NSE vulnerability scan (--script vuln)? (y/N): {Fore.YELLOW}").strip().lower() == 'y'
    custom_nse = input(f"{Fore.WHITE}Use custom NSE script? (y/N): {Fore.YELLOW}").strip().lower() == 'y'
    
    # Directory busting
    print(f"\n{Fore.CYAN}[+] Directory busting:{Style.RESET_ALL}\n")
    use_dirb = input(f"{Fore.WHITE}Run dirb? (Y/n): {Fore.YELLOW}").strip().lower() != 'n'
    use_gobuster = input(f"{Fore.WHITE}Run gobuster? (Y/n): {Fore.YELLOW}").strip().lower() != 'n'
    wordlist_path = input(f"{Fore.WHITE}Wordlist path (press Enter for default): {Fore.YELLOW}").strip()
    
    # Subdomain tools
    print(f"\n{Fore.CYAN}[+] Subdomain enumeration:{Style.RESET_ALL}\n")
    use_subfinder = input(f"{Fore.WHITE}Run subfinder? (Y/n): {Fore.YELLOW}").strip().lower() != 'n'
    use_chaos = input(f"{Fore.WHITE}Run chaos (needs API key)? (y/N): {Fore.YELLOW}").strip().lower() == 'y'
    chaos_key = ""
    if use_chaos:
        chaos_key = input(f"{Fore.WHITE}Chaos API key: {Fore.YELLOW}").strip()
    
    print(f"\n{Fore.CYAN}[+] Threading Options:{Style.RESET_ALL}")
    max_workers = input(f"{Fore.WHITE}Max threads for scanning (default 10): {Fore.YELLOW}").strip()
    max_workers = int(max_workers) if max_workers.isdigit() else 10
    
    print(f"\n{Fore.GREEN}[+] Target: {Fore.YELLOW}{target}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Starting reconnaissance...{Style.RESET_ALL}\n")
    
    start_time = time.time()
    
    # ============================================================
    # Passive Recon
    # ============================================================
    if show_terminal:
        print(f"{Fore.CYAN}[*] Phase 1: Passive Reconnaissance{Style.RESET_ALL}")
    
    passive = PassiveRecon(target)
    if chaos_key:
        passive.chaos_api_key = chaos_key
    
    if show_terminal:
        print(f"  {Fore.GREEN}- Checking malware...{Style.RESET_ALL}", end=" ", flush=True)
    # passive.malicious_link_checker() 
    if show_terminal:
        print(f"{Fore.GREEN}done{Style.RESET_ALL}")
    
    if show_terminal:
        print(f"  {Fore.GREEN}- Running Google dorks...{Style.RESET_ALL}", end=" ", flush=True)
    passive.dork()
    if show_terminal:
        print(f"{Fore.GREEN}done{Style.RESET_ALL}")
    
    if show_terminal:
        print(f"  {Fore.GREEN}- Finding subdomains...{Style.RESET_ALL}", end=" ", flush=True)
    passive.passive_subdomain_finder()
    total_subs = len(passive.results.get('all_subdomains', []))
    if show_terminal:
        print(f"{Fore.GREEN}done ({Fore.YELLOW}{total_subs}{Fore.GREEN} found){Style.RESET_ALL}")
    
    if show_terminal:
        print(f"  {Fore.GREEN}- Detecting technologies...{Style.RESET_ALL}", end=" ", flush=True)
    passive.passive_technology_detection()
    if show_terminal:
        print(f"{Fore.GREEN}done{Style.RESET_ALL}")
    
    if show_terminal:
        print(f"  {Fore.GREEN}- Fetching archives...{Style.RESET_ALL}", end=" ", flush=True)
    passive.archive_detection()
    arch_count = len(passive.results.get('all_archives', []))
    if show_terminal:
        print(f"{Fore.GREEN}done ({Fore.YELLOW}{arch_count}{Fore.GREEN} found){Style.RESET_ALL}")
    
    if show_terminal:
        print(f"  {Fore.GREEN}- Discovering endpoints...{Style.RESET_ALL}", end=" ", flush=True)
    passive.passive_endpoint_discovery()
    total_endpoints = len(passive.results.get('endpoints', []))
    if show_terminal:
        print(f"{Fore.GREEN}done ({Fore.YELLOW}{total_endpoints}{Fore.GREEN} found){Style.RESET_ALL}")
    
    if show_terminal:
        print(f"  {Fore.GREEN}- Detecting origin IP...{Style.RESET_ALL}", end=" ", flush=True)
    passive.origin_ip_detection()
    ip_info = passive.results.get('origin_ip', {})
    if show_terminal:
        print(f"{Fore.GREEN}done (IP: {Fore.YELLOW}{ip_info.get('ip', 'N/A')}{Fore.GREEN}, CDN: {Fore.YELLOW}{ip_info.get('cdn', 'N/A')}{Fore.GREEN}){Style.RESET_ALL}")
    
    if not passive.results.get("all_subdomains"):
        if show_terminal:
            print(f"\n{Fore.RED}[-] No subdomains found, skipping active recon{Style.RESET_ALL}")
        if save_json:
            with open(f"recon_{target}.json", "w") as f:
                json.dump({"passive": passive.results}, f, indent=2, default=str)
            print(f"{Fore.GREEN}[+] Results saved to recon_{target}.json{Style.RESET_ALL}")
        return
    
    # ============================================================
    # Active Recon
    # ============================================================
    if show_terminal:
        print(f"\n{Fore.CYAN}[*] Phase 2: Active Reconnaissance{Style.RESET_ALL}")
    
    active = ActiveRecon(target, os_detection=os_detection, nse=nse_vuln, custom_nse=custom_nse, ports=ports, max_workers=max_workers)
    if chaos_key:
        active.chaos_api_key = chaos_key
    if wordlist_path:
        active.wordlist_path = wordlist_path
    
    if show_terminal:
        print(f"  {Fore.GREEN}- Active subdomain enumeration...{Style.RESET_ALL}", end=" ", flush=True)
    active.active_subdomain_finder()
    active_subs = len(active.results.get('active_subdomains', {}).get('all_subdomains', []))
    if show_terminal:
        print(f"{Fore.GREEN}done ({Fore.YELLOW}{active_subs}{Fore.GREEN} found){Style.RESET_ALL}")
    
    if os_detection or nse_vuln or custom_nse:
        if show_terminal:
            print(f"  {Fore.GREEN}- Nmap scanning... (this may take a while){Style.RESET_ALL}", end=" ", flush=True)
        active.nmap_scaning()
        if show_terminal:
            print(f"{Fore.GREEN}done{Style.RESET_ALL}")
    else:
        if show_terminal:
            print(f"  {Fore.YELLOW}- Nmap scanning... skipped{Style.RESET_ALL}")
    
    if use_dirb or use_gobuster:
        if show_terminal:
            print(f"  {Fore.GREEN}- Directory detection... (this may take a while){Style.RESET_ALL}", end=" ", flush=True)
        active.directory_detection()
        dirs = active.results.get('directories', [])
        high_priority = len([d for d in dirs if d.get('priority', 0) >= 50])
        if show_terminal:
            print(f"{Fore.GREEN}done ({Fore.YELLOW}{len(dirs)}{Fore.GREEN} found, {Fore.RED}{high_priority}{Fore.GREEN} high priority){Style.RESET_ALL}")
    else:
        if show_terminal:
            print(f"  {Fore.YELLOW}- Directory detection... skipped{Style.RESET_ALL}")
        dirs = []
    
    if show_terminal:
        print(f"  {Fore.GREEN}- Active technology detection...{Style.RESET_ALL}", end=" ", flush=True)
    active.active_technology_detection()
    if show_terminal:
        print(f"{Fore.GREEN}done{Style.RESET_ALL}")
    
    if show_terminal:
        print(f"  {Fore.GREEN}- Active endpoint discovery...{Style.RESET_ALL}", end=" ", flush=True)
    active.active_endpoint_discovery()
    if show_terminal:
        print(f"{Fore.GREEN}done{Style.RESET_ALL}")
    
    # ============================================================
    # Summary
    # ============================================================
    elapsed = time.time() - start_time
    
    print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}RECONNAISSANCE COMPLETED{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Time: {Fore.WHITE}{elapsed:.2f}{Fore.GREEN} seconds{Style.RESET_ALL}")
    print(f"\n{Fore.MAGENTA}Passive Results:{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Subdomains:{Style.RESET_ALL} {total_subs}")
    print(f"  {Fore.WHITE}Endpoints:{Style.RESET_ALL} {total_endpoints}")
    print(f"  {Fore.WHITE}Origin IP:{Style.RESET_ALL} {ip_info.get('ip', 'N/A')}")
    print(f"  {Fore.WHITE}CDN:{Style.RESET_ALL} {ip_info.get('cdn', 'N/A')}")
    print(f"\n{Fore.MAGENTA}Active Results:{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Subdomains:{Style.RESET_ALL} {active_subs}")
    print(f"  {Fore.WHITE}Directories:{Style.RESET_ALL} {len(dirs)}")
    
    tech = passive.results.get('passive_technology', {})
    if tech:
        print(f"\n{Fore.MAGENTA}Technologies:{Style.RESET_ALL}")
        for k, v in list(tech.items())[:5]:
            print(f"  {Fore.WHITE}{k}:{Style.RESET_ALL} {v}")
    
    print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    
    # ============================================================
    # Save results
    # ============================================================
    results = {"passive": passive.results, "active": active.results}
    
    if save_json:
        with open(f"recon_{target}.json", "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"{Fore.GREEN}[+] JSON saved to recon_{target}.json{Style.RESET_ALL}")
    
    if output_html:
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recon Report - {target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f0f2f5; padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        .header h1 {{ font-size: 28px; margin-bottom: 10px; }}
        .header p {{ color: #aaa; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }}
        .stat-card {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }}
        .stat-card h3 {{ font-size: 32px; color: #1a1a2e; margin-bottom: 5px; }}
        .stat-card p {{ color: #666; font-size: 14px; text-transform: uppercase; letter-spacing: 1px; }}
        .card {{ background: white; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; overflow: hidden; }}
        .card-header {{ background: #1a1a2e; color: white; padding: 15px 20px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; }}
        .card-header:hover {{ background: #16213e; }}
        .card-header h2 {{ font-size: 18px; }}
        .card-header span {{ font-size: 12px; background: rgba(255,255,255,0.2); padding: 4px 8px; border-radius: 20px; }}
        .card-body {{ padding: 20px; display: block; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
        th {{ text-align: left; padding: 12px; background: #f5f5f5; border-bottom: 2px solid #ddd; font-weight: 600; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #eee; }}
        tr:hover {{ background: #f9f9f9; }}
        .subdomain {{ color: #0066cc; font-family: monospace; }}
        .directory {{ color: #cc6600; font-family: monospace; }}
        .endpoint {{ color: #009933; font-family: monospace; }}
        .tech {{ color: #993399; font-family: monospace; }}
        .search {{ margin-bottom: 15px; }}
        .search input {{ width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; font-size: 14px; }}
        .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }}
        .badge-high {{ background: #ff4444; color: white; }}
        .badge-medium {{ background: #ffaa00; color: white; }}
        .badge-low {{ background: #00cc66; color: white; }}
        .footer {{ text-align: center; padding: 20px; color: #666; font-size: 12px; }}
        .json-view {{ background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 5px; font-family: monospace; font-size: 12px; overflow-x: auto; max-height: 500px; overflow-y: auto; }}
        @media (max-width: 768px) {{ .stats {{ grid-template-columns: repeat(2, 1fr); }} }}
    </style>
    <script>
        function toggleSection(id) {{
            var body = document.getElementById(id);
            if (body.style.display === "none") {{
                body.style.display = "block";
            }} else {{
                body.style.display = "none";
            }}
        }}
        function searchTable(tableId, inputId) {{
            var input = document.getElementById(inputId);
            var filter = input.value.toLowerCase();
            var table = document.getElementById(tableId);
            var rows = table.getElementsByTagName("tr");
            for (var i = 1; i < rows.length; i++) {{
                var text = rows[i].innerText.toLowerCase();
                rows[i].style.display = text.includes(filter) ? "" : "none";
            }}
        }}
    </script>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Reconnaissance Report</h1>
        <p>Target: {target} | Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="stats">
        <div class="stat-card"><h3>{total_subs}</h3><p>Subdomains</p></div>
        <div class="stat-card"><h3>{len(dirs)}</h3><p>Directories</p></div>
        <div class="stat-card"><h3>{total_endpoints}</h3><p>Endpoints</p></div>
        <div class="stat-card"><h3>{ip_info.get('ip', 'N/A')}</h3><p>Origin IP</p></div>
        <div class="stat-card"><h3>{ip_info.get('cdn', 'N/A')}</h3><p>CDN</p></div>
        <div class="stat-card"><h3>{elapsed:.1f}s</h3><p>Time</p></div>
    </div>
    
    <div class="card">
        <div class="card-header" onclick="toggleSection('subdomains-body')">
            <h2>Subdomains ({total_subs})</h2>
            <span>click to expand/collapse</span>
        </div>
        <div id="subdomains-body" class="card-body">
            <div class="search"><input type="text" id="subSearch" placeholder="Search subdomains..." onkeyup="searchTable('subTable', 'subSearch')"></div>
            <table id="subTable">
                <thead><tr><th>Subdomain</th></tr></thead>
                <tbody>
"""
        for sub in passive.results.get('all_subdomains', [])[:500]:
            html_content += f"<tr><td class='subdomain'>{sub}</td> </tr>\n"
        if total_subs > 500:
            html_content += f"<tr><td><em>... and {total_subs - 500} more (see JSON)</em></td></tr>\n"
        html_content += """</tbody>
            </table>
        </div>
    </div>
    
    <div class="card">
        <div class="card-header" onclick="toggleSection('dirs-body')">
            <h2>Directories (""" + str(len(dirs)) + """)</h2>
            <span>click to expand/collapse</span>
        </div>
        <div id="dirs-body" class="card-body">
            <div class="search"><input type="text" id="dirSearch" placeholder="Search directories..." onkeyup="searchTable('dirTable', 'dirSearch')"></div>
            <table id="dirTable">
                <thead><tr><th>Path</th><th>Status</th><th>Priority</th></tr></thead>
                <tbody>
"""
        for d in dirs[:200]:
            priority_class = "badge-high" if d.get('priority', 0) >= 50 else ("badge-medium" if d.get('priority', 0) >= 20 else "badge-low")
            html_content += f"<tr><td class='directory'>{d.get('path', '')}</td><td>{d.get('status', '')}</td><td><span class='badge {priority_class}'>{d.get('priority', 0)}</span></td></tr>\n"
        if len(dirs) > 200:
            html_content += f"<tr><td colspan='3'><em>... and {len(dirs) - 200} more (see JSON)</em></td></tr>\n"
        html_content += """</tbody>
            </table>
        </div>
    </div>
    
    <div class="card">
        <div class="card-header" onclick="toggleSection('endpoints-body')">
            <h2>Endpoints (""" + str(total_endpoints) + """)</h2>
            <span>click to expand/collapse</span>
        </div>
        <div id="endpoints-body" class="card-body">
            <div class="search"><input type="text" id="epSearch" placeholder="Search endpoints..." onkeyup="searchTable('epTable', 'epSearch')"></div>
            <table id="epTable">
                <thead><tr><th>Endpoint</th></tr></thead>
                <tbody>
"""
        for ep in passive.results.get('endpoints', [])[:200]:
            html_content += f"<tr><td class='endpoint'>{ep}</td></tr>\n"
        if total_endpoints > 200:
            html_content += f"<tr><td><em>... and {total_endpoints - 200} more (see JSON)</em></td></tr>\n"
        html_content += """</tbody>
            </table>
        </div>
    </div>
    
    <div class="card">
        <div class="card-header" onclick="toggleSection('tech-body')">
            <h2>Technologies</h2>
            <span>click to expand/collapse</span>
        </div>
        <div id="tech-body" class="card-body">
            <table>
                <thead><tr><th>Technology</th><th>Value</th></tr></thead>
                <tbody>
"""
        tech = passive.results.get('passive_technology', {})
        for k, v in tech.items():
            html_content += f"<tr><td class='tech'>{k}</td><td>{v}</td></tr>\n"
        html_content += """</tbody>
            </table>
        </div>
    </div>
    
    <div class="card">
        <div class="card-header" onclick="toggleSection('json-body')">
            <h2>Full JSON Results</h2>
            <span>click to expand/collapse</span>
        </div>
        <div id="json-body" class="card-body">
            <div class="json-view">"""
        html_content += json.dumps(results, indent=2, default=str)
        html_content += """</div>
        </div>
    </div>
    
    <div class="footer">Generated by Recon Tool | All results are saved in JSON format</div>
</div>
</body>
</html>"""
        
        with open(f"recon_{target}.html", "w", encoding='utf-8') as f:
            f.write(html_content)
        print(f"{Fore.GREEN}[+] HTML report saved to recon_{target}.html{Style.RESET_ALL}")
    
    if output_csv:
        with open(f"recon_{target}.csv", "w", newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Type", "Name", "Status", "Priority", "Extra"])
            
            for sub in passive.results.get('all_subdomains', []):
                writer.writerow(["subdomain", sub, "", "", ""])
            
            for d in dirs:
                writer.writerow(["directory", d.get('path', ''), d.get('status', ''), d.get('priority', ''), ""])
            
            for ep in passive.results.get('endpoints', [])[:1000]:
                writer.writerow(["endpoint", ep, "", "", ""])
            
            tech = passive.results.get('passive_technology', {})
            for k, v in tech.items():
                writer.writerow(["technology", k, "", "", str(v)])
            
            ip_info = passive.results.get('origin_ip', {})
            writer.writerow(["origin_ip", ip_info.get('ip', 'N/A'), "", "", ip_info.get('cdn', 'N/A')])
            
            active_subs_data = active.results.get('active_subdomains', {}).get('all_subdomains', [])
            for sub in active_subs_data[:1000]:
                writer.writerow(["active_subdomain", sub, "", "", ""])
        
        print(f"{Fore.GREEN}[+] CSV saved to recon_{target}.csv{Style.RESET_ALL}")
    
    if output_markdown:
        md_content = f"# Reconnaissance Report for {target}\n\n"
        md_content += f"## Summary\n\n- **Subdomains:** {total_subs}\n- **Directories:** {len(dirs)}\n- **Endpoints:** {total_endpoints}\n- **Origin IP:** {ip_info.get('ip', 'N/A')}\n- **CDN:** {ip_info.get('cdn', 'N/A')}\n\n"
        md_content += f"## Subdomains ({total_subs})\n\n```\n"
        for sub in passive.results.get('all_subdomains', [])[:50]:
            md_content += f"{sub}\n"
        md_content += "```\n\n## Directories ({len(dirs)})\n\n```\n"
        for d in dirs[:30]:
            md_content += f"{d.get('path', '')} (status: {d.get('status', '')})\n"
        md_content += "```\n"
        
        with open(f"recon_{target}.md", "w", encoding='utf-8') as f:
            f.write(md_content)
        print(f"{Fore.GREEN}[+] Markdown report saved to recon_{target}.md{Style.RESET_ALL}")
    
    # ============================================================
    # Send notifications
    # ============================================================
    results_str = json.dumps(results, indent=2, default=str)
    
    if discord_webhook:
        try:
            if len(results_str) > 1900:
                summary = f"Recon {target}: {total_subs} subs, {len(dirs)} dirs, {total_endpoints} endpoints"
                requests.post(discord_webhook, json={"content": summary}, timeout=30)
                print(f"{Fore.GREEN}[+] Summary sent to Discord{Style.RESET_ALL}")
            else:
                requests.post(discord_webhook, json={"content": f"```json\n{results_str}\n```"}, timeout=30)
                print(f"{Fore.GREEN}[+] Full results sent to Discord{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to send to Discord: {e}{Style.RESET_ALL}")
    
    if tg_bot and tg_chat:
        try:
            if len(results_str) > 4000:
                for i in range(0, len(results_str), 4000):
                    chunk = results_str[i:i+4000]
                    requests.post(f"https://api.telegram.org/bot{tg_bot}/sendMessage", json={"chat_id": tg_chat, "text": f"```json\n{chunk}\n```"}, timeout=30)
                print(f"{Fore.GREEN}[+] Full results sent to Telegram (multiple messages){Style.RESET_ALL}")
            else:
                requests.post(f"https://api.telegram.org/bot{tg_bot}/sendMessage", json={"chat_id": tg_chat, "text": f"```json\n{results_str}\n```"}, timeout=30)
                print(f"{Fore.GREEN}[+] Full results sent to Telegram{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to send to Telegram: {e}{Style.RESET_ALL}")
    
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()
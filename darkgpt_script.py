#!/usr/bin/env python3
import asyncio
import aiohttp
import ssl
import socket
import dns.resolver
from urllib.parse import urlparse
import json
import sys

class ReconScanner:
    def __init__(self, target_url):
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.domain = self.parsed_url.netloc
        self.session = None
        self.results = {
            "target": target_url,
            "domain": self.domain,
            "ip_addresses": [],
            "dns_records": {},
            "headers": {},
            "ssl_info": {},
            "common_paths": {}
        }

    async def resolve_dns(self):
        loop = asyncio.get_running_loop()
        resolver = dns.resolver.Resolver()
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        
        for rtype in record_types:
            try:
                answers = await loop.run_in_executor(
                    None, lambda: resolver.resolve(self.domain, rtype)
                )
                self.results["dns_records"][rtype] = [str(r) for r in answers]
                if rtype == 'A':
                    self.results["ip_addresses"].extend([str(r) for r in answers])
            except Exception:
                self.results["dns_records"][rtype] = []

    async def get_ssl_certificate(self):
        if self.parsed_url.scheme != 'https':
            return
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            loop = asyncio.get_running_loop()
            def fetch_cert():
                with socket.create_connection((self.domain, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                        return ssock.getpeercert()

            cert = await loop.run_in_executor(None, fetch_cert)
            self.results["ssl_info"] = {
                "subject": dict(x[0] for x in cert.get('subject', [])),
                "issuer": dict(x[0] for x in cert.get('issuer', [])),
                "version": cert.get('version'),
                "notBefore": cert.get('notBefore'),
                "notAfter": cert.get('notAfter')
            }
        except Exception as e:
            self.results["ssl_info"] = {"error": str(e)}

    async def check_path(self, path):
        url = f"{self.target_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            async with self.session.get(url, allow_redirects=False, timeout=5) as response:
                self.results["common_paths"][path] = response.status
        except Exception:
            self.results["common_paths"][path] = "Timeout/Error"

    async def run_scan(self):
        print(f"[*] Initializing reconnaissance on: {self.target_url}")
        
        # DNS & IP Resolution
        print("[*] Resolving DNS and IP structures...")
        await self.resolve_dns()

        # SSL Inspection
        print("[*] Inspecting TLS/SSL certificate parameters...")
        await self.get_ssl_certificate()

        # HTTP Headers and Directory Brute
        common_paths = [
            "robots.txt", ".git/HEAD", "sitemap.xml", "admin/", 
            "config.json", ".env", "api/", "wp-login.php", "login"
        ]

        connector = aiohttp.TCPConnector(ssl=False, limit=50)
        async with aiohttp.ClientSession(connector=connector, headers={"User-Agent": "Mozilla/5.0 (Compatible; ReconBot/1.0)"}) as session:
            self.session = session
            
            print("[*] Grabbing HTTP response headers...")
            try:
                async with session.get(self.target_url, timeout=10) as response:
                    self.results["headers"] = dict(response.headers)
            except Exception as e:
                self.results["headers"] = {"error": str(e)}

            print("[*] Enumerating common administrative and configuration paths...")
            tasks = [self.check_path(path) for path in common_paths]
            await asyncio.gather(*tasks)

        print("[+] Reconnaissance complete.")
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <target_domain_or_url>")
        sys.exit(1)

    target = sys.argv[1]
    scanner = ReconScanner(target)
    
    loop = asyncio.get_event_loop()
    scan_results = loop.run_until_complete(scanner.run_scan())
    
    print(json.dumps(scan_results, indent=4))
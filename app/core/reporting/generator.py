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


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

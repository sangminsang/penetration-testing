# app/core/recon/scanner_integrations.py

import subprocess
import json
import logging
import tempfile
from typing import List, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)

class NucleiScanner:
    """Nuclei 스캐너 통합"""
    
    def __init__(self, templates_path: str = None):
        self.templates_path = templates_path or r"C:\Users\Windows10\nuclei-templates"
    
    # ⭐ 이 메서드 추가!
    def _categorize_from_tags(self, tags: List[str]) -> str:
        """태그로부터 카테고리 추론"""
        tags_str = " ".join(tags).lower()
        
        if any(x in tags_str for x in ["cms", "wordpress", "drupal", "joomla"]):
            return "cms"
        elif any(x in tags_str for x in ["javascript", "js", "frontend", "angular", "react", "vue"]):
            return "frontend"
        elif any(x in tags_str for x in ["backend", "server", "api"]):
            return "backend"
        elif any(x in tags_str for x in ["database", "mysql", "postgres", "mongodb"]):
            return "database"
        elif any(x in tags_str for x in ["panel", "admin", "login"]):
            return "application"
        else:
            return "other"
    
    def scan_tech_detection(self, target: str) -> List[Dict[str, Any]]:
        """Retire.js를 사용하여 취약한 JavaScript 라이브러리 스캔"""
        technologies = []
        try:
            print(f"[RETIRE.JS] Scanning JavaScript libraries at {target}...")
            
            # Windows PowerShell용 경로 체크
            retire_paths = [
                'retire',
                r'C:\Users\Windows10\AppData\Roaming\npm\retire.cmd',
            ]
            
            retire_cmd = None
            for path in retire_paths:
                try:
                    result = subprocess.run(
                        [path, '--version'],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        shell=True
                    )
                    if result.returncode == 0:
                        retire_cmd = path
                        print(f"[RETIRE.JS] ✓ Found retire at: {path}")
                        break
                except Exception:
                    continue
            
            if not retire_cmd:
                logger.error("RETIRE.JS: retire not found")
                return technologies
            
            # ✅ 옵션 수정: --js 제거, --jspath 또는 --jsrepo 사용
            cmd = [
                retire_cmd,
                '--outputformat', 'json',
                '--outputpath', '-',  # stdout
                '--jsrepo', target,  # ← --js 대신 --jsrepo 사용
            ]
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=30,
                shell=True
            )
            
            # retire.js는 취약점 발견 시 exit code 13 반환
            if result.returncode not in [0, 13]:
                logger.warning(f"RETIRE.JS: Warning: {result.stderr}")
            
            if not result.stdout.strip():
                print("RETIRE.JS: No vulnerable libraries found")
                return technologies
            
            try:
                data = json.loads(result.stdout)
                
                for entry in data:
                    filepath = entry.get('file', '')
                    results = entry.get('results', [])
                    
                    for res in results:
                        component = res.get('component', '')
                        version = res.get('version', '')
                        vulnerabilities = res.get('vulnerabilities', [])
                        
                        vuln_info = []
                        for vuln in vulnerabilities:
                            vuln_info.append({
                                'severity': vuln.get('severity', 'unknown'),
                                'identifiers': vuln.get('identifiers', {}),
                                'info': vuln.get('info', [])
                            })
                        
                        tech = {
                            'name': component,
                            'version': version,
                            'product': component,
                            'category': 'javascript-library',
                            'source': 'retire.js',
                            'vulnerable': True,
                            'vulnerabilities': vuln_info,
                            'filepath': filepath,
                            'severity': self.get_max_severity(vuln_info)
                        }
                        technologies.append(tech)
                        print(f"[RETIRE.JS] 🔴 VULNERABLE: {component} {version} - {len(vulnerabilities)} CVEs")
                
                print(f"[RETIRE.JS] Scan completed - Found {len(technologies)} vulnerable libraries")
                
            except json.JSONDecodeError as e:
                logger.error(f"RETIRE.JS: Failed to parse JSON: {e}")
                
        except FileNotFoundError:
            logger.error("RETIRE.JS: retire not found")
        except subprocess.TimeoutExpired:
            logger.error("RETIRE.JS: Scan timeout")
        except Exception as e:
            logger.error(f"RETIRE.JS: Scan failed: {e}")
        
        return technologies

class HttpxScanner:
    """httpx 스캐너 통합"""
    
    def scan_tech_detection(self, target: str) -> List[Dict[str, Any]]:
        """
        httpx로 웹 서버 정보 수집
        """
        technologies = []
        try:
            print(f"[HTTPX] Running scan on {target}...")
            
            cmd = [
                "httpx",
                "-tech-detect",
                "-server",
                "-title",
                "-status-code",
                "-json",
                "-silent"
            ]
            
            result = subprocess.run(
                cmd,
                input=target + "\n",
                capture_output=True,
                text=True,
                timeout=30
            )
            
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    
                    # Server 헤더
                    server = data.get("server", "")
                    if server:
                        name = server.split("/")[0]
                        version = server.split("/")[1] if "/" in server else ""
                        technologies.append({
                            "name": name,
                            "version": version,
                            "category": "webserver",
                            "source": "httpx"
                        })
                    
                    # 기술 탐지
                    for tech in data.get("tech", []):
                        technologies.append({
                            "name": tech,
                            "version": "",
                            "category": "detected",
                            "source": "httpx"
                        })
                except json.JSONDecodeError:
                    continue
            
            print(f"[HTTPX] Found {len(technologies)} technologies")
        except Exception as e:
            logger.error(f"[HTTPX] Scan failed: {e}")
        
        return technologies

class RetireJsScanner:
    """Retire.js를 이용한 취약한 JavaScript 라이브러리 탐지"""
    
    def scan_tech_detection(self, target: str) -> List[Dict[str, Any]]:
        """Retire.js를 사용하여 취약한 JavaScript 라이브러리 스캔"""
        technologies = []
        try:
            print(f"[RETIRE.JS] Scanning JavaScript libraries at {target}...")
            
            # ✅ Windows PowerShell에서 사용 가능한 경로들
            retire_paths = [
                'retire',  # PATH에 있으면 바로 실행
                r'C:\Users\Windows10\AppData\Roaming\npm\retire.cmd',
                r'C:\Users\Windows10\AppData\Roaming\npm\retire.ps1',
            ]
            
            retire_cmd = None
            
            # ✅ 사용 가능한 retire 찾기
            for path in retire_paths:
                try:
                    result = subprocess.run(
                        [path, '--version'],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        shell=True  # ✅ PowerShell에서 실행
                    )
                    if result.returncode == 0:
                        retire_cmd = path
                        print(f"[RETIRE.JS] ✓ Found retire at: {path}")
                        break
                except Exception:
                    continue
            
            if not retire_cmd:
                logger.error("RETIRE.JS: retire not found in PATH. Please install retire.js globally (npm install -g retire)")
                return technologies
            
            # ✅ 실제 스캔 실행
            cmd = [
                retire_cmd,
                '--outputformat', 'json',
                '--outputpath', '-',  # stdout으로 출력
                '--js',  # JavaScript만 스캔
                target
            ]
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=30,
                shell=True  # ✅ PowerShell 환경
            )
            
            # retire.js는 취약점 발견 시 exit code 13 반환
            if result.returncode not in [0, 13]:
                logger.warning(f"RETIRE.JS: Warning: {result.stderr}")
            
            if not result.stdout.strip():
                print("RETIRE.JS: No vulnerable libraries found")
                return technologies
            
            try:
                data = json.loads(result.stdout)
                
                # retire.js 출력 파싱
                for entry in data:
                    filepath = entry.get('file', '')
                    results = entry.get('results', [])
                    
                    for res in results:
                        component = res.get('component', '')
                        version = res.get('version', '')
                        vulnerabilities = res.get('vulnerabilities', [])
                        
                        vuln_info = []
                        for vuln in vulnerabilities:
                            vuln_info.append({
                                'severity': vuln.get('severity', 'unknown'),
                                'identifiers': vuln.get('identifiers', {}),
                                'info': vuln.get('info', [])
                            })
                        
                        tech = {
                            'name': component,
                            'version': version,
                            'product': component,
                            'category': 'javascript-library',
                            'source': 'retire.js',
                            'vulnerable': True,
                            'vulnerabilities': vuln_info,
                            'filepath': filepath,
                            'severity': self.get_max_severity(vuln_info)
                        }
                        technologies.append(tech)
                        print(f"[RETIRE.JS] 🔴 VULNERABLE: {component} {version} - {len(vulnerabilities)} CVEs")
                
                print(f"[RETIRE.JS] Scan completed - Found {len(technologies)} vulnerable libraries")
                
            except json.JSONDecodeError as e:
                logger.error(f"RETIRE.JS: Failed to parse JSON: {e}")
                
        except FileNotFoundError:
            logger.error("RETIRE.JS: retire not found in PATH. Please install retire.js globally (npm install -g retire)")
        except subprocess.TimeoutExpired:
            logger.error("RETIRE.JS: Scan timeout")
        except Exception as e:
            logger.error(f"RETIRE.JS: Scan failed: {e}")
        
        return technologies
    
    def get_max_severity(self, vulns: List[Dict]) -> str:
        """취약점 목록에서 최고 심각도 반환"""
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'unknown': 0}
        max_sev = 'unknown'
        max_val = 0
        
        for vuln in vulns:
            sev = vuln.get('severity', 'unknown').lower()
            if severity_order.get(sev, 0) > max_val:
                max_val = severity_order[sev]
                max_sev = sev
        
        return max_sev

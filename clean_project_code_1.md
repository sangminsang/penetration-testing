# Project Code Extract (Part 1/5)
- **Root:** `d:\3차 프로젝트\worker_entry`
- **Files included:** 15 (Total: 72)

---

## File 1: __init__.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\__init__.py`

```python
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
import os

db = SQLAlchemy()
socketio = SocketIO()

def create_app():
    app = Flask(__name__)
    basedir = os.path.abspath(os.path.dirname(__file__))
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, '../project.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'security-secret-key'

    db.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*")

    # 웹소켓 핸들러 등록
    from app.api.websocket import register_socketio_handlers, ScanProgressEmitter
    register_socketio_handlers(socketio, ScanProgressEmitter(socketio))

    from app.routes import bp
    app.register_blueprint(bp)

    with app.app_context():
        db.create_all()

    return app, socketio


```
---

## File 2: __init__.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\api\__init__.py`

```python
# API endpoints

```
---

## File 3: websocket.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\api\websocket.py`

```python
from flask_socketio import emit
from app.models import Project
from app import db
import traceback
import subprocess
import os
import shutil
from app.core.distributor import spawn_workers

class ScanProgressEmitter:
    def __init__(self, socketio):
        self.socketio = socketio

    def emit_log(self, msg, stage='info', progress=0):
        self.socketio.emit('scan_progress', {'stage': stage, 'progress': progress, 'current_item': msg})

def register_socketio_handlers(socketio, scan_emitter):
    @socketio.on('start_scan')
    def handle_start_scan(data):
        target = data.get('target')
        project = Project.query.filter_by(target=target).first()
        socketio.start_background_task(run_integrated_scan, target, project.id if project else None, scan_emitter)

def run_integrated_scan(target, project_id, emitter):
    import time
    import glob
    import json
    from pathlib import Path
    
    try:
        emitter.emit_log(f"🔍 1단계: 마스터 정찰(Katana) 시작 - {target}", 'recon', 10)
        
        # 1. 메인 서버에서 Katana를 먼저 실행하여 전체 URL 수집
        katana_path = shutil.which('katana') or '/usr/local/bin/katana'
        temp_urls_file = f"temp_urls_{int(os.getpid())}.txt"
        
        katana_cmd = [katana_path, '-u', target, '-silent', '-jc', '-kf', 'all', '-o', temp_urls_file]
        subprocess.run(katana_cmd, timeout=120)

        # 2. 수집된 URL 리스트 읽기
        discovered_urls = []
        if os.path.exists(temp_urls_file):
            with open(temp_urls_file, 'r') as f:
                discovered_urls = [line.strip() for line in f if line.strip()]
            os.remove(temp_urls_file)

        if not discovered_urls:
            discovered_urls = [target] # 추출 실패 시 입력값이라도 사용

        emitter.emit_log(f"📦 2단계: {len(discovered_urls)}개 URL 발견. 6개 워커로 분산 스캔 시작!", 'analysis', 30)

        # 3. 발견된 모든 URL을 6개 워커에게 배분 (진정한 분산 처리)
        spawn_workers(discovered_urls, worker_count=6)
        
        emitter.emit_log(f"🚀 6개 워커가 동시에 Nuclei/ZAP 스캔 중입니다...", 'crawling', 70)
        
        # 4. 결과 파일을 모니터링하며 대시보드로 전송
        # 프로젝트 루트 기준으로 경로 계산 (작업 디렉토리 문제 해결)
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        result_dir = os.path.join(base_dir, "scan_results")
        
        # 디렉토리가 없으면 생성
        os.makedirs(result_dir, exist_ok=True)
        
        domain_part = target.split("://")[-1].split("/")[0].replace(".", "_")
        pattern = os.path.join(result_dir, f"*{domain_part}*.json")
        
        # 워커가 결과를 생성할 때까지 대기 (최대 10분)
        max_wait_time = 600
        start_time = time.time()
        processed_files = set()
        
        while time.time() - start_time < max_wait_time:
            # 결과 파일 찾기
            result_files = glob.glob(pattern)
            
            for file_path in result_files:
                if file_path in processed_files:
                    continue
                    
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        result_data = json.load(f)
                    
                    # 기술 스택을 대시보드 형식으로 변환하여 전송
                    webtechnologies = result_data.get('webtechnologies', [])
                    nuclei_vulns = result_data.get('nuclei_vulns', [])
                    
                    # 기술별로 취약점 그룹화
                    tech_vuln_map = {}
                    for vuln in nuclei_vulns:
                        # 취약점을 CVE 형식으로 변환
                        cve_obj = {
                            'cve_id': vuln.get('template_id', vuln.get('name', 'Unknown')),
                            'severity': vuln.get('severity', 'medium').upper(),
                            'description': vuln.get('name', ''),
                            'url': vuln.get('url', '')
                        }
                        
                        # 기술과 연결 (첫 번째 기술에 연결하거나, URL 기반으로 매칭)
                        tech_name = 'Unknown'
                        if webtechnologies:
                            tech_name = webtechnologies[0].get('name', 'Unknown')
                        
                        if tech_name not in tech_vuln_map:
                            tech_vuln_map[tech_name] = []
                        tech_vuln_map[tech_name].append(cve_obj)
                    
                    # 기술 스택 전송 (취약점 포함)
                    for tech in webtechnologies:
                        tech_name = tech.get('name', 'Unknown')
                        tech_obj = {
                            'name': tech_name,
                            'version': tech.get('version', ''),
                            'source': tech.get('source', 'Unknown'),
                            'cves': tech_vuln_map.get(tech_name, [])
                        }
                        emitter.socketio.emit('technology_detected', tech_obj)
                    
                    # 취약점만 있고 기술 스택이 없는 경우도 처리
                    if not webtechnologies and nuclei_vulns:
                        for vuln in nuclei_vulns:
                            cve_obj = {
                                'cve_id': vuln.get('template_id', vuln.get('name', 'Unknown')),
                                'severity': vuln.get('severity', 'medium').upper(),
                                'description': vuln.get('name', ''),
                                'url': vuln.get('url', '')
                            }
                            tech_obj = {
                                'name': 'Vulnerability',
                                'version': '',
                                'source': 'Nuclei',
                                'cves': [cve_obj]
                            }
                            emitter.socketio.emit('technology_detected', tech_obj)
                    
                    processed_files.add(file_path)
                    emitter.emit_log(f"✅ 결과 파일 처리 완료: {os.path.basename(file_path)}", 'success', 85)
                    
                except Exception as e:
                    emitter.emit_log(f"⚠️ 결과 파일 처리 실패: {e}", 'error')
            
            # 모든 워커가 완료되었는지 확인 (파일 수가 안정화되면)
            if len(result_files) >= len(discovered_urls) * 0.8:  # 80% 이상 완료
                time.sleep(5)  # 마지막 파일들이 완료될 시간
                break
                
            time.sleep(2)  # 2초마다 체크
        
        emitter.emit_log(f"✅ 모든 워커 배정 완료. {len(processed_files)}개 결과 파일 처리됨.", 'completed', 90)
        
        # 5. CVE 매칭 및 AI 시나리오 생성
        emitter.emit_log(f"🔍 3단계: CVE 매칭 및 AI 시나리오 생성 시작...", 'analysis', 92)
        
        try:
            # 모든 결과 파일에서 기술 스택 수집
            all_technologies = []
            all_cves_from_nuclei = []
            
            for file_path in processed_files:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        result_data = json.load(f)
                    
                    # 기술 스택 수집
                    webtechnologies = result_data.get('webtechnologies', [])
                    for tech in webtechnologies:
                        tech_dict = {
                            'product': tech.get('name', 'unknown'),
                            'version': tech.get('version', ''),
                            'source': tech.get('source', 'Unknown')
                        }
                        if tech_dict not in all_technologies:
                            all_technologies.append(tech_dict)
                    
                    # Nuclei 취약점 수집
                    nuclei_vulns = result_data.get('nuclei_vulns', [])
                    for vuln in nuclei_vulns:
                        cve_id = vuln.get('template_id', vuln.get('name', ''))
                        if cve_id and cve_id.startswith('CVE-'):
                            all_cves_from_nuclei.append({
                                'id': cve_id,
                                'description': vuln.get('name', ''),
                                'severity': vuln.get('severity', 'medium'),
                                'url': vuln.get('url', '')
                            })
                except Exception as e:
                    continue
            
            # CVE 매칭 수행 (기술 스택 기반)
            if all_technologies:
                emitter.emit_log(f"📊 {len(all_technologies)}개 기술 스택에 대한 CVE 검색 중...", 'analysis', 94)
                
                from app.core.cve.cpe_generator import batch_generate_cpes
                from app.core.cve.async_nvd_client import AsyncNvdClient
                from app.core.cve.cache_manager import get_cache_manager
                import asyncio
                from app.config import Config
                
                # CVE 매칭 함수 import
                try:
                    from app.core.cve.matcher import search_cves_for_technologies as search_cves_func
                except ImportError:
                    try:
                        from app.core.cve.matcher import search_cves_universal as search_cves_func
                    except ImportError:
                        search_cves_func = None
                
                if search_cves_func:
                    # CPE 생성
                    technologies_with_cpe = batch_generate_cpes(all_technologies)
                    cpe_techs = [t for t in technologies_with_cpe if t.get('cpe')]
                    
                    # NVD 클라이언트 초기화 (설정값 직접 사용)
                    nvd_client = AsyncNvdClient(
                        api_key=getattr(Config, 'NVD_API_KEY', None),
                        base_url=getattr(Config, 'NVD_BASE_URL', "https://services.nvd.nist.gov/rest/json/cves/2.0")
                    )
                    cache_manager = get_cache_manager()
                    
                    # 비동기 CVE 검색
                    async def search_all_cves():
                        all_cves = []
                        for tech in cpe_techs:
                            prod = tech.get('product')
                            ver = tech.get('version')
                            try:
                                cves = await search_cves_func(prod, ver, nvd_client=nvd_client, cache_manager=cache_manager)
                                if cves:
                                    all_cves.extend(cves)
                            except Exception:
                                pass
                        return all_cves
                    
                    # 이벤트 루프 실행
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        matched_cves = loop.run_until_complete(search_all_cves())
                        # Nuclei에서 발견한 CVE와 병합
                        matched_cves.extend(all_cves_from_nuclei)
                        # 중복 제거
                        unique_cves = {}
                        for cve in matched_cves:
                            cve_id = cve.get('id') or cve.get('cve_id')
                            if cve_id:
                                unique_cves[cve_id] = cve
                        matched_cves = list(unique_cves.values())
                        
                        emitter.emit_log(f"✅ {len(matched_cves)}개 CVE 발견!", 'success', 96)
                    finally:
                        loop.close()
                else:
                    matched_cves = all_cves_from_nuclei
                    emitter.emit_log(f"⚠️ CVE 매칭 함수를 사용할 수 없습니다. Nuclei 결과만 사용합니다.", 'warning', 96)
            else:
                matched_cves = all_cves_from_nuclei
                emitter.emit_log(f"⚠️ 기술 스택이 없습니다. Nuclei 결과만 사용합니다.", 'warning', 96)
            
            # AI 시나리오 생성
            if matched_cves or all_technologies:
                emitter.emit_log(f"🤖 AI 기반 공격 시나리오 생성 중...", 'analysis', 97)
                
                try:
                    from app.core.scenario.generator import call_ollama
                    from flask import current_app
                    
                    # Flask 애플리케이션 컨텍스트 설정 (Ollama 호출을 위해 필요)
                    from app import create_app
                    app, _ = create_app()
                    
                    with app.app_context():
                        # 프롬프트 생성
                        prompt_lines = [f"Analyze the security posture of {target}."]
                        
                        if all_technologies:
                            tech_names = [t.get('product', 'unknown') for t in all_technologies]
                            prompt_lines.append(f"Technologies: {', '.join(set(tech_names))}.")
                        
                        if matched_cves:
                            prompt_lines.append(f"Vulnerabilities: {len(matched_cves)} found.")
                            sorted_cves = sorted(matched_cves, key=lambda x: float(x.get('cvss', 0) or 0), reverse=True)
                            for cve in sorted_cves[:5]:
                                cve_id = cve.get('id', cve.get('cve_id', 'Unknown'))
                                desc = cve.get('description', '')[:100].replace('\n', ' ')
                                prompt_lines.append(f"- {cve_id}: {desc}...")
                        
                        prompt_lines.append("Based on this, create a short penetration testing scenario.")
                        final_prompt = " ".join(prompt_lines)
                        
                        # Ollama 호출
                        scenario_text = call_ollama(final_prompt)
                    
                    # 시나리오를 대시보드로 전송
                    if isinstance(scenario_text, str):
                        scenario_object = {
                            "title": f"Penetration Test Scenario for {target}",
                            "summary": scenario_text[:200] + "..." if len(scenario_text) > 200 else scenario_text,
                            "content": scenario_text,
                            "steps": [
                                {"name": "Reconnaissance", "details": f"Found {len(all_technologies)} tech stacks"},
                                {"name": "Scanning", "details": f"Detected {len(matched_cves)} CVEs"},
                                {"name": "Analysis", "details": "High risk vulnerabilities identified"}
                            ]
                        }
                    else:
                        scenario_object = scenario_text
                    
                    emitter.socketio.emit('ai_scenario_ready', scenario_object)
                    emitter.emit_log(f"✅ AI 시나리오 생성 완료!", 'success', 99)
                    
                except Exception as e:
                    emitter.emit_log(f"⚠️ AI 시나리오 생성 실패: {str(e)}", 'warning', 99)
                    # 폴백 시나리오
                    fallback_scenario = {
                        "title": f"Penetration Test Scenario for {target}",
                        "summary": f"Found {len(all_technologies)} technologies and {len(matched_cves)} CVEs.",
                        "content": f"Attack Scenario for {target}:\n1. Reconnaissance: Discovered {len(all_technologies)} technologies.\n2. Vulnerability Analysis: Identified {len(matched_cves)} potential vulnerabilities.",
                        "steps": [
                            {"name": "Reconnaissance", "details": f"Found {len(all_technologies)} tech stacks"},
                            {"name": "Scanning", "details": f"Detected {len(matched_cves)} CVEs"}
                        ]
                    }
                    emitter.socketio.emit('ai_scenario_ready', fallback_scenario)
        
        except Exception as e:
            emitter.emit_log(f"⚠️ CVE 매칭/AI 시나리오 생성 중 오류: {str(e)}", 'warning', 99)
            traceback.print_exc()
        
        emitter.emit_log(f"✅ 스캔 완료!", 'completed', 100)
        emitter.socketio.emit('scan_completed', {})

    except Exception as e:
        traceback.print_exc()
        emitter.emit_log(f"❌ 분산 처리 중 오류: {str(e)}", 'error')
```
---

## File 4: config.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\config.py`

```python
# app/config.py

class Config:
    # cve-search api
    CVE_SEARCH_BASE_URL = "https://localhost"

    # ollama
    OLLAMA_BASE_URL = "http://localhost:11434"
    OLLAMA_MODEL = "gemma3:4b"

    # nmap 등 옵션
    # 🆕 HTTP 헤더 감지 추가
    NMAP_ARGS = "-sV -sT -Pn --script=http-headers,http-server-header"

    # 데모 시 보안 관련 옵션(예: 실제 IP 마스킹)
    MASK_REAL_IP = True

    # NVD 관련 설정
    NVD_API_KEY = "fe4669a1-c66f-4058-bc9e-5440b5919e2f"
    NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_RESULTS_PER_PAGE = 50
    REQUEST_TIMEOUT = 15

    # ZAP Docker 설정
    ZAP_API_KEY = '12345'
    ZAP_PROXY_HOST = '127.0.0.1'
    ZAP_PROXY_PORT = 8080
    ZAP_TIMEOUT = 600  # 10분
    ZAP_DEFAULT_RISK_LEVELS = ['High', 'Medium']
```
---

## File 5: __init__.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\__init__.py`

```python
# Core modules for penetration testing automation

```
---

## File 6: __init__.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\cve\__init__.py`

```python
# CVE related modules

```
---

## File 7: async_nvd_client.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\cve\async_nvd_client.py`

```python
# app/core/cve/async_nvd_client.py

"""
NVD API v2.0 비동기 클라이언트 (최적화 버전)
- Rate limiting 강화
- CPE 기반 검색
- 403 에러 방지
"""

import asyncio
import aiohttp
import time
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import quote

logger = logging.getLogger(__name__)


class AsyncNvdClient:
    """비동기 NVD API 클라이언트"""
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0",
        results_per_page: int = 50,
        request_timeout: int = 15,
        rate_limit_delay: float = 0.6,
        use_local_cve_search: bool = True  # 로컬 DB 사용 여부
    ):
        self.api_key = api_key
        self.base_url = base_url
        self.results_per_page = results_per_page
        self.request_timeout = request_timeout
        self.rate_limit_delay = rate_limit_delay
        self.use_local_cve_search = use_local_cve_search
        
        # 통계
        self.stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "cache_hits": 0,
            "api_errors": 0,
            "rate_limit_errors": 0,
            "total_cves_found": 0
        }
        
        self._last_request_time = 0
    
    
    async def _wait_for_rate_limit(self):
        """Rate limiting: API 호출 간격 제어"""
        current_time = time.time()
        elapsed = current_time - self._last_request_time
        
        if elapsed < self.rate_limit_delay:
            wait_time = self.rate_limit_delay - elapsed
            logger.debug(f"[NVD] Rate limiting: waiting {wait_time:.2f}s")
            await asyncio.sleep(wait_time)
        
        self._last_request_time = time.time()
    
    async def search_cves_by_cpe_local(
        self,
        cpe: str,
        base_url: str = "https://localhost:443"
    ) -> List[Dict[str, Any]]:
        """
        로컬 cve-search Docker에서 CVE 검색
        """
        # 🔥 올바른 엔드포인트: /api/cvefor/{cpe}
        from urllib.parse import quote
        cpe_encoded = quote(cpe, safe='')
        url = f"{base_url}/api/cvefor/{cpe_encoded}"
        
        logger.info(f"[CVE-SEARCH] Querying: {url}")
        
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                    self.stats["total_requests"] += 1
                    
                    if response.status == 200:
                        self.stats["successful_requests"] += 1
                        data = await response.json()
                        
                        # 응답 처리
                        if isinstance(data, list):
                            logger.info(f"[CVE-SEARCH] ✅ Found {len(data)} CVEs for {cpe}")
                            return data
                        elif isinstance(data, dict) and "id" in data:
                            logger.info(f"[CVE-SEARCH] ✅ Found 1 CVE for {cpe}")
                            return [data]
                        else:
                            logger.warning(f"[CVE-SEARCH] Unexpected response format")
                            return []
                    
                    elif response.status == 404:
                        logger.info(f"[CVE-SEARCH] No CVEs found for {cpe}")
                        return []
                    
                    else:
                        self.stats["failed_requests"] += 1
                        logger.warning(f"[CVE-SEARCH] HTTP {response.status}")
                        return []
                        
        except Exception as e:
            self.stats["api_errors"] += 1
            logger.exception(f"[CVE-SEARCH] Error for {cpe}: {e}")
            return []

    
    async def search_cves_by_cpe(
        self,
        cpe: str,
        max_results: int = 100
    ) -> List[Dict[str, Any]]:
        """
        CPE 문자열로 CVE 검색 (로컬/원격 자동 선택)
        """
        # 로컬 DB 우선 사용
        if self.use_local_cve_search:
            logger.info(f"[NVD] Using local cve-search for: {cpe}")
            return await self.search_cves_by_cpe_local(cpe)
        
        # 기존 NVD API 사용
        logger.info(f"[NVD] Using NVD API for: {cpe}")
        await self._wait_for_rate_limit()
        
        params = {
            "cpeName": cpe,
            "resultsPerPage": self.results_per_page
        }
        
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        all_cves = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.base_url,
                    params=params,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.request_timeout)
                ) as response:
                    self.stats["total_requests"] += 1
                    
                    if response.status == 200:
                        self.stats["successful_requests"] += 1
                        data = await response.json()
                        vulnerabilities = data.get("vulnerabilities", [])
                        all_cves.extend(vulnerabilities)
                        logger.info(f"[NVD] Found {len(vulnerabilities)} CVEs for {cpe}")
                    
                    elif response.status == 404:
                        logger.warning(f"[NVD] CPE not found in database: {cpe}")
                    
                    elif response.status == 403:
                        self.stats["rate_limit_errors"] += 1
                        logger.error(f"[NVD] 403 Forbidden - Rate limit exceeded")
                    
                    else:
                        self.stats["failed_requests"] += 1
                        logger.warning(f"[NVD] HTTP {response.status} for CPE: {cpe}")
        
        except asyncio.TimeoutError:
            self.stats["api_errors"] += 1
            logger.error(f"[NVD] Timeout for CPE: {cpe}")
        
        except Exception as e:
            self.stats["api_errors"] += 1
            logger.exception(f"[NVD] Exception for CPE {cpe}: {e}")
        
        self.stats["total_cves_found"] += len(all_cves)
        return all_cves[:max_results]
    
    
    async def search_cves_by_keyword(
        self,
        keyword: str,
        max_results: int = 50
    ) -> List[Dict[str, Any]]:
        """키워드로 CVE 검색"""
        logger.info(f"[NVD] Searching by keyword: {keyword}")
        await self._wait_for_rate_limit()
        
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": self.results_per_page
        }
        
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        all_cves = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.base_url,
                    params=params,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.request_timeout)
                ) as response:
                    self.stats["total_requests"] += 1
                    
                    if response.status == 200:
                        self.stats["successful_requests"] += 1
                        data = await response.json()
                        vulnerabilities = data.get("vulnerabilities", [])
                        all_cves.extend(vulnerabilities)
                        logger.info(f"[NVD] Found {len(vulnerabilities)} CVEs for keyword: {keyword}")
                    
                    elif response.status == 403:
                        self.stats["rate_limit_errors"] += 1
                        logger.error(f"[NVD] 403 Forbidden")
                    
                    else:
                        self.stats["failed_requests"] += 1
                        logger.warning(f"[NVD] HTTP {response.status}")
        
        except asyncio.TimeoutError:
            self.stats["api_errors"] += 1
            logger.error(f"[NVD] Timeout")
        
        except Exception as e:
            self.stats["api_errors"] += 1
            logger.exception(f"[NVD] Exception: {e}")
        
        self.stats["total_cves_found"] += len(all_cves)
        return all_cves[:max_results]
    
    
    def get_stats(self) -> Dict[str, int]:
        """통계 정보 반환"""
        return self.stats.copy()
    
    
    def reset_stats(self):
        """통계 초기화"""
        for key in self.stats:
            self.stats[key] = 0
```
---

## File 8: cache_manager.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\cve\cache_manager.py`

```python
# app/core/cve/cache_manager.py
# 영구 캐시 매니저 (SQLite/Redis)

import json
import time
import logging
import sqlite3
from typing import Optional, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)

class CacheManager:
    """
    CVE 캐시 매니저
    - 메모리 캐시 (1차: 빠름)
    - 영구 캐시 (2차: 재시작 후에도 유지)
    - TTL 지원
    """
    
    def __init__(
        self,
        backend="sqlite",
        ttl=86400,  # 24시간
        db_path="data/cve_cache.db"
    ):
        """
        Args:
            backend: "memory", "sqlite", "redis"
            ttl: Time-to-live (초), 기본 24시간
            db_path: SQLite DB 경로
        """
        self.backend = backend
        self.ttl = ttl
        self.memory_cache = {}
        self.conn = None
        self.redis_client = None
        
        if backend == "sqlite":
            self._init_sqlite(db_path)
        elif backend == "redis":
            self._init_redis()
        
        logger.info(f"CacheManager initialized (backend={backend}, ttl={ttl}s)")
    
    def _init_sqlite(self, db_path: str):
        """SQLite 캐시 초기화"""
        # 디렉토리 생성
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS cve_cache (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            )
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_expires_at ON cve_cache(expires_at)
        """)
        self.conn.commit()
        logger.info(f"SQLite cache initialized: {db_path}")
    
    def _init_redis(self):
        """Redis 캐시 초기화"""
        try:
            import redis
            self.redis_client = redis.Redis(
                host='localhost',
                port=6379,
                db=0,
                decode_responses=True
            )
            # 연결 테스트
            self.redis_client.ping()
            logger.info("Redis cache initialized")
        except Exception as e:
            logger.error(f"Redis initialization failed: {e}")
            logger.warning("Falling back to memory-only cache")
            self.backend = "memory"
    
    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """
        캐시 조회 (메모리 → 영구 순서)
        
        Args:
            key: 캐시 키
        
        Returns:
            캐시된 데이터 또는 None
        """
        # 1. 메모리 캐시 확인
        if key in self.memory_cache:
            data, expires_at = self.memory_cache[key]
            if time.time() < expires_at:
                logger.debug(f"Memory cache HIT: {key[:60]}...")
                return data
            else:
                # 만료된 캐시 삭제
                del self.memory_cache[key]
        
        # 2. 영구 캐시 확인
        if self.backend == "sqlite":
            return self._get_sqlite(key)
        elif self.backend == "redis":
            return self._get_redis(key)
        
        return None
    
    def _get_sqlite(self, key: str) -> Optional[Dict[str, Any]]:
        """SQLite에서 조회"""
        try:
            cursor = self.conn.execute(
                "SELECT value, expires_at FROM cve_cache WHERE key = ?",
                (key,)
            )
            row = cursor.fetchone()
            
            if row:
                value_json, expires_at = row
                
                # 만료 확인
                if time.time() < expires_at:
                    data = json.loads(value_json)
                    # 메모리 캐시에도 저장
                    self.memory_cache[key] = (data, expires_at)
                    logger.debug(f"SQLite cache HIT: {key[:60]}...")
                    return data
                else:
                    # 만료된 캐시 삭제
                    self.conn.execute("DELETE FROM cve_cache WHERE key = ?", (key,))
                    self.conn.commit()
                    logger.debug(f"SQLite cache EXPIRED: {key[:60]}...")
            
            return None
        
        except Exception as e:
            logger.error(f"SQLite get error: {e}")
            return None
    
    def _get_redis(self, key: str) -> Optional[Dict[str, Any]]:
        """Redis에서 조회"""
        try:
            value_json = self.redis_client.get(f"cve:{key}")
            if value_json:
                data = json.loads(value_json)
                # 메모리 캐시에도 저장
                expires_at = int(time.time() + self.ttl)
                self.memory_cache[key] = (data, expires_at)
                logger.debug(f"Redis cache HIT: {key[:60]}...")
                return data
            return None
        
        except Exception as e:
            logger.error(f"Redis get error: {e}")
            return None
    
    def set(self, key: str, value: Dict[str, Any]):
        """
        캐시 저장 (메모리 + 영구)
        
        Args:
            key: 캐시 키
            value: 저장할 데이터
        """
        expires_at = int(time.time() + self.ttl)
        created_at = int(time.time())
        
        # 1. 메모리 캐시
        self.memory_cache[key] = (value, expires_at)
        
        # 2. 영구 캐시
        if self.backend == "sqlite":
            self._set_sqlite(key, value, expires_at, created_at)
        elif self.backend == "redis":
            self._set_redis(key, value)
        
        logger.debug(f"Cache SET: {key[:60]}...")
    
    def _set_sqlite(self, key: str, value: Dict[str, Any], expires_at: int, created_at: int):
        """SQLite에 저장"""
        try:
            value_json = json.dumps(value, ensure_ascii=False)
            self.conn.execute(
                "INSERT OR REPLACE INTO cve_cache (key, value, expires_at, created_at) VALUES (?, ?, ?, ?)",
                (key, value_json, expires_at, created_at)
            )
            self.conn.commit()
        except Exception as e:
            logger.error(f"SQLite set error: {e}")
    
    def _set_redis(self, key: str, value: Dict[str, Any]):
        """Redis에 저장"""
        try:
            value_json = json.dumps(value, ensure_ascii=False)
            self.redis_client.setex(
                f"cve:{key}",
                self.ttl,
                value_json
            )
        except Exception as e:
            logger.error(f"Redis set error: {e}")
    
    def clear_expired(self) -> int:
        """
        만료된 캐시 정리
        
        Returns:
            삭제된 캐시 수
        """
        current_time = int(time.time())
        deleted_count = 0
        
        # 메모리 캐시 정리
        expired_keys = [
            key for key, (_, expires_at) in self.memory_cache.items()
            if expires_at < current_time
        ]
        for key in expired_keys:
            del self.memory_cache[key]
            deleted_count += 1
        
        # 영구 캐시 정리
        if self.backend == "sqlite":
            try:
                cursor = self.conn.execute(
                    "DELETE FROM cve_cache WHERE expires_at < ?",
                    (current_time,)
                )
                self.conn.commit()
                deleted_count += cursor.rowcount
            except Exception as e:
                logger.error(f"SQLite clear_expired error: {e}")
        
        if deleted_count > 0:
            logger.info(f"Cleared {deleted_count} expired cache entries")
        
        return deleted_count
    
    def clear_all(self):
        """전체 캐시 삭제"""
        self.memory_cache.clear()
        
        if self.backend == "sqlite":
            try:
                self.conn.execute("DELETE FROM cve_cache")
                self.conn.commit()
                logger.info("All SQLite cache cleared")
            except Exception as e:
                logger.error(f"SQLite clear_all error: {e}")
        
        elif self.backend == "redis":
            try:
                for key in self.redis_client.scan_iter("cve:*"):
                    self.redis_client.delete(key)
                logger.info("All Redis cache cleared")
            except Exception as e:
                logger.error(f"Redis clear_all error: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """캐시 통계"""
        stats = {
            "backend": self.backend,
            "ttl": f"{self.ttl}s",
            "memory_cache_size": len(self.memory_cache)
        }
        
        if self.backend == "sqlite":
            try:
                cursor = self.conn.execute("SELECT COUNT(*) FROM cve_cache")
                count = cursor.fetchone()[0]
                stats["sqlite_cache_size"] = count
            except Exception as e:
                logger.error(f"SQLite stats error: {e}")
        
        elif self.backend == "redis":
            try:
                count = len(list(self.redis_client.scan_iter("cve:*")))
                stats["redis_cache_size"] = count
            except Exception as e:
                logger.error(f"Redis stats error: {e}")
        
        return stats
    
    def __del__(self):
        """소멸자: 연결 종료"""
        if self.conn:
            self.conn.close()
```
---

## File 9: cpe_generator.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\cve\cpe_generator.py`

```python
"""
CPE(Common Platform Enumeration) 생성기
- NVD의 CPE 표준에 맞춰 기술 스택 정보를 CPE로 변환
"""

import re
import logging
from typing import Optional, Dict, List, Any

logger = logging.getLogger(__name__)


# ================================================================================
# PRODUCT NORMALIZATION MAP
# ================================================================================

PRODUCT_NORMALIZATION_MAP = {
    # Web Servers
    "apache": "apache:http_server",        # ✅ 변경!
    "apache httpd": "apache:http_server",  # ✅ 변경!
    "httpd": "apache:http_server",         # ✅ 변경!
    "nginx": "nginx:nginx",
    "iis": "microsoft:internet_information_services",
    "microsoft-iis": "microsoft:internet_information_services",
    
    # Languages & Runtimes
    "node": "nodejs:node.js",
    "node.js": "nodejs:node.js",
    "nodejs": "nodejs:node.js",
    "php": "php:php",
    "python": "python:python",
    "java": "oracle:jdk",
    
    # Web Frameworks
    "express": "expressjs:express",
    "expressjs": "expressjs:express",
    "django": "djangoproject:django",
    "flask": "palletsprojects:flask",
    "spring": "vmware:spring_framework",
    "spring boot": "vmware:spring_boot",
    "laravel": "laravel:laravel",
    "rails": "rubyonrails:rails",
    "ruby on rails": "rubyonrails:rails",
    
    # Databases
    "mysql": "oracle:mysql",
    "mariadb": "mariadb:mariadb",
    "postgresql": "postgresql:postgresql",
    "postgres": "postgresql:postgresql",
    "sqlite": "sqlite:sqlite",
    "mongodb": "mongodb:mongodb",
    "redis": "redis:redis",
    "elasticsearch": "elastic:elasticsearch",
    "mssql": "microsoft:sql_server",
    "sql server": "microsoft:sql_server",
    
    # JavaScript Libraries
    "jquery": "jquery:jquery",
    "angular": "angular:angular",
    "angularjs": "angular:angular",
    "react": "facebook:react",
    "vue": "vuejs:vue.js",
    "vue.js": "vuejs:vue.js",
    "bootstrap": "getbootstrap:bootstrap",
    
    # CMS
    "wordpress": "wordpress:wordpress",
    "joomla": "joomla:joomla",
    "drupal": "drupal:drupal",
    
    # Others
    "owasp juice shop": "owasp:juice_shop",
    "juice shop": "owasp:juice_shop",
    "docker": "docker:docker",
    "kubernetes": "kubernetes:kubernetes",
    "openssl": "openssl:openssl",
    "openssh": "openbsd:openssh",
}


# ================================================================================
# CPE BLACKLIST
# ================================================================================

CPE_BLACKLIST = [
    # HTML/CSS/Markup
    "html", "html5", "css", "css3", "javascript", "js", "xml", "json", "yaml", "markdown", "svg",
    
    # Network/Protocol
    "ip", "tcp", "udp", "http", "https", "ssl", "tls", "dns", "dhcp", "nat", "vpn", "firewall",
    
    # Generic Terms
    "server", "client", "api", "web", "application", "service", "protocol", "port", "host", "network",
    "unknown", "na", "none", "null", "empty",
    
    # UI/Meta
    "title", "description", "version", "name", "type", "category", "tag", "label", "country", "language",
    "font", "icon", "image", "video", "audio", "button", "menu", "form", "table", "chart"
]


def is_blacklisted(product: str) -> bool:
    """블랙리스트 제품인지 확인"""
    if not product:
        return True
    
    product_lower = product.lower().strip()
    
    # 너무 짧은 제품명은 스킵
    if not product_lower or len(product_lower) < 2:
        return True
    
    # 완전 일치
    for blacklisted in CPE_BLACKLIST:
        if product_lower == blacklisted:
            logger.debug(f"[CPE] Blacklisted (exact match): {product}")
            return True
    
    # 단어 포함
    if f" {product_lower} " in f" {' '.join(CPE_BLACKLIST)} ":
        logger.debug(f"[CPE] Blacklisted (word found): {product}")
        return True
    
    return False


def normalize_product_name(product: str) -> str:
    """제품명을 CPE 표준으로 정규화"""
    if not product:
        return ""
    
    product_lower = product.lower().strip()
    
    # 완전 일치
    if product_lower in PRODUCT_NORMALIZATION_MAP:
        return PRODUCT_NORMALIZATION_MAP[product_lower]
    
    # 부분 매칭
    for key, value in PRODUCT_NORMALIZATION_MAP.items():
        if key in product_lower or product_lower.startswith(key):
            return value
    
    # 공백/특수문자 제거 (Apache2.4.41 -> apache)
    normalized = re.sub(r'[^a-z0-9_]', '', product_lower)
    normalized = normalized.replace('_', '')
    
    return normalized


def generate_cpe(vendor: str, product: str, version: str) -> str:
    """CPE 2.3 문자열 생성"""
    # 버전 정규화
    if not version or version.lower() in ["na", "unknown", ""]:
        version = "*"
    
    cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    return cpe


def parse_vendor_product(normalized_product: str) -> tuple:
    """정규화된 제품명에서 vendor와 product 분리"""
    if ":" in normalized_product:
        parts = normalized_product.split(":", 1)
        return parts[0], parts[1]
    else:
        return normalized_product, normalized_product


def infer_vendor(product: str) -> str:
    """제품명에서 벤더 추론"""
    VENDOR_MAP = {
        "jquery": "jquery",
        "express": "expressjs",
        "nginx": "nginx",
        "apache": "apache",
        "http_server": "apache",  # ✅ 추가
        "mysql": "mysql",
        "postgresql": "postgresql",
        "redis": "redis",
        "mongodb": "mongodb",
        "php": "php",
        "python": "python",
        "node.js": "nodejs",
        "nodejs": "nodejs",
        "wordpress": "wordpress",
        "drupal": "drupal",
        "joomla": "joomla",
        "owasp juice shop": "owasp",
        "juice shop": "owasp",
        "application": "application",
    }
    
    product_normalized = product.replace("_", " ").strip()
    
    if product_normalized in VENDOR_MAP:
        return VENDOR_MAP[product_normalized]
    
    # 공백이 있으면 첫 단어를 벤더로 사용
    return product.split()[0] if product else "unknown"


def extract_version_from_product(product_string: str) -> tuple:
    """
    복잡한 제품 문자열에서 제품명과 버전 추출
    
    Examples:
        "Apache/2.4.7 (Ubuntu)" → ("apache", "2.4.7")
        "PHP/5.5.9-1ubuntu4.14" → ("php", "5.5.9")
        "mysql 5.7.35" → ("mysql", "5.7.35")
    
    Returns:
        (product, version)
    """
    if not product_string:
        return ("", "")
    
    # 1. "제품/버전 (OS)" 패턴
    match = re.match(r'^(\w+)/(\d+(?:\.\d+)*)', product_string, re.IGNORECASE)
    if match:
        return (match.group(1).lower(), match.group(2))
    
    # 2. "제품 버전" 패턴
    match = re.match(r'^([\w\s]+)\s+(\d+(?:\.\d+)*)', product_string)
    if match:
        return (match.group(1).strip().lower(), match.group(2))
    
    # 3. 버전이 없는 경우
    return (product_string.lower().strip(), "")


def extract_cpe_from_tech(tech: Dict[str, Any]) -> Optional[str]:
    """
    기술 정보에서 CPE 추출/생성 (개선 버전)
    """
    original_product = tech.get("original_name", "") or tech.get("product", "")
    product = tech.get("product", "").lower().strip()
    version = tech.get("version", "").strip()
    vendor = tech.get("vendor", "").lower().strip()
    
    # 🆕 버전이 복잡한 문자열인 경우 파싱
    if not version or version in ["N/A", "", "unknown"]:
        # original_name에서 버전 추출 시도
        _, extracted_version = extract_version_from_product(original_product)
        if extracted_version:
            version = extracted_version
    
    # 🆕 제품명 정규화 시도
    if not product or product == "n/a":
        extracted_product, extracted_version = extract_version_from_product(original_product)
        if extracted_product:
            product = extracted_product
        if extracted_version and not version:
            version = extracted_version
    
    if not product:
        return None
    
    # 🆕 제품명 정규화 (apache/2.4.7 → apache, Apache/2.4.7 (Ubuntu) → apache)
    product = re.sub(r'[/\s\-\(\)]+.*$', '', product).lower()
    
    # 🆕 버전 정규화 (5.5.9-1ubuntu4.14 → 5.5.9)
    if version and version not in ["N/A", "unknown"]:
        version_match = re.match(r'^(\d+(?:\.\d+){0,2})', version)
        if version_match:
            version = version_match.group(1)
        else:
            version = "*"
    else:
        version = "*"
    
    # 🔥 핵심 수정: PRODUCT_NORMALIZATION_MAP 적용
    if product in PRODUCT_NORMALIZATION_MAP:
        normalized = PRODUCT_NORMALIZATION_MAP[product]
        if ":" in normalized:
            vendor, product = normalized.split(":", 1)
        else:
            product = normalized
    
    # 벤더 추론
    if not vendor:
        vendor = infer_vendor(product)
    
    # 제품명 정규화 (공백 → 언더스코어)
    product_normalized = product.replace(" ", "_")
    
    # "vendor:product" 형태면 중복 제거 (http_server:http_server → http_server)
    if vendor and product_normalized.startswith(f"{vendor}_"):
        product_normalized = product_normalized[len(vendor) + 1:]
    
    cpe = f"cpe:2.3:a:{vendor}:{product_normalized}:{version}:*:*:*:*:*:*:*"
    return cpe


def batch_generate_cpes(technologies: List[Dict]) -> List[Dict]:
    """
    기술 스택 목록에 대해 CPE를 일괄 생성
    CPE 2.3 표준 준수
    """
    # ✅ 수정: 주요 서버 스택 포함
    VALID_CATEGORIES = [
        "frontend",    # jQuery, Angular, React, Vue
        "backend",     # Express, Django, Flask
        "framework",
        "library",
        "cms",
        "platform",
        "language",
        "runtime",
        "webserver",   # Apache, Nginx, IIS
        "appserver",
        "database",    # MySQL, PostgreSQL
        "application",
        "detected",    # ← 추가! recog에서 탐지된 것들
        "os"          # ← 추가! Linux, Ubuntu 등
    ]
    
    # ✅ 수정: 블랙리스트 축소
    PRODUCT_BLACKLIST = [
        'unknown', 'http', 'https', 'ssl', 'tls',
        'html5', 'html', 'css', 'javascript',
        'title', 'country', 'ip', 'script',
        'uncommonheaders', 'x-frame-options', 'x-content-type-options',
        'redirectlocation', 'httpserver', 'cookies', 'passwordfield'
    ]
    
    # ✅ 수정: KNOWN_PRODUCTS 대폭 확장
    KNOWN_PRODUCTS = [
        # 웹 서버
        'apache', 'httpd', 'apache httpd', 'apache/2', 'apache httpserver',
        'nginx', 'iis', 'lighttpd', 'caddy',
        
        # 프로그래밍 언어
        'php', 'python', 'ruby', 'perl', 'java', 'node', 'nodejs', 'node.js',
        
        # 데이터베이스
        'mysql', 'mariadb', 'postgresql', 'postgres', 'mongodb', 'redis',
        'sqlite', 'cassandra', 'elasticsearch', 'mssql', 'sql server',
        
        # 웹 프레임워크
        'express', 'django', 'flask', 'spring', 'laravel', 'rails',
        
        # JavaScript 라이브러리
        'jquery', 'angular', 'angularjs', 'react', 'vue', 'vue.js', 'bootstrap',
        
        # CMS
        'wordpress', 'joomla', 'drupal',
        
        # 운영체제
        'linux', 'ubuntu', 'debian', 'centos', 'redhat', 'windows',
        
        # 테스트 앱
        'owasp juice shop', 'juice shop', 'application', 'bwapp', 'dvwa'
    ]
    
    result = []
    filtered_count = 0
    
    for tech in technologies:
        product = tech.get("product", "").lower().strip()
        category = tech.get("category", "other")
        
        # 1️⃣ 블랙리스트 체크
        if not product or product in PRODUCT_BLACKLIST:
            logger.debug(f"[CPE] Blacklisted product: {product}")
            filtered_count += 1
            continue
        
        # 2️⃣ 카테고리 체크
        should_generate_cpe = False
        
        if category in VALID_CATEGORIES:
            # ✅ 정상 카테고리
            should_generate_cpe = True
            logger.debug(f"[CPE] Valid category '{category}' for product: {product}")
        
        elif category == "other":
            # ✅ 핵심 수정: "other" 카테고리도 적극 허용
            if product in KNOWN_PRODUCTS:
                should_generate_cpe = True
                logger.info(f"[CPE] Known product in 'other' category: {product}")
            else:
                # 부분 매칭 시도 (예: "apache/2.4.7" → "apache")
                for known in KNOWN_PRODUCTS:
                    if known in product or product.startswith(known):
                        should_generate_cpe = True
                        logger.info(f"[CPE] Partial match in 'other' category: {product} → {known}")
                        break
            
            if not should_generate_cpe:
                logger.info(f"[CPE] Skipping 'other' category product: {product}")
                filtered_count += 1
                continue
        else:
            logger.info(f"[CPE] Skipping unknown category '{category}': {product}")
            filtered_count += 1
            continue
        
        # 3️⃣ CPE 생성
        if should_generate_cpe:
            cpe = extract_cpe_from_tech(tech)
            
            if cpe:
                tech["cpe"] = cpe
                result.append(tech)
                logger.info(f"[CPE] Generated: {product} (category: {category}) -> {cpe}")
            else:
                logger.debug(f"[CPE] Failed to generate CPE: {product}")
    
    logger.info(f"[CPE] Generated {len(result)} CPEs from {len(technologies)} technologies ({filtered_count} filtered)")
    return result
```
---

## File 10: matcher.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\cve\matcher.py`

```python
# app/core/cve/matcher.py

# CVE 매칭 엔진 (완전 개선 버전)

import time
import logging
import re
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import aiohttp

from .cpe_generator import (
    batch_generate_cpes,
    is_blacklisted,
    normalize_product_name,
    extract_cpe_from_tech
)

# Config import (상대 경로 사용)
# 프로젝트 루트를 sys.path에 추가
project_root = Path(__file__).parent.parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# Config import 시도 (여러 방법)
try:
    from app.config import Config  # type: ignore
except ImportError:
    try:
        # 직접 import 시도
        import config  # type: ignore
        Config = config.Config
    except ImportError:
        # 최후의 수단: 기본값 사용
        class Config:  # type: ignore
            NVD_API_KEY = None
            NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            NVD_RESULTS_PER_PAGE = 50
            REQUEST_TIMEOUT = 15

logger = logging.getLogger(__name__)

# 버전 비교 라이브러리
try:
    from packaging import version
    VERSION_COMPARE_AVAILABLE = True
except ImportError:
    VERSION_COMPARE_AVAILABLE = False
    logger.warning("packaging 모듈이 없어 버전 필터링이 비활성화됩니다. pip install packaging 권장")

# Product → (vendor, product) 매핑 테이블 (확장)
PRODUCT_TO_VENDOR_PRODUCT = {
    # 웹 서버
    "apache httpd": ("apache", "http_server"),
    "apache": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "iis": ("microsoft", "internet_information_services"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "caddy": ("caddyserver", "caddy"),

    # 데이터베이스
    "mysql": ("mysql", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "postgres": ("postgresql", "postgresql"),
    "mongodb": ("mongodb", "mongodb"),
    "redis": ("redis", "redis"),
    "sqlite": ("sqlite", "sqlite"),
    "cassandra": ("apache", "cassandra"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "memcached": ("memcached", "memcached"),

    # SSH/FTP
    "openssh": ("openssh", "openssh"),
    "dropbear": ("dropbear", "dropbear_ssh_server"),
    "vsftpd": ("vsftpd", "vsftpd"),
    "proftpd": ("proftpd", "proftpd"),

    # 메일 서버
    "postfix": ("postfix", "postfix"),
    "sendmail": ("sendmail", "sendmail"),
    "exim": ("exim", "exim"),
    "dovecot": ("dovecot", "dovecot"),

    # Python 웹 프레임워크/서버
    "werkzeug": ("palletsprojects", "werkzeug"),
    "gunicorn": ("benoitc", "gunicorn"),
    "flask": ("palletsprojects", "flask"),
    "django": ("djangoproject", "django"),
    "tornado": ("tornado", "tornado"),
    "bottle": ("bottlepy", "bottle"),
    "fastapi": ("tiangolo", "fastapi"),
    "uvicorn": ("encode", "uvicorn"),

    # JavaScript 런타임/프레임워크
    "node.js": ("nodejs", "node.js"),
    "node": ("nodejs", "node.js"),
    "express": ("expressjs", "express"),
    "react": ("facebook", "react"),
    "vue": ("vuejs", "vue"),
    "angular": ("angular", "angular"),

    # 애플리케이션 서버
    "tomcat": ("apache", "tomcat"),
    "jetty": ("eclipse", "jetty"),
    "wildfly": ("redhat", "wildfly"),
    "jboss": ("redhat", "jboss_application_server"),

    # 프로그래밍 언어
    "python": ("python", "python"),
    "php": ("php", "php"),
    "ruby": ("ruby-lang", "ruby"),
    "perl": ("perl", "perl"),
    "java": ("oracle", "jdk"),

    # 기타
    "docker": ("docker", "docker"),
    "kubernetes": ("kubernetes", "kubernetes"),
    "git": ("git-scm", "git"),
}

def normalize_product_name(product: str) -> str:
    """
    Nmap product 이름을 정규화

    Args:
        product: 원본 제품명

    Returns:
        정규화된 제품명 (소문자, 공백 제거)
    """
    if not product:
        return ""

    # 소문자 변환, 앞뒤 공백 제거
    normalized = product.lower().strip()

    # 슬래시로 구분된 경우 첫 번째 부분만 사용
    # 예: "Werkzeug/3.1.4" -> "werkzeug"
    if "/" in normalized:
        normalized = normalized.split("/")[0].strip()

    # 특수문자 제거 (하이픈, 언더스코어는 유지)
    normalized = re.sub(r'[^\w\s\-_.]', '', normalized)

    return normalized

def parse_and_normalize_version(version_str: str) -> Optional[str]:
    """
    버전 문자열에서 실제 버전 번호만 추출 및 정규화

    Examples:
        "Werkzeug/3.1.4 Python/3.11.14" -> "3.1.4"
        "2.4.41-dev" -> "2.4.41"
        "3.1.4+build123" -> "3.1.4"
        "Apache httpd 2.4.41" -> "2.4.41"

    Args:
        version_str: 원본 버전 문자열

    Returns:
        정규화된 버전 번호 또는 None
    """
    if not version_str:
        return None

    # 슬래시로 구분된 경우 버전 추출
    # 예: "Werkzeug/3.1.4 Python/3.11.14" -> "3.1.4"
    if "/" in version_str:
        parts = version_str.split()
        for part in parts:
            if "/" in part:
                version_part = part.split("/")[-1]
                # 버전 번호 패턴 추출
                version_match = re.search(r'(\d+(?:\.\d+)*)', version_part)
                if version_match:
                    return version_match.group(1)

    # 일반적인 버전 번호 패턴 추출
    # 숫자.숫자.숫자 형식 (예: "2.4.41", "3.1.4")
    version_match = re.search(r'(\d+(?:\.\d+)*)', version_str)
    if version_match:
        version = version_match.group(1)
        # 빌드 번호, dev, alpha 등 제거
        # 예: "2.4.41-dev" -> "2.4.41", "3.1.4+build123" -> "3.1.4"
        version = re.sub(r'[-+].*$', '', version)
        return version

    return None

def extract_product_from_version_string(version_str: str) -> Optional[str]:
    """
    복잡한 version 문자열에서 제품명 추출

    Examples:
        "Werkzeug/3.1.4 Python/3.11.14" -> "Werkzeug"
        "Apache httpd 2.4.41" -> "Apache httpd"

    Args:
        version_str: 버전 문자열

    Returns:
        제품명 또는 None
    """
    if not version_str:
        return None

    # 슬래시로 구분된 경우 첫 번째 제품명 추출
    if "/" in version_str:
        first_part = version_str.split()[0] if version_str.split() else ""
        if "/" in first_part:
            product = first_part.split("/")[0].strip()
            if product:
                return product

    # 일반적인 패턴: "제품명 버전" 형식
    # 예: "Apache httpd 2.4.41" -> "Apache httpd"
    version_match = re.search(r'^(.+?)\s+(\d+(?:\.\d+)*)', version_str)
    if version_match:
        product = version_match.group(1).strip()
        if product:
            return product

    return None

def parse_complex_version_string(version_str: str) -> Dict[str, str]:
    """
    복잡한 버전 문자열 파싱 (여러 형식 지원) - 🆕 신규 함수

    Examples:
        "Apache/2.4.66" → {"product": "Apache", "version": "2.4.66"}
        "mysql 5.7.35" → {"product": "mysql", "version": "5.7.35"}
        "nginx 1.19.0" → {"product": "nginx", "version": "1.19.0"}
        "Werkzeug/3.1.4 Python/3.11.14" → {"product": "Werkzeug", "version": "3.1.4"}
        "Apache httpd 2.4.41 (Ubuntu)" → {"product": "Apache httpd", "version": "2.4.41"}
        "OpenSSH_7.4" → {"product": "OpenSSH", "version": "7.4"} # 🆕 추가

    Args:
        version_str: 버전 문자열

    Returns:
        {"product": "제품명", "version": "버전"}
    """
    if not version_str:
        return {"product": "", "version": ""}

    # 1. 슬래시로 구분 (Apache/2.4.66, Werkzeug/3.1.4)
    if "/" in version_str:
        # 첫 번째 슬래시 항목만 처리
        first_part = version_str.split()[0] if version_str.split() else version_str
        if "/" in first_part:
            parts = first_part.split("/")
            product = parts[0].strip()
            version = parse_and_normalize_version(parts[1]) if len(parts) > 1 else ""
            return {"product": product, "version": version or ""}

    # 🆕 2. 언더스코어로 구분 (OpenSSH_7.4, Python_3.11.14)
    if "_" in version_str:
        # 언더스코어 뒤에 버전 번호가 있는지 확인
        parts = version_str.split("_")
        if len(parts) >= 2:
            # 마지막 부분이 버전 번호인지 확인
            potential_version = parts[-1]
            if re.match(r'^\d+(\.\d+)*', potential_version):
                product = "_".join(parts[:-1])
                version = parse_and_normalize_version(potential_version)
                return {"product": product, "version": version or ""}

    # 3. 공백으로 구분 (mysql 5.7.35, Apache httpd 2.4.41)
    if " " in version_str:
        parts = version_str.split()
        # 마지막 부분이 버전 번호인지 확인
        for i in range(len(parts) - 1, -1, -1):
            if re.match(r'[\d.]+', parts[i]):
                # 버전 발견
                product = " ".join(parts[:i])
                version = parse_and_normalize_version(parts[i])
                return {"product": product, "version": version or ""}

        # 버전 번호가 없으면 전체를 제품명으로
        product = extract_product_from_version_string(version_str)
        if product:
            version = parse_and_normalize_version(version_str)
            return {"product": product, "version": version or ""}

    # 4. 버전만 있는 경우 (1.19.0)
    if re.match(r'^[\d.]+$', version_str):
        return {"product": "", "version": version_str}

    # 5. 제품명만 있는 경우 (nginx)
    return {"product": version_str, "version": ""}

def map_product_to_vendor_product(product: str) -> Optional[Tuple[str, str]]:
    """
    Product 이름을 (vendor, product) 튜플로 변환

    Args:
        product: 제품명

    Returns:
        (vendor, product) 튜플 또는 None
    """
    normalized = normalize_product_name(product)
    if not normalized:
        return None

    # 1. 정확한 매칭 시도
    if normalized in PRODUCT_TO_VENDOR_PRODUCT:
        return PRODUCT_TO_VENDOR_PRODUCT[normalized]

    # 2. 부분 매칭 시도 (키워드 포함)
    for key, value in PRODUCT_TO_VENDOR_PRODUCT.items():
        if key in normalized or normalized in key:
            logger.debug(f"Product mapping (partial match): {product} -> {value}")
            return value

    # 3. 단어 단위 매칭 시도
    normalized_words = set(normalized.split())
    for key, value in PRODUCT_TO_VENDOR_PRODUCT.items():
        key_words = set(key.split())
        if normalized_words & key_words:  # 교집합이 있으면
            logger.debug(f"Product mapping (word match): {product} -> {value}")
            return value

    logger.debug(f"Product mapping failed: {product}")
    return None

def build_cpe_string(vendor: str, product: str, version: str = "*") -> str:
    """
    CPE 2.3 형식 문자열 생성

    Format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*

    Args:
        vendor: 벤더명
        product: 제품명
        version: 버전 (기본값 "*")

    Returns:
        CPE 2.3 문자열
    """
    vendor_clean = vendor.replace(" ", "_").lower()
    product_clean = product.replace(" ", "_").lower()
    version_clean = version if version else "*"

    return f"cpe:2.3:a:{vendor_clean}:{product_clean}:{version_clean}:*:*:*:*:*:*:*"

def parse_cpe_uri(cpe_uri: str) -> Optional[Tuple[str, str]]:
    """
    CPE URI 문자열에서 vendor와 product를 추출

    Format: cpe:2.3:a:vendor:product:version:...

    Args:
        cpe_uri: CPE URI 문자열

    Returns:
        (vendor, product) 튜플 또는 None
    """
    if not cpe_uri or not cpe_uri.startswith("cpe:2.3:"):
        return None

    try:
        parts = cpe_uri.split(":")
        if len(parts) >= 5:
            # cpe:2.3:a:vendor:product:...
            vendor = parts[3].lower().replace("_", " ")
            product = parts[4].lower().replace("_", " ")
            return (vendor, product)
    except Exception as e:
        logger.debug(f"CPE URI 파싱 실패: {cpe_uri}, err={e}")

    return None

def extract_cve_summary(
    vuln_item: Dict[str, Any],
    target_version: str = None,
    target_vendor: str = None,
    target_product: str = None,
    original_product: str = None
) -> Dict[str, Any]:
    """
    NVD v2 응답에서 CVE 요약 정보 추출

    Args:
        vuln_item: NVD API 응답 항목 또는 로컬 cve-search 응답
        target_version: 타겟 버전
        target_vendor: 타겟 벤더
        target_product: 타겟 제품명
        original_product: 원본 제품명 (매핑 전)

    Returns:
        CVE 요약 정보 딕셔너리
    """
    # 🆕 로컬 cve-search 형식 감지 및 변환
    if "id" in vuln_item and "cve" not in vuln_item:
        logger.debug(f"[MATCHER] Detected local cve-search format, converting to NVD format")
        
        # 🔥 CVSS 점수 추출 (CVE-Search API 대응 개선)
        cvss_score = None
        cvss_vector = ""
        
        # 1단계: CVSS v3 우선 추출
        if "cvss3" in vuln_item and vuln_item["cvss3"]:
            cvss_score = vuln_item["cvss3"]
            logger.debug(f"[MATCHER-CVSS] Using cvss3: {cvss_score}")
            if "cvss3Vector" in vuln_item:
                cvss_vector = vuln_item["cvss3Vector"]
        
        # 2단계: CVSS v2 폴백 (cvss 필드)
        if not cvss_score and "cvss" in vuln_item and vuln_item["cvss"]:
            cvss_score = vuln_item["cvss"]
            logger.debug(f"[MATCHER-CVSS] Fallback to cvss (v2): {cvss_score}")
            if "cvssVector" in vuln_item:
                cvss_vector = vuln_item["cvssVector"]
        
        # 3단계: cvss2 필드도 확인
        if not cvss_score and "cvss2" in vuln_item and vuln_item["cvss2"]:
            cvss_score = vuln_item["cvss2"]
            logger.debug(f"[MATCHER-CVSS] Fallback to cvss2: {cvss_score}")
        
        # 4단계: impact 구조에서 추출 시도 (NVD 형식)
        if not cvss_score and "impact" in vuln_item:
            impact = vuln_item["impact"]
            if "baseMetricV3" in impact:
                cvss_data = impact["baseMetricV3"].get("cvssV3", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString", "")
                logger.debug(f"[MATCHER-CVSS] Using impact.baseMetricV3: {cvss_score}")
            elif "baseMetricV2" in impact:
                cvss_data = impact["baseMetricV2"].get("cvssV2", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString", "")
                logger.debug(f"[MATCHER-CVSS] Using impact.baseMetricV2: {cvss_score}")
        
        # 5단계: 최종 확인 (None 체크)
        if not cvss_score:
            logger.warning(f"[MATCHER-CVSS] No CVSS found in vuln_item, available keys: {list(vuln_item.keys())}")
        
        # NVD API v2 형식으로 변환
        vuln_item = {
            "cve": {
                "id": vuln_item.get("id", "CVE-UNKNOWN"),
                "descriptions": [
                    {"lang": "en", "value": vuln_item.get("summary", "")}
                ],
                "metrics": {},
                "configurations": []
            }
        }
        
        # CVSS 메트릭 추가
        if cvss_score:
            vuln_item["cve"]["metrics"]["cvssMetricV31"] = [{
                "cvssData": {
                    "baseScore": cvss_score,
                    "vectorString": cvss_vector
                }
            }]
        
        # 취약한 설정 정보 추가
        if "vulnerable_configuration" in vuln_item:
            vuln_item["cve"]["configurations"] = [{
                "nodes": [{
                    "cpeMatch": [
                        {"vulnerable": True, "criteria": cpe}
                        for cpe in vuln_item["vulnerable_configuration"]
                    ]
                }]
            }]
    
    # 기존 코드 (그대로 유지)
    cve = vuln_item.get("cve", {})
    cve_id = cve.get("id")
    
    # 설명 추출
    descriptions = cve.get("descriptions", [])
    desc_text = ""
    for d in descriptions:
        if d.get("lang") == "en":
            desc_text = d.get("value", "")
            break
    
    # CVSS 점수 추출 (v31 > v30 > v2 순서)
    metrics = cve.get("metrics", {})
    cvss_score = None
    cvss_vector = None
    
    if "cvssMetricV31" in metrics:
        cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
        cvss_score = cvss_data["baseScore"]
        cvss_vector = cvss_data.get("vectorString", "")
    elif "cvssMetricV30" in metrics:
        cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
        cvss_score = cvss_data["baseScore"]
        cvss_vector = cvss_data.get("vectorString", "")
    elif "cvssMetricV2" in metrics:
        cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
        cvss_score = cvss_data["baseScore"]
        cvss_vector = cvss_data.get("vectorString", "")
    
    cvss_val = float(cvss_score) if cvss_score is not None else 0.0
    severity = cvss_to_severity(cvss_val)
    
    # 버전 매칭 및 신뢰도 계산
    is_vulnerable = False
    match_confidence = "none"
    vulnerable_ranges = []
    
    # 원본 product 이름 정규화
    normalized_original_product = None
    if original_product:
        normalized_original_product = normalize_product_name(original_product)
    
    configurations = cve.get("configurations", [])
    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable"):
                    continue
                
                # 버전 범위 정보 추출
                start_inc = cpe_match.get("versionStartIncluding")
                start_exc = cpe_match.get("versionStartExcluding")
                end_inc = cpe_match.get("versionEndIncluding")
                end_exc = cpe_match.get("versionEndExcluding")
                
                # 버전 범위 문자열 생성
                range_parts = []
                if start_inc:
                    range_parts.append(f">={start_inc}")
                elif start_exc:
                    range_parts.append(f">{start_exc}")
                
                if end_inc:
                    range_parts.append(f"<={end_inc}")
                elif end_exc:
                    range_parts.append(f"<{end_exc}")
                
                if range_parts:
                    range_text = " ".join(range_parts)
                else:
                    cpe_version = cpe_match.get("criteria", "").split(":")[-1] if ":" in cpe_match.get("criteria", "") else "*"
                    if cpe_version not in ["*", "-"]:
                        range_text = f"={cpe_version}"
                    else:
                        range_text = "모든 버전"
                
                if range_text not in vulnerable_ranges:
                    vulnerable_ranges.append(range_text)
                
                # CPE URI에서 vendor/product 추출
                cpe_uri = cpe_match.get("criteria", "")
                
                # === 1단계: vendor/product 정확 매칭 (최고 신뢰도) ===
                vendor_product_match = False
                confidence_level = "none"
                
                if target_vendor and target_product:
                    vendor_match = target_vendor.lower() in cpe_uri.lower()
                    product_match = target_product.lower() in cpe_uri.lower()
                    
                    if vendor_match and product_match:
                        vendor_product_match = True
                        confidence_level = "high"
                
                # === 2단계: CPE URI에서 추출한 정보로 매칭 (중간 신뢰도) ===
                if not vendor_product_match:
                    cpe_info = parse_cpe_uri(cpe_uri)
                    if cpe_info:
                        cpe_vendor, cpe_product = cpe_info
                        product_to_check = original_product or target_product
                        
                        if product_to_check:
                            normalized_product = normalize_product_name(product_to_check)
                            if (normalized_product in cpe_product or
                                cpe_product in normalized_product or
                                normalized_product == cpe_product):
                                vendor_product_match = True
                                confidence_level = "medium"
                
                # === 3단계: CVE 설명에서 원본 product 이름 확인 (낮은 신뢰도) ===
                description_match = False
                if not vendor_product_match and normalized_original_product:
                    desc_lower = desc_text.lower()
                    if normalized_original_product in desc_lower and len(normalized_original_product) >= 3:
                        description_match = True
                        confidence_level = "low"
                
                # === 최종 판단 ===
                if vendor_product_match or description_match:
                    # 버전 정보가 있으면 버전 범위도 확인
                    if target_version:
                        if is_version_vulnerable(target_version, cpe_match):
                            is_vulnerable = True
                            match_confidence = confidence_level
                            break
                    else:
                        # 버전이 없으면 매칭 성공만으로 판단
                        is_vulnerable = True
                        match_confidence = confidence_level
                        break
            
            if is_vulnerable:
                break
        
        if is_vulnerable:
            break
    
    return {
        "cve_id": cve_id,
        "description": desc_text,
        "cvss": cvss_val,
        "cvss_vector": cvss_vector,
        "severity": severity,
        "is_vulnerable": is_vulnerable,
        "match_confidence": match_confidence,
        "vulnerable_ranges": vulnerable_ranges,
    }


def is_version_vulnerable(target_version: str, cpe_match: dict) -> bool:
    """
    타겟 버전이 CVE의 영향 범위에 포함되는지 확인

    Args:
        target_version: 타겟 버전
        cpe_match: CPE 매치 정보

    Returns:
        취약 여부
    """
    if not target_version:
        return False

    if not VERSION_COMPARE_AVAILABLE:
        # packaging 모듈이 없으면 보수적 접근
        cpe_version = cpe_match.get("criteria", "").split(":")[-1] if ":" in cpe_match.get("criteria", "") else "*"
        if cpe_version in ["*", "-"]:
            return True
        return False

    try:
        target_ver = version.parse(target_version)
    except Exception as e:
        logger.debug(f"버전 파싱 실패: {target_version}, err={e}")
        return False

    start_inc = cpe_match.get("versionStartIncluding")
    start_exc = cpe_match.get("versionStartExcluding")
    end_inc = cpe_match.get("versionEndIncluding")
    end_exc = cpe_match.get("versionEndExcluding")

    # 버전 범위 정보가 없으면 CPE의 version 필드 확인
    if not any([start_inc, start_exc, end_inc, end_exc]):
        cpe_version = cpe_match.get("criteria", "").split(":")[-1] if ":" in cpe_match.get("criteria", "") else "*"
        if cpe_version in ["*", "-"]:
            return True
        try:
            cpe_ver = version.parse(cpe_version)
            return target_ver == cpe_ver
        except:
            return target_version == cpe_version

    # 하한선 체크
    if start_inc:
        try:
            if target_ver < version.parse(start_inc):
                return False
        except Exception as e:
            logger.debug(f"start_inc 파싱 실패: {start_inc}, err={e}")

    if start_exc:
        try:
            if target_ver <= version.parse(start_exc):
                return False
        except Exception as e:
            logger.debug(f"start_exc 파싱 실패: {start_exc}, err={e}")

    # 상한선 체크
    if end_inc:
        try:
            if target_ver > version.parse(end_inc):
                return False
        except Exception as e:
            logger.debug(f"end_inc 파싱 실패: {end_inc}, err={e}")

    if end_exc:
        try:
            if target_ver >= version.parse(end_exc):
                return False
        except Exception as e:
            logger.debug(f"end_exc 파싱 실패: {end_exc}, err={e}")

    return True

async def auto_discover_cpe_from_nvd(
    product_name: str,
    session: aiohttp.ClientSession,
    api_key: str = None
) -> Optional[str]:
    """
    NVD CPE Dictionary API로 제품명 → CPE 자동 변환

    Args:
        product_name: 제품명 (예: "OWASP Juice Shop", "Express", "nginx")
        session: aiohttp 세션
        api_key: NVD API 키

    Returns:
        CPE 문자열 또는 None
    """
    url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    params = {
        "keywordSearch": product_name,
        "resultsPerPage": 5
    }

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    try:
        async with session.get(url, params=params, headers=headers, timeout=10) as response:
            if response.status == 200:
                data = await response.json()
                products = data.get("products", [])

                if products:
                    # 첫 번째 매칭 결과 사용
                    cpe_name = products[0].get("cpe", {}).get("cpeName")
                    if cpe_name:
                        logger.info(f"[MATCHER] Auto-discovered CPE: {product_name} → {cpe_name}")
                        return cpe_name

                logger.warning(f"[MATCHER] No CPE found in NVD for: {product_name}")
                return None
            else:
                logger.error(f"[MATCHER] CPE discovery failed: HTTP {response.status}")
                return None

    except Exception as e:
        logger.error(f"[MATCHER] CPE discovery error: {e}")
        return None

async def search_cves_universal(
    product: str,
    version: str,
    nvd_client,
    cache_manager=None,
    max_results: int = 100
) -> List[Dict[str, Any]]:
    """
    CPE 기반 검색을 우선 시도하고, 실패 시 키워드 검색으로 폴백

    Args:
        product: 제품명
        version: 버전
        nvd_client: AsyncNvdClient 인스턴스
        cache_manager: CacheManager 인스턴스
        max_results: 최대 결과 수

    Returns:
        CVE 정보 리스트
    """
    # 블랙리스트 체크
    if is_blacklisted(product):
        logger.info(f"[MATCHER] Skipping blacklisted product: {product}")
        return []

    # CPE 생성 시도
    tech = {"product": product, "version": version}
    cpe = extract_cpe_from_tech(tech)

    all_cves = []

    if cpe:
        # CPE로 검색
        logger.info(f"[MATCHER] Searching with CPE: {cpe}")

        # 캐시 확인
        if cache_manager:
            cached = cache_manager.get(cpe)
            if cached is not None:
                logger.info(f"[MATCHER] Cache hit for CPE: {cpe}")
                return cached

        # NVD API 호출
        cves = await nvd_client.search_cves_by_cpe(cpe, max_results=max_results)

        if cves:
            logger.info(f"[MATCHER] Found {len(cves)} CVEs via CPE")
            # 캐시 저장
            if cache_manager:
                cache_manager.set(cpe, cves)
            return cves
        else:
            logger.info(f"[MATCHER] No CVEs found via CPE, trying keyword search")

    # 폴백: 키워드 검색
    keyword = f"{product} {version}".strip()
    logger.info(f"[MATCHER] Fallback to keyword search: {keyword}")

    # 캐시 확인
    if cache_manager:
        cached = cache_manager.get(keyword)
        if cached is not None:
            logger.info(f"[MATCHER] Cache hit for keyword: {keyword}")
            return cached

    # NVD API 호출
    cves = await nvd_client.search_cves_by_keyword(keyword, max_results=max_results)

    if cves:
        logger.info(f"[MATCHER] Found {len(cves)} CVEs via keyword")
        # 캐시 저장
        if cache_manager:
            cache_manager.set(keyword, cves)

    return cves

def cvss_to_severity(score: float) -> str:
    """
    CVSS 점수를 위험도 라벨로 변환

    Args:
        score: CVSS 점수 (0.0 ~ 10.0)

    Returns:
        위험도 라벨 (Critical/High/Medium/Low/None)
    """
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0:
        return "Low"
    else:
        return "None"

def deduplicate_cves(cves: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    CVE 중복 제거 (CVE ID 기준, CVSS 높은 것 우선)
    """
    seen = {}
    skipped_count = 0

    for idx, cve in enumerate(cves):
        # 🔥 핵심 수정: 두 가지 키 모두 시도
        cve_id = cve.get("cve_id") or cve.get("cveid")  # ← 이 줄만 수정!

        if not cve_id:
            skipped_count += 1
            logger.warning(f"[CVE-DEDUP] Skipping CVE without ID: keys={list(cve.keys())[:5]}")
            continue

        # 🔥 동일 CVE ID면 CVSS 높은 것만 유지
        if cve_id in seen:
            existing_cvss = seen[cve_id].get("cvss", 0) or seen[cve_id].get("cvss_score", 0)
            new_cvss = cve.get("cvss", 0) or cve.get("cvss_score", 0)

            # float 변환
            try:
                existing_cvss = float(existing_cvss) if existing_cvss else 0.0
                new_cvss = float(new_cvss) if new_cvss else 0.0
            except (ValueError, TypeError):
                existing_cvss = 0.0
                new_cvss = 0.0

            if new_cvss > existing_cvss:
                seen[cve_id] = cve
                logger.debug(f"[CVE-DEDUP] Updated {cve_id}: CVSS {existing_cvss} -> {new_cvss}")
        else:
            seen[cve_id] = cve
            logger.debug(f"[CVE-DEDUP] Added {cve_id}")

    logger.info(f"[CVE-DEDUP] Skipped {skipped_count} CVEs without ID")
    logger.info(f"[CVE-DEDUP] Deduplication: {len(cves)} -> {len(seen)} unique CVEs")

    return list(seen.values())
```
---

## File 11: distributor.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\distributor.py`

```python
import subprocess
import os
import math
import logging

logger = logging.getLogger(__name__)

def spawn_workers(target_list, worker_count=6): # 20에서 8로 하향 조정
    total_targets = len(target_list)
    if total_targets == 0:
        return
        
    result_dir = os.path.abspath("./scan_results")
    if not os.path.exists(result_dir):
        os.makedirs(result_dir)
        
    chunk_size = math.ceil(total_targets / worker_count)
    print(f"[*] 총 {total_targets}개 타겟을 {worker_count}개 워커로 분산합니다.")

    for i in range(worker_count):
        start_idx = i * chunk_size
        end_idx = start_idx + chunk_size
        batch = target_list[start_idx:end_idx]

        if not batch:
            break

        worker_name = f"scanner-worker-{i+1}"
        target_str = ",".join(batch)

        docker_cmd = [
            "docker", "run", "-d",
            "--name", worker_name,
            "-v", f"{result_dir}:/app/results",
            "-e", f"TARGET_URLS={target_str}",
            "my-scanner-image:latest"
        ]

        try:
            subprocess.run(["docker", "rm", "-f", worker_name], capture_output=True)
            subprocess.run(docker_cmd)
            print(f"[+] {worker_name} 가동 시작 (할당: {len(batch)}개 타겟)")
        except Exception as e:
            print(f"[!] {worker_name} 실행 실패: {e}")

    print("[✅] 6워커 최적화 배치가 완료되었습니다.")
```
---

## File 12: __init__.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\exploit\__init__.py`

```python
# app/core/exploit/__init__.py

from .verifier import ExploitVerifier
from .web_vulnerabilities import WebVulnerabilityScanner
from .attack_chain import AttackChainBuilder, Vulnerability, AttackStep, AttackPath
from .latest_vectors import LatestAttackVectors
from .auth_session import AuthSessionTester
from .db_advanced import AdvancedDatabaseAttacks

__all__ = [
    'ExploitVerifier',
    'WebVulnerabilityScanner',
    'AttackChainBuilder',
    'Vulnerability',
    'AttackStep',
    'AttackPath',
    'LatestAttackVectors',
    'AuthSessionTester',
    'AdvancedDatabaseAttacks'
]

```
---

## File 13: advanced_verification.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\exploit\advanced_verification.py`

```python
# app/core/exploit/advanced_verification.py
# 다단계 검증 및 컨텍스트 인식 탐지

import time
import random
import statistics
import logging
from typing import Dict, Any, List, Optional
import requests

logger = logging.getLogger(__name__)


class AdvancedVerification:
    """
    다단계 검증 및 컨텍스트 인식 탐지
    """
    
    def __init__(self, min_samples: int = 3, confidence_threshold: float = 0.8):
        """
        Args:
            min_samples: 최소 샘플 수 (통계적 유의성)
            confidence_threshold: 신뢰도 임계값
        """
        self.min_samples = min_samples
        self.confidence_threshold = confidence_threshold
    
    def verify_time_based_sqli(
        self,
        url: str,
        payload: str,
        expected_delay: float = 5.0,
        samples: int = 5
    ) -> Dict[str, Any]:
        """
        Time-based SQL Injection 다단계 검증
        
        여러 번 반복 측정하여 통계적 유의성 확인
        """
        delays = []
        status_codes = []
        content_lengths = []
        
        for i in range(samples):
            try:
                start = time.time()
                response = requests.get(
                    url,
                    params={"id": payload},
                    timeout=expected_delay + 5,
                    verify=False
                )
                elapsed = time.time() - start
                
                delays.append(elapsed)
                status_codes.append(response.status_code)
                content_lengths.append(len(response.content))
                
                # 랜덤 딜레이 (Rate Limiting 대응)
                time.sleep(random.uniform(0.5, 1.5))
                
            except Exception as e:
                logger.debug(f"Time-based SQLi 검증 샘플 {i+1} 실패: {e}")
                continue
        
        if len(delays) < self.min_samples:
            return {
                "verified": False,
                "reason": f"충분한 샘플 수집 실패 (수집: {len(delays)}, 필요: {self.min_samples})"
            }
        
        # 통계 분석
        mean_delay = statistics.mean(delays)
        median_delay = statistics.median(delays)
        std_dev = statistics.stdev(delays) if len(delays) > 1 else 0
        
        # 신뢰도 계산
        delay_diff = abs(mean_delay - expected_delay)
        confidence = 1.0 - min(1.0, delay_diff / expected_delay)
        
        # 컨텍스트 분석
        status_consistent = len(set(status_codes)) == 1
        content_stable = max(content_lengths) - min(content_lengths) < 100
        
        # 최종 판단
        is_vulnerable = (
            mean_delay >= expected_delay * 0.9 and  # 90% 이상 지연
            confidence >= self.confidence_threshold and  # 신뢰도 임계값 이상
            std_dev < expected_delay * 0.3  # 표준편차가 작음 (일관성)
        )
        
        return {
            "verified": is_vulnerable,
            "confidence": confidence,
            "statistics": {
                "mean_delay": mean_delay,
                "median_delay": median_delay,
                "std_dev": std_dev,
                "samples": len(delays),
                "expected_delay": expected_delay
            },
            "context": {
                "status_consistent": status_consistent,
                "content_stable": content_stable,
                "status_codes": status_codes,
                "content_lengths": content_lengths
            }
        }
    
    def verify_error_based_sqli(
        self,
        url: str,
        payload: str,
        error_patterns: List[str]
    ) -> Dict[str, Any]:
        """
        Error-based SQL Injection 컨텍스트 인식 탐지
        
        HTTP 상태 코드, 응답 시간, 콘텐츠 길이 변화 종합 분석
        """
        try:
            # 정상 요청 (베이스라인)
            baseline_response = requests.get(
                url,
                params={"id": "1"},
                timeout=10,
                verify=False
            )
            baseline_status = baseline_response.status_code
            baseline_length = len(baseline_response.content)
            baseline_time = baseline_response.elapsed.total_seconds()
            
            # 페이로드 요청
            payload_response = requests.get(
                url,
                params={"id": payload},
                timeout=10,
                verify=False
            )
            payload_status = payload_response.status_code
            payload_length = len(payload_response.content)
            payload_time = payload_response.elapsed.total_seconds()
            
            # 컨텍스트 분석
            status_changed = baseline_status != payload_status
            length_changed = abs(baseline_length - payload_length) > 100
            time_changed = abs(baseline_time - payload_time) > 1.0
            
            # 에러 패턴 매칭
            error_found = False
            matched_pattern = None
            response_text = payload_response.text.lower()
            
            for pattern in error_patterns:
                if pattern.lower() in response_text:
                    error_found = True
                    matched_pattern = pattern
                    break
            
            # 신뢰도 계산
            confidence = 0.0
            if error_found:
                confidence += 0.5
            if status_changed:
                confidence += 0.2
            if length_changed:
                confidence += 0.2
            if time_changed:
                confidence += 0.1
            
            is_vulnerable = confidence >= self.confidence_threshold
            
            return {
                "verified": is_vulnerable,
                "confidence": confidence,
                "error_found": error_found,
                "matched_pattern": matched_pattern,
                "context": {
                    "status_changed": status_changed,
                    "length_changed": length_changed,
                    "time_changed": time_changed,
                    "baseline": {
                        "status": baseline_status,
                        "length": baseline_length,
                        "time": baseline_time
                    },
                    "payload": {
                        "status": payload_status,
                        "length": payload_length,
                        "time": payload_time
                    }
                }
            }
            
        except requests.Timeout as e:
            logger.warning(f"Timeout during error-based SQLi verification: {url}")
            return {
                "verified": False,
                "error": f"Timeout: {str(e)}"
            }
        except requests.ConnectionError as e:
            logger.error(f"Connection error during error-based SQLi verification: {e}")
            return {
                "verified": False,
                "error": f"Connection error: {str(e)}"
            }
        except Exception as e:
            logger.exception(f"Unexpected error during error-based SQLi verification: {e}")
            return {
                "verified": False,
                "error": str(e)
            }
    
    def verify_boolean_based_sqli(
        self,
        url: str,
        parameter: str,
        true_payload: str,
        false_payload: str,
        samples: int = 3
    ) -> Dict[str, Any]:
        """
        Boolean-based Blind SQL Injection 다단계 검증
        
        Args:
            url: 기본 URL
            parameter: 파라미터 이름
            true_payload: True 조건 페이로드
            false_payload: False 조건 페이로드
            samples: 샘플 수
        """
        from urllib.parse import quote
        
        true_responses = []
        false_responses = []
        
        for i in range(samples):
            try:
                # True 조건
                true_response = requests.get(
                    url,
                    params={parameter: true_payload},
                    timeout=10,
                    verify=False
                )
                true_responses.append({
                    "length": len(true_response.content),
                    "status": true_response.status_code,
                    "time": true_response.elapsed.total_seconds()
                })
                
                time.sleep(random.uniform(0.5, 1.0))
                
                # False 조건
                false_response = requests.get(
                    url,
                    params={parameter: false_payload},
                    timeout=10,
                    verify=False
                )
                false_responses.append({
                    "length": len(false_response.content),
                    "status": false_response.status_code,
                    "time": false_response.elapsed.total_seconds()
                })
                
                time.sleep(random.uniform(0.5, 1.0))
                
            except Exception as e:
                logger.debug(f"Boolean-based SQLi 검증 샘플 {i+1} 실패: {e}")
                continue
        
        if len(true_responses) < self.min_samples or len(false_responses) < self.min_samples:
            return {
                "verified": False,
                "reason": "충분한 샘플 수집 실패"
            }
        
        # 통계 분석
        true_lengths = [r["length"] for r in true_responses]
        false_lengths = [r["length"] for r in false_responses]
        
        true_mean = statistics.mean(true_lengths)
        false_mean = statistics.mean(false_lengths)
        
        length_diff = abs(true_mean - false_mean)
        length_diff_ratio = length_diff / max(true_mean, false_mean) if max(true_mean, false_mean) > 0 else 0
        
        # 신뢰도 계산
        confidence = min(1.0, length_diff_ratio * 2)  # 차이가 클수록 높은 신뢰도
        
        is_vulnerable = (
            length_diff > 100 and  # 최소 100바이트 차이
            confidence >= self.confidence_threshold
        )
        
        return {
            "verified": is_vulnerable,
            "confidence": confidence,
            "statistics": {
                "true_mean_length": true_mean,
                "false_mean_length": false_mean,
                "length_difference": length_diff,
                "samples": len(true_responses)
            }
        }

```
---

## File 14: attack_chain.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\exploit\attack_chain.py`

```python
# app/core/exploit/attack_chain.py
# 익스플로잇 체인 구축 및 Attack Path Analysis

import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class Vulnerability:
    """취약점 정보"""
    cve_id: Optional[str] = None
    type: str = ""
    severity: str = "MEDIUM"
    cvss_score: float = 0.0
    cvss_vector: str = ""
    description: str = ""
    exploit_verified: bool = False
    confidence: float = 0.0
    affected_component: str = ""
    attack_vector: str = ""


@dataclass
class AttackStep:
    """공격 단계"""
    step_id: int = 0
    vulnerability: Vulnerability = field(default_factory=Vulnerability)
    required_access: str = "None"  # None, Low, Medium, High, Root
    gained_access: str = "None"
    description: str = ""
    prerequisites: List[int] = field(default_factory=list)  # 선행 단계 ID


@dataclass
class AttackPath:
    """공격 경로"""
    path_id: str = ""
    steps: List[AttackStep] = field(default_factory=list)
    total_cvss: float = 0.0
    feasibility: float = 0.0
    impact: str = ""


class AttackChainBuilder:
    """
    익스플로잇 체인 구축 및 Attack Path Analysis
    """
    
    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []
        self.attack_paths: List[AttackPath] = []
    
    def add_vulnerability(self, vuln: Vulnerability):
        """취약점 추가"""
        self.vulnerabilities.append(vuln)
    
    def generate_cvss_vector(self, vuln: Vulnerability) -> str:
        """
        CVSS 3.1 벡터 문자열 생성
        
        Args:
            vuln: 취약점 정보
        
        Returns:
            CVSS 벡터 문자열 (예: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        """
        # Attack Vector
        if vuln.attack_vector:
            av = vuln.attack_vector[:1]  # N, A, L, P
        else:
            av = "N"  # Network (기본값)
        
        # Attack Complexity
        if vuln.detection_method == "time_based" or vuln.detection_method == "boolean_based":
            ac = "H"  # High (복잡함)
        else:
            ac = "L"  # Low
        
        # Privileges Required
        pr = "N"  # None (기본값)
        
        # User Interaction
        ui = "N"  # None (기본값)
        
        # Scope
        s = "U"  # Unchanged (기본값)
        
        # Confidentiality Impact
        if vuln.severity == "CRITICAL":
            c = "H"
        elif vuln.severity == "HIGH":
            c = "H"
        elif vuln.severity == "MEDIUM":
            c = "L"
        else:
            c = "N"
        
        # Integrity Impact
        i = c  # 동일하게 설정
        
        # Availability Impact
        if "DoS" in vuln.type or "Denial" in vuln.type:
            a = "H"
        else:
            a = "N"
        
        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
        return vector
    
    def calculate_cvss(self, vuln: Vulnerability) -> float:
        """
        CVSS 3.1 스코어 계산 (개선된 버전)
        
        실제로는 CVSS 계산 라이브러리 사용 권장
        """
        # CVSS 벡터가 없으면 생성
        if not vuln.cvss_vector:
            vuln.cvss_vector = self.generate_cvss_vector(vuln)
        
        # 실제 CVSS 라이브러리 사용 시도
        try:
            from cvss import CVSS3
            
            c = CVSS3(vuln.cvss_vector)
            return c.base_score
        except ImportError:
            logger.debug("cvss 라이브러리가 없어 기본 계산 사용")
        except Exception as e:
            logger.debug(f"CVSS 라이브러리 사용 실패: {e}")
        
        # Fallback: 개선된 계산
        severity_scores = {
            "CRITICAL": 9.0,
            "HIGH": 7.5,
            "MEDIUM": 5.0,
            "LOW": 3.5
        }
        
        base_score = severity_scores.get(vuln.severity, 5.0)
        
        # Attack Vector 가중치
        av_weights = {
            "NETWORK": 0.85,
            "ADJACENT": 0.62,
            "LOCAL": 0.55,
            "PHYSICAL": 0.2
        }
        
        av_weight = av_weights.get(vuln.attack_vector, 0.85)
        base_score *= av_weight
        
        # Exploit 검증 보너스
        if vuln.exploit_verified:
            base_score = min(10.0, base_score + 0.5)
        
        # Confidence 보정 (0.7 ~ 1.0 범위)
        confidence_factor = 0.7 + 0.3 * vuln.confidence
        base_score *= confidence_factor
        
        return min(10.0, max(0.0, base_score))
    
    def build_attack_paths(self) -> List[AttackPath]:
        """
        공격 경로 자동 구축
        
        정보 노출 → 권한 상승 → RCE로 이어지는 경로 매핑
        """
        paths = []
        
        # 1단계: 정보 노출 취약점 찾기
        info_disclosure = [v for v in self.vulnerabilities if self._is_info_disclosure(v)]
        
        # 2단계: 권한 상승 취약점 찾기
        privilege_escalation = [v for v in self.vulnerabilities if self._is_privilege_escalation(v)]
        
        # 3단계: RCE 취약점 찾기
        rce_vulns = [v for v in self.vulnerabilities if self._is_rce(v)]
        
        # 경로 1: 정보 노출 → RCE
        for info_vuln in info_disclosure:
            for rce_vuln in rce_vulns:
                path = AttackPath(
                    path_id=f"INFO_TO_RCE_{len(paths)}",
                    steps=[
                        AttackStep(
                            step_id=1,
                            vulnerability=info_vuln,
                            required_access="None",
                            gained_access="Low",
                            description="정보 노출을 통한 초기 접근",
                            prerequisites=[]
                        ),
                        AttackStep(
                            step_id=2,
                            vulnerability=rce_vuln,
                            required_access="Low",
                            gained_access="Root",
                            description="RCE를 통한 완전한 시스템 제어",
                            prerequisites=[1]
                        )
                    ],
                    total_cvss=self.calculate_cvss(info_vuln) + self.calculate_cvss(rce_vuln),
                    feasibility=self._calculate_feasibility([info_vuln, rce_vuln]),
                    impact="CRITICAL"
                )
                paths.append(path)
        
        # 경로 2: 정보 노출 → 권한 상승 → RCE
        for info_vuln in info_disclosure:
            for priv_vuln in privilege_escalation:
                for rce_vuln in rce_vulns:
                    path = AttackPath(
                        path_id=f"INFO_TO_PRIV_TO_RCE_{len(paths)}",
                        steps=[
                            AttackStep(
                                step_id=1,
                                vulnerability=info_vuln,
                                required_access="None",
                                gained_access="Low",
                                description="정보 노출",
                                prerequisites=[]
                            ),
                            AttackStep(
                                step_id=2,
                                vulnerability=priv_vuln,
                                required_access="Low",
                                gained_access="High",
                                description="권한 상승",
                                prerequisites=[1]
                            ),
                            AttackStep(
                                step_id=3,
                                vulnerability=rce_vuln,
                                required_access="High",
                                gained_access="Root",
                                description="RCE",
                                prerequisites=[2]
                            )
                        ],
                        total_cvss=(
                            self.calculate_cvss(info_vuln) +
                            self.calculate_cvss(priv_vuln) +
                            self.calculate_cvss(rce_vuln)
                        ),
                        feasibility=self._calculate_feasibility([info_vuln, priv_vuln, rce_vuln]),
                        impact="CRITICAL"
                    )
                    paths.append(path)
        
        # CVSS 점수로 정렬
        paths.sort(key=lambda p: p.total_cvss, reverse=True)
        
        self.attack_paths = paths
        return paths
    
    def _is_info_disclosure(self, vuln: Vulnerability) -> bool:
        """정보 노출 취약점 판단"""
        info_types = [
            "LFI", "Path Traversal", "XXE", "SSRF",
            "Information Disclosure", "Directory Listing"
        ]
        return any(t in vuln.type for t in info_types)
    
    def _is_privilege_escalation(self, vuln: Vulnerability) -> bool:
        """권한 상승 취약점 판단"""
        priv_types = [
            "Broken Authentication", "Session Fixation",
            "IDOR", "Privilege Escalation"
        ]
        return any(t in vuln.type for t in priv_types)
    
    def _is_rce(self, vuln: Vulnerability) -> bool:
        """RCE 취약점 판단"""
        rce_types = [
            "Command Injection", "Code Injection", "RCE",
            "SSTI", "Deserialization", "Log4Shell"
        ]
        return any(t in vuln.type for t in rce_types)
    
    def _calculate_feasibility(self, vulns: List[Vulnerability]) -> float:
        """공격 경로의 실행 가능성 계산"""
        if not vulns:
            return 0.0
        
        # 모든 취약점이 검증되었는지
        all_verified = all(v.exploit_verified for v in vulns)
        
        # 평균 신뢰도
        avg_confidence = sum(v.confidence for v in vulns) / len(vulns)
        
        # 실행 가능성 = (검증 여부 * 0.5) + (신뢰도 * 0.5)
        feasibility = (1.0 if all_verified else 0.5) * 0.5 + avg_confidence * 0.5
        
        return feasibility
    
    def get_critical_paths(self, limit: int = 5) -> List[AttackPath]:
        """가장 위험한 공격 경로 반환"""
        if not self.attack_paths:
            self.build_attack_paths()
        
        return self.attack_paths[:limit]
    
    def generate_post_exploitation_scenarios(self, initial_access: str) -> List[Dict[str, Any]]:
        """
        Post-Exploitation 시뮬레이션
        
        권한 획득 후 추가 정찰 및 피벗팅 시나리오
        """
        scenarios = []
        
        if initial_access in ["Low", "Medium", "High", "Root"]:
            # 시나리오 1: 추가 정보 수집
            scenarios.append({
                "scenario": "Information Gathering",
                "steps": [
                    "Enumerate system information",
                    "Check for sensitive files",
                    "Search for credentials",
                    "Identify network topology"
                ],
                "impact": "MEDIUM"
            })
            
            # 시나리오 2: 권한 상승 시도
            if initial_access != "Root":
                scenarios.append({
                    "scenario": "Privilege Escalation",
                    "steps": [
                        "Check for SUID binaries",
                        "Analyze running processes",
                        "Check for misconfigured services",
                        "Search for kernel exploits"
                    ],
                    "impact": "HIGH"
                })
            
            # 시나리오 3: 피벗팅
            scenarios.append({
                "scenario": "Pivoting",
                "steps": [
                    "Map internal network",
                    "Identify additional targets",
                    "Establish persistent access",
                    "Lateral movement"
                ],
                "impact": "HIGH"
            })
        
        return scenarios

```
---

## File 15: auth_session.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\core\exploit\auth_session.py`

```python
# app/core/exploit/auth_session.py
# 인증 및 세션 관리 테스트

import requests
import time
import re
import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


class AuthSessionTester:
    """
    인증 및 세션 관리 취약점 테스트
    """
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    def test_broken_authentication(self, url: str) -> Dict[str, Any]:
        """
        Broken Authentication 테스트
        
        패스워드 정책, 세션 타임아웃, 다중 로그인 테스트
        """
        vulnerabilities = []
        
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            # 1. 약한 패스워드 정책 테스트
            weak_passwords = [
                "password", "123456", "admin", "root",
                "test", "12345", "qwerty", "letmein"
            ]
            
            login_endpoints = ["/login", "/signin", "/auth", "/api/login"]
            
            for endpoint in login_endpoints:
                try:
                    login_url = urljoin(base_url, endpoint)
                    
                    # 약한 패스워드로 로그인 시도
                    for password in weak_passwords[:5]:
                        try:
                            response = requests.post(
                                login_url,
                                data={"username": "admin", "password": password},
                                timeout=self.timeout,
                                verify=False,
                                headers={"User-Agent": self.user_agent},
                                allow_redirects=False
                            )
                            
                            # 로그인 성공 확인
                            if response.status_code in [200, 302, 301]:
                                if "dashboard" in response.text.lower() or "welcome" in response.text.lower():
                                    vulnerabilities.append({
                                        "type": "Weak Password Policy",
                                        "endpoint": endpoint,
                                        "password": password,
                                        "severity": "HIGH",
                                        "details": "Weak password accepted"
                                    })
                                    break
                        except requests.Timeout:
                            logger.warning(f"Timeout during authentication test: {login_url}")
                            continue
                        except requests.ConnectionError as e:
                            logger.error(f"Connection error: {e}")
                            continue
                        except Exception as e:
                            logger.exception(f"Unexpected error during authentication test: {e}")
                            continue
                        except requests.Timeout:
                            logger.warning(f"Timeout during OAuth test: {oauth_url}")
                            continue
                        except requests.ConnectionError as e:
                            logger.error(f"Connection error: {e}")
                            continue
                        except Exception as e:
                            logger.exception(f"Unexpected error during OAuth test: {e}")
                            continue
            
            # 2. 세션 타임아웃 테스트
            try:
                # 로그인 후 세션 쿠키 획득
                session = requests.Session()
                login_response = session.post(
                    urljoin(base_url, "/login"),
                    data={"username": "test", "password": "test"},
                    timeout=self.timeout,
                    verify=False
                )
                
                # 세션 쿠키가 있으면 타임아웃 테스트
                if session.cookies:
                    # 1시간 후에도 세션이 유효한지 확인 (실제로는 시간이 걸리므로 간단히 체크)
                    vulnerabilities.append({
                        "type": "Session Timeout Test",
                        "severity": "MEDIUM",
                        "details": "Session timeout configuration needs manual verification",
                        "note": "Requires time-based testing"
                    })
            except:
                pass
            
            # 3. 다중 로그인 테스트
            try:
                session1 = requests.Session()
                session2 = requests.Session()
                
                # 두 세션으로 동시 로그인 시도
                login_url = urljoin(base_url, "/login")
                session1.post(login_url, data={"username": "user1", "password": "pass1"}, verify=False)
                session2.post(login_url, data={"username": "user1", "password": "pass1"}, verify=False)
                
                # 두 세션이 모두 유효하면 다중 로그인 허용
                if session1.cookies and session2.cookies:
                    vulnerabilities.append({
                        "type": "Multiple Login Sessions",
                        "severity": "MEDIUM",
                        "details": "Multiple concurrent sessions allowed for same user"
                    })
            except:
                pass
                
        except Exception as e:
            logger.warning(f"Broken Authentication 테스트 실패: {e}")
        
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerabilities": vulnerabilities,
            "tested": True
        }
    
    def test_oauth_oidc(self, url: str) -> Dict[str, Any]:
        """
        OAuth/OIDC 취약점 테스트
        
        리다이렉션 조작, state 파라미터 검증, 토큰 탈취 시나리오
        """
        vulnerabilities = []
        
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            # OAuth 엔드포인트 찾기
            oauth_endpoints = [
                "/oauth/authorize",
                "/oauth2/authorize",
                "/auth/oauth",
                "/login/oauth"
            ]
            
            for endpoint in oauth_endpoints:
                try:
                    oauth_url = urljoin(base_url, endpoint)
                    
                    # 1. Open Redirect 테스트
                    redirect_urls = [
                        "http://evil.com",
                        "https://attacker.com/callback",
                        "javascript:alert(1)"
                    ]
                    
                    for redirect in redirect_urls:
                        try:
                            response = requests.get(
                                oauth_url,
                                params={
                                    "client_id": "test",
                                    "redirect_uri": redirect,
                                    "response_type": "code",
                                    "state": "test"
                                },
                                timeout=self.timeout,
                                verify=False,
                                allow_redirects=False,
                                headers={"User-Agent": self.user_agent}
                            )
                            
                            # 리다이렉션 허용 확인
                            if response.status_code in [301, 302, 307, 308]:
                                location = response.headers.get("Location", "")
                                if redirect in location or "evil.com" in location:
                                    vulnerabilities.append({
                                        "type": "OAuth Open Redirect",
                                        "endpoint": endpoint,
                                        "redirect_uri": redirect,
                                        "severity": "HIGH",
                                        "details": "Unvalidated redirect URI"
                                    })
                                    break
                        except requests.Timeout:
                            logger.warning(f"Timeout during authentication test: {login_url}")
                            continue
                        except requests.ConnectionError as e:
                            logger.error(f"Connection error: {e}")
                            continue
                        except Exception as e:
                            logger.exception(f"Unexpected error during authentication test: {e}")
                            continue
                    
                    # 2. State 파라미터 검증 테스트
                    try:
                        # State 파라미터 없이 요청
                        response_no_state = requests.get(
                            oauth_url,
                            params={
                                "client_id": "test",
                                "redirect_uri": "http://localhost",
                                "response_type": "code"
                            },
                            timeout=self.timeout,
                            verify=False,
                            headers={"User-Agent": self.user_agent}
                        )
                        
                        if response_no_state.status_code == 200:
                            vulnerabilities.append({
                                "type": "OAuth Missing State Parameter",
                                "endpoint": endpoint,
                                "severity": "MEDIUM",
                                "details": "State parameter not required or validated"
                            })
                    except requests.Timeout:
                        logger.warning("Timeout during state parameter test")
                    except requests.ConnectionError as e:
                        logger.error(f"Connection error: {e}")
                    except Exception as e:
                        logger.exception(f"Unexpected error during state parameter test: {e}")
                    
                    if vulnerabilities:
                        break
                        
                        except requests.Timeout:
                            logger.warning(f"Timeout during OAuth test: {oauth_url}")
                            continue
                        except requests.ConnectionError as e:
                            logger.error(f"Connection error: {e}")
                            continue
                        except Exception as e:
                            logger.exception(f"Unexpected error during OAuth test: {e}")
                            continue
                    
        except Exception as e:
            logger.warning(f"OAuth/OIDC 테스트 실패: {e}")
        
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerabilities": vulnerabilities,
            "tested": True
        }
    
    def test_api_keys(self, url: str) -> Dict[str, Any]:
        """
        API 키 및 토큰 관리 테스트
        
        하드코딩된 시크릿 탐지, 토큰 만료 검증
        """
        vulnerabilities = []
        
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            # JavaScript 파일에서 API 키 검색
            js_files = [
                "/static/js/app.js",
                "/js/main.js",
                "/assets/app.js",
                "/bundle.js"
            ]
            
            api_key_patterns = [
                r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)',
                r'apikey["\']?\s*[:=]\s*["\']([^"\']+)',
                r'secret["\']?\s*[:=]\s*["\']([^"\']+)',
                r'token["\']?\s*[:=]\s*["\']([^"\']+)',
                r'AKIA[0-9A-Z]{16}',  # AWS Access Key
                r'sk_live_[0-9a-zA-Z]{24}',  # Stripe Secret Key
                r'AIza[0-9A-Za-z-_]{35}',  # Google API Key
            ]
            
            for js_file in js_files:
                try:
                    js_url = urljoin(base_url, js_file)
                    response = requests.get(
                        js_url,
                        timeout=self.timeout,
                        verify=False,
                        headers={"User-Agent": self.user_agent}
                    )
                    
                    if response.status_code == 200:
                        content = response.text
                        
                        for pattern in api_key_patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            if matches:
                                vulnerabilities.append({
                                    "type": "Hardcoded API Key/Secret",
                                    "file": js_file,
                                    "pattern": pattern,
                                    "severity": "CRITICAL",
                                    "details": f"Potential API key found in {js_file}"
                                })
                                break
                        except requests.Timeout:
                            logger.warning(f"Timeout during OAuth test: {oauth_url}")
                            continue
                        except requests.ConnectionError as e:
                            logger.error(f"Connection error: {e}")
                            continue
                        except Exception as e:
                            logger.exception(f"Unexpected error during OAuth test: {e}")
                            continue
            
            # HTML 소스에서도 검색
            try:
                response = requests.get(
                    base_url,
                    timeout=self.timeout,
                    verify=False,
                    headers={"User-Agent": self.user_agent}
                )
                
                html_content = response.text
                for pattern in api_key_patterns:
                    matches = re.findall(pattern, html_content, re.IGNORECASE)
                    if matches:
                        vulnerabilities.append({
                            "type": "Hardcoded API Key/Secret in HTML",
                            "severity": "CRITICAL",
                            "details": "API key found in page source"
                        })
                        break
            except:
                pass
                
        except Exception as e:
            logger.warning(f"API Key 테스트 실패: {e}")
        
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerabilities": vulnerabilities,
            "tested": True
        }

```
---

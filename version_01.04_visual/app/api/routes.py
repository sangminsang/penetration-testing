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

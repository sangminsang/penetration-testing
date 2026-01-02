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

# app/api/routes.py의 async_scan_workflow 함수 전체 (ZAP 통합 버전)

async def async_scan_workflow(target: str):
    """
    통합 취약점 스캔 워크플로우 (Nmap + CVE + ZAP + AI)
    """
    from ..core.recon.network import run_recon
    from ..core.recon.web import collect_web_info
    from ..core.cve.cpe_generator import batch_generate_cpes
    from ..core.cve.async_nvd_client import AsyncNvdClient
    from ..core.verifier import VulnerabilityVerifier
    from ..core.scenario.generator import build_prompt, call_ollama
    from ..utils.exploit import search_exploits_for_cves
    from ..core.scanner.zap_scanner import ZapScanner, format_alerts_for_dashboard
    
    logger.info("="*70)
    logger.info(f"WORKFLOW: Starting comprehensive scan for {target}")
    logger.info("="*70)
    
    # ========== Step 1: Nmap 스캔 ==========
    print(f"WORKFLOW: Step 1 - Running Nmap scan on {target}...")
    logger.info(f"WORKFLOW: Step 1 - Nmap scan starting")
    recon_result = run_recon(target)
    print(f"WORKFLOW: Found {len(recon_result)} hosts")
    logger.info(f"WORKFLOW: Nmap found {len(recon_result)} hosts")
    
    # ========== Step 2: Web Recon ==========
    print(f"WORKFLOW: Step 2 - Running web reconnaissance...")
    logger.info("WORKFLOW: Step 2 - Web recon starting")
    web_info = {}
    os_info = {}
    network_info = {}
    database_info = {}
    cloud_info = {}
    container_info = {}

    try:
        web_info = collect_web_info(target)
        
        # ===== 수정: web_technologies 키 확인 =====
        web_technologies = web_info.get('webtechnologies', [])  # ⭐ 변수명 web_technologies (밑줄 포함!)
        print(f"DEBUG: Type of web_technologies: {type(web_technologies)}")
        print(f"DEBUG: web_technologies content: {web_technologies[:3] if len(web_technologies) > 0 else 'empty'}")
        print(f"WORKFLOW: Web recon completed - Found {len(web_technologies)} technologies")

        
        # ===== 디버깅: web_info 구조 확인 =====
        print(f"DEBUG: web_info keys = {list(web_info.keys())}")
        
    except Exception as e:
        logger.exception(f"Web recon failed: {e}")
        print(f"WORKFLOW: Web recon failed: {e}")
        web_techs = []


    # ========== Step 3: OS/Network/Database/Cloud/Container 정보 수집 ==========
    print(f"WORKFLOW: Step 3 - Collecting additional infrastructure info...")
    logger.info("WORKFLOW: Step 3 - Infrastructure detection")

    try:
        from ..core.recon.os import detect_os
        os_info = detect_os(recon_result, web_info)
    except Exception as e:
        logger.warning(f"OS detection failed: {e}")
        os_info = {}

    try:
        from ..core.recon.network import detect_network_devices
        network_info = detect_network_devices(recon_result)
    except Exception as e:
        logger.warning(f"Network detection failed: {e}")
        network_info = {}

    try:
        from ..core.recon.database import detect_databases
        database_info = detect_databases(recon_result, web_info)
    except Exception as e:
        logger.warning(f"Database detection failed: {e}")
        database_info = {}

    try:
        from ..core.recon.cloud import detect_cloud_services
        cloud_info = detect_cloud_services(target, web_info)
    except Exception as e:
        logger.warning(f"Cloud detection failed: {e}")
        cloud_info = {}

    try:
        from ..core.recon.container import detect_containers
        container_info = detect_containers(recon_result, web_info)
    except Exception as e:
        logger.warning(f"Container detection failed: {e}")
        container_info = {}

    print(f"WORKFLOW: Infrastructure detection completed")

    # ========== Step 4: CPE 생성 ==========
    print(f"WORKFLOW: Step 4 - Generating CPE identifiers...")
    logger.info("WORKFLOW: Step 4 - CPE generation")

    technologies_with_cpe = []

    # Nmap 결과에서 기술 스택 추출
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

    if web_info and 'webtechnologies' in web_info:  # ⭐ 밑줄 제거!
        web_techs = web_info['webtechnologies']  # ⭐ 밑줄 제거!
        print(f"DEBUG: Found {len(web_techs)} web technologies")
        
        for idx, tech_info in enumerate(web_techs):
            print(f"DEBUG: Processing tech #{idx+1}: {tech_info}")
            
            tech = {
                'product': tech_info.get('name', tech_info.get('product', 'unknown')),  # ⭐ name 또는 product
                'version': tech_info.get('version', ''),
                'service': 'web',
                'source': tech_info.get('source', 'web_recon'),  # ⭐ web_recon (밑줄 포함!)
                'category': tech_info.get('category', 'other'),
                'host_ip': 'localhost',  # ⭐ host_ip (밑줄 포함!)
                'port': 3000
            }
            technologies_with_cpe.append(tech)
            print(f"DEBUG: ✅ Added web tech #{idx+1}: {tech['product']} v{tech['version']}")

    print(f"DEBUG: Total technologies before CPE generation: {len(technologies_with_cpe)}")


    # CPE 생성
    technologies_with_cpe = batch_generate_cpes(technologies_with_cpe)

    cpe_techs = [t for t in technologies_with_cpe if t.get("cpe")]
    print(f"WORKFLOW: Generated CPE for {len(cpe_techs)} technologies")
    logger.info(f"WORKFLOW: CPE generation complete - {len(cpe_techs)} valid CPEs")


    # ========== Step 5: CVE 검색 ==========
    print(f"WORKFLOW: Step 5 - Searching for CVEs...")
    logger.info(f"WORKFLOW: Step 5 - CVE search starting for {len(cpe_techs)} technologies")

    nvd_client = AsyncNvdClient(
        api_key=current_app.config.get("NVD_API_KEY"),
        base_url=current_app.config.get("NVD_BASE_URL"),
        results_per_page=current_app.config.get("NVD_RESULTS_PER_PAGE", 50)
    )

    # ===== 수정: get_cache_manager()는 이미 routes.py에 정의되어 있음 =====
    cache_manager = get_cache_manager()  # ← import 없이 바로 호출

    all_cves = []
    try:
        all_cves = await search_cves_for_technologies(
            cpe_techs,
            nvd_client=nvd_client,
            cache_manager=cache_manager
        )
        print(f"WORKFLOW: Found {len(all_cves)} CVEs")
        logger.info(f"WORKFLOW: CVE search completed - {len(all_cves)} CVEs found")
        
        stats = nvd_client.get_stats()
        logger.info(f"CVE search stats: {stats}")
    except Exception as e:
        logger.exception(f"CVE search failed: {e}")
        print(f"WORKFLOW: CVE search failed: {e}")

    # ========== Step 6: 결과 분류 ==========
    print(f"WORKFLOW: Step 6 - Categorizing results...")
    
    recon_by_category = {
        "web": [],
        "network": [],
        "os": [],
        "database": [],
        "cloud": [],
        "container": []
    }
    
    for tech in technologies_with_cpe:
        source = tech.get("source", "").lower()
        if "web" in source:
            recon_by_category["web"].append(tech)
        elif "network" in source or "ssh" in source or "ftp" in source:
            recon_by_category["network"].append(tech)
        elif "os" in source:
            recon_by_category["os"].append(tech)
        elif "database" in source:
            recon_by_category["database"].append(tech)
        elif "cloud" in source:
            recon_by_category["cloud"].append(tech)
        elif "container" in source or "docker" in source:
            recon_by_category["container"].append(tech)
    
    cves_by_category = {
        "web": [],
        "network": [],
        "os": [],
        "database": [],
        "cloud": [],
        "container": []
    }
    
    for cve in all_cves:
        service = cve.get("service", "").lower()
        if any(x in service for x in ["http", "web", "apache", "nginx"]):
            cves_by_category["web"].append(cve)
        elif any(x in service for x in ["ssh", "ftp", "telnet", "rdp"]):
            cves_by_category["network"].append(cve)
        elif any(x in service for x in ["mysql", "postgres", "mongo", "redis"]):
            cves_by_category["database"].append(cve)
        elif any(x in service for x in ["docker", "kubernetes"]):
            cves_by_category["container"].append(cve)
    
    # ========== Step 6.5: ZAP 보안 스캔 ==========
    print(f"WORKFLOW: Step 6.5 - Running OWASP ZAP security scan...")
    logger.info("WORKFLOW: Step 6.5 - ZAP scan starting")

    zap_alerts = []
    zap_summary = {}

    try:
        print("DEBUG: ZAP Step 6.5 - Creating ZapScanner...")  # ← 디버그 추가
        
        zap_scanner = ZapScanner(
            api_key=current_app.config.get("ZAP_API_KEY", "change-me-9203935709"),
            proxy_host=current_app.config.get("ZAP_PROXY_HOST", "127.0.0.1"),
            proxy_port=current_app.config.get("ZAP_PROXY_PORT", 8080),
            timeout=600
        )
        
        print("DEBUG: ZAP Step 6.5 - Starting full_scan...")  # ← 디버그 추가
        
        zap_result = zap_scanner.full_scan(
            target_url=target,
            run_spider=True,
            run_active=False,
            risk_levels=["High", "Medium", "Low"]
        )
        
        print(f"DEBUG: ZAP Step 6.5 - Scan result: {zap_result.keys()}")  # ← 디버그 추가
        
        if "error" not in zap_result:
            zap_alerts = zap_result.get("alerts", [])
            zap_summary = zap_result.get("summary", {})
            
            print(f"WORKFLOW: ZAP scan completed!")
            print(f"WORKFLOW: - Total alerts: {zap_summary.get('total_alerts', 0)}")
            print(f"WORKFLOW: - High: {zap_summary.get('high', 0)}")
            print(f"WORKFLOW: - Medium: {zap_summary.get('medium', 0)}")
            print(f"WORKFLOW: - Low: {zap_summary.get('low', 0)}")
            
            logger.info(f"ZAP scan completed: {zap_summary}")
        else:
            print(f"WORKFLOW: ZAP scan failed: {zap_result.get('error')}")
            logger.error(f"ZAP scan error: {zap_result.get('error')}")
            
    except Exception as e:
        logger.exception(f"ZAP scan failed: {e}")
        print(f"WORKFLOW: ZAP scan exception: {e}")
        import traceback
        traceback.print_exc()  # ← 상세 에러 출력

        
    # ========== Step 7: 취약점 검증 ==========
    verification_results = []
    try:
        print(f"WORKFLOW: Step 7 - Verifying vulnerabilities...")
        logger.info("WORKFLOW: Step 7 - Vulnerability verification")
        
        # 엔드포인트 수집
        all_endpoints = []
        
        if web_info and "discovered_paths" in web_info:
            for path_info in web_info.get("discovered_paths", []):
                path = path_info.get("path", "")
                if path:
                    all_endpoints.append(path)
        
        if web_info and "js_analysis" in web_info:
            for api_info in web_info.get("js_analysis", []):
                if isinstance(api_info, str):
                    all_endpoints.append(api_info)
                elif isinstance(api_info, dict):
                    path = api_info.get("path", "")
                    if path:
                        all_endpoints.append(path)
        
        if web_info and "api_endpoints" in web_info:
            for endpoint in web_info.get("api_endpoints", []):
                if isinstance(endpoint, str):
                    all_endpoints.append(endpoint)
                elif isinstance(endpoint, dict):
                    path = endpoint.get("path", "")
                    if path:
                        all_endpoints.append(path)
        
        all_endpoints = list(set(all_endpoints))
        
        if not all_endpoints:
            all_endpoints = ["/", "/api", "/admin", "/.env", "/.git/config"]
        
        print(f"WORKFLOW: Total endpoints for verification: {len(all_endpoints)}")
        logger.info(f"WORKFLOW: Endpoints: {all_endpoints}")
        
        verifier = VulnerabilityVerifier(
            target_url=target,
            endpoints=all_endpoints,
            cves=all_cves,
            technologies=technologies_with_cpe
        )
        
        verification_results = verifier.verify_all()
        
        exploitable_count = sum(1 for v in verification_results if v.get("exploitable", False))
        high_confidence = sum(1 for v in verification_results if v.get("confidence") == "high")
        
        print(f"WORKFLOW: Verification complete")
        print(f"WORKFLOW: - Total checks: {len(verification_results)}")
        print(f"WORKFLOW: - Exploitable: {exploitable_count}")
        print(f"WORKFLOW: - High confidence: {high_confidence}")
        
    except Exception as e:
        logger.exception(f"WORKFLOW: Verification failed: {e}")
        print(f"WORKFLOW: Verification failed: {e}")
        verification_results = []
    
    # ========== Step 8: Exploit 검색 ==========
    print(f"WORKFLOW: Step 8 - Searching for exploits...")
    proof = []
    try:
        proof = search_exploits_for_cves(all_cves)
        print(f"WORKFLOW: Found {len(proof)} exploits")
    except Exception as e:
        logger.exception(f"Exploit search failed: {e}")
        print(f"WORKFLOW: Exploit search failed: {e}")
    
    # ========== Step 9: AI 공격 시나리오 생성 ==========
    print(f"WORKFLOW: Step 9 - Generating AI-powered attack scenario...")
    print(f"WORKFLOW: This may take a moment (calling Ollama API)...")
    scenario_lines = []
    
    try:
        prompt = build_prompt(recon_result, all_cves, verification_results)
        scenario_text = call_ollama(
            prompt,
            model=current_app.config.get("OLLAMA_MODEL", "gemma2:9b"),
            base_url=current_app.config.get("OLLAMA_BASE_URL", "http://localhost:11434")
        )
        scenario_lines = scenario_text.split("\n")
        print(f"WORKFLOW: AI scenario generated successfully")
    except Exception as e:
        logger.exception(f"AI scenario generation failed: {e}")
        scenario_lines = [f"❌ AI scenario generation failed: {str(e)}"]
        print(f"WORKFLOW: AI scenario generation failed: {e}")
    
    # ========== 완료 ==========
    print("="*70)
    print(f"WORKFLOW: SCAN COMPLETED")
    print(f"WORKFLOW: - Technologies: {len(technologies_with_cpe)}")
    print(f"WORKFLOW: - CVEs: {len(all_cves)}")
    print(f"WORKFLOW: - Verifications: {len(verification_results)}")
    print(f"WORKFLOW: - Exploits: {len(proof)}")
    print(f"WORKFLOW: - ZAP Alerts: {len(zap_alerts)}")
    print(f"WORKFLOW: - AI Scenario: {'Generated' if scenario_lines and '❌' not in scenario_lines[0] else 'Failed'}")
    print("="*70)
    
    return {
        "recon": recon_result,
        "recon_by_category": recon_by_category,
        "cves": all_cves,
        "cves_by_category": cves_by_category,
        "scenario": scenario_lines,
        "proof": proof,
        "verifications": verification_results,
        "web_info": web_info,
        "os_info": os_info,
        "network_info": network_info,
        "database_info": database_info,
        "cloud_info": cloud_info,
        "container_info": container_info,
        "technologies": technologies_with_cpe,
        "categorized": {
            "recon": recon_by_category,
            "cves": cves_by_category
        },
        # ========== ZAP 결과 추가 (NEW!) ==========
        "zap_scan": {
            "alerts": zap_alerts,
            "summary": zap_summary,
            "risk_breakdown": {
                "high": [a for a in zap_alerts if a.get("risk") == "High"],
                "medium": [a for a in zap_alerts if a.get("risk") == "Medium"],
                "low": [a for a in zap_alerts if a.get("risk") == "Low"]
            }
        }
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
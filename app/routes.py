# app/routes.py

from flask import Blueprint, render_template, request, jsonify, current_app

from .nmap_recon import run_recon
from .ai_client import build_prompt, call_ollama
from .loot_generator import enrich_loot
from .nvd_client import NvdClient
from .searchsploit_client import search_exploits_for_cves

bp = Blueprint("main", __name__)


def score_cve_exploitability(cve_item: dict, exploit_map: dict) -> int:
    """
    CVE의 실제 공격 가능성 점수 계산 (높을수록 우선순위).
    """
    score = 0

    # 1. CVSS 기본 점수
    cvss = cve_item.get("cvss", 0)
    if cvss >= 9.0:
        score += 10
    elif cvss >= 7.0:
        score += 5

    # 2. Searchsploit에 실제 exploit 있으면 대폭 가산
    if cve_item.get("cve_id") in exploit_map:
        score += 20

    # 3. 최근 CVE일수록 높은 점수 (2024년 이후)
    try:
        year = int(cve_item.get("cve_id", "CVE-2000-0000").split("-")[1])
        if year >= 2024:
            score += 15
        elif year >= 2022:
            score += 5
    except:
        pass

    return score


def build_attack_chains(recon_result, all_cves, exploit_map):
    """
    여러 CVE를 엮은 공격 체인 후보를 만든다.
    exploit_map을 참고하여 실제 공격 가능한 CVE 우선 배치.
    """
    chains = []
    chain_id = 1

    # CVE들을 공격 가능성 점수로 정렬
    scored_cves = [
        (cve, score_cve_exploitability(cve, exploit_map)) for cve in all_cves
    ]
    scored_cves.sort(key=lambda x: x[1], reverse=True)

    # 역할별로 분류 (높은 점수 우선)
    initial = [c for c, s in scored_cves if c.get("cvss", 0) >= 7.0]
    privesc = [
        c
        for c, s in scored_cves
        if "privilege" in (c.get("description") or "").lower()
    ]
    exfil = [
        c
        for c, s in scored_cves
        if "sql" in (c.get("description") or "").lower()
        or "information disclosure" in (c.get("description") or "").lower()
        or "data leak" in (c.get("description") or "").lower()
    ]

    print("[DEBUG] initial_access 후보 CVE 수:", len(initial))
    print("[DEBUG] privesc 후보 CVE 수:", len(privesc))
    print("[DEBUG] exfil 후보 CVE 수:", len(exfil))

    if not initial:
        return chains

    max_chain = 3
    for i, init_cve in enumerate(initial[:max_chain]):
        chain_steps = []

        host_ip = init_cve.get("host_ip") or (
            recon_result[0].get("ip") if recon_result else "127.0.0.x"
        )
        service = init_cve.get("service") or "unknown"
        port = init_cve.get("port")

        # 1단계: initial_access
        chain_steps.append(
            {
                "step": 1,
                "role": "initial_access",
                "cve_id": init_cve.get("cve_id"),
                "cvss": init_cve.get("cvss"),
                "service": service,
                "port": port,
            }
        )

        step_num = 2

        # 2단계: privilege_escalation
        if privesc:
            pe = privesc[i % len(privesc)]
            chain_steps.append(
                {
                    "step": step_num,
                    "role": "privilege_escalation",
                    "cve_id": pe.get("cve_id"),
                    "cvss": pe.get("cvss"),
                    "service": pe.get("service") or "unknown",
                    "port": pe.get("port"),
                }
            )
            step_num += 1

        # 3단계: data_exfiltration
        if exfil:
            de = exfil[i % len(exfil)]
            chain_steps.append(
                {
                    "step": step_num,
                    "role": "data_exfiltration",
                    "cve_id": de.get("cve_id"),
                    "cvss": de.get("cvss"),
                    "service": de.get("service") or "unknown",
                    "port": de.get("port"),
                }
            )

        chains.append(
            {
                "chain_id": chain_id,
                "host_ip": host_ip,
                "steps": chain_steps,
            }
        )
        chain_id += 1

    print("[DEBUG] 생성된 체인 개수:", len(chains))
    return chains


@bp.route("/")
def index():
    return render_template("dashboard.html")


@bp.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json() or {}
    target = data.get("target")

    if not target:
        return jsonify({"error": "target is required"}), 400

    # 1. Recon
    recon_result = run_recon(
        target,
        nmap_args=current_app.config["NMAP_ARGS"],
        mask=current_app.config.get("MASK_REAL_IP", True),
    )
    print("[DEBUG] Recon 결과 호스트 수:", len(recon_result))

    # 2. NVD 클라이언트 준비
    nvd = NvdClient()

    all_cves = []

    for host in recon_result:
        host_ip = host.get("ip")
        for port in host.get("ports", []):
            product = port.get("product")
            service_name = port.get("service")
            version_raw = port.get("version")
            full_version = port.get("full_version")

            if not product and not service_name:
                port["cves"] = []
                continue

            # 버전 파싱 및 정규화 (복잡한 버전 문자열에서 실제 버전만 추출)
            from .core.cve.matcher import parse_and_normalize_version, extract_product_from_version_string
            
            version = None
            if version_raw:
                version = parse_and_normalize_version(version_raw)
            
            # full_version에서도 버전 추출 시도
            if not version and full_version:
                version = parse_and_normalize_version(full_version)
            
            # product가 없고 full_version에 제품명이 포함된 경우 추출
            if not product and full_version:
                extracted_product = extract_product_from_version_string(full_version)
                if extracted_product:
                    product = extracted_product
                    print(f"[DEBUG] full_version에서 제품명 추출: {extracted_product}")

            # 하이브리드 검색: CPE 우선, 실패 시 키워드 검색
            # 키워드 폴백용 문자열 생성
            keyword_fallback = None
            if full_version:
                parts = full_version.split()
                if parts:
                    keyword_fallback = parts[0].split("/")[0]
            if not keyword_fallback and product:
                keyword_fallback = product
            if not keyword_fallback:
                keyword_fallback = service_name or "unknown"

            print(f"[DEBUG] 하이브리드 검색 시작: product={product!r}, version={version!r} (원본: {version_raw!r}), keyword_fallback={keyword_fallback!r}")

            try:
                # 하이브리드 검색 실행 (CPE 우선, 실패 시 키워드)
                nvd_items = nvd.search_hybrid(
                    product=product or service_name or "unknown",
                    version=version,
                    keyword_fallback=keyword_fallback,
                    max_pages=1,
                )
                print(f"[DEBUG] 하이브리드 검색 결과 (필터링 전): {len(nvd_items)}개")

                # is_vulnerable=True인 것만 남김 (강화된 필터링 적용됨)
                nvd_items = [
                    item for item in nvd_items if item.get("is_vulnerable", False)
                ]
                print(f"[DEBUG] 하이브리드 검색 결과 (필터링 후): {len(nvd_items)}개")

            except Exception as e:
                print(f"[WARN] 하이브리드 검색 실패: product={product!r}, version={version!r}, err={e}")
                nvd_items = []

            # 각 CVE에 host/port/service 정보 태깅
            for item in nvd_items:
                item["host_ip"] = host_ip
                item["service"] = service_name or product
                item["port"] = port.get("port")

            port["cves"] = nvd_items
            all_cves.extend(nvd_items)

    print("[DEBUG] 전체 CVE 수 (필터링 후):", len(all_cves))

    # 3. Searchsploit으로 exploit 제목/ID 매핑
    unique_cve_ids = sorted({c["cve_id"] for c in all_cves if c.get("cve_id")})
    exploit_map = search_exploits_for_cves(unique_cve_ids, max_per_cve=5)
    print("[DEBUG] Searchsploit 매핑된 CVE 수:", len(exploit_map))

    # 4. 공격 체인 후보 생성 (exploit 우선순위 반영)
    chains = build_attack_chains(recon_result, all_cves, exploit_map)

    # 5. AI 시나리오 생성
    if all_cves and chains:
        prompt = build_prompt(all_cves, recon_result, chains, exploit_map)
        ai_result = call_ollama(prompt)
    else:
        ai_result = {
            "selected_chains": [],
            "scenario": ["[경고] 매핑된 CVE가 없어 공격 시나리오 생성을 건너뜀."],
            "proof": {"loot_files": [], "logs": []},
        }

    scenario = ai_result.get("scenario", [])
    proof = enrich_loot(ai_result.get("proof"))
    selected_chains = ai_result.get("selected_chains", [])

    # 6. 프론트엔드 응답
    response = {
        "recon": recon_result,
        "cves": all_cves,
        "chains": selected_chains,
        "scenario": scenario,
        "proof": proof,
        "exploits": exploit_map,
    }

    return jsonify(response)

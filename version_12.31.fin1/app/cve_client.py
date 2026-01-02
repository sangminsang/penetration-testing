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

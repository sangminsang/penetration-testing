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

# Project Code Extract (Part 4/5)
- **Root:** `d:\3차 프로젝트\6트\12.26 app`
- **Files included:** 19 (Total: 92)

---

## File 58: extensions.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\extensions.py`

```python
from flask_socketio import SocketIO
socketio = SocketIO(cors_allowed_origins="*")
```
---

## File 59: loot_generator.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\loot_generator.py`

```python
import random
import datetime

def enrich_loot(base_proof: dict):
    """
    LLM이 준 proof 에 더미 데이터를 추가하거나 형식을 보정.
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

## File 60: main.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\main.py`

```python
# main.py
from .nvd_client import NvdClient


def main():
    client = NvdClient()

    # 여기서 서비스/버전 문자열 넣어서 테스트
    # 예: service = "nginx 1.24", "apache httpd 2.4.59" 등[web:137]
    service_version = input("검색할 서비스/버전 키워드 입력 (예: 'nginx 1.24'): ").strip()

    if not service_version:
        print("키워드를 입력해주세요.")
        return

    print(f"\n[NVD 검색] 키워드: {service_version}")
    cve_list = client.search_and_summarize(service_version, max_pages=1)

    if not cve_list:
        print("검색 결과가 없습니다.")
        return

    for idx, item in enumerate(cve_list, start=1):
        print(f"\n[{idx}] CVE ID: {item['cve_id']}")
        print(f"    CVSS: {item['cvss']}")
        print(f"    DESC: {item['description'][:200]}")  # 너무 길면 앞 200자만


if __name__ == "__main__":
    main()
```
---

## File 61: models.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\models.py`

```python
from app import db
from datetime import datetime

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    target = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    data = db.Column(db.JSON)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
```
---

## File 62: nmap_recon.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\nmap_recon.py`

```python
import nmap
import re

def mask_ip(ip: str) -> str:
    # 192.168.0.10 -> 192.168.0.x 형태로 마스킹
    parts = ip.split(".")
    if len(parts) == 4:
        parts[-1] = "x"
        return ".".join(parts)
    return ip

def parse_service_version(product: str, version: str) -> str:
    if product and version:
        return f"{product} {version}"
    if product:
        return product
    return "unknown"

def run_recon(target: str, nmap_args: str = "-sV -Pn", mask: bool = True):
    nm = nmap.PortScanner()
    nm.scan(target, arguments=nmap_args)

    hosts = []
    for host in nm.all_hosts():
        host_ip = mask_ip(host) if mask else host
        host_data = {
            "ip": host_ip,
            "hostname": nm[host].hostname() or "",
            "state": nm[host].state(),
            "os": nm[host].get("osmatch", []),
            "ports": []
        }

        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in sorted(lport):
                svc = nm[host][proto][port]
                service_name = svc.get("name", "")
                product = svc.get("product", "")
                version = svc.get("version", "")
                full_version = parse_service_version(product, version)

                host_data["ports"].append({
                    "port": port,
                    "protocol": proto,
                    "state": svc.get("state", ""),
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "full_version": full_version
                })

        hosts.append(host_data)

    return hosts
```
---

## File 63: nvd_client.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\nvd_client.py`

```python
# app/nvd_client.py
import time
import requests
import re
from typing import List, Dict, Any, Optional, Tuple

from .config import Config

# 버전 비교를 위한 라이브러리 (pip install packaging 필요)
try:
    from packaging import version
    VERSION_COMPARE_AVAILABLE = True
except ImportError:
    VERSION_COMPARE_AVAILABLE = False
    print("[WARN] packaging 모듈이 없어 버전 필터링이 비활성화됩니다. pip install packaging 권장")

# Product → (vendor, product) 매핑 테이블
# Nmap의 product 이름을 NVD CPE 표준 vendor/product로 변환
PRODUCT_TO_VENDOR_PRODUCT = {
    # 웹 서버
    "apache httpd": ("apache", "http_server"),
    "apache": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "iis": ("microsoft", "internet_information_services"),
    "lighttpd": ("lighttpd", "lighttpd"),
    
    # 데이터베이스
    "mysql": ("mysql", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "postgres": ("postgresql", "postgresql"),
    "mongodb": ("mongodb", "mongodb"),
    "redis": ("redis", "redis"),
    "sqlite": ("sqlite", "sqlite"),
    
    # SSH/FTP
    "openssh": ("openssh", "openssh"),
    "dropbear": ("dropbear", "dropbear"),
    "vsftpd": ("vsftpd", "vsftpd"),
    "proftpd": ("proftpd", "proftpd"),
    
    # 메일 서버
    "postfix": ("postfix", "postfix"),
    "sendmail": ("sendmail", "sendmail"),
    "exim": ("exim", "exim"),
    
    # 기타
    "tomcat": ("apache", "tomcat"),
    "jetty": ("eclipse", "jetty"),
    "node.js": ("nodejs", "node"),
    "python": ("python", "python"),
    "php": ("php", "php"),
}


def normalize_product_name(product: str) -> str:
    """
    Nmap product 이름을 정규화 (소문자, 공백 제거 등).
    """
    if not product:
        return ""
    return product.lower().strip()


def map_product_to_vendor_product(product: str) -> Optional[Tuple[str, str]]:
    """
    Product 이름을 (vendor, product) 튜플로 변환.
    매핑 테이블에 없으면 None 반환.
    """
    normalized = normalize_product_name(product)
    
    # 정확한 매칭 시도
    if normalized in PRODUCT_TO_VENDOR_PRODUCT:
        return PRODUCT_TO_VENDOR_PRODUCT[normalized]
    
    # 부분 매칭 시도 (예: "Apache httpd 2.4.49" -> "apache httpd" 매칭)
    for key, value in PRODUCT_TO_VENDOR_PRODUCT.items():
        if key in normalized or normalized in key:
            return value
    
    return None


def build_cpe_string(vendor: str, product: str, version: str = "*") -> str:
    """
    CPE 2.3 형식 문자열 생성.
    형식: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
    """
    # CPE 형식에 맞게 특수문자 처리
    vendor_clean = vendor.replace(" ", "_").lower()
    product_clean = product.replace(" ", "_").lower()
    version_clean = version if version else "*"
    
    return f"cpe:2.3:a:{vendor_clean}:{product_clean}:{version_clean}:*:*:*:*:*:*:*"


class NvdClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = None,
        results_per_page: int = None,
        sleep_sec: float = 0.5,
    ):
        self.api_key = api_key or Config.NVD_API_KEY
        self.base_url = base_url or Config.NVD_BASE_URL
        self.results_per_page = results_per_page or Config.NVD_RESULTS_PER_PAGE
        self.sleep_sec = sleep_sec

    def _get(self, params: Dict[str, Any]) -> Dict[str, Any]:
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        resp = requests.get(
            self.base_url,
            params=params,
            headers=headers,
            timeout=Config.REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        time.sleep(self.sleep_sec)
        return resp.json()

    def search_cves_by_keyword(
        self,
        keyword: str,
        max_pages: int = 1,
    ) -> List[Dict[str, Any]]:
        """
        keyword 로 CVE 검색 (서비스 이름, 버전 등).
        """
        all_items: List[Dict[str, Any]] = []
        start_index = 0

        for _ in range(max_pages):
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": self.results_per_page,
                "startIndex": start_index,
            }
            data = self._get(params)

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break

            all_items.extend(vulnerabilities)

            total_results = data.get("totalResults", 0)
            start_index += self.results_per_page
            if start_index >= total_results:
                break

        return all_items

    def search_cves_by_cpe(
        self,
        cpe_string: str,
        max_pages: int = 1,
    ) -> List[Dict[str, Any]]:
        """
        CPE 문자열로 CVE 검색 (더 정확한 매칭).
        NVD API v2.0의 cpeMatchString 파라미터 사용.
        
        참고: NVD API v2.0 CVE 검색 엔드포인트는 cpeMatchString 파라미터를 지원합니다.
        형식: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
        
        만약 cpeMatchString이 작동하지 않으면, cpeName을 시도합니다.
        """
        all_items: List[Dict[str, Any]] = []
        start_index = 0

        # NVD API v2.0에서 지원하는 파라미터 시도 순서
        # 1. cpeMatchString (공식 문서에 명시된 파라미터)
        # 2. cpeName (일부 버전에서 지원될 수 있음)
        param_names = ["cpeMatchString", "cpeName"]
        last_error = None

        for param_name in param_names:
            try:
                all_items = []
                start_index = 0
                
                for _ in range(max_pages):
                    params = {
                        param_name: cpe_string,
                        "resultsPerPage": self.results_per_page,
                        "startIndex": start_index,
                    }
                    data = self._get(params)

                    vulnerabilities = data.get("vulnerabilities", [])
                    if not vulnerabilities:
                        break

                    all_items.extend(vulnerabilities)

                    total_results = data.get("totalResults", 0)
                    start_index += self.results_per_page
                    if start_index >= total_results:
                        break

                # 성공적으로 결과를 받았으면 반환
                if all_items or param_name == param_names[-1]:
                    print(f"[DEBUG] CPE 검색 성공 (파라미터: {param_name}): {len(all_items)}개 CVE 발견")
                    return all_items
                    
            except requests.exceptions.HTTPError as e:
                last_error = e
                print(f"[DEBUG] CPE 검색 실패 (파라미터: {param_name}): {e}")
                # 다음 파라미터 시도
                continue
            except Exception as e:
                last_error = e
                print(f"[DEBUG] CPE 검색 오류 (파라미터: {param_name}): {e}")
                continue

        # 모든 파라미터 시도 실패
        print(f"[WARN] CPE 검색 완전 실패: {cpe_string}, 마지막 오류: {last_error}")
        return []

    def cvss_to_severity(self, score: float) -> str:
        """
        CVSS 점수를 위험도 라벨로 변환.
        
        공식 기준:
        - FIRST CVSS v3.1 Specification (Table 14):
          https://www.first.org/cvss/v3-1/specification-document
        - NVD Vulnerability Metrics:
          https://nvd.nist.gov/vuln-metrics/cvss
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

    def is_version_vulnerable(self, target_version: str, cpe_match: dict) -> bool:
        """
        타겟 버전이 CVE의 영향 범위에 포함되는지 확인.
        NVD configurations의 versionStartIncluding/versionEndExcluding 등을 파싱.
        강화된 버전: 버전 정보가 없거나 불확실하면 False 반환 (보수적 접근).
        """
        if not target_version:
            # 타겟 버전이 없으면 매칭 불가
            return False

        if not VERSION_COMPARE_AVAILABLE:
            # packaging 모듈이 없으면 버전 비교 불가
            # CPE에 version이 "*"이거나 없으면 True, 있으면 정확히 일치해야 함
            cpe_version = cpe_match.get("version", "*")
            if cpe_version == "*" or cpe_version == "-":
                return True
            # 정확한 버전 비교는 불가하므로 False 반환 (보수적)
            return False

        try:
            target_ver = version.parse(target_version)
        except Exception as e:
            # 버전 파싱 실패 시 False 반환 (보수적 접근)
            print(f"[DEBUG] 버전 파싱 실패: {target_version}, err={e}")
            return False

        start_inc = cpe_match.get("versionStartIncluding")
        start_exc = cpe_match.get("versionStartExcluding")
        end_inc = cpe_match.get("versionEndIncluding")
        end_exc = cpe_match.get("versionEndExcluding")

        # 버전 범위 정보가 없으면 CPE의 version 필드 확인
        if not any([start_inc, start_exc, end_inc, end_exc]):
            cpe_version = cpe_match.get("version", "*")
            if cpe_version == "*" or cpe_version == "-":
                return True
            # 정확한 버전 비교 시도
            try:
                cpe_ver = version.parse(cpe_version)
                return target_ver == cpe_ver
            except:
                # 파싱 실패 시 문자열 비교
                return target_version == cpe_version

        # 하한선 체크
        if start_inc:
            try:
                if target_ver < version.parse(start_inc):
                    return False
            except Exception as e:
                print(f"[DEBUG] start_inc 파싱 실패: {start_inc}, err={e}")

        if start_exc:
            try:
                if target_ver <= version.parse(start_exc):
                    return False
            except Exception as e:
                print(f"[DEBUG] start_exc 파싱 실패: {start_exc}, err={e}")

        # 상한선 체크
        if end_inc:
            try:
                if target_ver > version.parse(end_inc):
                    return False
            except Exception as e:
                print(f"[DEBUG] end_inc 파싱 실패: {end_inc}, err={e}")

        if end_exc:
            try:
                if target_ver >= version.parse(end_exc):
                    return False
            except Exception as e:
                print(f"[DEBUG] end_exc 파싱 실패: {end_exc}, err={e}")

        # 모든 범위 체크를 통과하면 취약
        return True

    def extract_cve_summary(
        self, vuln_item: Dict[str, Any], target_version: str = None, 
        target_vendor: str = None, target_product: str = None
    ) -> Dict[str, Any]:
        """
        NVD v2 응답에서 CVE ID, 설명, CVSS 점수 + Severity + 버전 필터링.
        강화된 버전: vendor/product 매칭도 확인.
        """
        cve = vuln_item.get("cve", {})
        cve_id = cve.get("id")

        descriptions = cve.get("descriptions", [])
        desc_text = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc_text = d.get("value", "")
                break

        metrics = vuln_item.get("cve", {}).get("metrics", {})
        cvss_score = None

        # v31, v30, v2 순으로 스코어 추출
        if "cvssMetricV31" in metrics:
            cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV30" in metrics:
            cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV2" in metrics:
            cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

        cvss_val = float(cvss_score) if cvss_score is not None else 0.0
        severity = self.cvss_to_severity(cvss_val)

        # ===== 강화된 버전 필터링 =====
        is_vulnerable = False  # 기본값을 False로 변경 (보수적 접근)

        configurations = cve.get("configurations", [])
        
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if not cpe_match.get("vulnerable"):
                        continue
                    
                    # CPE 문자열에서 vendor/product 추출
                    cpe_uri = cpe_match.get("criteria", "")
                    if target_vendor and target_product:
                        # vendor/product 매칭 확인
                        vendor_match = target_vendor.lower() in cpe_uri.lower()
                        product_match = target_product.lower() in cpe_uri.lower()
                        if not (vendor_match and product_match):
                            continue
                    
                    # 버전 매칭 확인
                    if target_version:
                        if self.is_version_vulnerable(target_version, cpe_match):
                            is_vulnerable = True
                            break
                    else:
                        # 버전이 없으면 CPE 매칭만으로 판단
                        is_vulnerable = True
                        break
                    
                if is_vulnerable:
                    break
            if is_vulnerable:
                break

        return {
            "cve_id": cve_id,
            "description": desc_text,
            "cvss": cvss_val,
            "severity": severity,
            "is_vulnerable": is_vulnerable,
        }

    def search_and_summarize(
        self, keyword: str, max_pages: int = 1, target_version: str = None
    ) -> List[Dict[str, Any]]:
        """
        keyword로 검색하고, 각 CVE를 요약 리스트로 반환.
        target_version이 주어지면 버전 필터링 수행.
        """
        vulns = self.search_cves_by_keyword(keyword, max_pages=max_pages)
        result = []

        for v in vulns:
            summary = self.extract_cve_summary(v, target_version=target_version)
            result.append(summary)

        return result

    def search_hybrid(
        self,
        product: str,
        version: str = None,
        keyword_fallback: str = None,
        max_pages: int = 1,
    ) -> List[Dict[str, Any]]:
        """
        하이브리드 검색: CPE 기반 검색을 우선 시도, 실패 시 키워드 검색으로 폴백.
        
        Args:
            product: Nmap에서 감지한 product 이름 (예: "Apache httpd")
            version: 감지한 버전 (예: "2.4.49")
            keyword_fallback: CPE 검색 실패 시 사용할 키워드 (None이면 product+version 조합)
            max_pages: 최대 검색 페이지 수
        
        Returns:
            필터링된 CVE 리스트
        """
        # 1단계: Product → Vendor/Product 매핑
        vendor_product = map_product_to_vendor_product(product)
        
        if not vendor_product:
            # 매핑 실패 시 키워드 검색으로 폴백
            print(f"[DEBUG] Product 매핑 실패: {product}, 키워드 검색으로 폴백")
            keyword = keyword_fallback or product
            if version:
                keyword = f"{keyword} {version}"
            return self.search_and_summarize(keyword, max_pages=max_pages, target_version=version)
        
        vendor, mapped_product = vendor_product
        print(f"[DEBUG] Product 매핑 성공: {product} -> vendor={vendor}, product={mapped_product}")
        
        # 2단계: CPE 문자열 생성 및 검색 시도
        cpe_string = build_cpe_string(vendor, mapped_product, version or "*")
        print(f"[DEBUG] CPE 검색 시도: {cpe_string}")
        
        try:
            vulns = self.search_cves_by_cpe(cpe_string, max_pages=max_pages)
            
            if vulns:
                print(f"[DEBUG] CPE 검색 성공: {len(vulns)}개 CVE 발견")
                result = []
                for v in vulns:
                    summary = self.extract_cve_summary(
                        v,
                        target_version=version,
                        target_vendor=vendor,
                        target_product=mapped_product,
                    )
                    result.append(summary)
                return result
            else:
                print(f"[DEBUG] CPE 검색 결과 없음, 키워드 검색으로 폴백")
        except Exception as e:
            print(f"[WARN] CPE 검색 중 오류: {e}, 키워드 검색으로 폴백")
        
        # 3단계: CPE 검색 실패 시 키워드 검색으로 폴백
        keyword = keyword_fallback or product
        if version:
            # 버전이 있으면 메이저.마이너만 추가
            ver_parts = version.split(".")
            if len(ver_parts) >= 2:
                short_ver = ".".join(ver_parts[:2])
                keyword = f"{keyword} {short_ver}"
            else:
                keyword = f"{keyword} {version}"
        
        print(f"[DEBUG] 키워드 검색으로 폴백: {keyword}")
        vulns = self.search_cves_by_keyword(keyword, max_pages=max_pages)
        result = []
        
        for v in vulns:
            summary = self.extract_cve_summary(
                v,
                target_version=version,
                target_vendor=vendor,
                target_product=mapped_product,
            )
            result.append(summary)
        
        return result
```
---

## File 64: routes.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\routes.py`

```python
from flask import Blueprint, render_template, request, jsonify, redirect, url_for
from app.models import Project, ScanResult
from app import db
import re

bp = Blueprint("main", __name__)

@bp.route('/')
def index():
    return redirect(url_for('main.projects'))

@bp.route('/projects')
def projects():
    all_projects = Project.query.all()
    return render_template('projects.html', projects=all_projects)

@bp.route('/project/new', methods=['POST'])
def create_project():
    name, target = request.form.get('name'), request.form.get('target')
    if name and target:
        db.session.add(Project(name=name, target=target))
        db.session.commit()
    return redirect(url_for('main.projects'))

@bp.route('/project/delete/<int:project_id>', methods=['POST'])
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)
    ScanResult.query.filter_by(project_id=project_id).delete()
    db.session.delete(project)
    db.session.commit()
    return redirect(url_for('main.projects'))

@bp.route('/live-scan/<int:project_id>')
def live_scan(project_id):
    project = Project.query.get_or_404(project_id)
    return render_template('live_scan.html', project=project)

@bp.route('/url-tree/<int:project_id>')
def url_tree(project_id):
    project = Project.query.get_or_404(project_id)
    return render_template('url_tree.html', project=project)

@bp.route('/api/project/<int:project_id>/tree-data')
def get_tree_data(project_id):
    last_scan = ScanResult.query.filter_by(project_id=project_id).order_by(ScanResult.timestamp.desc()).first()
    project = Project.query.get(project_id)
    tree = {"name": project.target, "children": []}
    
    if not last_scan or not last_scan.data.get('urls'):
        return jsonify(tree)

    # 고유 URL 정렬
    urls = sorted(list(set(last_scan.data['urls'])))
    for url in urls:
        # 경로 추출 (도메인 이후 부분)
        path_str = url.replace(project.target, "").strip("/")
        if not path_str: continue
        
        parts = [p for p in path_str.split('/') if p]
        curr = tree['children']
        for p in parts:
            node = next((item for item in curr if item["name"] == p), None)
            if not node:
                new_node = {"name": p, "children": []}
                curr.append(new_node)
                curr = new_node["children"]
            else:
                curr = node["children"]
    return jsonify(tree)
```
---

## File 65: searchsploit_client.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\searchsploit_client.py`

```python
# app/searchsploit_client.py

import json
import subprocess
from typing import List, Dict


def search_exploits_for_cves(cve_ids: List[str], max_per_cve: int = 5) -> Dict[str, List[Dict]]:
    """
    여러 CVE ID에 대해 searchsploit --json을 호출하고,
    각 CVE별로 'title' 과 'id' 만 추출해서 반환.

    반환 예:
    {
      "CVE-2021-41773": [
        {"title": "Apache HTTP Server 2.4.49 - Path Traversal & RCE", "id": "50383"},
        {"title": "Apache 2.4.49/2.4.50 - Traversal Shell (Metasploit)", "id": "50406"},
      ],
      ...
    }
    """
    results: Dict[str, List[Dict]] = {}
    for cve in cve_ids:
        exploits = search_exploits_for_single_cve(cve, max_per_cve=max_per_cve)
        if exploits:
            results[cve] = exploits
    return results


def search_exploits_for_single_cve(cve_id: str, max_per_cve: int = 5) -> List[Dict]:
    """
    단일 CVE에 대해 searchsploit --json 실행.

    출력 예:
    [
        {"title": "...", "id": "50383"},
        ...
    ]
    """
    cmd = ["searchsploit", "--json", cve_id]

    try:
        proc = subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"[WARN] searchsploit 실패: {cve_id}, err={e}")
        return []

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(f"[WARN] searchsploit JSON 파싱 실패: {cve_id}")
        return []

    # searchsploit --json 구조는 보통:
    # { "RESULTS_EXPLOIT": [ { "Title": "...", "EDB-ID": "50383", ... }, ... ],
    #   "RESULTS_SHELLCODE": [ ... ] }
    exploits = []

    for key in ("RESULTS_EXPLOIT", "RESULTS_SHELLCODE"):
        arr = data.get(key) or []
        if not isinstance(arr, list):
            continue
        for item in arr:
            title = item.get("Title") or item.get("title")
            edb_id = item.get("EDB-ID") or item.get("id")
            if not title or not edb_id:
                continue
            exploits.append({"title": title, "id": str(edb_id)})

    # 상위 N개만
    return exploits[:max_per_cve]
```
---

## File 66: intelligence.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\services\intelligence.py`

```python
import re

class IntelligenceEngine:
    """
    스캔 데이터 정제 및 검증 힌트 생성 엔진
    """

    def __init__(self):
        self.tech_stack = {} 

    def _normalize_name(self, name):
        return str(name).lower().strip()

    def _generate_manual_hint(self, tech_name, category, version, url="TARGET_URL"):
        """
        기술 스택에 따른 실무자용 수동 검증 명령어 생성
        """
        tech_lower = tech_name.lower()
        cat_lower = category.lower()
        hints = []

        # 1. 웹 서버 / 언어 관련 (HTTP 헤더 검증)
        if cat_lower in ['web server', 'language', 'operating system']:
            hints.append(f"curl -I -v {url}")
            hints.append(f"whatweb -v {url}")

        # 2. 데이터베이스 (SQL Injection 검증)
        if 'sql' in tech_lower or cat_lower == 'database':
            hints.append(f"sqlmap -u \"{url}\" --batch --dbs")
            hints.append("Manual Check: Add ' OR 1=1 -- to input fields")

        # 3. CMS (WordPress, Drupal 등)
        if 'wordpress' in tech_lower:
            hints.append(f"wpscan --url {url} --enumerate u,p,t")
        elif 'joomla' in tech_lower:
            hints.append(f"joomscan -u {url}")

        # 4. Nginx/Apache 구체적 버전
        if 'nginx' in tech_lower:
            hints.append(f"nikto -h {url} -Tuning b")
        
        # 5. PHP
        if 'php' in tech_lower:
            hints.append(f"curl -X GET {url} -H 'X-Powered-By: verify'")

        if not hints:
            hints.append(f"nuclei -u {url} -t http/technologies")

        return hints

    def add_finding(self, tech_name, version, category, source_tool, evidence, confidence="High"):
        if not tech_name or tech_name.lower() == 'unknown':
            return

        key = self._normalize_name(tech_name)
        
        if version and version.lower() in ['n/a', 'unknown', 'none']:
            version = ""
            
        evidence_str = f"[{source_tool}] {evidence}" if evidence else f"[{source_tool}] Detected"

        if key not in self.tech_stack:
            self.tech_stack[key] = {
                "name": tech_name,
                "version": version,
                "category": category,
                "sources": [source_tool],
                "evidence": [evidence_str],
                "confidence": confidence,
                "hints": [] # 힌트 리스트 초기화
            }
        else:
            existing = self.tech_stack[key]
            if source_tool not in existing["sources"]:
                existing["sources"].append(source_tool)
            if evidence_str not in existing["evidence"]:
                existing["evidence"].append(evidence_str)
            if not existing["version"] and version:
                existing["version"] = version
            elif version and len(version) > len(existing["version"]):
                existing["version"] = version

    def refine_data(self, scan_results, target_url="http://localhost"):
        """
        데이터 정제 메인 함수
        """
        self.tech_stack = {} 

        # 1. 헤더 분석
        headers = scan_results.get('headers', {})
        if isinstance(headers, dict):
            if 'server' in headers:
                self.add_finding("Web Server", headers['server'], "Web Server", "Header", f"Server: {headers['server']}")
            if 'x-powered-by' in headers:
                self.add_finding("Language", headers['x-powered-by'], "Language", "Header", f"X-Powered-By: {headers['x-powered-by']}")

        # 2. 통합 리스트 (Nuclei, WhatWeb 등)
        tech_list = scan_results.get('webtechnologies', [])
        if isinstance(tech_list, list):
            for tech in tech_list:
                if not isinstance(tech, dict): continue
                self.add_finding(
                    tech.get('name'), 
                    tech.get('version', ''), 
                    tech.get('category', 'Generic'), 
                    tech.get('source', 'Scanner'),
                    tech.get('evidence')
                )

        # 3. 데이터 후처리 (힌트 생성)
        final_list = []
        for tech in self.tech_stack.values():
            # 힌트 생성 (현재 타겟 URL 기준)
            tech['hints'] = self._generate_manual_hint(tech['name'], tech['category'], tech['version'], target_url)
            final_list.append(tech)
            
        return final_list
```
---

## File 67: live_scan.css
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\static\css\live_scan.css`

```css
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
    min-height: 100vh;
    padding: 20px;
}

.container {
    max-width: 1800px;
    margin: 0 auto;
    background: white;
    border-radius: 12px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.2);
    padding: 30px;
}

header {
    text-align: center;
    margin-bottom: 30px;
    padding-bottom: 20px;
    border-bottom: 3px solid #1976d2;
}

header h1 {
    font-size: 2.5em;
    color: #1976d2;
    margin-bottom: 10px;
    text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
}

header p {
    color: #666;
    font-size: 1.1em;
}

/* Control Panel */
.control-panel {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    padding: 20px;
    border-radius: 12px;
    margin-bottom: 25px;
}

.input-row {
    display: flex;
    gap: 15px;
    align-items: center;
}

.input-row input[type="text"] {
    flex: 1;
    padding: 12px 20px;
    font-size: 16px;
    border: 2px solid rgba(255,255,255,0.3);
    border-radius: 8px;
    background: rgba(255,255,255,0.95);
}

.checkbox-label {
    color: white;
    font-size: 16px;
    display: flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
}

.checkbox-label input[type="checkbox"] {
    width: 20px;
    height: 20px;
    cursor: pointer;
}

.btn-primary, .btn-secondary {
    padding: 12px 28px;
    font-size: 16px;
    font-weight: 600;
    border: none;
    border-radius: 8px;
    cursor: pointer;
    transition: all 0.3s;
    white-space: nowrap;
}

.btn-primary {
    background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);
    color: #1a1a1a;
}

.btn-primary:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(67, 233, 123, 0.4);
}

.btn-primary:disabled {
    opacity: 0.6;
    cursor: not-allowed;
    transform: none;
}

.btn-secondary {
    background: white;
    color: #667eea;
    border: 2px solid white;
}

.btn-secondary:hover {
    background: rgba(255,255,255,0.9);
}

/* Statistics Cards */
.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 20px;
    margin-bottom: 25px;
}

.stat-card {
    display: flex;
    align-items: center;
    gap: 20px;
    padding: 25px;
    border-radius: 12px;
    color: white;
    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
}

.card-blue { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
.card-green { background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); }
.card-red { background: linear-gradient(135deg, #eb3349 0%, #f45c43 100%); }

.stat-icon {
    font-size: 3em;
}

.stat-content h3 {
    font-size: 2.5em;
    margin-bottom: 5px;
}

.stat-content p {
    font-size: 1em;
    opacity: 0.9;
}

/* Activity Banner */
.activity-banner {
    background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 15px 25px;
    border-radius: 8px;
    margin-bottom: 25px;
    font-size: 1.1em;
    font-weight: 500;
    display: flex;
    align-items: center;
    gap: 15px;
    animation: pulse 2s infinite;
}

@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.85; }
}

.activity-icon {
    font-size: 1.5em;
}

/* Main Content Layout */
.main-content {
    display: grid;
    grid-template-columns: 2fr 1fr;
    gap: 25px;
    margin-bottom: 25px;
}

.panel {
    background: #fafafa;
    border-radius: 12px;
    padding: 20px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
}

.panel h2 {
    font-size: 1.4em;
    color: #333;
    margin-bottom: 15px;
    padding-bottom: 10px;
    border-bottom: 2px solid #e0e0e0;
}

/* Force Graph */
.graph-panel {
    min-height: 600px;
}

.graph-container {
    background: white;
    border-radius: 8px;
    border: 2px solid #e0e0e0;
    overflow: hidden;
}

/* Sidebar */
.sidebar {
    display: flex;
    flex-direction: column;
    gap: 20px;
}

/* Progress Panel */
.progress-panel {
    flex: 1;
}

.progress-bars {
    display: flex;
    flex-direction: column;
    gap: 15px;
}

.progress-item {
    display: flex;
    flex-direction: column;
    gap: 8px;
}

.progress-label {
    font-weight: 600;
    color: #555;
    font-size: 0.95em;
}

.progress-bar-container {
    position: relative;
    background: #e0e0e0;
    border-radius: 20px;
    height: 24px;
    overflow: hidden;
}

.progress-bar {
    height: 100%;
    background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
    border-radius: 20px;
    transition: width 0.3s ease;
}

.progress-text {
    position: absolute;
    right: 10px;
    top: 50%;
    transform: translateY(-50%);
    font-size: 0.85em;
    font-weight: 600;
    color: #333;
}

/* Log Panel */
.log-panel {
    flex: 1;
    max-height: 400px;
}

.log-container {
    background: #1e1e1e;
    border-radius: 8px;
    padding: 15px;
    max-height: 300px;
    overflow-y: auto;
    font-family: 'Courier New', monospace;
    font-size: 0.9em;
}

.log-entry {
    display: flex;
    gap: 10px;
    padding: 8px;
    margin-bottom: 5px;
    border-radius: 4px;
    animation: slideIn 0.3s ease;
}

@keyframes slideIn {
    from {
        opacity: 0;
        transform: translateX(-10px);
    }
    to {
        opacity: 1;
        transform: translateX(0);
    }
}

.log-icon {
    font-size: 1.2em;
}

.log-message {
    flex: 1;
    color: #e0e0e0;
}

.log-info { background: rgba(33, 150, 243, 0.2); }
.log-success { background: rgba(76, 175, 80, 0.2); }
.log-critical { background: rgba(211, 47, 47, 0.3); }
.log-high { background: rgba(245, 124, 0, 0.3); }
.log-medium { background: rgba(251, 192, 45, 0.2); }
.log-error { background: rgba(244, 67, 54, 0.3); }

/* Legend */
.legend {
    background: #f5f5f5;
    padding: 20px;
    border-radius: 8px;
}

.legend h3 {
    font-size: 1.2em;
    margin-bottom: 15px;
    color: #333;
}

.legend-items {
    display: flex;
    flex-wrap: wrap;
    gap: 20px;
}

.legend-item {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 14px;
}

.node-sample {
    width: 20px;
    height: 20px;
    border-radius: 50%;
    border: 2px solid #333;
}

/* Scrollbar */
.log-container::-webkit-scrollbar {
    width: 8px;
}

.log-container::-webkit-scrollbar-track {
    background: #2d2d2d;
    border-radius: 4px;
}

.log-container::-webkit-scrollbar-thumb {
    background: #667eea;
    border-radius: 4px;
}

/* Responsive */
@media (max-width: 1200px) {
    .main-content {
        grid-template-columns: 1fr;
    }

    .sidebar {
        flex-direction: row;
    }
}

@media (max-width: 768px) {
    .input-row {
        flex-direction: column;
    }

    .sidebar {
        flex-direction: column;
    }

    .stats-grid {
        grid-template-columns: 1fr;
    }
}
```
---

## File 68: style.css
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\static\css\style.css`

```css
body {
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}

.card {
  border-radius: 0.5rem;
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

.terminal-text {
  background-color: #000;
  color: #0f0;
  padding: 1rem;
  border-radius: 0.5rem;
  font-family: "Fira Code", monospace;
  font-size: 0.9rem;
  max-height: 100%;
  overflow-y: auto;
}

/* 타이핑 효과를 JS로 구현할 것이라, 여기서는 기본 스타일만 */

/* 취약 버전 범위 스타일 */
td small {
  font-size: 0.85rem;
  color: #6c757d;
}

/* 테이블 반응형 */
table {
  font-size: 0.9rem;
}

@media (max-width: 1200px) {
  table {
    font-size: 0.8rem;
  }
}

/* CVE 테이블 링크 호버 효과 */
table tbody tr:hover {
  background-color: rgba(255, 255, 255, 0.1);
}
/* ✅ 마크다운 렌더링 스타일 */
.markdown-content {
    line-height: 1.6;
}

.markdown-content h1 {
    color: #e74c3c;
    border-bottom: 2px solid #e74c3c;
    padding-bottom: 10px;
    margin-top: 20px;
}

.markdown-content h2 {
    color: #3498db;
    border-bottom: 1px solid #3498db;
    padding-bottom: 8px;
    margin-top: 18px;
}

.markdown-content h3 {
    color: #2ecc71;
    margin-top: 15px;
}

.markdown-content ul {
    margin-left: 20px;
}

.markdown-content li {
    margin-bottom: 8px;
}

.markdown-content code {
    background: #2c3e50;
    color: #e74c3c;
    padding: 2px 6px;
    border-radius: 3px;
    font-family: 'Courier New', monospace;
}

.markdown-content pre {
    background: #2c3e50;
    color: #ecf0f1;
    padding: 15px;
    border-radius: 5px;
    overflow-x: auto;
}

.markdown-content blockquote {
    border-left: 4px solid #3498db;
    padding-left: 15px;
    color: #95a5a6;
    font-style: italic;
}

.markdown-content strong {
    color: #e74c3c;
    font-weight: bold;
}

/* ✅ 검증 상태 배지 */
.verification-badge {
    padding: 4px 10px;
    border-radius: 12px;
    font-size: 0.85em;
    font-weight: bold;
    white-space: nowrap;
}

.verified-exploitable {
    background: #e74c3c;
    color: white;
}

.verified-safe {
    background: #2ecc71;
    color: white;
}

.not-verified {
    background: #95a5a6;
    color: white;
}

/* ✅ 모달 스타일 */
.modal {
    display: none;
    position: fixed;
    z-index: 1000;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
    overflow: auto;
    background-color: rgba(0, 0, 0, 0.8);
}

.modal-content {
    background-color: #1e2a38;
    margin: 5% auto;
    padding: 30px;
    border: 1px solid #3498db;
    border-radius: 10px;
    width: 80%;
    max-width: 1000px;
    color: #ecf0f1;
}

.close {
    color: #95a5a6;
    float: right;
    font-size: 32px;
    font-weight: bold;
    cursor: pointer;
}

.close:hover,
.close:focus {
    color: #e74c3c;
}

.tech-category {
    margin-bottom: 25px;
}

.tech-category h3 {
    color: #3498db;
    border-bottom: 1px solid #3498db;
    padding-bottom: 8px;
    margin-bottom: 12px;
}

.tech-category ul {
    list-style: none;
    padding-left: 0;
}

.tech-category li {
    padding: 8px;
    margin: 5px 0;
    background: #2c3e50;
    border-radius: 5px;
    border-left: 3px solid #3498db;
}

.tech-category li .tech-name {
    font-weight: bold;
    color: #3498db;
}

.tech-category li .tech-version {
    color: #e74c3c;
    margin-left: 10px;
}

.tech-category li .tech-source {
    color: #95a5a6;
    font-size: 0.85em;
    margin-left: 10px;
}

/* ✅ 버튼 스타일 */
.secondary-btn {
    background: #3498db;
    color: white;
    border: none;
    padding: 10px 20px;
    border-radius: 5px;
    cursor: pointer;
    margin-top: 10px;
    font-size: 0.95em;
    transition: background 0.3s;
}

.secondary-btn:hover {
    background: #2980b9;
}

/* ✅ 민감 파일 리스트 스타일 */
.loot-subsection {
    margin-bottom: 20px;
}

.loot-subsection h3 {
    color: #e74c3c;
    margin-bottom: 10px;
}

#sensitive-files-list {
    list-style: none;
    padding: 0;
}

#sensitive-files-list li {
    padding: 8px;
    margin: 5px 0;
    background: #2c3e50;
    border-radius: 5px;
    border-left: 3px solid #e74c3c;
}

#sensitive-files-list .file-path {
    color: #3498db;
    font-weight: bold;
}

#sensitive-files-list .file-status {
    color: #e74c3c;
    margin-left: 10px;
}

#sensitive-files-list .file-note {
    color: #95a5a6;
    font-size: 0.9em;
    margin-left: 10px;
}
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    color: #ecf0f1;
    line-height: 1.6;
}

header {
    background: linear-gradient(90deg, #0f3460 0%, #16213e 100%);
    padding: 30px;
    text-align: center;
    border-bottom: 3px solid #e94560;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.3);
}

header h1 {
    font-size: 2.5em;
    color: #e94560;
    font-weight: 700;
    letter-spacing: 2px;
}

main {
    max-width: 1400px;
    margin: 30px auto;
    padding: 0 20px;
}

.input-section {
    display: flex;
    gap: 15px;
    margin-bottom: 30px;
    background: #0f3460;
    padding: 20px;
    border-radius: 8px;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
}

#target-input {
    flex: 1;
    padding: 12px 15px;
    border: 2px solid #16213e;
    background: #1a1a2e;
    color: #ecf0f1;
    border-radius: 5px;
    font-size: 1em;
    transition: all 0.3s ease;
}

#target-input:focus {
    outline: none;
    border-color: #e94560;
    box-shadow: 0 0 10px rgba(233, 69, 96, 0.3);
}

#scan-btn {
    padding: 12px 30px;
    background: linear-gradient(90deg, #e94560 0%, #f39c12 100%);
    color: white;
    border: none;
    border-radius: 5px;
    font-size: 1em;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.3s ease;
    box-shadow: 0 4px 15px rgba(233, 69, 96, 0.3);
}

#scan-btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(233, 69, 96, 0.4);
}

#scan-btn:disabled {
    opacity: 0.7;
    cursor: not-allowed;
}

.dashboard {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 30px;
    margin-bottom: 30px;
}

@media (max-width: 1200px) {
    .dashboard {
        grid-template-columns: 1fr;
    }
}

.section {
    background: #0f3460;
    padding: 25px;
    border-radius: 8px;
    border-left: 4px solid #e94560;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
    margin-bottom: 25px;
}

.section h2 {
    font-size: 1.5em;
    margin-bottom: 20px;
    color: #e94560;
    font-weight: 700;
    border-bottom: 2px solid #16213e;
    padding-bottom: 10px;
}

.info-text {
    font-size: 0.9em;
    color: #95a5a6;
    margin-bottom: 15px;
}

.highlight {
    color: #3498db;
    font-weight: bold;
}

.secondary {
    color: #7f8c8d;
}

.tech-list {
    list-style: none;
    padding: 0;
}

.tech-list li {
    padding: 10px;
    margin: 8px 0;
    background: #1a1a2e;
    border-left: 3px solid #3498db;
    border-radius: 5px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.tech-name {
    color: #3498db;
    font-weight: bold;
    flex: 1;
}

.tech-version {
    color: #e74c3c;
    margin: 0 15px;
    font-weight: bold;
}

.tech-source {
    color: #7f8c8d;
    font-size: 0.85em;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 15px;
}

thead {
    background: #16213e;
    border-bottom: 2px solid #e94560;
}

th {
    padding: 15px;
    text-align: left;
    color: #e94560;
    font-weight: 700;
}

td {
    padding: 12px 15px;
    border-bottom: 1px solid #16213e;
}

tr:hover {
    background: rgba(233, 69, 96, 0.1);
}

.exploitable-row {
    background: rgba(231, 76, 60, 0.1) !important;
}

.cve-link {
    color: #3498db;
    text-decoration: none;
    font-weight: bold;
    transition: color 0.3s ease;
}

.cve-link:hover {
    color: #e94560;
}

.cvss-badge {
    padding: 5px 10px;
    border-radius: 5px;
    font-weight: bold;
    font-size: 0.85em;
}

.cvss-badge.critical {
    background: #e74c3c;
    color: white;
}

.cvss-badge.high {
    background: #e67e22;
    color: white;
}

.cvss-badge.medium {
    background: #f39c12;
    color: white;
}

.cvss-badge.low {
    background: #2ecc71;
    color: white;
}

.description-cell {
    font-size: 0.85em;
    color: #bdc3c7;
    max-width: 300px;
}

/* Markdown 스타일 */
.markdown-content h1,
.markdown-content h2,
.markdown-content h3,
.markdown-content h4,
.markdown-content h5,
.markdown-content h6 {
    margin-top: 20px;
    margin-bottom: 10px;
    font-weight: 700;
    color: #e94560;
}

.markdown-content h2 {
    border-bottom: 2px solid #3498db;
    padding-bottom: 10px;
    color: #3498db;
}

.markdown-content h3 {
    color: #2ecc71;
}

.markdown-content ul,
.markdown-content ol {
    margin-left: 20px;
    margin-bottom: 15px;
}

.markdown-content li {
    margin-bottom: 8px;
    color: #ecf0f1;
}

.markdown-content strong {
    color: #e74c3c;
    font-weight: bold;
}

.markdown-content em {
    color: #f39c12;
    font-style: italic;
}

.markdown-content code {
    background: #1a1a2e;
    color: #2ecc71;
    padding: 2px 6px;
    border-radius: 3px;
    font-family: 'Courier New', monospace;
}

.markdown-content pre {
    background: #1a1a2e;
    color: #2ecc71;
    padding: 15px;
    border-radius: 5px;
    border-left: 4px solid #e94560;
    overflow-x: auto;
    margin: 15px 0;
}

.markdown-content pre code {
    background: none;
    color: inherit;
    padding: 0;
}

.markdown-content blockquote {
    border-left: 4px solid #3498db;
    padding-left: 15px;
    color: #95a5a6;
    font-style: italic;
    margin-left: 0;
}

/* Loot 리스트 */
#sensitive-files-list {
    list-style: none;
    padding: 0;
}

#sensitive-files-list li {
    padding: 12px;
    margin: 8px 0;
    background: #1a1a2e;
    border-left: 3px solid #e74c3c;
    border-radius: 5px;
    color: #ecf0f1;
}

#sensitive-files-list li.exploitable {
    border-left-color: #e74c3c;
    background: rgba(231, 76, 60, 0.1);
}

#sensitive-files-list li.warning {
    border-left-color: #f39c12;
    background: rgba(243, 156, 18, 0.1);
}

.file-path {
    color: #3498db;
    font-weight: bold;
    display: inline-block;
    margin-right: 10px;
}

.file-status {
    color: #e74c3c;
    font-weight: bold;
    display: inline-block;
    margin-right: 10px;
}

.file-note {
    color: #7f8c8d;
    font-size: 0.85em;
    display: block;
    margin-top: 5px;
}

/* 모달 */
.modal {
    display: none;
    position: fixed;
    z-index: 1000;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
    overflow: auto;
    background-color: rgba(0, 0, 0, 0.8);
    animation: fadeIn 0.3s ease;
}

@keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
}

.modal-content {
    background: linear-gradient(135deg, #0f3460 0%, #16213e 100%);
    margin: 5% auto;
    padding: 30px;
    border: 2px solid #e94560;
    border-radius: 10px;
    width: 90%;
    max-width: 1000px;
    color: #ecf0f1;
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
}

.close {
    color: #95a5a6;
    float: right;
    font-size: 32px;
    font-weight: bold;
    cursor: pointer;
    transition: color 0.3s ease;
}

.close:hover {
    color: #e94560;
}

.tech-category {
    margin-bottom: 25px;
}

.tech-category h3 {
    color: #3498db;
    border-bottom: 2px solid #3498db;
    padding-bottom: 10px;
    margin-bottom: 15px;
}

.tech-category ul {
    list-style: none;
    padding: 0;
}

.tech-category li {
    padding: 10px;
    margin: 8px 0;
    background: #1a1a2e;
    border-left: 3px solid #3498db;
    border-radius: 5px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.no-data {
    color: #95a5a6;
    text-align: center;
    padding: 20px;
    font-style: italic;
}

.error-message {
    color: #e74c3c;
    background: rgba(231, 76, 60, 0.1);
    padding: 15px;
    border-radius: 5px;
    border-left: 4px solid #e74c3c;
}

.loading {
    color: #3498db;
    font-weight: bold;
    animation: pulse 1.5s infinite;
}

@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
}

.secondary-btn {
    background: #3498db;
    color: white;
    border: none;
    padding: 10px 20px;
    border-radius: 5px;
    cursor: pointer;
    font-size: 0.95em;
    transition: all 0.3s ease;
    display: inline-block;
    margin-top: 10px;
}

.secondary-btn:hover {
    background: #2980b9;
    transform: translateY(-2px);
    box-shadow: 0 4px 15px rgba(52, 152, 219, 0.3);
}
/* 화이트해커용 근거 박스 스타일 */
.tech-card {
    background: #2d2d2d; border-left: 4px solid #007bff;
    margin-bottom: 10px; padding: 12px; border-radius: 4px;
}
.evidence-btn {
    background: #444; color: #aaa; border: none; font-size: 11px;
    cursor: pointer; padding: 2px 8px; margin-top: 5px; border-radius: 3px;
}
.evidence-btn:hover { background: #555; color: #fff; }
.evidence-content {
    display: none; background: #1a1a1a; color: #00ff00;
    padding: 8px; margin-top: 8px; font-family: monospace; font-size: 12px;
    border-radius: 3px; border: 1px dashed #333;
}
.source-badge {
    background: #0056b3; font-size: 10px; padding: 1px 5px;
    border-radius: 4px; margin-left: 5px;
}
```
---

## File 69: url_tree.css
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\static\css\url_tree.css`

```css
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    min-height: 100vh;
    padding: 20px;
}

.container {
    max-width: 1600px;
    margin: 0 auto;
    background: white;
    border-radius: 12px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.1);
    padding: 30px;
}

header {
    text-align: center;
    margin-bottom: 30px;
    padding-bottom: 20px;
    border-bottom: 2px solid #e0e0e0;
}

header h1 {
    font-size: 2.5em;
    color: #333;
    margin-bottom: 10px;
}

header p {
    color: #666;
    font-size: 1.1em;
}

.control-panel {
    background: #f5f5f5;
    padding: 20px;
    border-radius: 8px;
    margin-bottom: 30px;
}

.input-group {
    display: flex;
    gap: 10px;
    margin-bottom: 15px;
}

.input-group input {
    flex: 1;
    padding: 12px 20px;
    font-size: 16px;
    border: 2px solid #ddd;
    border-radius: 6px;
    transition: border-color 0.3s;
}

.input-group input:focus {
    outline: none;
    border-color: #667eea;
}

.button-group {
    display: flex;
    gap: 10px;
    justify-content: center;
}

.btn-primary, .btn-secondary {
    padding: 12px 24px;
    font-size: 16px;
    font-weight: 600;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    transition: all 0.3s;
}

.btn-primary {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
}

.btn-primary:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
}

.btn-secondary {
    background: #fff;
    color: #667eea;
    border: 2px solid #667eea;
}

.btn-secondary:hover {
    background: #667eea;
    color: white;
}

.loading {
    text-align: center;
    padding: 40px;
    background: #f9f9f9;
    border-radius: 8px;
    margin: 20px 0;
}

.spinner {
    border: 4px solid #f3f3f3;
    border-top: 4px solid #667eea;
    border-radius: 50%;
    width: 50px;
    height: 50px;
    animation: spin 1s linear infinite;
    margin: 0 auto 20px;
}

@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}

.stats-container {
    margin: 20px 0;
}

.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}

.stat-card {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 25px;
    border-radius: 8px;
    text-align: center;
    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
}

.stat-card h3 {
    font-size: 2.5em;
    margin-bottom: 10px;
}

.stat-card p {
    font-size: 1.1em;
    opacity: 0.9;
}

.legend {
    background: #f9f9f9;
    padding: 20px;
    border-radius: 8px;
    margin-bottom: 20px;
}

.legend h3 {
    font-size: 1.2em;
    margin-bottom: 15px;
    color: #333;
}

.legend-items {
    display: flex;
    flex-wrap: wrap;
    gap: 20px;
}

.legend-item {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 14px;
}

.color-box {
    width: 20px;
    height: 20px;
    border-radius: 4px;
    border: 2px solid #333;
}

.tree-container {
    overflow: auto;
    background: #fafafa;
    border-radius: 8px;
    padding: 20px;
    border: 1px solid #e0e0e0;
}

.node circle {
    cursor: pointer;
}

.node text {
    font: 12px sans-serif;
    font-weight: 500;
}

.link {
    fill: none;
    stroke: #ccc;
    stroke-width: 2px;
}

@media (max-width: 768px) {
    .container {
        padding: 15px;
    }

    header h1 {
        font-size: 1.8em;
    }

    .input-group {
        flex-direction: column;
    }

    .button-group {
        flex-direction: column;
    }

    .stats-grid {
        grid-template-columns: 1fr;
    }
}
```
---

## File 70: dashboard.js
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\static\js\dashboard.js`

```javascript
(() => {
    // 1. 소켓 안전 연결 (전역 window 객체 공유)
    if (!window.socket) {
        window.socket = io();
    }
    const socket = window.socket;

    document.addEventListener('DOMContentLoaded', () => {
        // 2. 안전장치: 대시보드 요소 확인
        const scanBtn = document.getElementById('scan-btn');
        const targetInput = document.getElementById('target-input');

        // 요소가 없으면 조용히 종료 (상세 페이지 등에서 에러 방지)
        if (!scanBtn || !targetInput) {
            // console.log('[INFO] Dashboard skipped (Not on dashboard page)');
            return;
        }

        console.log('[INIT] Dashboard initialized');

        // 3. 스캔 시작 로직
        scanBtn.addEventListener('click', () => {
            const target = targetInput.value.trim();
            if (!target) {
                alert('Please enter a valid URL');
                return;
            }

            scanBtn.disabled = true;
            scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Starting...';

            socket.emit('create_project', { target: target });
        });
    });

    // 4. 소켓 이벤트 리스너
    socket.on('project_created', (data) => {
        if (data.project_id) {
            console.log(`[SUCCESS] Project created: ${data.project_id}`);
            window.location.href = `/live-scan/${data.project_id}`;
        }
    });

    socket.on('error', (data) => {
        const scanBtn = document.getElementById('scan-btn');
        if (scanBtn) { // 버튼이 있는 경우에만 처리
            console.error('[ERROR]', data.message);
            scanBtn.disabled = false;
            scanBtn.innerHTML = 'Start Scan';
            alert('Error: ' + data.message);
        }
    });
})();
```
---

## File 71: live_scan.js
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\static\js\live_scan.js`

```javascript
console.log("⚡ LIVE SCAN JS RELOADED - Clean Version");

// 1. Socket Connection
if (!window.socket) {
    console.log("[DEBUG] Creating new socket connection...");
    window.socket = io();
} else {
    console.log("[DEBUG] Reusing existing socket connection");
}

const liveSocket = window.socket;

// URL Parsing for Project ID
const pathParts = window.location.pathname.split('/');
let pid = pathParts.pop();
if (!pid) pid = pathParts.pop(); // handle trailing slash
const projectId = pid;

let scanActive = false;
let foundTechnologies = {};

// 2. Initialize
document.addEventListener("DOMContentLoaded", function() {
    console.log("[DEBUG] DOMContentLoaded event fired");

    const startBtn = document.getElementById("start-scan-btn");
    
    // [FIX] Restore from LocalStorage (새로고침 시 결과 유지)
    const savedResults = localStorage.getItem("scanResults");
    if (savedResults) {
        try {
            foundTechnologies = JSON.parse(savedResults);
            Object.values(foundTechnologies).forEach(tech => renderTechCard(tech));
            console.log("[DEBUG] Restored previous results from LocalStorage");
        } catch(e) {
            console.error("[ERROR] Failed to restore LocalStorage", e);
            localStorage.removeItem("scanResults");
        }
    }

    if (startBtn) {
        // Remove existing listeners by cloning
        const newBtn = startBtn.cloneNode(true);
        startBtn.parentNode.replaceChild(newBtn, startBtn);
        
        newBtn.addEventListener("click", startScan);
    } else {
        console.error("[ERROR] Start button 'start-scan-btn' NOT FOUND in DOM!");
    }
});

// 3. Socket Events
liveSocket.on("connect", () => {
    console.log("[DEBUG] Socket connected successfully ID:", liveSocket.id);
});

liveSocket.on("scan_progress", (data) => {
    const term = document.getElementById("log-terminal");
    if (!term) return;

    const line = document.createElement("div");
    line.className = "log-line";
    
    let colorClass = "text-light";
    if (data.stage === "error") colorClass = "text-danger";
    else if (data.stage === "success") colorClass = "text-success";
    else if (data.stage === "recon") colorClass = "text-info";

    line.innerHTML = `<span class="text-muted">[${new Date().toLocaleTimeString()}]</span> <span class="${colorClass}">${data.current_item}</span>`;
    
    term.appendChild(line);
    term.scrollTop = term.scrollHeight;

    const progBar = document.getElementById("scan-progress-bar");
    if (progBar) {
        progBar.style.width = data.progress + "%";
        progBar.setAttribute("aria-valuenow", data.progress);
    }
});

liveSocket.on("technology_detected", (tech) => {
    console.log("[DEBUG] Tech detected:", tech.name);
    const techKey = tech.name.toLowerCase();
    
    foundTechnologies[techKey] = tech;
    
    // [FIX] Save to LocalStorage
    localStorage.setItem("scanResults", JSON.stringify(foundTechnologies));

    renderTechCard(tech);
});

liveSocket.on("scan_completed", () => {
    console.log("[DEBUG] Scan completed");
    const statusDiv = document.getElementById("scan-status");
    if(statusDiv) statusDiv.innerHTML = '<span class="badge bg-success">Completed</span>';
    
    const startBtn = document.getElementById("start-scan-btn");
    if(startBtn) startBtn.disabled = false;
    
    scanActive = false;
});

// 4. Core Functions
function startScan() {
    if (scanActive) return;

    const targetUrlElem = document.getElementById("target-url");
    if (!targetUrlElem) return alert("Error: Target URL element not found.");

    const targetUrl = targetUrlElem.textContent.trim();
    if (!targetUrl) return alert("Target URL is empty!");

    // [FIX] Reset Previous Data
    localStorage.removeItem("scanResults");
    foundTechnologies = {};
    const grid = document.getElementById("tech-grid");
    if(grid) grid.innerHTML = "";
    
    const term = document.getElementById("log-terminal");
    if(term) term.innerHTML = '<div class="text-info">Requesting scan start...</div>';

    // UI Updates
    scanActive = true;
    const startBtn = document.getElementById("start-scan-btn");
    if(startBtn) startBtn.disabled = true;

    const statusDiv = document.getElementById("scan-status");
    if(statusDiv) statusDiv.innerHTML = '<span class="badge bg-warning text-dark">Scanning...</span>';

    console.log("[DEBUG] Emitting start_scan event...");
    liveSocket.emit("start_scan", { target: targetUrl, project_id: projectId });
}

function renderTechCard(tech) {
    const grid = document.getElementById("tech-grid");
    if (!grid) return;

    // Check Duplicate
    if (document.getElementById(`tech-card-${tech.name}`)) return;

    const col = document.createElement("div");
    col.className = "col-md-3 mb-3";
    col.innerHTML = `
        <div class="card h-100 shadow-sm tech-card" id="tech-card-${tech.name}" 
             onclick="window.showTechDetail('${tech.name}')" 
             style="cursor: pointer; transition: transform 0.2s;">
            <div class="card-body text-center">
                <h5 class="card-title fw-bold text-primary">${tech.name}</h5>
                <p class="card-text text-muted small">${tech.version || "Version Detected"}</p>
                <span class="badge bg-secondary">${tech.source || "Detected"}</span>
            </div>
        </div>
    `;
    grid.appendChild(col);
}

// Global function for onclick in HTML
window.showTechDetail = function(techName) {
    console.log("[DEBUG] Opening detail for:", techName);
    const tech = foundTechnologies[techName.toLowerCase()];
    if (!tech) return;

    const modalEl = document.getElementById("techModal");
    if (!modalEl) return;

    const modalTitle = document.getElementById("techModalLabel");
    const modalBody = modalEl.querySelector(".modal-body");

    modalTitle.innerHTML = `${tech.name} <span class="badge bg-primary ms-2">${tech.version || "N/A"}</span>`;

    let evidenceList = tech.evidence || [];
    if (typeof evidenceList === 'string') evidenceList = evidenceList.split('\n');
    else if (!Array.isArray(evidenceList)) evidenceList = [evidenceList];

    let hints = tech.hints || ["No specific verification hints available."];
    
    // Safe HTML Generation
    let evidenceHtml = evidenceList.map(ev => {
        return `<tr><td class="text-primary fw-bold">Scanner</td><td class="font-monospace small">${ev}</td></tr>`;
    }).join('');

    let hintsText = Array.isArray(hints) ? hints.join('\n') : hints;

    modalBody.innerHTML = `
        <div class="container-fluid">
            <div class="row mb-3">
                <div class="col-md-6"><small class="text-muted text-uppercase">Confidence</small><br>
                    <span class="fw-bold ${tech.confidence === 'High' ? 'text-success' : 'text-warning'}">${tech.confidence || "Medium"}</span>
                </div>
                <div class="col-md-6"><small class="text-muted text-uppercase">Source</small><br>
                    <span class="fw-bold">${tech.source}</span>
                </div>
            </div>
            <hr>
            <h6 class="fw-bold text-dark mb-2">Evidence</h6>
            <div class="table-responsive mb-3">
                <table class="table table-sm table-bordered">
                    <thead class="table-light"><tr><th>Source</th><th>Raw Evidence</th></tr></thead>
                    <tbody>${evidenceHtml}</tbody>
                </table>
            </div>
            <h6 class="fw-bold text-dark mb-2">Manual Verification</h6>
            <div class="bg-dark text-light p-3 rounded position-relative font-monospace small">
                <button class="btn btn-sm btn-outline-light position-absolute top-0 end-0 m-2 copy-btn">Copy</button>
                <div id="hint-content">${hintsText}</div>
            </div>
        </div>
    `;

    // Show Modal
    const modal = new bootstrap.Modal(modalEl);
    modal.show();
};

// 5. Global Event Listener (Cleanup & Fixes)
document.addEventListener("click", function(e) {
    // Copy Button
    const copyBtn = e.target.closest(".copy-btn");
    if (copyBtn) {
        const content = document.getElementById("hint-content");
        if (content) {
            navigator.clipboard.writeText(content.innerText).then(() => {
                const original = copyBtn.innerHTML;
                copyBtn.innerHTML = '<i class="fas fa-check"></i> Copied!';
                setTimeout(() => copyBtn.innerHTML = original, 1500);
            });
        }
    }
});
```
---

## File 72: url_tree.js
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\static\js\url_tree.js`

```javascript
class URLTreeVisualizer {
    constructor(containerId) {
        this.container = d3.select(`#${containerId}`);
        this.margin = {top: 20, right: 120, bottom: 20, left: 120};
        this.width = 1400 - this.margin.right - this.margin.left;
        this.height = 800 - this.margin.top - this.margin.bottom;
        this.duration = 750;
        this.i = 0;

        this.tree = d3.tree().size([this.height, this.width]);

        this.svg = this.container.append("svg")
            .attr("width", this.width + this.margin.right + this.margin.left)
            .attr("height", this.height + this.margin.top + this.margin.bottom)
            .append("g")
            .attr("transform", `translate(${this.margin.left},${this.margin.top})`);
    }

    async loadData(targetUrl) {
        try {
            const response = await fetch('/api/url-tree', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({target: targetUrl})
            });
            const data = await response.json();

            if (data.tree) {
                this.root = d3.hierarchy(data.tree);
                this.root.x0 = this.height / 2;
                this.root.y0 = 0;

                this.root.children.forEach(d => this.collapse(d));
                this.update(this.root);
                return data;
            }
        } catch (error) {
            console.error('Error loading tree data:', error);
            throw error;
        }
    }

    collapse(d) {
        if (d.children) {
            d._children = d.children;
            d._children.forEach(child => this.collapse(child));
            d.children = null;
        }
    }

    update(source) {
        const treeData = this.tree(this.root);
        const nodes = treeData.descendants();
        const links = treeData.descendants().slice(1);

        nodes.forEach(d => { d.y = d.depth * 180; });

        const node = this.svg.selectAll('g.node')
            .data(nodes, d => d.id || (d.id = ++this.i));

        const nodeEnter = node.enter().append('g')
            .attr('class', 'node')
            .attr('transform', d => `translate(${source.y0},${source.x0})`)
            .on('click', (event, d) => this.click(d));

        nodeEnter.append('circle')
            .attr('r', 1e-6)
            .style('fill', d => d._children ? '#90caf9' : '#fff')
            .style('stroke', d => this.getNodeColor(d.data))
            .style('stroke-width', '3px');

        nodeEnter.append('text')
            .attr('dy', '.35em')
            .attr('x', d => d.children || d._children ? -13 : 13)
            .attr('text-anchor', d => d.children || d._children ? 'end' : 'start')
            .text(d => d.data.name)
            .style('fill-opacity', 1e-6);

        const nodeUpdate = nodeEnter.merge(node);

        nodeUpdate.transition()
            .duration(this.duration)
            .attr('transform', d => `translate(${d.y},${d.x})`);

        nodeUpdate.select('circle')
            .attr('r', 6)
            .style('fill', d => d._children ? '#90caf9' : '#fff')
            .style('stroke', d => this.getNodeColor(d.data))
            .attr('cursor', 'pointer');

        nodeUpdate.select('text')
            .style('fill-opacity', 1);

        const nodeExit = node.exit().transition()
            .duration(this.duration)
            .attr('transform', d => `translate(${source.y},${source.x})`)
            .remove();

        nodeExit.select('circle')
            .attr('r', 1e-6);

        nodeExit.select('text')
            .style('fill-opacity', 1e-6);

        const link = this.svg.selectAll('path.link')
            .data(links, d => d.id);

        const linkEnter = link.enter().insert('path', 'g')
            .attr('class', 'link')
            .attr('d', d => {
                const o = {x: source.x0, y: source.y0};
                return this.diagonal(o, o);
            });

        const linkUpdate = linkEnter.merge(link);

        linkUpdate.transition()
            .duration(this.duration)
            .attr('d', d => this.diagonal(d, d.parent));

        link.exit().transition()
            .duration(this.duration)
            .attr('d', d => {
                const o = {x: source.x, y: source.y};
                return this.diagonal(o, o);
            })
            .remove();

        nodes.forEach(d => {
            d.x0 = d.x;
            d.y0 = d.y;
        });
    }

    diagonal(s, d) {
        return `M ${s.y} ${s.x}
                C ${(s.y + d.y) / 2} ${s.x},
                  ${(s.y + d.y) / 2} ${d.x},
                  ${d.y} ${d.x}`;
    }

    click(d) {
        if (d.children) {
            d._children = d.children;
            d.children = null;
        } else {
            d.children = d._children;
            d._children = null;
        }
        this.update(d);
    }

    getNodeColor(nodeData) {
        if (nodeData.status_code) {
            if (nodeData.status_code >= 200 && nodeData.status_code < 300) return '#4caf50';
            if (nodeData.status_code >= 300 && nodeData.status_code < 400) return '#ff9800';
            if (nodeData.status_code >= 400 && nodeData.status_code < 500) return '#f44336';
            if (nodeData.status_code >= 500) return '#9c27b0';
        }
        return '#1976d2';
    }

    expandAll() {
        this.root.children.forEach(d => this.expandRecursive(d));
        this.update(this.root);
    }

    collapseAll() {
        this.root.children.forEach(d => this.collapse(d));
        this.update(this.root);
    }

    expandRecursive(d) {
        if (d._children) {
            d.children = d._children;
            d._children = null;
        }
        if (d.children) {
            d.children.forEach(child => this.expandRecursive(child));
        }
    }
}

let treeVisualizer;

async function scanAndVisualize() {
    const targetUrl = document.getElementById('targetUrl').value;
    if (!targetUrl) {
        alert('Please enter a target URL');
        return;
    }

    document.getElementById('loadingIndicator').style.display = 'block';
    document.getElementById('treeContainer').innerHTML = '';
    document.getElementById('statsContainer').innerHTML = '';

    try {
        treeVisualizer = new URLTreeVisualizer('treeContainer');
        const data = await treeVisualizer.loadData(targetUrl);

        document.getElementById('statsContainer').innerHTML = `
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>${data.total_urls}</h3>
                    <p>Total URLs</p>
                </div>
                <div class="stat-card">
                    <h3>${data.tree_nodes || data.statistics?.total_nodes || 'N/A'}</h3>
                    <p>Tree Nodes</p>
                </div>
                <div class="stat-card">
                    <h3>${data.max_depth || data.statistics?.max_depth || 'N/A'}</h3>
                    <p>Max Depth</p>
                </div>
            </div>
        `;

        document.getElementById('loadingIndicator').style.display = 'none';
    } catch (error) {
        document.getElementById('loadingIndicator').style.display = 'none';
        alert('Error loading tree: ' + error.message);
    }
}

function expandAll() {
    if (treeVisualizer) {
        treeVisualizer.expandAll();
    }
}

function collapseAll() {
    if (treeVisualizer) {
        treeVisualizer.collapseAll();
    }
}
```
---

## File 73: base.html
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\templates\base.html`

```html
<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <title>CVE Recon & AI Dashboard</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
  <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
</head>
<body class="bg-dark text-light">
  <nav class="navbar navbar-dark bg-black border-bottom border-secondary mb-3">
    <div class="container-fluid">
      <span class="navbar-brand mb-0 h1">CVE Attack Simulation Dashboard</span>
    </div>
  </nav>

  <div class="container-fluid">
    {% block content %}{% endblock %}
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <script src="{{ url_for('static', filename='js/dashboard.js') }}"></script>
</body>
</html>
```
---

## File 74: dashboard copy.html
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\templates\dashboard copy.html`

```html
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Dashboard</title>
    <!-- Socket.IO Library 추가 -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: #e0e0e0; line-height: 1.6; }
        .container { max-width: 1600px; margin: 0 auto; padding: 20px; }
        header { text-align: center; padding: 40px 0 20px; border-bottom: 2px solid #0f3460; margin-bottom: 30px; }
        h1 { font-size: 2.5em; color: #00d4ff; text-shadow: 0 0 10px rgba(0, 212, 255, 0.5); margin-bottom: 10px; }
        .scan-section { margin-bottom: 30px; background: rgba(15, 52, 96, 0.5); border: 1px solid #0f3460; border-radius: 8px; padding: 20px; backdrop-filter: blur(10px); }
        .scan-controls { display: flex; gap: 15px; margin-bottom: 20px; flex-wrap: wrap; }
        input[type="text"], input[type="url"] { flex: 1; min-width: 300px; padding: 12px 15px; background: rgba(255, 255, 255, 0.1); border: 1px solid #0f3460; border-radius: 6px; color: #e0e0e0; font-size: 14px; }
        input[type="text"]:focus, input[type="url"]:focus { outline: none; border-color: #00d4ff; box-shadow: 0 0 10px rgba(0, 212, 255, 0.3); }
        button { padding: 12px 30px; background: linear-gradient(135deg, #00d4ff 0%, #0099cc 100%); border: none; border-radius: 6px; color: #000; font-weight: bold; cursor: pointer; transition: all 0.3s ease; font-size: 14px; }
        button:hover { transform: translateY(-2px); box-shadow: 0 10px 20px rgba(0, 212, 255, 0.3); }
        button:disabled { background: #666; cursor: not-allowed; opacity: 0.6; }
        .loading { display: flex; align-items: center; justify-content: center; gap: 10px; padding: 20px; color: #00d4ff; }
        .spinner { border: 3px solid rgba(0, 212, 255, 0.2); border-top: 3px solid #00d4ff; border-radius: 50%; width: 30px; height: 30px; animation: spin 1s linear infinite; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        
        /* [NEW] 실시간 로그 박스 스타일 */
        #live-log-container { display: none; margin-top: 20px; background: rgba(0, 0, 0, 0.8); border: 1px solid #0f3460; border-radius: 8px; padding: 15px; }
        #live-scan-log { height: 200px; overflow-y: auto; font-family: 'Courier New', monospace; font-size: 0.9em; color: #00ff88; }
        .log-info { color: #00d4ff; }
        .log-success { color: #00ff88; font-weight: bold; }
        .log-error { color: #ff4444; }

        .section-title { font-size: 1.5em; color: #00d4ff; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 2px solid #0f3460; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 25px; }
        .stat-card { background: rgba(0, 212, 255, 0.1); border: 1px solid #00d4ff; border-radius: 6px; padding: 15px; text-align: center; }
        .stat-label { font-size: 0.9em; color: #aaa; margin-bottom: 8px; }
        .stat-value { font-size: 2em; font-weight: bold; color: #00d4ff; }
        .severity-high { color: #ff4444; }
        .severity-medium { color: #ffaa00; }
        .severity-low { color: #00ff88; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        thead { background: rgba(0, 212, 255, 0.15); }
        th { padding: 12px; text-align: left; color: #00d4ff; font-weight: bold; border-bottom: 2px solid #0f3460; }
        td { padding: 12px; border-bottom: 1px solid rgba(0, 212, 255, 0.1); }
        tr:hover { background: rgba(0, 212, 255, 0.05); }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 0.85em; font-weight: bold; margin-right: 5px; }
        .badge-high { background: rgba(255, 68, 68, 0.3); color: #ff4444; border: 1px solid #ff4444; }
        .badge-medium { background: rgba(255, 170, 0, 0.3); color: #ffaa00; border: 1px solid #ffaa00; }
        .badge-low { background: rgba(0, 255, 136, 0.3); color: #00ff88; border: 1px solid #00ff88; }
        .badge-info { background: rgba(0, 212, 255, 0.3); color: #00d4ff; border: 1px solid #00d4ff; }
        .tabs { display: flex; gap: 10px; margin-bottom: 20px; border-bottom: 2px solid #0f3460; flex-wrap: wrap; }
        .tab-button { padding: 10px 20px; background: transparent; border: none; border-bottom: 3px solid transparent; color: #aaa; cursor: pointer; font-weight: bold; transition: all 0.3s ease; }
        .tab-button.active { color: #00d4ff; border-bottom-color: #00d4ff; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .cve-item { background: rgba(0, 0, 0, 0.3); border-left: 4px solid #00d4ff; padding: 15px; margin-bottom: 10px; border-radius: 4px; }
        .cve-id { font-weight: bold; color: #00d4ff; font-family: monospace; }
        .cve-description { margin-top: 8px; color: #bbb; font-size: 0.95em; }
        .alert-item { background: rgba(0, 0, 0, 0.3); border-left: 4px solid #ffaa00; padding: 15px; margin-bottom: 10px; border-radius: 4px; }
        .alert-item.high { border-left-color: #ff4444; }
        .alert-item.low { border-left-color: #00ff88; }
        .tech-list { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .tech-card { background: rgba(0, 212, 255, 0.1); border: 1px solid #00d4ff; border-radius: 6px; padding: 15px; }
        .tech-name { font-weight: bold; color: #00d4ff; margin-bottom: 8px; }
        .tech-version { color: #aaa; font-size: 0.9em; margin-bottom: 5px; }
        .tech-source { font-size: 0.85em; color: #888; }
        .scenario-box { background: rgba(0, 0, 0, 0.5); border: 1px solid #0f3460; border-radius: 6px; padding: 20px; white-space: pre-wrap; word-wrap: break-word; font-family: 'Courier New', monospace; font-size: 0.95em; color: #00ff88; max-height: 500px; overflow-y: auto; }
        .error-message { background: rgba(255, 68, 68, 0.2); border: 1px solid #ff4444; border-radius: 6px; padding: 15px; color: #ff8888; margin-bottom: 20px; }
        .success-message { background: rgba(0, 255, 136, 0.2); border: 1px solid #00ff88; border-radius: 6px; padding: 15px; color: #00ff88; margin-bottom: 20px; }
        .empty-state { text-align: center; padding: 40px; color: #aaa; }
        .footer { text-align: center; padding: 20px; color: #666; border-top: 2px solid #0f3460; margin-top: 40px; }
        .severity-indicator { display: inline-block; width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; }
        .severity-indicator.high { background: #ff4444; }
        .severity-indicator.medium { background: #ffaa00; }
        .severity-indicator.low { background: #00ff88; }
        .scroll-table { overflow-x: auto; }
        .json-viewer { background: rgba(0, 0, 0, 0.5); border: 1px solid #0f3460; border-radius: 6px; padding: 15px; font-family: 'Courier New', monospace; font-size: 0.9em; color: #00d4ff; max-height: 400px; overflow-y: auto; }
        .filter-buttons { margin-bottom: 15px; display: flex; gap: 10px; flex-wrap: wrap; }
        .filter-btn { padding: 8px 16px; background: rgba(0, 212, 255, 0.3); color: #00d4ff; border: 1px solid #00d4ff; border-radius: 6px; cursor: pointer; transition: all 0.3s ease; }
        .filter-btn.active { background: #00d4ff; color: #000; }
        .filter-btn:hover { background: rgba(0, 212, 255, 0.5); }
        @media (max-width: 768px) {
            h1 { font-size: 1.8em; }
            .scan-controls { flex-direction: column; }
            input[type="text"], input[type="url"] { min-width: auto; }
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
            .tech-list { grid-template-columns: 1fr; }
            .tabs { flex-wrap: wrap; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Security Scan Dashboard</h1>
            <p>Comprehensive vulnerability assessment and analysis</p>
        </header>

        <!-- Scan Controls -->
        <div class="scan-section">
            <div class="scan-controls">
                <input type="url" id="targetInput" placeholder="Enter target URL (e.g., http://127.0.0.1:3000)" value="http://127.0.0.1:3000">
                <button id="scanButton" onclick="startScan()">🚀 Start Scan</button>
            </div>
            
            <div id="loadingIndicator" class="loading" style="display: none;">
                <div class="spinner"></div>
                <span>Scanning in progress... This may take several minutes</span>
            </div>
            
            <!-- [NEW] 실시간 로그 박스 -->
            <div id="live-log-container">
                <div style="margin-bottom: 5px; color: #aaa; font-size: 0.8em; border-bottom: 1px solid #333; padding-bottom: 5px;">
                    ⚡ LIVE SCAN LOGS
                </div>
                <div id="live-scan-log"></div>
            </div>

            <div id="errorMessage" class="error-message" style="display: none;"></div>
            <div id="successMessage" class="success-message" style="display: none;"></div>
        </div>

        <!-- Summary Stats -->
        <div class="scan-section" id="statsSection" style="display: none;">
            <h2 class="section-title">Scan Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">Technologies Detected</div>
                    <div class="stat-value" id="techCount">0</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">CVEs Found</div>
                    <div class="stat-value" id="cveCount">0</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">ZAP Alerts</div>
                    <div class="stat-value" id="zapCount">0</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Vulnerabilities Verified</div>
                    <div class="stat-value" id="verifyCount">0</div>
                </div>
            </div>

            <!-- Alert Breakdown -->
            <div style="margin-top: 20px;">
                <h3 style="color: #00d4ff; margin-bottom: 10px;">Alert Severity Breakdown</h3>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-label">High Risk</div>
                        <div class="stat-value severity-high" id="highCount">0</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Medium Risk</div>
                        <div class="stat-value severity-medium" id="mediumCount">0</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Low Risk</div>
                        <div class="stat-value severity-low" id="lowCount">0</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Results Tabs -->
        <div class="scan-section" id="resultsSection" style="display: none;">
            <div class="tabs">
                <button class="tab-button active" onclick="switchTab(event, 'technologies')">Technologies</button>
                <button class="tab-button" onclick="switchTab(event, 'cves')">CVEs</button>
                <button class="tab-button" onclick="switchTab(event, 'zap-alerts')">ZAP Alerts</button>
                <button class="tab-button" onclick="switchTab(event, 'verification')">Verification</button>
                <button class="tab-button" onclick="switchTab(event, 'scenario')">AI Scenario</button>
                <button class="tab-button" onclick="switchTab(event, 'raw-data')">Raw Data</button>
            </div>

            <!-- Technologies Tab -->
            <div id="technologies" class="tab-content active">
                <h2 class="section-title">Detected Technologies</h2>
                <div id="techContainer" class="tech-list"></div>
            </div>

            <!-- CVEs Tab -->
            <div id="cves" class="tab-content">
                <h2 class="section-title">CVE Vulnerabilities</h2>
                <div class="scroll-table">
                    <table>
                        <thead>
                            <tr>
                                <th>CVE ID</th>
                                <th>CVSS</th>
                                <th>Description</th>
                                <th>Product</th>
                            </tr>
                        </thead>
                        <tbody id="cveTable"></tbody>
                    </table>
                </div>
            </div>

            <!-- ZAP Alerts Tab -->
            <div id="zap-alerts" class="tab-content">
                <h2 class="section-title">OWASP ZAP Security Alerts</h2>
                <!-- Filter Buttons -->
                <div class="filter-buttons">
                    <button class="filter-btn active" onclick="filterZapAlerts(event, 'all')">All</button>
                    <button class="filter-btn" onclick="filterZapAlerts(event, 'High')">High</button>
                    <button class="filter-btn" onclick="filterZapAlerts(event, 'Medium')">Medium</button>
                    <button class="filter-btn" onclick="filterZapAlerts(event, 'Low')">Low</button>
                </div>
                <div id="zapContainer"></div>
            </div>

            <!-- Verification Tab -->
            <div id="verification" class="tab-content">
                <h2 class="section-title">Vulnerability Verification Results</h2>
                <div class="scroll-table">
                    <table>
                        <thead>
                            <tr>
                                <th>CVE ID</th>
                                <th>Endpoint</th>
                                <th>Status</th>
                                <th>Confidence</th>
                                <th>Exploitable</th>
                            </tr>
                        </thead>
                        <tbody id="verificationTable"></tbody>
                    </table>
                </div>
            </div>

            <!-- AI Scenario Tab -->
            <div id="scenario" class="tab-content">
                <h2 class="section-title">🤖 AI-Powered Attack Scenario</h2>
                <div id="scenarioContainer" class="scenario-box"></div>
            </div>

            <!-- Raw Data Tab -->
            <div id="raw-data" class="tab-content">
                <h2 class="section-title">Raw API Response</h2>
                <div id="rawDataContainer" class="json-viewer"></div>
            </div>
        </div>

        <footer class="footer">
            <p>Security Scan Dashboard | Powered by Nmap, CVE Database, and OWASP ZAP</p>
        </footer>
    </div>

    <!-- 메인 로직은 dashboard.js에 위임하되, 전역 변수 설정 -->
    <script>
        let currentScanData = null;
        let allZapAlerts = [];
        let currentZapFilter = 'all';
    </script>
    
    <!-- 기존 JS 파일 로드 -->
    <script src="{{ url_for('static', filename='js/dashboard.js') }}"></script>
</body>
</html>
```
---

## File 75: dashboard.html
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\templates\dashboard.html`

```html
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e0e0e0;
            line-height: 1.6;
        }

        .container {
            max-width: 1600px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            text-align: center;
            padding: 40px 0 20px;
            border-bottom: 2px solid #0f3460;
            margin-bottom: 30px;
        }

        h1 {
            font-size: 2.5em;
            color: #00d4ff;
            text-shadow: 0 0 10px rgba(0, 212, 255, 0.5);
            margin-bottom: 10px;
        }

        .scan-section {
            margin-bottom: 30px;
            background: rgba(15, 52, 96, 0.5);
            border: 1px solid #0f3460;
            border-radius: 8px;
            padding: 20px;
            backdrop-filter: blur(10px);
        }

        .scan-controls {
            display: flex;
            gap: 15px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }

        input[type="text"],
        input[type="url"] {
            flex: 1;
            min-width: 300px;
            padding: 12px 15px;
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid #0f3460;
            border-radius: 6px;
            color: #e0e0e0;
            font-size: 14px;
        }

        input[type="text"]:focus,
        input[type="url"]:focus {
            outline: none;
            border-color: #00d4ff;
            box-shadow: 0 0 10px rgba(0, 212, 255, 0.3);
        }

        button {
            padding: 12px 30px;
            background: linear-gradient(135deg, #00d4ff 0%, #0099cc 100%);
            border: none;
            border-radius: 6px;
            color: #000;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s ease;
            font-size: 14px;
        }

        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0, 212, 255, 0.3);
        }

        button:disabled {
            background: #666;
            cursor: not-allowed;
            opacity: 0.6;
        }

        .loading {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            padding: 20px;
            color: #00d4ff;
        }

        .spinner {
            border: 3px solid rgba(0, 212, 255, 0.2);
            border-top: 3px solid #00d4ff;
            border-radius: 50%;
            width: 30px;
            height: 30px;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .section-title {
            font-size: 1.5em;
            color: #00d4ff;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #0f3460;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }

        .stat-card {
            background: rgba(0, 212, 255, 0.1);
            border: 1px solid #00d4ff;
            border-radius: 6px;
            padding: 15px;
            text-align: center;
        }

        .stat-label {
            font-size: 0.9em;
            color: #aaa;
            margin-bottom: 8px;
        }

        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #00d4ff;
        }

        .severity-high {
            color: #ff4444;
        }

        .severity-medium {
            color: #ffaa00;
        }

        .severity-low {
            color: #00ff88;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }

        thead {
            background: rgba(0, 212, 255, 0.15);
        }

        th {
            padding: 12px;
            text-align: left;
            color: #00d4ff;
            font-weight: bold;
            border-bottom: 2px solid #0f3460;
        }

        td {
            padding: 12px;
            border-bottom: 1px solid rgba(0, 212, 255, 0.1);
        }

        tr:hover {
            background: rgba(0, 212, 255, 0.05);
        }

        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            margin-right: 5px;
        }

        .badge-high {
            background: rgba(255, 68, 68, 0.3);
            color: #ff4444;
            border: 1px solid #ff4444;
        }

        .badge-medium {
            background: rgba(255, 170, 0, 0.3);
            color: #ffaa00;
            border: 1px solid #ffaa00;
        }

        .badge-low {
            background: rgba(0, 255, 136, 0.3);
            color: #00ff88;
            border: 1px solid #00ff88;
        }

        .badge-info {
            background: rgba(0, 212, 255, 0.3);
            color: #00d4ff;
            border: 1px solid #00d4ff;
        }

        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            border-bottom: 2px solid #0f3460;
            flex-wrap: wrap;
        }

        .tab-button {
            padding: 10px 20px;
            background: transparent;
            border: none;
            border-bottom: 3px solid transparent;
            color: #aaa;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.3s ease;
        }

        .tab-button.active {
            color: #00d4ff;
            border-bottom-color: #00d4ff;
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        .cve-item {
            background: rgba(0, 0, 0, 0.3);
            border-left: 4px solid #00d4ff;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 4px;
        }

        .cve-id {
            font-weight: bold;
            color: #00d4ff;
            font-family: monospace;
        }

        .cve-description {
            margin-top: 8px;
            color: #bbb;
            font-size: 0.95em;
        }

        .alert-item {
            background: rgba(0, 0, 0, 0.3);
            border-left: 4px solid #ffaa00;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 4px;
        }

        .alert-item.high {
            border-left-color: #ff4444;
        }

        .alert-item.low {
            border-left-color: #00ff88;
        }

        .tech-list {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }

        .tech-card {
            background: rgba(0, 212, 255, 0.1);
            border: 1px solid #00d4ff;
            border-radius: 6px;
            padding: 15px;
        }

        .tech-name {
            font-weight: bold;
            color: #00d4ff;
            margin-bottom: 8px;
        }

        .tech-version {
            color: #aaa;
            font-size: 0.9em;
            margin-bottom: 5px;
        }

        .tech-source {
            font-size: 0.85em;
            color: #888;
        }

        .scenario-box {
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid #0f3460;
            border-radius: 6px;
            padding: 20px;
            white-space: pre-wrap;
            word-wrap: break-word;
            font-family: 'Courier New', monospace;
            font-size: 0.95em;
            color: #00ff88;
            max-height: 500px;
            overflow-y: auto;
        }

        .error-message {
            background: rgba(255, 68, 68, 0.2);
            border: 1px solid #ff4444;
            border-radius: 6px;
            padding: 15px;
            color: #ff8888;
            margin-bottom: 20px;
        }

        .success-message {
            background: rgba(0, 255, 136, 0.2);
            border: 1px solid #00ff88;
            border-radius: 6px;
            padding: 15px;
            color: #00ff88;
            margin-bottom: 20px;
        }

        .empty-state {
            text-align: center;
            padding: 40px;
            color: #aaa;
        }

        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            border-top: 2px solid #0f3460;
            margin-top: 40px;
        }

        .severity-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }

        .severity-indicator.high {
            background: #ff4444;
        }

        .severity-indicator.medium {
            background: #ffaa00;
        }

        .severity-indicator.low {
            background: #00ff88;
        }

        .scroll-table {
            overflow-x: auto;
        }

        .json-viewer {
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid #0f3460;
            border-radius: 6px;
            padding: 15px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            color: #00d4ff;
            max-height: 400px;
            overflow-y: auto;
        }

        .filter-buttons {
            margin-bottom: 15px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        .filter-btn {
            padding: 8px 16px;
            background: rgba(0, 212, 255, 0.3);
            color: #00d4ff;
            border: 1px solid #00d4ff;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .filter-btn.active {
            background: #00d4ff;
            color: #000;
        }

        .filter-btn:hover {
            background: rgba(0, 212, 255, 0.5);
        }

        @media (max-width: 768px) {
            h1 {
                font-size: 1.8em;
            }

            .scan-controls {
                flex-direction: column;
            }

            input[type="text"],
            input[type="url"] {
                min-width: auto;
            }

            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }

            .tech-list {
                grid-template-columns: 1fr;
            }

            .tabs {
                flex-wrap: wrap;
            }
        }
    
/* Deep Fingerprinting Trace Styles */
.layer-card {
    background: rgba(0, 0, 0, 0.3);
    border-left: 4px solid #00d4ff;
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 20px;
    transition: all 0.3s ease;
    position: relative;
}

.layer-card.analyzing {
    border-left-color: #ffaa00;
    animation: pulse 1.5s infinite;
}

.layer-card.completed {
    border-left-color: #00ff88;
}

.layer-card.failed {
    border-left-color: #ff4444;
}

@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.7; }
}

.layer-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 15px;
}

.layer-title {
    font-size: 1.3em;
    color: #00d4ff;
    font-weight: bold;
}

.layer-status {
    display: inline-block;
    padding: 5px 15px;
    border-radius: 20px;
    font-size: 0.85em;
    font-weight: bold;
}

.layer-status.analyzing {
    background: rgba(255, 170, 0, 0.2);
    color: #ffaa00;
    border: 1px solid #ffaa00;
}

.layer-status.completed {
    background: rgba(0, 255, 136, 0.2);
    color: #00ff88;
    border: 1px solid #00ff88;
}

.layer-status.failed {
    background: rgba(255, 68, 68, 0.2);
    color: #ff4444;
    border: 1px solid #ff4444;
}

.layer-description {
    color: #aaa;
    font-size: 0.95em;
    margin-bottom: 15px;
}

.layer-metrics {
    display: flex;
    gap: 20px;
    margin-bottom: 15px;
    flex-wrap: wrap;
}

.layer-metric {
    display: flex;
    align-items: center;
    gap: 8px;
}

.layer-metric-label {
    color: #888;
    font-size: 0.9em;
}

.layer-metric-value {
    color: #00d4ff;
    font-weight: bold;
}

.tech-list-horizontal {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-top: 15px;
}

.tech-badge {
    background: rgba(0, 212, 255, 0.15);
    border: 1px solid #00d4ff;
    border-radius: 6px;
    padding: 8px 15px;
    display: flex;
    flex-direction: column;
    gap: 5px;
    min-width: 150px;
}

.tech-badge.verified {
    border-color: #00ff88;
    background: rgba(0, 255, 136, 0.15);
}

.tech-badge-name {
    color: #00d4ff;
    font-weight: bold;
    font-size: 0.95em;
}

.tech-badge.verified .tech-badge-name {
    color: #00ff88;
}

.tech-badge-meta {
    color: #888;
    font-size: 0.8em;
}

.tech-badge-version {
    color: #ffaa00;
    font-size: 0.85em;
    font-weight: bold;
}

.confidence-bar-container {
    background: rgba(255, 255, 255, 0.1);
    border-radius: 10px;
    height: 8px;
    overflow: hidden;
    margin-top: 5px;
}

.confidence-bar {
    height: 100%;
    background: linear-gradient(90deg, #ff4444 0%, #ffaa00 50%, #00ff88 100%);
    transition: width 0.3s ease;
    border-radius: 10px;
}

.layer-timeline-connector {
    width: 2px;
    height: 30px;
    background: linear-gradient(180deg, #00d4ff 0%, transparent 100%);
    margin: 0 auto;
}
</style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔐 Security Scan Dashboard</h1>
            <p>Comprehensive vulnerability assessment and analysis</p>
        </header>

        <!-- Scan Controls -->
        <div class="scan-section">
            <div class="scan-controls">
                <input type="url" id="targetInput" placeholder="Enter target URL (e.g., http://127.0.0.1:3000)" value="http://127.0.0.1:3000">
                <button id="scanButton" onclick="startScan()">🚀 Start Scan</button>
            </div>
            <div id="loadingIndicator" class="loading" style="display: none;">
                <div class="spinner"></div>
                <span>Scanning in progress... This may take several minutes</span>
            </div>
            <div id="errorMessage" class="error-message" style="display: none;"></div>
            <div id="successMessage" class="success-message" style="display: none;"></div>
        </div>

        <!-- Summary Stats -->
        <div class="scan-section" id="statsSection" style="display: none;">
            <h2 class="section-title">📊 Scan Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">Technologies Detected</div>
                    <div class="stat-value" id="techCount">0</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">CVEs Found</div>
                    <div class="stat-value" id="cveCount">0</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">ZAP Alerts</div>
                    <div class="stat-value" id="zapCount">0</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Vulnerabilities Verified</div>
                    <div class="stat-value" id="verifyCount">0</div>
                </div>
            </div>

            <!-- Alert Breakdown -->
            <div style="margin-top: 20px;">
                <h3 style="color: #00d4ff; margin-bottom: 10px;">Alert Severity Breakdown</h3>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-label">High Risk</div>
                        <div class="stat-value severity-high" id="highCount">0</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Medium Risk</div>
                        <div class="stat-value severity-medium" id="mediumCount">0</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Low Risk</div>
                        <div class="stat-value severity-low" id="lowCount">0</div>
                    </div>
                </div>
            </div>
        </div>

    
    <!-- Deep Fingerprinting Trace Section -->
    <div class="scan-section" id="deep-fingerprint-section" style="display: none;">
        <h2 class="section-title">🔍 Deep Fingerprinting Trace</h2>
        <p style="color: #aaa; margin-bottom: 20px;">
            Multi-layer technology detection with progressive confidence building
        </p>

        <!-- Timeline Visualization -->
        <div id="fingerprint-timeline" style="margin-bottom: 30px;">
            <!-- Layer cards will be dynamically inserted here -->
        </div>

        <!-- Summary Stats -->
        <div class="stats-grid" style="margin-top: 20px;">
            <div class="stat-card">
                <div class="stat-label">Total Layers</div>
                <div class="stat-value" id="fp-total-layers">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Technologies Found</div>
                <div class="stat-value" id="fp-total-techs">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Total Duration</div>
                <div class="stat-value" id="fp-duration">0s</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Avg Confidence</div>
                <div class="stat-value" id="fp-avg-confidence">0%</div>
            </div>
        </div>
    </div>

    <!-- Results Tabs -->
        <div class="scan-section" id="resultsSection" style="display: none;">
            <div class="tabs">
                <button class="tab-button active" onclick="switchTab(event, 'technologies')">🔧 Technologies</button>
                <button class="tab-button" onclick="switchTab(event, 'cves')">🚨 CVEs</button>
                <button class="tab-button" onclick="switchTab(event, 'zap-alerts')">⚠️ ZAP Alerts</button>
                <button class="tab-button" onclick="switchTab(event, 'verification')">✅ Verification</button>
                <button class="tab-button" onclick="switchTab(event, 'scenario')">🤖 AI Scenario</button>
                <button class="tab-button" onclick="switchTab(event, 'raw-data')">📋 Raw Data</button>
            </div>

            <!-- Technologies Tab -->
            <div id="technologies" class="tab-content active">
                <h2 class="section-title">Detected Technologies</h2>
                <div id="techContainer" class="tech-list"></div>
            </div>

            <!-- CVEs Tab -->
            <div id="cves" class="tab-content">
                <h2 class="section-title">CVE Vulnerabilities</h2>
                <div class="scroll-table">
                    <table>
                        <thead>
                            <tr>
                                <th>CVE ID</th>
                                <th>CVSS</th>
                                <th>Description</th>
                                <th>Product</th>
                            </tr>
                        </thead>
                        <tbody id="cveTable"></tbody>
                    </table>
                </div>
            </div>

            <!-- ZAP Alerts Tab -->
            <div id="zap-alerts" class="tab-content">
                <h2 class="section-title">OWASP ZAP Security Alerts</h2>
                
                <!-- Filter Buttons -->
                <div class="filter-buttons">
                    <button class="filter-btn active" onclick="filterZapAlerts(event, 'all')">All</button>
                    <button class="filter-btn" onclick="filterZapAlerts(event, 'High')">High</button>
                    <button class="filter-btn" onclick="filterZapAlerts(event, 'Medium')">Medium</button>
                    <button class="filter-btn" onclick="filterZapAlerts(event, 'Low')">Low</button>
                </div>

                <div id="zapContainer"></div>
            </div>

            <!-- Verification Tab -->
            <div id="verification" class="tab-content">
                <h2 class="section-title">Vulnerability Verification Results</h2>
                <div class="scroll-table">
                    <table>
                        <thead>
                            <tr>
                                <th>CVE ID</th>
                                <th>Endpoint</th>
                                <th>Status</th>
                                <th>Confidence</th>
                                <th>Exploitable</th>
                            </tr>
                        </thead>
                        <tbody id="verificationTable"></tbody>
                    </table>
                </div>
            </div>

            <!-- AI Scenario Tab -->
            <div id="scenario" class="tab-content">
                <h2 class="section-title">🤖 AI-Powered Attack Scenario</h2>
                <div id="scenarioContainer" class="scenario-box"></div>
            </div>

            <!-- Raw Data Tab -->
            <div id="raw-data" class="tab-content">
                <h2 class="section-title">Raw API Response</h2>
                <div id="rawDataContainer" class="json-viewer"></div>
            </div>
        </div>

        <footer class="footer">
            <p>Security Scan Dashboard | Powered by Nmap, CVE Database, and OWASP ZAP</p>
        </footer>
    </div>

    <script>
        let currentScanData = null;
        let allZapAlerts = [];
        let currentZapFilter = 'all';

        async function startScan() {
            const target = document.getElementById('targetInput').value.trim();
            
            if (!target) {
                showError('Please enter a target URL');
                return;
            }

            const scanButton = document.getElementById('scanButton');
            scanButton.disabled = true;
            document.getElementById('loadingIndicator').style.display = 'flex';
            document.getElementById('errorMessage').style.display = 'none';
            document.getElementById('successMessage').style.display = 'none';

            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ target })
                });

                if (!response.ok) {
                    throw new Error(`HTTP Error: ${response.status}`);
                }

                const data = await response.json();
                currentScanData = data;
                allZapAlerts = data.zap_scan?.alerts || [];

                displayResults(data);
                showSuccess('✅ Scan completed successfully!');
            } catch (error) {
                console.error('Scan error:', error);
                showError(`❌ Scan failed: ${error.message}`);
            } finally {
                scanButton.disabled = false;
                document.getElementById('loadingIndicator').style.display = 'none';
            }
        }

        function displayResults(data) {
            // Show sections
            document.getElementById('statsSection').style.display = 'block';
            document.getElementById('resultsSection').style.display = 'block';

            // Update stats
            document.getElementById('techCount').textContent = data.technologies?.length || 0;
            document.getElementById('cveCount').textContent = data.cves?.length || 0;
            document.getElementById('zapCount').textContent = data.zap_scan?.alerts?.length || 0;
            document.getElementById('verifyCount').textContent = data.verifications?.length || 0;

            // Severity breakdown
            const zapAlerts = data.zap_scan?.alerts || [];
            const highCount = zapAlerts.filter(a => a.risk === 'High').length;
            const mediumCount = zapAlerts.filter(a => a.risk === 'Medium').length;
            const lowCount = zapAlerts.filter(a => a.risk === 'Low').length;

            document.getElementById('highCount').textContent = highCount;
            document.getElementById('mediumCount').textContent = mediumCount;
            document.getElementById('lowCount').textContent = lowCount;

            // Display technologies
            displayTechnologies(data.technologies || []);

            // Display CVEs
            displayCVEs(data.cves || []);

            // Display ZAP Alerts
            displayZapAlerts(data.zap_scan?.alerts || []);

            // Display Verification Results
            displayVerification(data.verifications || []);

            // Display AI Scenario
            displayScenario(data.scenario || []);

            // Display Raw Data
            displayRawData(data);
        }

        function displayTechnologies(techs) {
            const container = document.getElementById('techContainer');
            
            if (techs.length === 0) {
                container.innerHTML = '<div class="empty-state">No technologies detected</div>';
                return;
            }

            container.innerHTML = techs.map(tech => `
                <div class="tech-card">
                    <div class="tech-name">${tech.product || 'Unknown'}</div>
                    <div class="tech-version">Version: ${tech.version || 'N/A'}</div>
                    <div class="tech-source">Source: <span class="badge badge-info">${tech.source || 'unknown'}</span></div>
                    ${tech.cpe ? `<div class="tech-source" style="margin-top: 10px; word-break: break-all;"><strong>CPE:</strong> <code style="color: #00ff88; font-size: 0.85em;">${tech.cpe}</code></div>` : ''}
                </div>
            `).join('');
        }

        function displayCVEs(cves) {
            const table = document.getElementById('cveTable');
            
            if (cves.length === 0) {
                table.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 20px;">No CVEs found</td></tr>';
                return;
            }

            table.innerHTML = cves.map(cve => `
                <tr>
                    <td><span class="cve-id">${cve.cve_id || 'N/A'}</span></td>
                    <td><span class="badge ${cve.cvss >= 7 ? 'badge-high' : cve.cvss >= 4 ? 'badge-medium' : 'badge-low'}">${cve.cvss || 'N/A'}</span></td>
                    <td>${truncate(cve.description || '', 100)}</td>
                    <td>${cve.product || 'N/A'}</td>
                </tr>
            `).join('');
        }

        function displayZapAlerts(alerts) {
            const container = document.getElementById('zapContainer');
            
            let filteredAlerts = alerts;
            if (currentZapFilter !== 'all') {
                filteredAlerts = alerts.filter(a => a.risk === currentZapFilter);
            }

            if (filteredAlerts.length === 0) {
                container.innerHTML = `<div class="empty-state">No ZAP alerts found for filter: ${currentZapFilter}</div>`;
                return;
            }

            container.innerHTML = filteredAlerts.slice(0, 50).map(alert => `
                <div class="alert-item ${alert.risk?.toLowerCase() || 'low'}">
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                        <span class="severity-indicator ${alert.risk?.toLowerCase() || 'low'}"></span>
                        <strong>${alert.name || 'Unknown Alert'}</strong>
                        <span class="badge ${alert.risk === 'High' ? 'badge-high' : alert.risk === 'Medium' ? 'badge-medium' : 'badge-low'}">${alert.risk || 'Unknown'}</span>
                    </div>
                    <div style="color: #bbb; font-size: 0.9em; margin-bottom: 5px; word-break: break-all;">
                        <strong>URL:</strong> ${alert.url || 'N/A'}
                    </div>
                    <div style="color: #999; font-size: 0.85em;">
                        ${truncate(alert.description || '', 200)}
                    </div>
                </div>
            `).join('');

            if (filteredAlerts.length > 50) {
                container.innerHTML += `<div style="text-align: center; color: #aaa; padding: 20px;">... and ${filteredAlerts.length - 50} more alerts</div>`;
            }
        }

        function displayVerification(verifications) {
            const table = document.getElementById('verificationTable');
            
            if (verifications.length === 0) {
                table.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 20px;">No verification results</td></tr>';
                return;
            }

            table.innerHTML = verifications.map(v => `
                <tr>
                    <td><span class="cve-id">${v.cve_id || 'N/A'}</span></td>
                    <td>${v.endpoint || 'N/A'}</td>
                    <td><span class="badge badge-info">${v.status || 'N/A'}</span></td>
                    <td>
                        <span class="badge ${v.confidence === 'high' ? 'badge-high' : v.confidence === 'medium' ? 'badge-medium' : 'badge-low'}">
                            ${v.confidence || 'N/A'}
                        </span>
                    </td>
                    <td>${v.exploitable ? '<span class="badge badge-high">Yes</span>' : '<span class="badge badge-low">No</span>'}</td>
                </tr>
            `).join('');
        }

        function displayScenario(scenario) {
            const container = document.getElementById('scenarioContainer');
            
            if (!scenario || scenario.length === 0) {
                container.textContent = 'No AI scenario generated';
                return;
            }

            container.textContent = Array.isArray(scenario) ? scenario.join('\n') : scenario;
        }

        function displayRawData(data) {
            const container = document.getElementById('rawDataContainer');
            container.textContent = JSON.stringify(data, null, 2);
        }

        function switchTab(event, tabName) {
            // Remove active class from all tab buttons
            document.querySelectorAll('.tab-button').forEach(btn => {
                btn.classList.remove('active');
            });

            // Remove active class from all tab contents
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });

            // Add active class to clicked button and corresponding content
            event.target.classList.add('active');
            document.getElementById(tabName).classList.add('active');
        }

        function filterZapAlerts(event, severity) {
            currentZapFilter = severity;
            
            // Update button styles
            document.querySelectorAll('.filter-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            event.target.classList.add('active');

            // Display filtered alerts
            displayZapAlerts(allZapAlerts);
        }

        function showError(message) {
            const errorDiv = document.getElementById('errorMessage');
            errorDiv.textContent = message;
            errorDiv.style.display = 'block';
        }

        function showSuccess(message) {
            const successDiv = document.getElementById('successMessage');
            successDiv.textContent = message;
            successDiv.style.display = 'block';
        }

        function truncate(str, length) {
            if (str.length <= length) return str;
            return str.substring(0, length) + '...';
        }

        console.log('🔐 Security Dashboard loaded and ready for scanning');
    </script>
    <script src="/static/js/dashboard.js?v=20260103c"></script>
</body>
</html>
```
---

## File 76: live_scan.html
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\templates\live_scan.html`

```html
{% extends "base.html" %}

{% block content %}
<style>
    /* UI 먹통 방지: 모달을 최상위 레이어로 강제 승격 */
    .modal-backdrop { z-index: 10050 !important; }
    .modal { z-index: 10055 !important; }
    .modal-dialog { z-index: 10060 !important; }
    .modal-content { z-index: 10065 !important; }
    /* 결과 카드가 모달 위를 덮지 못하게 설정 */
    .tech-card { position: relative; z-index: 1; }
</style>

<div class="container-fluid mt-4">
    <div class="row">
        <!-- Sidebar: Control Panel & Log -->
        <div class="col-md-4">
            <div class="card shadow mb-4">
                <div class="card-header py-3 d-flex justify-content-between align-items-center">
                    <h6 class="m-0 font-weight-bold text-primary">Live Scanner Control</h6>
                    <div id="scan-status"><span class="badge bg-secondary">Ready</span></div>
                </div>
                <div class="card-body">
                    <h5 class="mb-3">Target: <span id="target-url" class="text-info">{{ project.target }}</span></h5>
                    
                    <div class="progress mb-3" style="height: 20px;">
                        <div id="scan-progress-bar" class="progress-bar progress-bar-striped progress-bar-animated" role="progressbar" style="width: 0%"></div>
                    </div>

                    <button id="start-scan-btn" class="btn btn-primary w-100 btn-lg mb-3">
                        <i class="fas fa-radar"></i> Start Deep Recon
                    </button>

                    <div class="terminal-window bg-dark text-light p-3 rounded" style="height: 400px; overflow-y: auto; font-family: monospace; font-size: 0.85rem;" id="log-terminal">
                        <div class="text-muted">Waiting for command...</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Main Content: Stats & Grid -->
        <div class="col-md-8">
            <!-- Stats Row -->
            <div class="row">
                <!-- Open Ports -->
                <div class="col-xl-3 col-md-6 mb-4">
                    <div class="card border-left-primary shadow h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col mr-2">
                                    <div class="text-xs font-weight-bold text-primary text-uppercase mb-1">Open Ports</div>
                                    <div class="h5 mb-0 font-weight-bold text-gray-800" id="stat-ports">0</div>
                                </div>
                                <div class="col-auto"><i class="fas fa-network-wired fa-2x text-gray-300"></i></div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Tech Stack -->
                <div class="col-xl-3 col-md-6 mb-4">
                    <div class="card border-left-success shadow h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col mr-2">
                                    <div class="text-xs font-weight-bold text-success text-uppercase mb-1">Tech Stack</div>
                                    <div class="h5 mb-0 font-weight-bold text-gray-800" id="stat-tech">0</div>
                                </div>
                                <div class="col-auto"><i class="fas fa-layer-group fa-2x text-gray-300"></i></div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Vulnerabilities -->
                <div class="col-xl-3 col-md-6 mb-4">
                    <div class="card border-left-warning shadow h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col mr-2">
                                    <div class="text-xs font-weight-bold text-warning text-uppercase mb-1">Vulnerabilities</div>
                                    <div class="h5 mb-0 font-weight-bold text-gray-800" id="stat-vulns">0</div>
                                </div>
                                <div class="col-auto"><i class="fas fa-exclamation-triangle fa-2x text-gray-300"></i></div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Sitemap -->
                <div class="col-xl-3 col-md-6 mb-4">
                    <div class="card border-left-info shadow h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col mr-2">
                                    <div class="text-xs font-weight-bold text-info text-uppercase mb-1">Sitemap</div>
                                    <div class="h5 mb-0 font-weight-bold text-gray-800" id="stat-urls">0</div>
                                </div>
                                <div class="col-auto"><i class="fas fa-sitemap fa-2x text-gray-300"></i></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Tech Grid -->
            <div class="card shadow mb-4">
                <div class="card-header py-3">
                    <h6 class="m-0 font-weight-bold text-primary">Detected Technologies & Vulnerabilities</h6>
                </div>
                <div class="card-body">
                    <div class="row" id="tech-grid">
                        <!-- Tech Cards Injected Here -->
                    </div>
                </div>
            </div>

            <!-- Structure Map Placeholder -->
            <div class="card shadow">
                <div class="card-header py-3">
                    <h6 class="m-0 font-weight-bold text-primary">Target Structure Map</h6>
                </div>
                <div class="card-body text-center py-5 text-muted">
                    <i class="fas fa-sitemap fa-3x mb-3"></i><br>
                    Structure map will be implemented in Phase 2.
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Technology Detail Modal -->
<div class="modal fade" id="techModal" tabindex="-1" aria-labelledby="techModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header bg-light">
                <h5 class="modal-title fw-bold" id="techModalLabel">Technology Detail</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <!-- Modal content will be dynamically injected via JS -->
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>

<!-- Scripts -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
<script src="{{ url_for('static', filename='js/live_scan.js') }}?version=2"></script>
{% endblock %}
```
---

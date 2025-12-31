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

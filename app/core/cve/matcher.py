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
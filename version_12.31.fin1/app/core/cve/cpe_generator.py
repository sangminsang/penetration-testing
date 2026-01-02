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

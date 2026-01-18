"""
CPE 파서 모듈

스캔 결과에서 기술 스택 정보를 추출하고 CPE(Common Platform Enumeration) 형식으로 변환합니다.
"""

import re
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


# 제품명 정규화 맵 (일반적인 제품명을 CPE 형식으로 변환)
PRODUCT_NORMALIZATION_MAP = {
    # 웹 서버
    "apache": "apache:http_server",
    "apache httpd": "apache:http_server",
    "httpd": "apache:http_server",
    "nginx": "nginx:nginx",
    "iis": "microsoft:internet_information_services",
    
    # 데이터베이스
    "mysql": "oracle:mysql",
    "mariadb": "mariadb:mariadb",
    "postgresql": "postgresql:postgresql",
    "postgres": "postgresql:postgresql",
    "mongodb": "mongodb:mongodb",
    "redis": "redis:redis",
    
    # 웹 프레임워크
    "django": "djangoproject:django",
    "flask": "palletsprojects:flask",
    "express": "expressjs:express",
    "spring": "vmware:spring_framework",
    "wordpress": "wordpress:wordpress",
    
    # 기타
    "node.js": "nodejs:node.js",
    "node": "nodejs:node.js",
    "php": "php:php",
    "python": "python:python",
}

# CPE 블랙리스트 (기술이 아닌 메타데이터)
CPE_BLACKLIST = [
    "html", "css", "javascript", "http", "https", "tcp", "udp",
    "server", "client", "api", "web", "application", "unknown"
]


class CPEParser:
    """
    CPE 파서 클래스
    
    스캔 결과에서 기술 정보를 추출하고 CPE 형식으로 변환합니다.
    """
    
    @staticmethod
    def normalize_product_name(product: str) -> Optional[str]:
        """
        제품명 정규화
        
        Args:
            product: 원본 제품명
            
        Returns:
            정규화된 제품명 (vendor:product 형식) 또는 None
        """
        if not product:
            return None
        
        # 소문자 변환 및 공백 제거
        normalized = product.lower().strip()
        
        # 블랙리스트 체크
        if normalized in CPE_BLACKLIST:
            return None
        
        # 정규화 맵에서 찾기
        if normalized in PRODUCT_NORMALIZATION_MAP:
            return PRODUCT_NORMALIZATION_MAP[normalized]
        
        # 기본 정규화 (공백을 언더스코어로, 특수문자 제거)
        normalized = re.sub(r'[^a-z0-9\s]', '', normalized)
        normalized = re.sub(r'\s+', '_', normalized)
        
        # vendor:product 형식으로 변환 (간단한 추정)
        # 실제로는 더 정교한 매핑이 필요할 수 있음
        parts = normalized.split('_')
        if len(parts) >= 2:
            vendor = parts[0]
            product_name = '_'.join(parts[1:])
            return f"{vendor}:{product_name}"
        
        return normalized
    
    @staticmethod
    def extract_cpe_from_tech(tech: Dict[str, Any]) -> Optional[str]:
        """
        기술 정보에서 CPE 추출
        
        Args:
            tech: 기술 정보 딕셔너리
                {
                    'name': 'Apache',
                    'version': '2.4.41',
                    'product': 'httpd',
                    ...
                }
        
        Returns:
            CPE 문자열 (예: cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*)
        """
        # 제품명 추출
        product_name = tech.get('product') or tech.get('name', '')
        if not product_name:
            return None
        
        # 제품명 정규화
        normalized = CPEParser.normalize_product_name(product_name)
        if not normalized:
            return None
        
        # vendor:product 분리
        if ':' not in normalized:
            return None
        
        vendor, product = normalized.split(':', 1)
        
        # 버전 추출
        version = tech.get('version', '') or '*'
        if version:
            # 버전 정규화 (특수문자 제거)
            version = re.sub(r'[^a-zA-Z0-9._-]', '', version)
        else:
            version = '*'
        
        # CPE 2.3 형식 생성
        # cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
        cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
        
        return cpe
    
    @staticmethod
    def extract_cpes_from_scan_results(scan_results: Dict[str, Any]) -> List[str]:
        """
        스캔 결과에서 모든 CPE 추출
        
        Args:
            scan_results: 통합된 스캔 결과
                {
                    'nmap': {...},
                    'nuclei': {...},
                    'zap': {...}
                }
        
        Returns:
            CPE 문자열 목록
        """
        cpes = []
        
        # Nmap 결과에서 추출
        nmap_results = scan_results.get('nmap', {})
        for service in nmap_results.get('services', []):
            cpe = CPEParser.extract_cpe_from_tech(service)
            if cpe:
                cpes.append(cpe)
        
        # Nuclei 결과에서 추출 (기술 탐지)
        nuclei_results = scan_results.get('nuclei', {})
        for tech in nuclei_results.get('technologies', []):
            cpe = CPEParser.extract_cpe_from_tech(tech)
            if cpe:
                cpes.append(cpe)
        
        # 중복 제거
        cpes = list(set(cpes))
        
        logger.info(f"추출된 CPE: {len(cpes)}개")
        return cpes


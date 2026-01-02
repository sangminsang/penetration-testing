"""
Recog 지문 데이터베이스 파서
Rapid7 Recog XML을 파싱하여 서비스/제품 탐지
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Optional, Any
import xml.etree.ElementTree as ET

class RecogFingerprinter:
    """Rapid7 Recog 지문 분석"""
    
    def __init__(self, recog_xml_dir: str = "recog/xml"):
        self.recog_dir = Path(recog_xml_dir)
        self.fingerprints = {}
        if self.recog_dir.exists():
            self.load_all_fingerprints()
            print(f"[RECOG] Loaded {len(self.fingerprints)} fingerprint databases")
        else:
            print(f"[RECOG] Recog directory not found: {recog_xml_dir}")
    
    # ... (기존 메소드들) ...
    
    # ✅ 추가: matchall() 메소드
    def matchall(self, text: str) -> List[Dict[str, Any]]:
        """
        모든 지문 DB에서 매칭 시도
        
        Args:
            text: 매칭할 텍스트 (배너, 헤더 등)
        
        Returns:
            매칭된 결과 리스트 (여러 DB에서 매칭될 수 있음)
        """
        matches = []
        
        # 모든 DB를 순회하며 매칭 시도
        for dbname in self.fingerprints.keys():
            result = self.match(text, dbname=dbname)
            if result:
                matches.append(result)
        
        return matches


# ===== 🔥 간편 사용 함수 =====

def detect_with_recog(banner: str, banner_type: str = "auto") -> List[Dict[str, Any]]:
    """
    Recog를 사용하여 배너에서 기술 탐지
    
    Args:
        banner: 배너 문자열
        banner_type: "http", "ssh", "ftp", "auto"
    
    Returns:
        탐지된 기술 리스트
    """
    fingerprinter = RecogFingerprinter()
    
    if banner_type == "http":
        result = fingerprinter.match_http_header(banner)
        return [result] if result else []
    
    elif banner_type == "ssh":
        result = fingerprinter.match_ssh_banner(banner)
        return [result] if result else []
    
    else:  # auto
        return fingerprinter.match_all(banner)

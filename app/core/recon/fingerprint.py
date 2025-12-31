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
    """
    Rapid7 Recog 지문 데이터베이스를 사용한 기술 탐지
    """
    
    def __init__(self, recog_xml_dir: str = "recog/xml"):
        """
        Args:
            recog_xml_dir: Recog XML 파일들이 있는 디렉토리
        """
        self.recog_dir = Path(recog_xml_dir)
        self.fingerprints = {}
        
        if self.recog_dir.exists():
            self._load_all_fingerprints()
            print(f"[RECOG] Loaded {len(self.fingerprints)} fingerprint databases")
        else:
            print(f"[RECOG] ⚠️  Recog directory not found: {recog_xml_dir}")
            print(f"[RECOG] Run: git clone https://github.com/rapid7/recog.git")
    
    def _load_all_fingerprints(self):
        """모든 Recog XML 파일 로드"""
        xml_files = list(self.recog_dir.glob("*.xml"))
        
        for xml_file in xml_files:
            db_name = xml_file.stem  # http_header, ssh_banners 등
            
            try:
                fingerprints = self._parse_recog_xml(xml_file)
                if fingerprints:
                    self.fingerprints[db_name] = fingerprints
                    print(f"[RECOG] ✓ Loaded {db_name}: {len(fingerprints)} patterns")
            except Exception as e:
                print(f"[RECOG] ✗ Failed to load {db_name}: {e}")
    
    def _parse_recog_xml(self, xml_file: Path) -> List[Dict[str, Any]]:
        """
        Recog XML 파일 파싱
        
        XML 구조:
        <fingerprints>
          <fingerprint pattern="...">
            <param pos="0" name="service.product" value="Apache"/>
            <param pos="1" name="service.version"/>
          </fingerprint>
        </fingerprints>
        """
        fingerprints = []
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for fp in root.findall(".//fingerprint"):
                pattern_str = fp.get("pattern")
                if not pattern_str:
                    continue
                
                # 파라미터 추출
                params = {}
                for param in fp.findall("param"):
                    param_name = param.get("name")
                    param_value = param.get("value", "")
                    param_pos = param.get("pos")
                    
                    params[param_name] = {
                        "value": param_value,
                        "pos": int(param_pos) if param_pos else None
                    }
                
                # 정규식 컴파일 (실패하면 스킵)
                try:
                    compiled_pattern = re.compile(pattern_str, re.IGNORECASE)
                    
                    fingerprints.append({
                        "pattern": compiled_pattern,
                        "pattern_str": pattern_str,
                        "params": params
                    })
                except re.error:
                    # 정규식 오류는 조용히 스킵
                    continue
        
        except ET.ParseError as e:
            print(f"[RECOG] XML parse error in {xml_file.name}: {e}")
        
        return fingerprints
    
    def match(self, banner: str, db_name: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        배너 문자열에서 제품/버전 추출
        
        Args:
            banner: 서비스 배너 문자열 (HTTP 헤더, SSH 배너 등)
            db_name: 특정 DB만 검색 (예: "http_header", "ssh_banners")
        
        Returns:
            {
                "product": "Apache",
                "version": "2.4.41",
                "vendor": "Apache",
                "os": "Ubuntu",
                "matched_pattern": "...",
                "source": "recog:http_header"
            }
        """
        # 검색할 DB 목록
        if db_name and db_name in self.fingerprints:
            dbs_to_search = {db_name: self.fingerprints[db_name]}
        else:
            dbs_to_search = self.fingerprints
        
        # 각 DB에서 매칭 시도
        for db_name, fingerprints in dbs_to_search.items():
            for fp in fingerprints:
                pattern = fp["pattern"]
                match = pattern.search(banner)
                
                if match:
                    # 매칭 성공! 파라미터 추출
                    result = {
                        "matched_pattern": fp["pattern_str"],
                        "source": f"recog:{db_name}"
                    }
                    
                    # 각 파라미터 값 채우기
                    for param_name, param_info in fp["params"].items():
                        value = param_info["value"]
                        pos = param_info["pos"]
                        
                        # pos가 있으면 정규식 그룹에서 추출
                        if pos is not None and pos > 0:
                            try:
                                value = match.group(pos)
                            except IndexError:
                                value = ""
                        
                        # 파라미터 이름을 간단하게 변환
                        # service.product -> product
                        simple_name = param_name.split(".")[-1]
                        result[simple_name] = value
                    
                    return result
        
        return None
    
    def match_http_header(self, header_value: str) -> Optional[Dict[str, Any]]:
        """HTTP 헤더 값에서 기술 추출"""
        return self.match(header_value, db_name="http_header")
    
    def match_ssh_banner(self, banner: str) -> Optional[Dict[str, Any]]:
        """SSH 배너에서 기술 추출"""
        return self.match(banner, db_name="ssh_banners")
    
    def match_all(self, text: str) -> List[Dict[str, Any]]:
        """
        모든 DB에서 매칭 시도 (여러 개 반환 가능)
        """
        matches = []
        
        for db_name in self.fingerprints.keys():
            result = self.match(text, db_name=db_name)
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

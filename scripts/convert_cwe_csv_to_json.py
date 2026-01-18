#!/usr/bin/env python3
"""
CWE CSV 파일을 JSON으로 변환하는 스크립트

MITRE CWE 데이터베이스 CSV 파일을 파싱하여
대시보드에서 사용할 수 있는 JSON 형식으로 변환합니다.

사용법:
    python convert_cwe_csv_to_json.py 2000.csv data/cwe_metadata.json
"""

import csv
import json
import sys
from pathlib import Path
from typing import Dict, Any


def parse_cwe_csv(csv_path: str) -> Dict[str, Any]:
    """
    CWE CSV 파일을 파싱하여 JSON 형식으로 변환
    
    Args:
        csv_path: CSV 파일 경로
        
    Returns:
        CWE 메타데이터 딕셔너리
        {
            "CWE-79": {
                "cwe_id": "CWE-79",
                "name": "...",
                "description": "...",
                "extended_description": "...",
                "common_consequences": "...",
                "potential_mitigations": "...",
                "source": "mitre_cwe"
            },
            ...
        }
    """
    cwe_map = {}
    
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                cwe_id_raw = row.get('CWE-ID', '').strip()
                if not cwe_id_raw or not cwe_id_raw.isdigit():
                    continue
                
                # CWE-ID 정규화 (예: "79" -> "CWE-79")
                cwe_id = f"CWE-{cwe_id_raw}"
                
                # Name 추출
                name = row.get('Name', '').strip()
                
                # Description 추출
                description = row.get('Description', '').strip()
                
                # Extended Description 추출
                extended_description = row.get('Extended Description', '').strip()
                
                # Common Consequences 추출 (간단히 처리)
                common_consequences = row.get('Common Consequences', '').strip()
                
                # Potential Mitigations 추출 (간단히 처리)
                potential_mitigations = row.get('Potential Mitigations', '').strip()
                
                # 메타데이터 구성
                cwe_metadata = {
                    'cwe_id': cwe_id,
                    'name': name if name else f"CWE-{cwe_id_raw}",
                    'description': description if description else '설명 없음',
                    'extended_description': extended_description,
                    'common_consequences': common_consequences,
                    'potential_mitigations': potential_mitigations,
                    'source': 'mitre_cwe'
                }
                
                cwe_map[cwe_id] = cwe_metadata
                
    except Exception as e:
        print(f"[ERROR] CSV 파일 파싱 실패: {e}", file=sys.stderr)
        sys.exit(1)
    
    return cwe_map


def save_json(cwe_map: Dict[str, Any], output_path: str):
    """
    CWE 메타데이터를 JSON 파일로 저장
    
    Args:
        cwe_map: CWE 메타데이터 딕셔너리
        output_path: 출력 JSON 파일 경로
    """
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(cwe_map, f, ensure_ascii=False, indent=2)
        
        print(f"[SUCCESS] JSON 파일 저장 완료: {output_path}")
        print(f"   - 총 {len(cwe_map)}개 CWE 메타데이터 변환됨")
        
    except Exception as e:
        print(f"[ERROR] JSON 파일 저장 실패: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    """메인 함수"""
    if len(sys.argv) < 2:
        print("사용법: python convert_cwe_csv_to_json.py <csv_file> [output_json]")
        print("예시: python convert_cwe_csv_to_json.py 2000.csv data/cwe_metadata.json")
        sys.exit(1)
    
    csv_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else 'data/cwe_metadata.json'
    
    if not Path(csv_path).exists():
        print(f"[ERROR] CSV 파일을 찾을 수 없습니다: {csv_path}", file=sys.stderr)
        sys.exit(1)
    
    print(f"[INFO] CWE CSV 파일 파싱 시작: {csv_path}")
    cwe_map = parse_cwe_csv(csv_path)
    
    print(f"[SUCCESS] {len(cwe_map)}개 CWE 메타데이터 파싱 완료")
    
    # 주요 CWE 확인
    important_cwes = ['CWE-79', 'CWE-89', 'CWE-20', 'CWE-119', 'CWE-352']
    found_important = [cwe for cwe in important_cwes if cwe in cwe_map]
    print(f"   - 주요 CWE 포함: {', '.join(found_important)}")
    
    print(f"[INFO] JSON 파일 저장 중: {output_path}")
    save_json(cwe_map, output_path)
    
    print("\n[SUCCESS] 변환 완료!")
    print(f"   - 입력 파일: {csv_path}")
    print(f"   - 출력 파일: {output_path}")
    print(f"   - 총 CWE 개수: {len(cwe_map)}개")


if __name__ == '__main__':
    main()

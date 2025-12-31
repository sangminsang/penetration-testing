# test.py (수정된 버전)
import sys
import os
from pathlib import Path

# test.py의 위치: app/test.py
# matcher.py의 위치: app/core/cve/matcher.py
# test.py에서 matcher.py를 직접 import하기 위해 app 디렉토리를 path에 추가
current_dir = Path(__file__).parent  # app/
sys.path.insert(0, str(current_dir))

# 이제 app 패키지를 거치지 않고 core 모듈을 직접 import
# app/__init__.py를 실행하지 않으므로 Flask 의존성 문제 없음
from core.cve.matcher import (
    parse_complex_version_string,
    normalize_product_name,
    parse_and_normalize_version
)

# ===========================
# 테스트 1: parse_complex_version_string
# ===========================
print("=" * 60)
print("Test 1: parse_complex_version_string")
print("=" * 60)

test_cases = [
    "Apache/2.4.66",
    "mysql 5.7.35",
    "nginx 1.19.0",
    "Werkzeug/3.1.4 Python/3.11.14",
    "Apache httpd 2.4.41 (Ubuntu)",
    "PostgreSQL 13.4",
    "OpenSSH_7.4",
]

for test in test_cases:
    result = parse_complex_version_string(test)
    print(f"Input:  {test}")
    print(f"Output: product='{result['product']}', version='{result['version']}'")
    print()

# ===========================
# 테스트 2: extract_tech_info_from_scanner (network.py 출력)
# ===========================
print("=" * 60)
print("Test 2: extract_tech_info_from_scanner (network.py)")
print("=" * 60)

# 간단한 추출 함수 (routes.py 로직 재현)
def extract_tech_info_from_scanner(tech_item):
    # Case 1: network.py 출력 (full_version 필드 우선 사용)
    if "full_version" in tech_item and tech_item.get("full_version"):
        parsed = parse_complex_version_string(tech_item["full_version"])
        return {"product": parsed["product"], "version": parsed["version"]}
    
    # Case 2: network.py 출력 (product + version 필드)
    if "product" in tech_item and "version" in tech_item:
        return {
            "product": normalize_product_name(tech_item["product"]),
            "version": tech_item["version"]
        }
    
    # Case 3: web.py, database.py 출력 ("name" 필드)
    if "name" in tech_item:
        parsed = parse_complex_version_string(tech_item["name"])
        return {"product": parsed["product"], "version": parsed["version"]}
    
    return {"product": "", "version": ""}

network_outputs = [
    {"full_version": "nginx 1.19.0", "product": "nginx", "version": "1.19.0"},
    {"product": "mysql", "version": "5.7.35"},
]

for output in network_outputs:
    result = extract_tech_info_from_scanner(output)
    print(f"Input:  {output}")
    print(f"Output: {result}")
    print()

# ===========================
# 테스트 3: extract_tech_info_from_scanner (web.py 출력)
# ===========================
print("=" * 60)
print("Test 3: extract_tech_info_from_scanner (web.py)")
print("=" * 60)

web_outputs = [
    {"name": "Apache/2.4.66", "type": "web_server"},
    {"name": "Werkzeug/3.1.4", "type": "framework"},
    {"name": "Django/4.2", "type": "framework"},
]

for output in web_outputs:
    result = extract_tech_info_from_scanner(output)
    print(f"Input:  {output}")
    print(f"Output: {result}")
    print()

# ===========================
# 테스트 4: extract_tech_info_from_scanner (database.py 출력)
# ===========================
print("=" * 60)
print("Test 4: extract_tech_info_from_scanner (database.py)")
print("=" * 60)

db_outputs = [
    {"name": "mysql 5.7.35", "type": "database", "port": 3306},
    {"name": "PostgreSQL 13.4", "type": "database", "port": 5432},
    {"name": "redis 6.2.0", "type": "database", "port": 6379},
]

for output in db_outputs:
    result = extract_tech_info_from_scanner(output)
    print(f"Input:  {output}")
    print(f"Output: {result}")
    print()

print("=" * 60)
print("All tests completed!")
print("=" * 60)

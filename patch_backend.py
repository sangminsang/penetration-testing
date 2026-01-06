import os

target_file = 'app/core/recon/web.py' # 파일 경로가 다르면 수정하세요
if not os.path.exists(target_file):
    print(f"Error: {target_file} not found.")
    exit(1)

with open(target_file, 'r', encoding='utf-8') as f:
    content = f.read()

# 데이터를 정제하고 병합하는 신규 로직 정의
new_logic = """
def refine_tech_data(raw_results):
    merged = {}
    for item in raw_results:
        # 1. 이름과 버전 정제 (v 제거 및 분리)
        name = str(item.get('name', '')).lower().strip()
        ver = str(item.get('version', '')).replace('v', '').strip()
        source = item.get('source', 'Unknown')
        
        if ':' in name:
            name, ver = name.split(':', 1)
        elif '/' in name:
            name, ver = name.split('/', 1)
            
        if not ver or ver.lower() == 'unknown':
            ver = "Unknown"

        # 2. 기술명 기준으로 데이터 통합
        if name not in merged:
            merged[name] = {
                "name": name,
                "version": ver,
                "sources": [source],
                "evidences": {source: item.get('raw_data', f"Detected via {source}")}
            }
        else:
            if merged[name]["version"] == "Unknown" and ver != "Unknown":
                merged[name]["version"] = ver
            if source not in merged[name]["sources"]:
                merged[name]["sources"].append(source)
                merged[name]["evidences"][source] = item.get('raw_data', f"Confirmed via {source}")
    
    return list(merged.values())
"""

# 기존 collect_web_info 함수 등의 반환 직전에 refine_tech_data 적용 로직 추가
# (이 부분은 기존 코드 구조에 따라 수동 조정이 필요할 수 있으나, 일단 로직 파일만 생성)
with open('app/core/recon/refine_logic.py', 'w', encoding='utf-8') as f:
    f.write(new_logic)

print("✅ 정제 로직 파일(refine_logic.py)이 생성되었습니다.")

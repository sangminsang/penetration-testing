
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

# app/searchsploit_client.py

import json
import subprocess
from typing import List, Dict


def search_exploits_for_cves(cve_ids: List[str], max_per_cve: int = 5) -> Dict[str, List[Dict]]:
    """
    여러 CVE ID에 대해 searchsploit --json을 호출하고,
    각 CVE별로 'title' 과 'id' 만 추출해서 반환.

    반환 예:
    {
      "CVE-2021-41773": [
        {"title": "Apache HTTP Server 2.4.49 - Path Traversal & RCE", "id": "50383"},
        {"title": "Apache 2.4.49/2.4.50 - Traversal Shell (Metasploit)", "id": "50406"},
      ],
      ...
    }
    """
    results: Dict[str, List[Dict]] = {}
    for cve in cve_ids:
        exploits = search_exploits_for_single_cve(cve, max_per_cve=max_per_cve)
        if exploits:
            results[cve] = exploits
    return results


def search_exploits_for_single_cve(cve_id: str, max_per_cve: int = 5) -> List[Dict]:
    """
    단일 CVE에 대해 searchsploit --json 실행.

    출력 예:
    [
        {"title": "...", "id": "50383"},
        ...
    ]
    """
    cmd = ["searchsploit", "--json", cve_id]

    try:
        proc = subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"[WARN] searchsploit 실패: {cve_id}, err={e}")
        return []

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(f"[WARN] searchsploit JSON 파싱 실패: {cve_id}")
        return []

    # searchsploit --json 구조는 보통:
    # { "RESULTS_EXPLOIT": [ { "Title": "...", "EDB-ID": "50383", ... }, ... ],
    #   "RESULTS_SHELLCODE": [ ... ] }
    exploits = []

    for key in ("RESULTS_EXPLOIT", "RESULTS_SHELLCODE"):
        arr = data.get(key) or []
        if not isinstance(arr, list):
            continue
        for item in arr:
            title = item.get("Title") or item.get("title")
            edb_id = item.get("EDB-ID") or item.get("id")
            if not title or not edb_id:
                continue
            exploits.append({"title": title, "id": str(edb_id)})

    # 상위 N개만
    return exploits[:max_per_cve]

# app/core/scenario/reporter.py
# 보고서 생성 모듈
# 기존 loot_generator.py를 기반으로 확장

import random
import datetime
from typing import Dict, Any, List


def enrich_loot(base_proof: Dict[str, Any]) -> Dict[str, Any]:
    """
    LLM이 준 proof에 더미 데이터를 추가하거나 형식을 보정.
    기존 loot_generator.py의 로직을 유지하면서 확장.
    
    Args:
        base_proof: AI가 생성한 proof 딕셔너리
            {
                "loot_files": [...],
                "logs": [...]
            }
    
    Returns:
        보강된 proof 딕셔너리
    """
    proof = base_proof or {}
    loot_files = proof.get("loot_files") or []
    logs = proof.get("logs") or []

    # 기본 /etc/passwd 더미가 없으면 하나 추가
    if not loot_files:
        loot_files.append({
            "path": "/etc/passwd",
            "content": (
                "root:x:0:0:root:/root:/bin/bash\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                "demo:x:1000:1000:demo:/home/demo:/bin/bash\n"
            )
        })

    # 로그에 타임스탬프 추가
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    logs.append(f"[{timestamp}] Demo attack simulation completed.")

    proof["loot_files"] = loot_files
    proof["logs"] = logs
    return proof


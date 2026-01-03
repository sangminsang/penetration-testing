# app/ai_client.py

import requests
import json
from flask import current_app


def build_prompt(cve_list, recon_info, chains, exploit_map):
    """
    - recon_info: Nmap 결과 (호스트/포트/서비스/버전)
    - cve_list: 전체 매핑된 CVE들 (cve-bin-tool 결과 + 필요시 cve-search 보강)
    - chains: 파이썬 코드가 만든 CVE 체인 후보 리스트
    - exploit_map: {CVE-ID: [ {title, id}, ... ], ...}

    exploit_map 예:
    {
      "CVE-2021-41773": [
        {"title": "Apache HTTP Server 2.4.49 - Path Traversal & RCE", "id": "50383"},
        {"title": "Apache 2.4.49/2.4.50 - Traversal Shell (Metasploit)", "id": "50406"}
      ]
    }
    """
    instructions = """
너는 15년 경력의 화이트해커이자 레드팀 리더야.
아래 제공하는 Nmap 스캔 결과(recon_info), CVE 목록(cve_list),
공격 체인 후보(chains), 그리고 각 CVE에 대한 Searchsploit exploit 리스트(exploit_map)를 바탕으로,
공격자 입장에서 가장 효율적인 '침투 체인(Exploit Chain)'을 설계해줘.

요구사항:

1. 반드시 chains에 있는 CVE들만 사용해서 공격 시나리오를 구성해.
   - 새로운 CVE ID를 만들어내거나, 입력에 없는 CVE를 사용하지 마.
2. 가능한 한 현실적인 1~2개의 공격 체인만 선택해서 상세 시나리오를 작성해.
   - 각 체인은 initial_access -> privilege_escalation -> lateral_movement -> data_exfiltration
     순서를 따르려고 노력해. 중간 단계가 없어도 괜찮지만, 순서를 뒤집지는 마.
3. Searchsploit ID는 "참고용"으로만 사용해.
   - 실제 payload 문자열이나 완전한 exploit 코드는 생성하지 말고,
     개념적인 단계와 영향만 설명해.
4. 모르는 부분은 지어내지 말고 "unknown"이라고 표기해.

출력 형식:

반드시 JSON 하나만 보내. 다른 설명 문장이나 주석은 넣지 마.

JSON 스키마 예시는 다음과 같아:

{
  "selected_chains": [
    {
      "chain_id": 1,
      "description": "요약 설명",
      "steps": [
        "1단계: CVE-XXXX-AAAA (initial_access), Searchsploit ID 50383을 참고하여 8080 포트 Apache 웹서버에서 Path Traversal 기반 RCE를 시도한다 ...",
        "2단계: CVE-YYYY-BBBB (privilege_escalation)를 이용해 www-data에서 root로 권한 상승을 시도한다 ...",
        "3단계: CVE-ZZZZ-CCCC (data_exfiltration)를 통해 MySQL DB에서 중요한 데이터를 덤프한다 ..."
      ]
    }
  ],
  "scenario": [
    "... 전체 공격 과정을 해커 입장에서 서술한 시나리오 ..."
  ],
  "proof": {
    "loot_files": [
      {
        "path": "/etc/passwd",
        "content": "root:x:0:0:root:/root:/bin/bash\n..."
      }
    ],
    "logs": [
      "[+] Exploit CVE-XXXX-AAAA sent to 203.0.113.10:8080",
      "[+] Got reverse shell: www-data@target",
      "[+] Escalated to root using CVE-YYYY-BBBB",
      "[+] Dumped /etc/passwd and user table from MySQL (size: 32KB)"
    ]
  }
}

주의:

- 실제 IP나 민감 정보는 모두 더미 값(예: 203.0.113.10, 198.51.100.5)으로 바꿔줘.
- selected_chains의 steps에는 반드시 어떤 CVE를 어떤 역할(role)로 쓰는지, 어느 포트/서비스와 연결되는지 명시해.
"""

    recon_text = json.dumps(recon_info, ensure_ascii=False, indent=2)
    cve_text = json.dumps(cve_list, ensure_ascii=False, indent=2)
    chains_text = json.dumps(chains, ensure_ascii=False, indent=2)
    exploit_text = json.dumps(exploit_map, ensure_ascii=False, indent=2)

    prompt = f"""{instructions}

[recon_info]
{recon_text}

[cve_list]
{cve_text}

[chains]
{chains_text}

[exploit_map]
{exploit_text}
"""
    return prompt


def call_ollama(prompt: str):
    base_url = current_app.config["OLLAMA_BASE_URL"]
    model = current_app.config["OLLAMA_MODEL"]
    url = f"{base_url}/api/generate"

    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
    }

    try:
        resp = requests.post(url, json=payload, timeout=300)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        return {
            "selected_chains": [],
            "scenario": [f"[AI 호출 실패] {e}"],
            "proof": {
                "loot_files": [],
                "logs": [],
            },
        }

    data = resp.json()
    raw_text = data.get("response", "")

    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError:
        parsed = {
            "selected_chains": [],
            "scenario": [raw_text],
            "proof": {
                "loot_files": [],
                "logs": [],
            },
        }

    return parsed

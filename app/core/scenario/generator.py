# app/core/scenario/generator.py

<<<<<<< HEAD
import requests
import json
from flask import current_app


def build_executive_prompt(cve_list, recon_info, chains, exploit_map):
    """
    Executive Summary용 프롬프트 (간결한 보고서)
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
  },
  "mermaid_diagram": "graph TD\n    A[정찰: Nmap Scan] --> B[CVE-XXXX-AAAA: Initial Access]\n    B --> C[CVE-YYYY-BBBB: Privilege Escalation]\n    C --> D[CVE-ZZZZ-CCCC: Data Exfiltration]\n    D --> E[Mission Complete]"
}

주의:

- 실제 IP나 민감 정보는 모두 더미 값(예: 203.0.113.10, 198.51.100.5)으로 바꿔줘.
- selected_chains의 steps에는 반드시 어떤 CVE를 어떤 역할(role)로 쓰는지, 어느 포트/서비스와 연결되는지 명시해.
- **mermaid_diagram 필드를 반드시 포함해. Mermaid.js flowchart 문법으로 작성해.**
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


def build_prompt(cve_list, recon_info, chains, exploit_map):
    """
    기존 호환성을 위한 래퍼 함수
    """
    return build_executive_prompt(cve_list, recon_info, chains, exploit_map)


def call_ollama(prompt: str):
    """
    Ollama LLM 호출
    """
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
            "mermaid_diagram": ""
        }

    data = resp.json()
    raw_text = data.get("response", "")

    try:
        parsed = json.loads(raw_text)
        
        # Mermaid diagram이 없으면 기본값 생성
        if "mermaid_diagram" not in parsed:
            parsed["mermaid_diagram"] = generate_default_mermaid(parsed.get("selected_chains", []))
        
        return parsed
    except json.JSONDecodeError:
        return {
            "selected_chains": [],
            "scenario": [raw_text],
            "proof": {
                "loot_files": [],
                "logs": [],
            },
            "mermaid_diagram": ""
        }


def generate_default_mermaid(chains):
    """
    LLM이 Mermaid를 생성하지 못했을 때 기본 다이어그램 생성
    """
    if not chains or len(chains) == 0:
        return "graph TD\n    A[No Attack Chain Available]"
    
    diagram = "graph TD\n"
    diagram += "    Start[정찰: Recon] --> Step1\n"
    
    for i, chain in enumerate(chains):
        steps = chain.get('steps', [])
        for j, step in enumerate(steps):
            node_id = f"Step{i+1}_{j+1}"
            # Extract CVE ID from step text
            import re
            cve_match = re.search(r'CVE-\d{4}-\d+', step)
            cve_id = cve_match.group(0) if cve_match else f"Step {j+1}"
            
            if j == 0:
                diagram += f"    Step1[{cve_id}] --> {node_id}\n"
            else:
                prev_node = f"Step{i+1}_{j}"
                diagram += f"    {prev_node}[{cve_id}] --> {node_id}\n"
    
    diagram += f"    Step{len(chains)}_{len(steps)}[Complete] --> End[Mission Complete]\n"
    
    return diagram
=======
"""
AI 기반 공격 시나리오 생성기 (CWE 정보 활용)
"""

import requests
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

def extract_cwe_from_cve(cve_data: Dict[str, Any]) -> List[str]:
    """
    🆕 CVE 데이터에서 CWE ID 추출
    """
    cwes = []
    try:
        cve = cve_data.get("cve", {})
        weaknesses = cve.get("weaknesses", [])
        
        for weakness in weaknesses:
            descriptions = weakness.get("description", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    cwe_value = desc.get("value", "")
                    if cwe_value.startswith("CWE-"):
                        cwes.append(cwe_value)
    except Exception as e:
        logger.warning(f"[CWE] Failed to extract CWE: {e}")
    
    return cwes

def build_prompt(recon_result, cves, verification_results=None):
    """
    AI 프롬프트 생성 (기존 로직 유지)
    """
    # 1. 타겟 정보 추출
    target_info = ""
    if recon_result and len(recon_result) > 0:
        if isinstance(recon_result[0], dict):
            host = recon_result[0]
            ip = host.get("ip", "unknown")
            ports = host.get("ports", [])
            
            target_info = f"- IP 주소: {ip}\n"
            target_info += f"- 오픈 포트: {len(ports)}개\n"
            
            # 주요 서비스 추출
            services = []
            for port in ports[:5]:  # 상위 5개만
                service_name = port.get("service", "unknown")
                port_num = port.get("port", "?")
                product = port.get("product", "")
                version = port.get("version", "")
                
                service_str = f"{service_name}/{port_num}"
                if product:
                    service_str += f" ({product}"
                    if version:
                        service_str += f" {version}"
                    service_str += ")"
                
                services.append(service_str)
            
            if services:
                target_info += "- 주요 서비스:\n"
                for svc in services:
                    target_info += f"  * {svc}\n"
        else:
            target_info = "- 타겟 정보 없음 (Recon 결과 형식 불일치)\n"
    
    # 2. CVE 정보 요약
    cve_summary = ""
    if cves and len(cves) > 0:
        # CVSS 점수별로 분류
        critical_cves = [c for c in cves if isinstance(c, dict) and c.get("cvss", 0) >= 9.0]
        high_cves = [c for c in cves if isinstance(c, dict) and 7.0 <= c.get("cvss", 0) < 9.0]
        medium_cves = [c for c in cves if isinstance(c, dict) and 4.0 <= c.get("cvss", 0) < 7.0]
        
        cve_summary += f"- 총 CVE: {len(cves)}개\n"
        cve_summary += f"  * Critical (9.0+): {len(critical_cves)}개\n"
        cve_summary += f"  * High (7.0-8.9): {len(high_cves)}개\n"
        cve_summary += f"  * Medium (4.0-6.9): {len(medium_cves)}개\n\n"
        
        # 상위 5개 CVE 상세 정보
        # 딕셔너리인지 확인하고 정렬
        valid_cves = [c for c in cves if isinstance(c, dict)]
        top_cves = sorted(valid_cves, key=lambda x: x.get("cvss", 0), reverse=True)[:5]
        
        cve_summary += "### 주요 취약점 (Top 5):\n"
        for idx, cve in enumerate(top_cves, 1):
            cve_id = cve.get("cve_id", cve.get("id", "N/A"))
            cvss = cve.get("cvss", 0)
            desc = cve.get("description", "")[:150]
            service = cve.get("service", "unknown")
            
            cve_summary += f"{idx}. **{cve_id}** (CVSS {cvss})\n"
            cve_summary += f"   - 서비스: {service}\n"
            cve_summary += f"   - 설명: {desc}...\n\n"
    
    # 3. 검증된 취약점 추가
    verified_info = ""
    if verification_results:
        exploitable = [v for v in verification_results if isinstance(v, dict) and v.get('exploitable')]
        if exploitable:
            verified_info = "\n### 🔥 실제 검증된 취약점:\n"
            for v in exploitable[:5]:
                cve_id = v.get('cve_id', 'N/A')
                endpoint = v.get('endpoint', 'N/A')
                confidence = v.get('confidence', 'unknown')
                verified_info += f"- **{cve_id}**: {endpoint} (신뢰도: {confidence})\n"
    
    # 4. 최종 프롬프트 조합
    prompt = f"""당신은 침투 테스트 전문가입니다. 아래 스캔 결과를 바탕으로 실전적인 공격 시나리오를 한국어로 생성해주세요.

## 타겟 정보
{target_info}

## 발견된 취약점
{cve_summary}
{verified_info}

## 요구사항
다음 단계를 포함하여 상세한 공격 체인(Attack Chain)을 생성해주세요:

1. **초기 침투 (Initial Access)**
   - 어떤 취약점을 이용할 것인지
   - 어떤 공격 기법을 사용할 것인지
   - 예상되는 공격 성공률

2. **권한 상승 (Privilege Escalation)**
   - 초기 침투 후 어떻게 권한을 상승시킬 것인지
   - 사용 가능한 Exploit 또는 기법

3. **지속성 확보 (Persistence)**
   - 재부팅 후에도 접근 가능하도록 하는 방법
   - Backdoor 설치 위치 및 방법

4. **데이터 탈취 (Data Exfiltration)**
   - 어떤 데이터를 탈취할 것인지
   - 탈취 방법 및 은닉 기법

5. **대응 방안 (Mitigation)**
   - 각 공격 단계별 방어 방법
   - 긴급 패치가 필요한 항목

**형식**: Markdown 형식으로, 각 단계를 명확히 구분하여 작성해주세요.
**톤**: 전문적이고 기술적인 어조를 유지하되, 이해하기 쉽게 설명해주세요.
**길이**: 총 300-500 단어 분량으로 작성해주세요.
"""
    return prompt

def get_available_model(base_url):
    """
    Ollama 서버에서 사용 가능한 모델을 자동으로 찾습니다.
    """
    try:
        resp = requests.get(f"{base_url}/api/tags", timeout=2)
        if resp.status_code == 200:
            models = resp.json().get('models', [])
            if models:
                # 1순위: llama3, 2순위: gemma, 3순위: 아무거나
                model_names = [m['name'] for m in models]
                
                for m in model_names:
                    if 'llama3' in m: return m
                for m in model_names:
                    if 'gemma' in m: return m
                
                return model_names[0] # 아무거나 반환
    except Exception:
        pass
    return "llama3" # 기본값

def call_ollama(
    prompt: str,
    model: str = None, # None이면 자동 감지
    base_url: str = "http://localhost:11434",
    timeout: int = 300
) -> str:
    """
    Ollama API 호출 (자동 모델 감지 기능 추가)
    """
    try:
        # 모델 자동 선택 로직
        target_model = model
        if not target_model:
            target_model = get_available_model(base_url)
            logger.info(f"[AI] Auto-detected model: {target_model}")

        url = f"{base_url}/api/generate"
        payload = {
            "model": target_model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.7,
                "top_p": 0.9,
                "max_tokens": 2000 
            }
        }
        
        logger.info(f"[AI] Calling Ollama API: {url} with model {target_model}")
        
        response = requests.post(url, json=payload, timeout=timeout)
        response.raise_for_status()
        
        result = response.json()
        scenario = result.get("response", "").strip()
        
        if not scenario:
            logger.warning("[AI] Empty response from Ollama")
            return None # None 반환 -> routes.py에서 Fallback 처리
        
        logger.info(f"[AI] ✓ Scenario generated successfully ({len(scenario)} chars)")
        return scenario
        
    except requests.exceptions.Timeout:
        logger.error(f"[AI] Ollama API timeout ({timeout}s)")
        return None
    except requests.exceptions.ConnectionError:
        logger.error(f"[AI] Cannot connect to Ollama at {base_url}")
        return None
    except Exception as e:
        logger.exception(f"[AI] Unexpected error: {e}")
        return None
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642

# app/core/scenario/generator.py

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
    
    Args:
        cve_data: NVD API 응답의 CVE 객체
    
    Returns:
        CWE ID 리스트 (예: ["CWE-89", "CWE-79"])
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
    AI 프롬프트 생성
    
    Args:
        recon_result: 정찰 결과
        cves: CVE 리스트
        verification_results: 검증 결과 (선택)
    
    Returns:
        완전한 AI 프롬프트 문자열
    """
    # 🔥 핵심 수정: 실제 프롬프트 생성!
    
    # 1. 타겟 정보 추출
    target_info = ""
    if recon_result and len(recon_result) > 0:
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
    
    # 2. CVE 정보 요약
    cve_summary = ""
    if cves and len(cves) > 0:
        # CVSS 점수별로 분류
        critical_cves = [c for c in cves if c.get("cvss", 0) >= 9.0]
        high_cves = [c for c in cves if 7.0 <= c.get("cvss", 0) < 9.0]
        medium_cves = [c for c in cves if 4.0 <= c.get("cvss", 0) < 7.0]
        
        cve_summary += f"- 총 CVE: {len(cves)}개\n"
        cve_summary += f"  * Critical (9.0+): {len(critical_cves)}개\n"
        cve_summary += f"  * High (7.0-8.9): {len(high_cves)}개\n"
        cve_summary += f"  * Medium (4.0-6.9): {len(medium_cves)}개\n\n"
        
        # 상위 5개 CVE 상세 정보
        cve_summary += "### 주요 취약점 (Top 5):\n"
        top_cves = sorted(cves, key=lambda x: x.get("cvss", 0), reverse=True)[:5]
        
        for idx, cve in enumerate(top_cves, 1):
            cve_id = cve.get("cve_id", "N/A")
            cvss = cve.get("cvss", 0)
            desc = cve.get("description", "")[:150]  # 150자로 제한
            service = cve.get("service", "unknown")
            
            cve_summary += f"{idx}. **{cve_id}** (CVSS {cvss})\n"
            cve_summary += f"   - 서비스: {service}\n"
            cve_summary += f"   - 설명: {desc}...\n\n"
    
    # 3. 검증된 취약점 추가
    verified_info = ""
    if verification_results:
        exploitable = [v for v in verification_results if v.get('exploitable')]
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


def call_ollama(
    prompt: str,
    model: str = "gemma2:9b",
    base_url: str = "http://localhost:11434",
    timeout: int = 300
) -> str:
    """
    Ollama API 호출 (타임아웃 증가, 더미 생성 제거)
    """
    try:
        url = f"{base_url}/api/generate"
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.7,
                "top_p": 0.9,
                "max_tokens": 1000  # 🆕 500 → 1000 토큰으로 증가
            }
        }
        
        logger.info(f"[AI] Calling Ollama API: {url}")
        logger.debug(f"[AI] Prompt length: {len(prompt)} characters")
        
        response = requests.post(url, json=payload, timeout=timeout)
        response.raise_for_status()
        
        result = response.json()
        scenario = result.get("response", "").strip()
        
        if not scenario:
            logger.warning("[AI] Empty response from Ollama")
            return ""
        
        logger.info(f"[AI] ✓ Scenario generated successfully ({len(scenario)} chars)")
        return scenario
        
    except requests.exceptions.Timeout:
        logger.error(f"[AI] Ollama API timeout ({timeout}s)")
        return ""
    except requests.exceptions.ConnectionError:
        logger.error(f"[AI] Cannot connect to Ollama at {base_url}")
        return ""
    except Exception as e:
        logger.exception(f"[AI] Unexpected error: {e}")
        return ""

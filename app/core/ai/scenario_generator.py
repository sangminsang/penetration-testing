"""
공격 시나리오 생성기

스캔 결과를 기반으로 AI가 공격 시나리오를 생성합니다.
"""

import json
import logging
from typing import Dict, List, Any
from app.core.ai.llama_client import LlamaClient

logger = logging.getLogger(__name__)


class ScenarioGenerator:
    """
    공격 시나리오 생성기 클래스
    
    스캔 결과와 CVE 정보를 기반으로 AI가 공격 시나리오를 생성합니다.
    """
    
    def __init__(self, llama_client: LlamaClient = None):
        """
        시나리오 생성기 초기화
        
        Args:
            llama_client: Llama 클라이언트 인스턴스
        """
        self.llama_client = llama_client or LlamaClient()
    
    def generate_attack_scenario(
        self,
        scan_results: Dict[str, Any],
        cve_mapping: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        공격 시나리오 생성
        
        Args:
            scan_results: 통합된 스캔 결과
            cve_mapping: CVE 매핑 결과
        
        Returns:
            공격 시나리오
            {
                'scenario': '전체 공격 시나리오 텍스트',
                'steps': [
                    {
                        'step': 1,
                        'description': '1단계 설명',
                        'cve': 'CVE-XXXX-XXXX',
                        'target': '타겟 정보'
                    },
                    ...
                ],
                'attack_chains': [...]
            }
        """
        logger.info("공격 시나리오 생성 시작")
        
        # 프롬프트 구성
        prompt = self._build_prompt(scan_results, cve_mapping)
        
        # 프롬프트 크기 로깅
        logger.debug(f"프롬프트 크기: {len(prompt)}자")
        
        # AI 호출
        result = self.llama_client.generate(prompt)
        
        # AI 응답 검증
        response_text = result.get('response', '')
        logger.debug(f"AI 응답 크기: {len(response_text)}자")
        logger.debug(f"AI 응답 처음 200자: {response_text[:200]}...")
        
        if result.get('error'):
            logger.error(f"❌ AI 호출 에러: {result.get('error')}")
            return {
                'selected_chains': [],
                'scenario': [],
                'error': f"AI 호출 실패: {result.get('error')}"
            }
        
        # 응답 파싱
        scenario = self._parse_response(response_text)
        
        # 파싱 결과 검증
        logger.debug(f"파싱된 시나리오 타입: {type(scenario)}")
        if isinstance(scenario, dict):
            logger.debug(f"시나리오 키: {list(scenario.keys())}")
            if 'error' in scenario:
                logger.warning(f"⚠️ 파싱 에러: {scenario.get('error')}")
            selected_chains = scenario.get('selected_chains', [])
            logger.debug(f"selected_chains 개수: {len(selected_chains)}")
        else:
            logger.error(f"❌ 파싱된 시나리오가 딕셔너리가 아닙니다!")
        
        logger.info("공격 시나리오 생성 완료")
        
        return scenario
    
    def _build_prompt(
        self,
        scan_results: Dict[str, Any],
        cve_mapping: Dict[str, Any]
    ) -> str:
        """
        AI 프롬프트 구성
        
        Args:
            scan_results: 스캔 결과
            cve_mapping: CVE 매핑 결과
        
        Returns:
            프롬프트 문자열
        """
        # 취약점 정보 요약
        vulnerabilities = scan_results.get('vulnerabilities', [])
        vuln_summary = []
        for vuln in vulnerabilities[:20]:  # 최대 20개만
            vuln_summary.append({
                'name': vuln.get('name', ''),
                'url': vuln.get('url', ''),
                'severity': vuln.get('severity', 'medium'),
                'cve': vuln.get('cve', [])
            })
        
        # 포트 정보 요약
        ports = scan_results.get('ports', [])
        port_summary = []
        for port in ports[:10]:  # 최대 10개만
            port_summary.append({
                'port': port.get('port', ''),
                'service': port.get('service', ''),
                'product': port.get('product', ''),
                'version': port.get('version', '')
            })
        
        # CVE 정보 요약
        cve_summary = []
        for cpe, cves in list(cve_mapping.get('cpe_to_cves', {}).items())[:10]:
            for cve in cves[:5]:  # CPE당 최대 5개
                cve_summary.append({
                    'cve_id': cve.get('cve_id', ''),
                    'description': cve.get('description', '')[:200],  # 200자 제한
                    'cvss_score': cve.get('cvss_score', 0.0)
                })
        
        # PoC 검증 결과가 포함된 취약점 필터링
        verified_vulns = [v for v in vulnerabilities if v.get('poc_code') and v.get('execution_result')]
        verified_vulns_summary = []
        for vuln in verified_vulns[:10]:  # 검증된 취약점 상위 10개
            verified_vuln_data = {
                'name': vuln.get('name', ''),
                'url': vuln.get('url', ''),
                'severity': vuln.get('severity', ''),
                'poc_code': vuln.get('poc_code', ''),
                'execution_result': vuln.get('execution_result', {}),
            }
            if vuln.get('execution_result', {}).get('extracted_data'):
                verified_vuln_data['extracted_data'] = vuln.get('execution_result', {}).get('extracted_data')
            verified_vulns_summary.append(verified_vuln_data)
        
        prompt = f"""너는 15년 경력의 화이트해커이자 레드팀 리더야.
아래 제공하는 보안 스캔 결과를 바탕으로, 공격자 입장에서 가장 효율적인 '침투 체인(Exploit Chain)'을 설계해줘.

## 스캔 결과 요약

### 발견된 취약점 ({len(vulnerabilities)}개)
{json.dumps(vuln_summary, ensure_ascii=False, indent=2)}

### PoC 검증 완료된 취약점 ({len(verified_vulns)}개)
{json.dumps(verified_vulns_summary, ensure_ascii=False, indent=2) if verified_vulns_summary else json.dumps([], ensure_ascii=False, indent=2)}

**중요:** 위 PoC 검증 완료된 취약점은 실제로 PoC 코드가 생성되고 실행되어 검증된 취약점입니다.
- `poc_code`: 실제 실행 가능한 PoC 코드
- `execution_result`: PoC 실행 결과
- `extracted_data`: PoC 실행으로 탈취한 실제 데이터 (있는 경우)

### 열린 포트 및 서비스 ({len(ports)}개)
{json.dumps(port_summary, ensure_ascii=False, indent=2)}

### 관련 CVE ({len(cve_summary)}개)
{json.dumps(cve_summary, ensure_ascii=False, indent=2)}

## 요구사항

1. 위에 제공된 취약점과 CVE만 사용해서 공격 시나리오를 구성해줘.
   - 새로운 CVE ID를 만들어내거나, 입력에 없는 CVE를 사용하지 마.
   - **PoC 검증 완료된 취약점을 우선적으로 활용**해줘 (이미 검증되었으므로 공격 성공 가능성이 높음).
2. 가능한 한 현실적인 1~2개의 공격 체인만 선택해서 상세 시나리오를 작성해줘.
   - 각 체인은 initial_access -> privilege_escalation -> lateral_movement -> data_exfiltration 순서를 따르려고 노력해.
3. **각 공격 단계마다 실제 실행 가능한 PoC 코드를 포함**해줘.
   - 개념적인 설명만 하지 말고, Python 코드로 작성된 실제 실행 가능한 exploit 코드를 포함해줘.
   - PoC 검증 완료된 취약점의 `poc_code`를 참고하여 유사한 형태로 작성해줘.
   - 코드는 requests 라이브러리를 사용하여 HTTP 요청을 보내는 형태로 작성해줘.
4. PoC 검증 완료된 취약점의 `extracted_data`가 있다면, 이를 활용하여 다음 단계 공격을 설계해줘.
   - 예: SQL Injection으로 탈취한 관리자 계정 정보를 사용하여 로그인 시도
5. 모르는 부분은 지어내지 말고 "unknown"이라고 표기해줘.

## 출력 형식 (절대 준수)

**🔴 최종 지시사항 (절대 준수) 🔴**

1. **순수 JSON만 출력하세요.**
   - 첫 번째 문자는 중괄호 여는 괄호 {{{{ 또는 단일 중괄호
   - 마지막 문자는 중괄호 닫는 괄호 }}}} 또는 단일 중괄호
   - 그 사이: 순수 JSON (설명 문장, 마크다운 코드 블록, 주석 없음)

2. **JSON 문자열 안의 줄바꿈은 반드시 \\\\n으로 이스케이프하세요.**
   - 잘못된 예: "poc_code": "\\nimport requests\\n"
   - 올바른 예: "poc_code": "\\\\nimport requests\\\\n"

3. **절대 금지 사항:**
   - ❌ "이 코드는..." 같은 설명 문장
   - ❌ "### selected_chains" 같은 마크다운 헤더
   - ❌ ```json ... ``` 같은 코드 블록
   - ❌ JSON 문자열 안의 실제 줄바꿈 문자

4. **응답 형식:**
{{
  "selected_chains": [
    {{
      "chain_id": 1,
      "description": "요약 설명",
      "steps": [
        {{
          "step_number": 1,
          "role": "initial_access",
          "description": "CVE-XXXX-AAAA (initial_access)를 통해 8080 포트 Apache 웹서버에서 Path Traversal 기반 RCE를 시도한다 ...",
          "poc_code": "\\nimport requests\\nurl = 'http://target.com/vulnerable'\\npayload = '...'\\nresponse = requests.get(url, params={{'param': payload}})\\nprint(response.text)",
          "expected_result": "예상 실행 결과 설명"
        }},
        {{
          "step_number": 2,
          "role": "privilege_escalation",
          "description": "CVE-YYYY-BBBB (privilege_escalation)를 이용해 www-data에서 root로 권한 상승을 시도한다 ...",
          "poc_code": "\\nimport requests\\n# 실제 실행 가능한 PoC 코드",
          "expected_result": "예상 실행 결과 설명"
        }},
        {{
          "step_number": 3,
          "role": "data_exfiltration",
          "description": "CVE-ZZZZ-CCCC (data_exfiltration)를 통해 MySQL DB에서 중요한 데이터를 덤프한다 ...",
          "poc_code": "\\nimport requests\\n# 실제 실행 가능한 PoC 코드",
          "expected_result": "예상 실행 결과 설명"
        }}
      ]
    }}
  ],
  "scenario": [
    "... 전체 공격 과정을 해커 입장에서 서술한 시나리오 ..."
  ]
}}

주의:
- 실제 IP나 민감 정보는 모두 더미 값(예: 203.0.113.10, 198.51.100.5)으로 바꿔줘.
- selected_chains의 steps에는 반드시 어떤 CVE를 어떤 역할(role)로 쓰는지, 어느 포트/서비스와 연결되는지 명시해줘.
"""
        
        return prompt
    
    def _parse_response(self, response_text: str) -> Dict[str, Any]:
        """
        개선된 AI 응답 파싱 로직
        
        Args:
            response_text: AI 응답 텍스트
        
        Returns:
            파싱된 시나리오 딕셔너리
        """
        import re
        
        original_text = response_text
        response_text = response_text.strip()
        
        logger.debug(f"원본 응답 길이: {len(original_text)}자")
        logger.debug(f"원본 응답 처음 300자: {original_text[:300]}...")
        
        try:
            # Step 1: 마크다운 코드 블록 제거 (모든 형식 지원)
            code_block_patterns = [
                r'```json\s*\n?(.*?)\n?```',  # ```json ... ```
                r'```\s*\n?(.*?)\n?```',      # ``` ... ```
            ]
            
            for pattern in code_block_patterns:
                match = re.search(pattern, response_text, re.DOTALL)
                if match:
                    response_text = match.group(1).strip()
                    logger.debug(f"마크다운 코드 블록에서 JSON 추출 성공")
                    break
            
            # Step 2: 설명 문장 제거 (JSON 객체 시작 찾기)
            json_start = response_text.find('{')
            if json_start == -1:
                # "selected_chains" 키워드로 찾기
                selected_chains_pos = response_text.find('"selected_chains"')
                if selected_chains_pos != -1:
                    json_start = response_text.rfind('{', 0, selected_chains_pos)
            
            if json_start == -1:
                logger.error("JSON 객체 시작을 찾을 수 없습니다")
                return {
                    'selected_chains': [],
                    'scenario': [],
                    'error': 'JSON 객체 시작을 찾을 수 없습니다',
                    'original_response': original_text[:1000]
                }
            
            # Step 3: 중괄호 매칭으로 정확한 JSON 범위 추출
            brace_count = 0
            in_string = False
            escape_next = False
            json_end = json_start
            
            for i in range(json_start, len(response_text)):
                char = response_text[i]
                
                if escape_next:
                    escape_next = False
                    continue
                
                if char == '\\':
                    escape_next = True
                    continue
                
                if char == '"' and not escape_next:
                    in_string = not in_string
                    continue
                
                if not in_string:
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            json_end = i + 1
                            break
            
            if brace_count != 0:
                logger.error(f"JSON 객체의 중괄호가 맞지 않습니다 (brace_count={brace_count})")
                return {
                    'selected_chains': [],
                    'scenario': [],
                    'error': f'JSON 객체의 중괄호가 맞지 않습니다 (brace_count={brace_count})',
                    'original_response': original_text[:1000]
                }
            
            json_text = response_text[json_start:json_end]
            
            # Step 4: 제어 문자 정리
            json_text_cleaned = self._clean_control_characters(json_text)
            
            logger.debug(f"JSON 파싱 대상 길이: {len(json_text_cleaned)}자")
            logger.debug(f"JSON 파싱 대상 처음 200자: {json_text_cleaned[:200]}...")
            
            # Step 5: JSON 파싱
            scenario = json.loads(json_text_cleaned)
            
            logger.debug(f"✅ JSON 파싱 성공")
            if isinstance(scenario, dict):
                logger.debug(f"파싱된 시나리오 키: {list(scenario.keys())}")
                if 'selected_chains' in scenario:
                    logger.debug(f"selected_chains 개수: {len(scenario.get('selected_chains', []))}")
            
            return scenario
            
        except json.JSONDecodeError as e:
            logger.error(f"❌ JSON 파싱 실패: {e}")
            logger.error(f"파싱 실패 위치: line {e.lineno if hasattr(e, 'lineno') else 'N/A'}, column {e.colno if hasattr(e, 'colno') else 'N/A'}, char {e.pos if hasattr(e, 'pos') else 'N/A'}")
            return {
                'selected_chains': [],
                'scenario': [],
                'error': f'JSON 파싱 실패: {str(e)}',
                'original_response': original_text[:1000]
            }
        except Exception as e:
            logger.error(f"❌ 파싱 중 예외 발생: {e}", exc_info=True)
            return {
                'selected_chains': [],
                'scenario': [],
                'error': f'파싱 중 예외 발생: {str(e)}',
                'original_response': original_text[:1000]
            }
    
    def _clean_control_characters(self, json_text: str) -> str:
        """
        JSON 문자열 안의 제어 문자를 이스케이프
        
        Args:
            json_text: 정리할 JSON 텍스트
        
        Returns:
            제어 문자가 이스케이프된 JSON 텍스트
        """
        result = []
        in_string = False
        escape_next = False
        i = 0
        
        while i < len(json_text):
            char = json_text[i]
            
            if escape_next:
                result.append(char)
                escape_next = False
                i += 1
                continue
            
            if char == '\\':
                result.append(char)
                escape_next = True
                i += 1
                continue
            
            if char == '"':
                in_string = not in_string
                result.append(char)
                i += 1
                continue
            
            if in_string:
                # 문자열 안에서 실제 제어 문자를 이스케이프
                if char == '\n':
                    result.append('\\n')
                elif char == '\r':
                    result.append('\\r')
                elif char == '\t':
                    result.append('\\t')
                elif ord(char) < 32:  # 기타 제어 문자
                    result.append(f'\\u{ord(char):04x}')
                else:
                    result.append(char)
            else:
                result.append(char)
            
            i += 1
        
        return ''.join(result)


"""
AI PoC 생성기 모듈

LLM을 이용하여 맞춤형 PoC(Proof of Concept) 코드를 생성하고 실행하여 검증합니다.
"""

import subprocess
import json
import logging
import tempfile
import os
import re
from typing import Dict, Any, Optional
from pathlib import Path
import requests
from app.config import Config

logger = logging.getLogger(__name__)


class AIPoCGenerator:
    """
    AI PoC 생성기 클래스
    
    취약점 정보를 바탕으로 LLM에게 PoC 코드를 요청하고,
    subprocess로 실행하여 검증 결과를 반환합니다.
    """
    
    def __init__(self, base_url: str = None, model: str = None):
        """
        AI PoC 생성기 초기화
        
        Args:
            base_url: Ollama 서버 URL (기본값: Config.OLLAMA_BASE_URL)
            model: 사용할 모델 이름 (기본값: Config.OLLAMA_MODEL)
        """
        self.base_url = base_url or Config.OLLAMA_BASE_URL
        self.model = model or Config.OLLAMA_MODEL
        self.api_url = f"{self.base_url}/api/generate"
    
    def generate_and_execute_poc(
        self,
        vulnerability: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        취약점에 대한 PoC 코드를 생성하고 실행하여 검증
        
        Args:
            vulnerability: 취약점 정보 딕셔너리
                {
                    'name': 'SQL Injection',
                    'url': 'http://target.com/login',
                    'severity': 'high',
                    'evidence': '...',
                    'description': '...'
                }
        
        Returns:
            검증 결과 딕셔너리
            {
                'status': 'success' | 'failed' | 'manual_verification_needed',
                'poc_code': {
                    'python_code': '...',
                    'language': 'python',
                    'requirements': ['requests']
                },
                'execution_result': {
                    'output': '...',
                    'error': None or '...',
                    'returncode': 0 or non-zero,
                    'attempts': 1
                }
            }
        """
        try:
            # Step 1: LLM에게 PoC 코드 생성 요청
            logger.info(f"PoC 코드 생성 시작: {vulnerability.get('name', 'Unknown')} - {vulnerability.get('url', 'N/A')}")
            poc_code = self._generate_poc_code(vulnerability)
            
            if not poc_code:
                logger.warning(f"PoC 코드 생성 실패: {vulnerability.get('name', 'Unknown')}")
                return {
                    'status': 'failed',
                    'poc_code': None,
                    'execution_result': {
                        'output': '',
                        'error': 'PoC 코드 생성 실패',
                        'returncode': -1,
                        'attempts': 1
                    }
                }
            
            # Step 2: 생성된 코드 실행 (Try-Once Strategy)
            logger.info(f"PoC 코드 실행 시작: {vulnerability.get('url', 'N/A')}")
            execution_result = self._execute_poc_code(poc_code, vulnerability.get('url', ''))
            
            # Step 3: 결과 파싱
            status = self._parse_execution_result(execution_result)
            
            return {
                'status': status,
                'poc_code': {
                    'python_code': poc_code,
                    'language': 'python',
                    'requirements': ['requests']
                },
                'execution_result': execution_result
            }
            
        except Exception as e:
            logger.error(f"PoC 생성 및 실행 중 오류 발생: {e}", exc_info=True)
            return {
                'status': 'failed',
                'poc_code': None,
                'execution_result': {
                    'output': '',
                    'error': str(e),
                    'returncode': -1,
                    'attempts': 1
                }
            }
    
    def _generate_poc_code(self, vulnerability: Dict[str, Any]) -> Optional[str]:
        """
        LLM에게 PoC 코드 생성 요청
        
        Args:
            vulnerability: 취약점 정보
        
        Returns:
            생성된 Python 코드 (문자열) 또는 None
        """
        try:
            # 프롬프트 구성
            prompt = self._build_poc_prompt(vulnerability)
            
            # Ollama API 호출
            payload = {
                'model': self.model,
                'prompt': prompt,
                'stream': False,
                'options': {
                    'temperature': 0.3  # 창의성은 낮게, 정확성 우선
                }
            }
            
            logger.info(f"Ollama API 호출: {self.api_url}, 모델: {self.model}")
            
            # 타임아웃을 30분으로 설정 (GNS 서버 스캔 등 긴 응답 시간 대비)
            import time
            start_time = time.time()
            
            try:
                response = requests.post(
                    self.api_url,
                    json=payload,
                    timeout=1800  # 30분 타임아웃 (실제 응답 시간 측정용)
                )
                elapsed_time = time.time() - start_time
                logger.info(f"✅ Ollama API 응답 성공! 응답 시간: {elapsed_time:.2f}초 ({elapsed_time/60:.2f}분)")
                
                response.raise_for_status()
                
                data = response.json()
                response_text = data.get('response', '').strip()
                
                # 마크다운 코드 블록 제거 (```python ... ```)
                if '```python' in response_text:
                    # ```python과 ``` 사이의 코드만 추출
                    start_idx = response_text.find('```python') + len('```python')
                    end_idx = response_text.find('```', start_idx)
                    if end_idx != -1:
                        response_text = response_text[start_idx:end_idx].strip()
                elif '```' in response_text:
                    # 일반 코드 블록도 처리
                    start_idx = response_text.find('```') + 3
                    end_idx = response_text.find('```', start_idx)
                    if end_idx != -1:
                        response_text = response_text[start_idx:end_idx].strip()
                
                if not response_text:
                    logger.warning("LLM 응답이 비어있음")
                    return None
                
                logger.info(f"PoC 코드 생성 완료 ({len(response_text)}자, 소요 시간: {elapsed_time:.2f}초)")
                return response_text
                
            except requests.exceptions.Timeout:
                elapsed_time = time.time() - start_time
                logger.error(f"Ollama API 호출 타임아웃 ({elapsed_time:.2f}초 경과, 30분 초과)")
                return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Ollama API 호출 실패: {e}")
            return None
        except Exception as e:
            logger.error(f"PoC 코드 생성 중 예외 발생: {e}", exc_info=True)
            return None
    
    def _build_poc_prompt(self, vulnerability: Dict[str, Any]) -> str:
        """
        PoC 코드 생성용 프롬프트 구성
        
        Args:
            vulnerability: 취약점 정보
        
        Returns:
            프롬프트 문자열
        """
        vuln_name = vulnerability.get('name', 'Unknown')
        vuln_url = vulnerability.get('url', '')
        vuln_evidence = vulnerability.get('evidence', '')
        vuln_description = vulnerability.get('description', '')
        
        prompt = f"""## 시스템 제약 조건 (절대 준수 필수)

1. **Python `requests` 라이브러리만 사용할 것** (다른 라이브러리 import 금지)
2. **결과는 반드시 표준 출력(stdout)으로 `VULNERABILITY_FOUND: {{"json_data"}}` 형식을 출력할 것**
   - 예시: `print('VULNERABILITY_FOUND: {{"affected_rows": 100, "data": "admin"}}')`
3. **마크다운 코드 블록(```python) 없이 순수 코드만 반환할 것**
4. **코드 설명이나 주석은 최소화하고 실행 가능한 코드만 작성할 것**

---

## 취약점 정보

- **취약점 이름**: {vuln_name}
- **대상 URL**: {vuln_url}
- **증거 (Evidence)**: {vuln_evidence}
- **설명**: {vuln_description}

---

## 요구사항

위 취약점을 검증할 수 있는 Python PoC 코드를 작성하세요.

**출력 형식 (반드시 준수)**:
- 코드 실행 후 취약점이 확인되면: `VULNERABILITY_FOUND: {{"key": "value"}}` 형식으로 출력
- 취약점이 확인되지 않으면: `VULNERABILITY_NOT_FOUND` 출력

**제약 사항**:
- `requests` 라이브러리만 사용
- 마크다운 코드 블록 없이 순수 Python 코드만 반환
- 코드 설명 없이 실행 가능한 코드만 작성

**코드 작성:**
"""
        
        return prompt
    
    def _execute_poc_code(
        self,
        poc_code: str,
        target_url: str
    ) -> Dict[str, Any]:
        """
        생성된 PoC 코드를 subprocess로 실행
        
        Args:
            poc_code: 실행할 Python 코드
            target_url: 대상 URL (디버깅용)
        
        Returns:
            실행 결과 딕셔너리
            {
                'output': '...',
                'error': '...',
                'returncode': 0 or non-zero
            }
        """
        # 임시 파일에 코드 저장
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.py',
            delete=False,
            encoding='utf-8'
        ) as f:
            f.write(poc_code)
            temp_file_path = f.name
        
        try:
            # subprocess로 실행
            logger.info(f"PoC 코드 실행: {temp_file_path}")
            result = subprocess.run(
                ['python', temp_file_path],
                capture_output=True,
                text=True,
                timeout=15,  # 15초 타임아웃
                encoding='utf-8',
                errors='replace'
            )
            
            execution_result = {
                'output': result.stdout.strip(),
                'error': result.stderr.strip() if result.stderr else None,
                'returncode': result.returncode,
                'attempts': 1
            }
            
            logger.info(f"PoC 실행 완료: returncode={result.returncode}")
            if result.stdout:
                logger.debug(f"출력: {result.stdout[:200]}...")  # 처음 200자만 로그
            
            return execution_result
            
        except subprocess.TimeoutExpired:
            logger.warning(f"PoC 실행 타임아웃 (15초 초과)")
            return {
                'output': '',
                'error': 'Execution timeout (15 seconds)',
                'returncode': -1,
                'attempts': 1
            }
        except Exception as e:
            logger.error(f"PoC 실행 중 오류: {e}", exc_info=True)
            return {
                'output': '',
                'error': str(e),
                'returncode': -1,
                'attempts': 1
            }
        finally:
            # 임시 파일 삭제
            try:
                if os.path.exists(temp_file_path):
                    os.unlink(temp_file_path)
            except Exception as e:
                logger.warning(f"임시 파일 삭제 실패: {e}")
    
    def _parse_execution_result(
        self,
        execution_result: Dict[str, Any]
    ) -> str:
        """
        실행 결과를 파싱하여 상태 반환 및 탈취 데이터 추출
        
        Args:
            execution_result: 실행 결과 딕셔너리 (수정됨)
        
        Returns:
            상태 문자열: 'success' | 'failed' | 'manual_verification_needed'
        """
        returncode = execution_result.get('returncode', -1)
        output = execution_result.get('output', '')
        error = execution_result.get('error', '')
        
        # VULNERABILITY_FOUND: {...} 형식에서 JSON 데이터 추출 (brace-counting 메커니즘 사용)
        extracted_data = None
        if 'VULNERABILITY_FOUND:' in output:
            try:
                # VULNERABILITY_FOUND: 위치 찾기
                prefix = 'VULNERABILITY_FOUND:'
                start_idx = output.find(prefix)
                if start_idx != -1:
                    json_start = start_idx + len(prefix)
                    # 공백 제거
                    json_start = json_start + len(output[json_start:]) - len(output[json_start:].lstrip())
                    
                    # 중괄호 카운팅으로 JSON 범위 찾기 (중첩 구조 처리)
                    brace_count = 0
                    in_string = False
                    escape_next = False
                    json_end = json_start
                    
                    for i in range(json_start, len(output)):
                        char = output[i]
                        
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
                    
                    if brace_count == 0 and json_end > json_start:
                        json_str = output[json_start:json_end]
                        extracted_data = json.loads(json_str)
                        # 추출한 데이터를 execution_result에 추가
                        execution_result['extracted_data'] = extracted_data
                        logger.info(f"✅ 탈취 데이터 추출 성공: {list(extracted_data.keys()) if isinstance(extracted_data, dict) else 'N/A'}")
            except json.JSONDecodeError as e:
                logger.warning(f"JSON 데이터 파싱 실패: {e}")
                if 'json_str' in locals():
                    logger.debug(f"JSON 문자열 (처음 200자): {json_str[:200]}")
            except Exception as e:
                logger.warning(f"탈취 데이터 추출 중 오류: {e}")
        
        # 성공 조건: returncode=0이고 출력에 VULNERABILITY_FOUND 포함
        if returncode == 0 and 'VULNERABILITY_FOUND' in output:
            logger.info("PoC 검증 성공: VULNERABILITY_FOUND 확인됨")
            if extracted_data:
                logger.info(f"탈취 데이터: {extracted_data}")
            return 'success'
        
        # 실패 조건: returncode != 0 또는 VULNERABILITY_FOUND 없음
        if returncode != 0:
            logger.warning(f"PoC 실행 실패: returncode={returncode}, error={error[:100]}")
            return 'failed'
        
        if 'VULNERABILITY_FOUND' not in output:
            logger.info("PoC 실행 성공했으나 취약점 확인되지 않음")
            return 'manual_verification_needed'
        
        # 기타 경우
        return 'failed'


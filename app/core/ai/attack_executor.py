"""
공격 실행기

AI가 생성한 공격 시나리오를 실제로 실행하고 결과를 수집합니다.
"""

import logging
import subprocess
import requests
import tempfile
import json
import os
from typing import Dict, List, Any, Optional
from app.core.ai.llama_client import LlamaClient

logger = logging.getLogger(__name__)


class AttackExecutor:
    """
    공격 실행기 클래스
    
    AI가 생성한 공격 시나리오를 실제로 실행합니다.
    주의: 실제 공격을 수행하므로 신중하게 사용해야 합니다.
    """
    
    def __init__(self, llama_client: LlamaClient = None):
        """
        공격 실행기 초기화
        
        Args:
            llama_client: Llama 클라이언트 (공격 스크립트 생성용)
        """
        self.llama_client = llama_client or LlamaClient()
    
    def execute_attack_scenario(
        self,
        scenario: Dict[str, Any],
        target_url: str
    ) -> Dict[str, Any]:
        """
        공격 시나리오 실행
        
        Args:
            scenario: 공격 시나리오
            target_url: 타겟 URL
        
        Returns:
            실행 결과
            {
                'success': True/False,
                'results': [
                    {
                        'step': 1,
                        'description': '...',
                        'status': 'success'/'failed',
                        'output': '...',
                        'evidence': '...'
                    },
                    ...
                ],
                'loot': {
                    'files': [...],
                    'data': {...}
                }
            }
        """
        logger.info(f"공격 시나리오 실행 시작: {target_url}")
        
        # [DEBUG] 시나리오 검증
        if scenario is None:
            logger.error("[DEBUG] ❌ scenario가 None입니다!")
            return {
                'success': False,
                'results': [],
                'loot': {'files': [], 'data': {}},
                'error': 'scenario is None'
            }
        
        if not isinstance(scenario, dict):
            logger.error(f"[DEBUG] ❌ scenario가 딕셔너리가 아닙니다 (타입: {type(scenario)})")
            return {
                'success': False,
                'results': [],
                'loot': {'files': [], 'data': {}},
                'error': f'scenario is not a dict (type: {type(scenario)})'
            }
        
        logger.info(f"[DEBUG] 시나리오 구조: {list(scenario.keys())}")
        
        results = {
            'success': False,
            'results': [],
            'loot': {
                'files': [],
                'data': {}
            }
        }
        
        # 각 단계 실행
        chains = scenario.get('selected_chains', [])
        logger.info(f"[DEBUG] selected_chains 개수: {len(chains)}")
        
        if not chains:
            logger.warning(f"[DEBUG] ⚠️ selected_chains가 비어있습니다!")
            logger.warning(f"[DEBUG] 시나리오 전체 구조: {json.dumps(scenario, ensure_ascii=False, indent=2)[:500]}...")
            return results  # 빈 results 반환
        
        total_steps = 0
        for chain_idx, chain in enumerate(chains, 1):
            logger.info(f"[DEBUG] 체인 {chain_idx}/{len(chains)} 처리 중...")
            if not isinstance(chain, dict):
                logger.warning(f"[DEBUG] ⚠️ 체인 {chain_idx}가 딕셔너리가 아닙니다 (타입: {type(chain)})")
                continue
            
            steps = chain.get('steps', [])
            logger.info(f"[DEBUG] 체인 {chain_idx}의 steps 개수: {len(steps)}")
            
            if not steps:
                logger.warning(f"[DEBUG] ⚠️ 체인 {chain_idx}의 steps가 비어있습니다!")
                continue
            
            for idx, step in enumerate(steps, 1):
                total_steps += 1
                logger.info(f"[DEBUG] 단계 {total_steps} 실행 중 (체인 {chain_idx}, 단계 {idx})...")
                # step이 문자열인 경우와 딕셔너리인 경우 모두 처리
                if isinstance(step, str):
                    step_description = step
                    step_data = None
                else:
                    step_description = step.get('description', '')
                    step_data = step
                
                step_result = self._execute_step(step_description, target_url, total_steps, step_data)
                results['results'].append(step_result)
                
                # [DEBUG] 단계 실행 결과 로깅
                if step_result.get('success'):
                    logger.info(f"[DEBUG] ✅ 단계 {total_steps} 성공")
                else:
                    logger.warning(f"[DEBUG] ❌ 단계 {total_steps} 실패: {step_result.get('error', 'N/A')}")
                
                # 실패 시 중단 (선택적)
                if not step_result.get('success'):
                    logger.warning(f"공격 단계 {total_steps} 실패: {step_result.get('error')}")
                    # 계속 진행할지 결정 (현재는 계속 진행)
        
        # 전체 성공 여부 판단
        results['success'] = any(r.get('success') for r in results['results'])
        
        logger.info(f"공격 시나리오 실행 완료: {len(results['results'])}개 단계")
        logger.info(f"[DEBUG] 최종 결과: success={results['success']}, 총 {len(results['results'])}개 단계 실행")
        
        return results
    
    def _execute_step(
        self,
        step_description: str,
        target_url: str,
        step_number: int,
        step_data: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        개별 공격 단계 실행
        
        Args:
            step_description: 단계 설명
            target_url: 타겟 URL
            step_number: 단계 번호
            step_data: 시나리오에서 생성된 단계 데이터 (poc_code 포함 가능)
        
        Returns:
            실행 결과
        """
        import time
        from datetime import datetime
        
        start_time = time.time()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        logger.info(f"공격 단계 {step_number} 실행: {step_description[:50]}...")
        
        # 시나리오에서 생성된 PoC 코드가 있으면 사용, 없으면 생성
        poc_code = None
        if step_data and step_data.get('poc_code'):
            poc_code = step_data.get('poc_code')
            logger.info(f"시나리오에서 생성된 PoC 코드 사용")
        else:
            # AI에게 공격 스크립트 생성 요청
            poc_code = self._generate_attack_script(step_description, target_url)
        
        # 실제 공격 실행 (PoC 코드를 subprocess로 실행)
        result = self._execute_attack_code(poc_code, target_url, step_description)
        
        elapsed = time.time() - start_time
        
        return {
            'step': step_number,
            'description': step_description,
            'timestamp': timestamp,
            'elapsed_seconds': round(elapsed, 2),
            'status': '✅ 성공' if result.get('success') else '❌ 실패',
            'poc_code': poc_code,
            'success': result.get('success', False),
            'output': result.get('output', ''),
            'evidence': result.get('evidence', ''),
            'extracted_data': result.get('extracted_data'),
            'error': result.get('error')
        }
    
    def _generate_attack_script(
        self,
        step_description: str,
        target_url: str
    ) -> str:
        """
        AI를 통해 공격 스크립트 생성
        
        Args:
            step_description: 단계 설명
            target_url: 타겟 URL
        
        Returns:
            공격 스크립트 (Python 코드)
        """
        prompt = f"""다음 공격 단계를 실행할 수 있는 Python 스크립트를 생성해줘.

공격 단계: {step_description}
타겟 URL: {target_url}

요구사항:
1. requests 라이브러리를 사용해서 HTTP 요청을 보내줘.
2. 실제로 위험한 공격은 수행하지 말고, 취약점 존재 여부만 확인하는 스크립트를 작성해줘.
3. 결과를 출력하고, 발견된 증거(evidence)를 반환해줘.

스크립트만 출력해줘. 설명은 필요 없어.
"""
        
        result = self.llama_client.generate(prompt)
        script = result.get('response', '')
        
        return script
    
    def _execute_attack_code(
        self,
        poc_code: str,
        target_url: str,
        step_description: str
    ) -> Dict[str, Any]:
        """
        생성된 PoC 코드를 실제로 실행
        
        Args:
            poc_code: 실행할 Python 코드
            target_url: 타겟 URL
            step_description: 단계 설명 (디버깅용)
        
        Returns:
            실행 결과
        """
        # 마크다운 코드 블록 제거 (```python ... ```)
        poc_code_clean = poc_code.strip()
        if poc_code_clean.startswith('```'):
            lines = poc_code_clean.split('\n')
            # 첫 줄과 마지막 줄 제거
            if lines[0].startswith('```'):
                lines = lines[1:]
            if lines and lines[-1].strip().startswith('```'):
                lines = lines[:-1]
            poc_code_clean = '\n'.join(lines)
        
        # 임시 파일에 코드 저장
        temp_file_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.py',
                delete=False,
                encoding='utf-8'
            ) as f:
                f.write(poc_code_clean)
                temp_file_path = f.name
            
            # subprocess로 실행
            result = subprocess.run(
                ['python', temp_file_path],
                capture_output=True,
                text=True,
                timeout=30,  # 30초 타임아웃
                encoding='utf-8',
                errors='replace'
            )
            
            output = result.stdout.strip()
            error = result.stderr.strip() if result.stderr else None
            
            # 탈취 데이터 추출 (VULNERABILITY_FOUND: {...} 형식)
            extracted_data = None
            if 'VULNERABILITY_FOUND:' in output:
                try:
                    prefix = 'VULNERABILITY_FOUND:'
                    start_idx = output.find(prefix)
                    if start_idx != -1:
                        json_start = start_idx + len(prefix)
                        json_start = json_start + len(output[json_start:]) - len(output[json_start:].lstrip())
                        
                        # 중괄호 매칭으로 JSON 추출
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
                            logger.info(f"✅ 탈취 데이터 추출 성공: {list(extracted_data.keys()) if isinstance(extracted_data, dict) else 'N/A'}")
                except json.JSONDecodeError as e:
                    logger.warning(f"JSON 데이터 파싱 실패: {e}")
                except Exception as e:
                    logger.warning(f"탈취 데이터 추출 중 오류: {e}")
            
            # 성공 여부 판단
            success = False
            if result.returncode == 0 and 'VULNERABILITY_FOUND' in output:
                success = True
            elif result.returncode == 0:
                # 실행은 성공했지만 취약점 확인되지 않음
                success = False
            
            return {
                'success': success,
                'output': output,
                'evidence': output[:500] if output else '',  # 처음 500자만
                'extracted_data': extracted_data,
                'error': error if result.returncode != 0 else None
            }
        
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'output': '',
                'evidence': '',
                'error': 'PoC 실행 타임아웃 (30초 초과)'
            }
        except Exception as e:
            logger.error(f"PoC 실행 중 오류: {e}", exc_info=True)
            return {
                'success': False,
                'output': '',
                'evidence': '',
                'error': str(e)
            }
        finally:
            # 임시 파일 삭제
            if temp_file_path and os.path.exists(temp_file_path):
                try:
                    os.unlink(temp_file_path)
                except Exception as e:
                    logger.warning(f"임시 파일 삭제 실패: {e}")


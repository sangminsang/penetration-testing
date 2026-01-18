"""
Llama AI 클라이언트

Ollama를 통해 Llama 모델과 통신합니다.
"""

import requests
import json
import logging
from typing import Dict, Any, Optional
from app.config import Config

logger = logging.getLogger(__name__)


class LlamaClient:
    """
    Llama AI 클라이언트 클래스
    
    Ollama API를 통해 Llama 모델과 통신합니다.
    """
    
    def __init__(self, base_url: str = None, model: str = None):
        """
        Llama 클라이언트 초기화
        
        Args:
            base_url: Ollama 서버 URL
            model: 사용할 모델 이름
        """
        self.base_url = base_url or Config.OLLAMA_BASE_URL
        self.model = model or Config.OLLAMA_MODEL
    
    def generate(self, prompt: str, stream: bool = False) -> Dict[str, Any]:
        """
        텍스트 생성
        
        Args:
            prompt: 프롬프트
            stream: 스트리밍 모드 사용 여부
        
        Returns:
            생성 결과
            {
                'response': '생성된 텍스트',
                'model': '사용된 모델',
                'done': True/False
            }
        """
        url = f"{self.base_url}/api/generate"
        
        payload = {
            'model': self.model,
            'prompt': prompt,
            'stream': stream
        }
        
        try:
            # 타임아웃 설정 (5분)
            response = requests.post(
                url,
                json=payload,
                timeout=1800  # 30분 타임아웃 (시스템 부하 및 네트워크 지연 대비)
            )
            response.raise_for_status()
            
            data = response.json()
            
            # 응답 크기 제한 (무한루프 방지)
            response_text = data.get('response', '')
            max_response_length = 50000  # 최대 50KB
            if len(response_text) > max_response_length:
                logger.warning(f"AI 응답이 너무 깁니다 ({len(response_text)}자). {max_response_length}자로 제한합니다.")
                response_text = response_text[:max_response_length]
            
            return {
                'response': response_text,
                'model': data.get('model', self.model),
                'done': data.get('done', True)
            }
        
        except requests.exceptions.Timeout:
            logger.error(f"Llama API 호출 타임아웃 (5분 초과)")
            return {
                'response': '[AI 호출 타임아웃] 응답 시간이 5분을 초과했습니다.',
                'model': self.model,
                'done': False,
                'error': 'timeout'
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"Llama API 호출 실패: {e}")
            return {
                'response': f'[AI 호출 실패] {str(e)}',
                'model': self.model,
                'done': False,
                'error': str(e)
            }
    
    def chat(self, messages: list, stream: bool = False) -> Dict[str, Any]:
        """
        채팅 모드로 대화
        
        Args:
            messages: 메시지 목록
                [
                    {'role': 'user', 'content': '...'},
                    {'role': 'assistant', 'content': '...'},
                    ...
                ]
            stream: 스트리밍 모드 사용 여부
        
        Returns:
            응답 결과
        """
        url = f"{self.base_url}/api/chat"
        
        payload = {
            'model': self.model,
            'messages': messages,
            'stream': stream
        }
        
        try:
            # 타임아웃 설정 (5분)
            response = requests.post(
                url,
                json=payload,
                timeout=1800  # 30분 타임아웃 (시스템 부하 및 네트워크 지연 대비)
            )
            response.raise_for_status()
            
            data = response.json()
            
            # 응답 크기 제한
            response_text = data.get('message', {}).get('content', '')
            max_response_length = 50000  # 최대 50KB
            if len(response_text) > max_response_length:
                logger.warning(f"AI 응답이 너무 깁니다 ({len(response_text)}자). {max_response_length}자로 제한합니다.")
                response_text = response_text[:max_response_length]
            
            return {
                'response': response_text,
                'model': data.get('model', self.model),
                'done': data.get('done', True)
            }
        
        except requests.exceptions.Timeout:
            logger.error(f"Llama Chat API 호출 타임아웃 (5분 초과)")
            return {
                'response': '[AI 호출 타임아웃] 응답 시간이 5분을 초과했습니다.',
                'model': self.model,
                'done': False,
                'error': 'timeout'
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"Llama Chat API 호출 실패: {e}")
            return {
                'response': f'[AI 호출 실패] {str(e)}',
                'model': self.model,
                'done': False,
                'error': str(e)
            }


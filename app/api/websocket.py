"""
WebSocket 핸들러

실시간으로 스캔 진행 상황을 클라이언트에 전송합니다.
"""

import json
import logging
import threading
from datetime import datetime
from threading import local
from flask_socketio import emit
from app import socketio

logger = logging.getLogger(__name__)

# Thread-local 스토리지 (재귀 호출 방지용)
_websocket_logging_context = local()


def register_socketio_handlers(socketio_instance):
    """
    WebSocket 이벤트 핸들러 등록
    
    Args:
        socketio_instance: SocketIO 인스턴스
    """
    
    @socketio_instance.on('connect')
    def handle_connect():
        """클라이언트 연결 시 호출"""
        logger.info('클라이언트가 연결되었습니다')
        emit('connected', {'message': '서버에 연결되었습니다'})
    
    @socketio_instance.on('disconnect')
    def handle_disconnect():
        """클라이언트 연결 해제 시 호출"""
        logger.info('클라이언트가 연결 해제되었습니다')
    
    @socketio_instance.on('subscribe_scan')
    def handle_subscribe_scan(data):
        """
        스캔 진행 상황 구독
        
        클라이언트가 특정 스캔의 진행 상황을 구독합니다.
        
        Args:
            data: {'scan_id': 123} 형식의 딕셔너리
        """
        scan_id = data.get('scan_id')
        logger.info(f'클라이언트가 스캔 {scan_id} 구독을 요청했습니다')
        emit('subscribed', {'scan_id': scan_id, 'message': '구독이 시작되었습니다'})


def emit_scan_progress(scan_id, progress_data, project_id=None):
    """
    스캔 진행 상황 브로드캐스트
    
    모든 구독자에게 스캔 진행 상황을 전송합니다.
    
    Args:
        scan_id: 스캔 ID
        progress_data: 진행 상황 데이터
            {
                'stage': 'nmap' | 'nuclei' | 'zap' | 'processing' | 'ai_analysis',
                'progress': 0-100,
                'message': '진행 상황 메시지',
                'data': {...}  # 선택적 추가 데이터
            }
        project_id: 프로젝트 ID (필터링용, 선택적)
    """
    emit_data = {
        'scan_id': scan_id,
        **progress_data
    }
    
    # project_id가 제공되면 포함
    if project_id is not None:
        emit_data['project_id'] = project_id
    
    socketio.emit('scan_progress', emit_data)


def emit_scan_complete(scan_id, results, project_id=None):
    """
    스캔 완료 알림 브로드캐스트
    
    Args:
        scan_id: 스캔 ID
        results: 스캔 결과 데이터
        project_id: 프로젝트 ID (필터링용, 선택적)
    """
    emit_data = {
        'scan_id': scan_id,
        'results': results
    }
    
    # project_id가 제공되면 포함
    if project_id is not None:
        emit_data['project_id'] = project_id
    
    socketio.emit('scan_complete', emit_data)


def emit_scan_error(scan_id, error_message, project_id=None):
    """
    스캔 오류 알림 브로드캐스트
    
    Args:
        scan_id: 스캔 ID
        error_message: 오류 메시지
        project_id: 프로젝트 ID (필터링용, 선택적)
    """
    emit_data = {
        'scan_id': scan_id,
        'error': error_message
    }
    
    # project_id가 제공되면 포함
    if project_id is not None:
        emit_data['project_id'] = project_id
    
    socketio.emit('scan_error', emit_data)


def emit_log_update(scan_id, log_line, project_id=None):
    """
    실시간 로그 업데이트 브로드캐스트
    
    docker logs -f와 유사하게 실행 중인 스캐너 컨테이너의 로그를 실시간으로 전송합니다.
    
    ⚠️ 안전장치:
    1. Thread-local 변수로 재귀 호출 방지
    2. 이 함수 내부에서는 절대 logger 사용 금지 (무한 루프 방지)
    
    Args:
        scan_id: 스캔 ID
        log_line: 로그 라인 (문자열)
        project_id: 프로젝트 ID (필터링용, 선택적)
    """
    # 안전장치: 재귀 호출 방지 (이미 핸들러가 실행 중이면 스킵)
    if hasattr(_websocket_logging_context, 'emitting'):
        return  # 무한 루프 방지
    
    try:
        # 플래그 설정 (이 스레드에서 emit 중임을 표시)
        _websocket_logging_context.emitting = True
        
        emit_data = {
            'scan_id': scan_id,
            'log': log_line,
            'timestamp': datetime.now().isoformat()
        }
        
        # project_id가 제공되면 포함
        if project_id is not None:
            emit_data['project_id'] = project_id
        
        # ⚠️ 여기서 logger.info() 등을 사용하면 무한 루프 발생!
        # 디버깅이 필요하면 print()를 사용하거나 로깅을 완전히 제거
        socketio.emit('log_update', emit_data)
    except Exception as e:
        # 예외 발생 시에도 logger 사용 금지! print()만 사용
        print(f"[WebSocket] 로그 전송 실패: {e}", flush=True)
    finally:
        # 플래그 해제
        if hasattr(_websocket_logging_context, 'emitting'):
            delattr(_websocket_logging_context, 'emitting')


class WebSocketLogHandler(logging.Handler):
    """
    WebSocket으로 로그를 실시간 전송하는 핸들러
    
    안전장치:
    1. Thread-local 변수로 재귀 호출 방지
    2. 특정 로거 이름 필터링 (websocket 모듈 자체 로그는 제외)
    3. emit_log_update 내부에서 로깅하지 않도록 보장
    """
    
    # 제외할 로거 이름 목록 (무한 루프 방지)
    EXCLUDED_LOGGERS = {
        'app.api.websocket',  # websocket 모듈 자체 로그는 제외
        'flask_socketio',     # SocketIO 내부 로그는 제외
    }
    
    def __init__(self, scan_id=None, project_id=None):
        super().__init__()
        self.scan_id = scan_id
        self.project_id = project_id
        self.setLevel(logging.INFO)  # INFO 레벨 이상만 전송
    
    def emit(self, record):
        """
        로그 레코드를 WebSocket으로 전송
        
        안전장치:
        1. 재귀 호출 방지 플래그 확인
        2. 제외된 로거 필터링
        3. scan_id가 없으면 스킵 (일반 로그는 전송 안 함)
        """
        # 안전장치 1: 재귀 호출 방지
        if hasattr(_websocket_logging_context, 'emitting'):
            return  # 이미 emit 중이면 스킵
        
        # 안전장치 2: 제외된 로거는 무시
        logger_name = record.name
        for excluded in self.EXCLUDED_LOGGERS:
            if logger_name.startswith(excluded):
                return  # 제외된 로거는 전송하지 않음
        
        # 안전장치 3: scan_id가 없으면 스킵 (일반 로그는 전송 안 함)
        if not self.scan_id:
            return
        
        try:
            # 로그 메시지 포맷팅
            log_message = self.format(record)
            
            # WebSocket으로 전송 (재귀 호출 방지 플래그는 emit_log_update 내부에서 처리)
            emit_log_update(self.scan_id, log_message, project_id=self.project_id)
        except Exception:
            # 핸들러 내부에서 예외가 발생해도 전체 로깅 시스템에 영향을 주지 않도록
            self.handleError(record)
    
    def filter(self, record):
        """
        추가 필터링: 특정 조건의 로그는 제외
        """
        # 부모 클래스의 필터 먼저 확인
        if not super().filter(record):
            return False
        
        # 제외된 로거는 필터링
        logger_name = record.name
        for excluded in self.EXCLUDED_LOGGERS:
            if logger_name.startswith(excluded):
                return False
        
        return True


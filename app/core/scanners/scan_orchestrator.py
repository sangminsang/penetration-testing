"""
스캔 오케스트레이터

3개의 도커 컨테이너에서 병렬로 스캔을 실행하고 결과를 통합합니다.
"""

import logging
import docker
import json
import time
import threading
import requests
import os
import platform
import sys
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
from app.config import Config
from app.api.websocket import emit_scan_progress, emit_scan_complete, emit_scan_error, emit_log_update, WebSocketLogHandler
from app.models import ScanResult
from app import db
from app.core.processors.ai_poc_generator import AIPoCGenerator

logger = logging.getLogger(__name__)


def _make_cve_search_request(url: str, timeout: int = 1800, max_retries: int = 3) -> Optional[requests.Response]:
    """
    CVE-Search API 요청 (프록시 비활성화 및 재시도 로직 포함)
    
    Args:
        url: API URL
        timeout: 타임아웃 (초)
        max_retries: 최대 재시도 횟수
    
    Returns:
        Response 객체 또는 None
    """
    proxies = {"http": None, "https": None}  # 프록시 비활성화
    for attempt in range(max_retries):
        try:
            response = requests.get(url, timeout=timeout, proxies=proxies)
            return response
        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
                wait_time = (attempt + 1) * 2  # 지수 백오프: 2초, 4초, 6초
                logger.warning(f"CVE-Search API 재시도 ({attempt + 1}/{max_retries}): {e}, {wait_time}초 후 재시도")
                time.sleep(wait_time)
            else:
                logger.error(f"CVE-Search API 최종 실패 ({max_retries}회 시도): {e}")
                return None
    return None


class ScanOrchestrator:
    """
    스캔 오케스트레이터 클래스
    
    Nmap, Nuclei, ZAP 스캔을 도커 컨테이너에서 병렬로 실행하고,
    결과를 통합하여 다음 단계로 전달합니다.
    """
    
    def __init__(self):
        """오케스트레이터 초기화"""
        try:
            print(f"\n[ORCHESTRATOR DEBUG] Docker 클라이언트 초기화 시도 중...", flush=True)
            self.docker_client = docker.from_env()
            
            # Docker 데몬 연결 상태 검증
            try:
                self.docker_client.ping()
                print(f"[ORCHESTRATOR DEBUG] ✅ Docker 데몬 연결 성공 (ping OK)", flush=True)
                logger.info("Docker 클라이언트 초기화 완료 (ping 검증 성공)")
            except Exception as ping_error:
                print(f"[ORCHESTRATOR DEBUG] ⚠️ Docker 데몬 ping 실패: {ping_error}", flush=True)
                logger.warning(f"Docker 클라이언트 초기화 완료했으나 ping 실패: {ping_error}")
        except Exception as e:
            print(f"\n[ORCHESTRATOR DEBUG] ❌ Docker 클라이언트 초기화 실패: {str(e)}", flush=True)
            logger.error(f"Docker 클라이언트 초기화 실패: {e}", exc_info=True)
            self.docker_client = None
        
        # WebSocket 로깅 핸들러 관리 (스캔별 핸들러 추적)
        self._active_handlers = {}  # scan_id -> handler 매핑
        
        # CWE 메타데이터 캐시 로드
        self.cwe_metadata_cache = self._load_cwe_metadata()
    
    def _setup_websocket_logging(self, scan_id, project_id):
        """
        스캔별 WebSocket 로깅 핸들러 설정
        
        안전장치: 한 스캔당 하나의 핸들러만 생성
        
        Args:
            scan_id: 스캔 ID
            project_id: 프로젝트 ID
        """
        # 이미 핸들러가 있으면 재사용
        if scan_id in self._active_handlers:
            return
        
        try:
            # 루트 로거에 핸들러 추가
            handler = WebSocketLogHandler(scan_id=scan_id, project_id=project_id)
            handler.setFormatter(logging.Formatter(
                '%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            ))
            
            # 루트 로거에 추가 (모든 로거의 로그를 캡처)
            root_logger = logging.getLogger()
            root_logger.addHandler(handler)
            
            self._active_handlers[scan_id] = handler
            logger.info(f"WebSocket 로깅 핸들러 설정 완료: scan_id={scan_id}")
        except Exception as e:
            logger.warning(f"WebSocket 로깅 핸들러 설정 실패: {e}")
    
    def _cleanup_websocket_logging(self, scan_id):
        """
        스캔 완료 후 핸들러 제거
        
        Args:
            scan_id: 스캔 ID
        """
        if scan_id in self._active_handlers:
            try:
                handler = self._active_handlers[scan_id]
                root_logger = logging.getLogger()
                root_logger.removeHandler(handler)
                del self._active_handlers[scan_id]
                logger.info(f"WebSocket 로깅 핸들러 제거 완료: scan_id={scan_id}")
            except Exception as e:
                logger.warning(f"WebSocket 로깅 핸들러 제거 실패: {e}")
    
    def _load_cwe_metadata(self) -> Dict[str, Any]:
        """CWE 메타데이터 JSON 파일 로드"""
        try:
            cwe_file = Path(Config.CWE_METADATA_PATH)
            if cwe_file.exists():
                with open(cwe_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    logger.info(f"✅ CWE 메타데이터 로드 완료: {len(data)}개")
                    return data
            else:
                logger.warning(f"⚠️ CWE 메타데이터 파일 없음: {cwe_file}")
        except Exception as e:
            logger.error(f"❌ CWE 메타데이터 로드 실패: {e}")
        return {}
    
    def _should_verify_with_poc(self, vuln: Dict[str, Any]) -> bool:
        """
        PoC 검증이 필요한 취약점인지 판단
        
        기준:
        1. Source: ZAP만 (Nuclei는 제외)
        2. Severity: High 또는 Critical
        3. Confidence: False Positive, Low, Medium (High/Confirmed는 제외)
        
        Args:
            vuln: 취약점 정보 딕셔너리
        
        Returns:
            PoC 검증 필요 여부 (True/False)
        """
        # 1. Source 체크 (ZAP만 검증 대상)
        source = vuln.get('source', '').lower()
        if source != 'zap':
            # Nuclei는 confidence 정보가 없어 PoC 검증에서 제외
            # (Nuclei 결과는 템플릿 기반 검증으로 이미 신뢰할 수 있음)
            return False
        
        # 2. Severity 체크 (High/Critical만)
        severity = vuln.get('severity', '').lower()
        if severity not in ['high', 'critical']:
            return False
        
        # 3. Confidence 체크 (ZAP만 해당)
        confidence = vuln.get('confidence')
        
        # Confidence가 None이면 제외 (ZAP은 일반적으로 confidence 정보가 있음)
        if not confidence or confidence is None:
            return False
        
        # Confidence 문자열 변환
        confidence_str = str(confidence).lower()
        
        # Low confidence 키워드 (False Positive도 Low로 간주)
        low_confidence_keywords = ['false positive', 'low']
        # Medium confidence 키워드
        medium_confidence_keywords = ['medium']
        
        # Low/Medium confidence이면 검증 대상
        if any(keyword in confidence_str for keyword in low_confidence_keywords + medium_confidence_keywords):
            return True
        
        # High, Confirmed인 경우는 ZAP 결과 신뢰 → 검증 불필요
        return False
    
    def start_full_scan(self, target_url: str, scan_id: int, enable_poc_verification: bool = True):
        """
        전체 스캔 시작 (비동기)
        
        Args:
            target_url: 타겟 URL
            scan_id: 스캔 결과 ID
            enable_poc_verification: PoC 검증 활성화 여부 (기본값: True)
        """
        import threading
        
        print(f"\n[ORCHESTRATOR DEBUG] ========== start_full_scan 호출됨 ==========", flush=True)
        print(f"[ORCHESTRATOR DEBUG] target_url: {target_url}, scan_id: {scan_id}", flush=True)
        print(f"[ORCHESTRATOR DEBUG] enable_poc_verification: {enable_poc_verification}", flush=True)
        print(f"[ORCHESTRATOR DEBUG] Docker 클라이언트 상태: {self.docker_client is not None}", flush=True)
        
        # 별도 스레드에서 실행 (Flask가 블로킹되지 않도록)
        thread = threading.Thread(
            target=self._run_full_scan,
            args=(target_url, scan_id, enable_poc_verification),
            daemon=True
        )
        print(f"[ORCHESTRATOR DEBUG] 백그라운드 스레드 생성 완료, 시작 중...", flush=True)
        thread.start()
        print(f"[ORCHESTRATOR DEBUG] 백그라운드 스레드 시작됨 (Thread ID: {thread.ident})", flush=True)
        
        logger.info(f"스캔 시작: {target_url} (Scan ID: {scan_id}, Thread ID: {thread.ident})")
        sys.stdout.flush()
    
    def _run_full_scan(self, target_url: str, scan_id: int, enable_poc_verification: bool = True):
        """
        전체 스캔 실행 (내부 메서드)
        
        워크플로우:
        1. Nmap, Nuclei, ZAP 스캔을 도커 컨테이너에서 병렬 실행
        2. 각 스캔 결과를 파일로 저장
        3. 결과 통합 및 다음 단계로 전달
        
        주의: 이 함수는 별도 스레드에서 실행되므로 Flask application context가 필요합니다.
        
        Args:
            target_url: 타겟 URL
            scan_id: 스캔 결과 ID
            enable_poc_verification: PoC 검증 활성화 여부 (기본값: True)
        """
        print(f"\n[ORCHESTRATOR DEBUG] ========== Scan {scan_id} Thread Started! ==========", flush=True)
        print(f"[ORCHESTRATOR DEBUG] Target URL: {target_url}", flush=True)
        print(f"[ORCHESTRATOR DEBUG] enable_poc_verification: {enable_poc_verification}", flush=True)
        print(f"[ORCHESTRATOR DEBUG] Thread ID: {threading.current_thread().ident}", flush=True)
        print(f"[ORCHESTRATOR DEBUG] Docker Client Available: {self.docker_client is not None}", flush=True)
        
        # Docker 클라이언트 상태 재검증
        if self.docker_client is None:
            print(f"[ORCHESTRATOR DEBUG] ❌ Docker 클라이언트가 None입니다. 초기화 시도...", flush=True)
            try:
                self.docker_client = docker.from_env()
                self.docker_client.ping()
                print(f"[ORCHESTRATOR DEBUG] ✅ Docker 클라이언트 재초기화 성공", flush=True)
            except Exception as e:
                print(f"[ORCHESTRATOR DEBUG] ❌ Docker 클라이언트 재초기화 실패: {str(e)}", flush=True)
                logger.error(f"Docker 클라이언트 재초기화 실패: {e}", exc_info=True)
                # project_id 가져오기 시도
                project_id = None
                try:
                    scan_result = ScanResult.query.get(scan_id)
                    if scan_result:
                        project_id = scan_result.project_id
                except Exception:
                    pass
                
                emit_scan_error(scan_id, f"Docker 클라이언트 초기화 실패: {e}", project_id=project_id)
                return
        
        # Flask application context 생성 (스레드에서 DB 접근을 위해 필수)
        try:
            print(f"[ORCHESTRATOR DEBUG] Flask application context 생성 중...", flush=True)
            from app import create_app
            app, _ = create_app()
            print(f"[ORCHESTRATOR DEBUG] ✅ Flask application context 생성 완료", flush=True)
            
            with app.app_context():
                print(f"[ORCHESTRATOR DEBUG] Flask app_context 진입, _run_full_scan_internal 호출 시작", flush=True)
                self._run_full_scan_internal(target_url, scan_id, enable_poc_verification=enable_poc_verification)
                print(f"[ORCHESTRATOR DEBUG] _run_full_scan_internal 완료", flush=True)
        except Exception as e:
            print(f"\n[ORCHESTRATOR DEBUG] ❌ _run_full_scan에서 예외 발생: {str(e)}", flush=True)
            logger.error(f"_run_full_scan 예외: {e}", exc_info=True)
            # project_id 가져오기 시도
            project_id = None
            try:
                scan_result = ScanResult.query.get(scan_id)
                if scan_result:
                    project_id = scan_result.project_id
            except Exception:
                pass
            
            emit_scan_error(scan_id, f"스캔 스레드 실행 실패: {e}", project_id=project_id)
    
    def _run_full_scan_internal(self, target_url: str, scan_id: int, enable_poc_verification: bool = True):
        """
        전체 스캔 실행 (내부 구현, Flask context 내부에서 실행됨)
        
        Args:
            target_url: 타겟 URL
            scan_id: 스캔 결과 ID
            enable_poc_verification: PoC 검증 활성화 여부 (기본값: True)
        """
        print(f"\n[ORCHESTRATOR DEBUG] _run_full_scan_internal 시작: target={target_url}, scan_id={scan_id}, enable_poc_verification={enable_poc_verification}", flush=True)
        
        # 프로젝트 ID 가져오기 (진행 상황 전송 시 필터링용)
        project_id = None
        try:
            scan_result = ScanResult.query.get(scan_id)
            if scan_result:
                project_id = scan_result.project_id
                logger.info(f"스캔 {scan_id}의 프로젝트 ID: {project_id}")
        except Exception as e:
            logger.warning(f"프로젝트 ID 조회 실패: {e}")
        
        # WebSocket 로깅 핸들러 설정 (Python 로그를 실시간으로 전송)
        try:
            self._setup_websocket_logging(scan_id, project_id)
        except Exception as e:
            logger.warning(f"WebSocket 로깅 핸들러 설정 실패 (계속 진행): {e}")
        
        # 전체 스캔 타임아웃 설정 (2시간) - ZAP 정밀 스캔, Llama 3.1 8B 추론, POC 검증 시간 확보
        overall_timeout = 7200  # 2시간 (7200초) - GNS 서버 등 긴 응답 시간 대비
        start_time = time.time()
        
        def check_timeout(stage_name: str):
            """타임아웃 체크"""
            elapsed = time.time() - start_time
            if elapsed > overall_timeout:
                raise TimeoutError(f"{stage_name} 단계에서 전체 타임아웃 발생 ({elapsed:.1f}초 초과, 제한: {overall_timeout}초)")
            return elapsed
        
        try:
            print(f"[ORCHESTRATOR DEBUG] 전체 스캔 시작: {target_url} (Scan ID: {scan_id})", flush=True)
            logger.info(f"전체 스캔 시작: {target_url} (Scan ID: {scan_id})")
            sys.stdout.flush()
            
            # Storage & Path Management: outputs/{target}_{timestamp}/ 구조 생성
            from urllib.parse import urlparse
            parsed = urlparse(target_url)
            target_host = parsed.hostname or parsed.netloc.split(':')[0]
            safe_target = target_host.replace('.', '_').replace(':', '_')
            timestamp = int(time.time())
            scan_output_dir = Path(Config.SCAN_RESULTS_DIR) / "outputs" / f"{safe_target}_{timestamp}"
            scan_output_dir.mkdir(parents=True, exist_ok=True)
            
            logger.info(f"스캔 결과 저장 디렉토리: {scan_output_dir}")
            print(f"[ORCHESTRATOR DEBUG] 스캔 결과 저장 디렉토리: {scan_output_dir}", flush=True)
            sys.stdout.flush()
            
            # 진행 상황 업데이트
            emit_scan_progress(scan_id, {
                'stage': 'starting',
                'progress': 0,
                'message': '스캔 준비 중...'
            }, project_id=project_id)
            
            # Step 1: 도커 컨테이너에서 병렬 스캔 실행
            print(f"[ORCHESTRATOR DEBUG] Step 1: 도커 컨테이너 스캔 실행 시작", flush=True)
            emit_scan_progress(scan_id, {
                'stage': 'scanning',
                'progress': 10,
                'message': '도커 컨테이너에서 스캔 시작 중...'
            }, project_id=project_id)
            sys.stdout.flush()
            
            check_timeout("스캔 시작")
            print(f"[ORCHESTRATOR DEBUG] _run_docker_scans 호출 직전...", flush=True)
            scan_results = self._run_docker_scans(target_url, scan_id, scan_output_dir)
            print(f"[ORCHESTRATOR DEBUG] _run_docker_scans 완료, 결과 키: {list(scan_results.keys())}", flush=True)
            sys.stdout.flush()
            
            # Step 2: 결과 파일 경로 찾기 (스캔 결과 디렉토리에서 최신 파일 찾기)
            # 파일이 생성될 때까지 대기 (최대 5분)
            emit_scan_progress(scan_id, {
                'stage': 'waiting_files',
                'progress': 65,
                'message': '스캔 결과 파일 대기 중...'
            }, project_id=project_id)
            
            # scan_output_dir 내에서 결과 파일 찾기
            nmap_file = self._wait_for_result_file(scan_output_dir, 'nmap', target_url, scan_id, timeout=300, project_id=project_id)
            nuclei_file = self._wait_for_result_file(scan_output_dir, 'nuclei', target_url, scan_id, timeout=300, project_id=project_id)
            zap_file = self._wait_for_result_file(scan_output_dir, 'zap', target_url, scan_id, timeout=600, project_id=project_id)
            
            check_timeout("결과 파일 대기")
            
            # Step 3: 결과 파일 통합 (타임아웃: 2분)
            emit_scan_progress(scan_id, {
                'stage': 'processing',
                'progress': 70,
                'message': '스캔 결과 통합 중...'
            }, project_id=project_id)
            
            check_timeout("결과 통합")
            from app.core.processors.data_aggregator import DataAggregator
            aggregator = DataAggregator(scan_results_dir=str(scan_output_dir))
            
            # 결과 통합 실행 (타임아웃: 2분)
            # 부분 결과 처리: 하나라도 성공하면 통합 리포트 생성
            step_start_time = time.time()
            
            # 생성된 파일 확인 및 로깅
            available_files = []
            if nmap_file and nmap_file.exists():
                available_files.append(f"Nmap: {nmap_file}")
            if nuclei_file and nuclei_file.exists():
                available_files.append(f"Nuclei: {nuclei_file}")
            if zap_file and zap_file.exists():
                available_files.append(f"ZAP: {zap_file}")
            
            if available_files:
                logger.info(f"✅ 부분 결과로 통합 리포트 생성: {len(available_files)}/{3}개 스캔 성공")
                for file_info in available_files:
                    logger.info(f"   - {file_info}")
            else:
                logger.warning(f"⚠️ 사용 가능한 스캔 결과 파일이 없습니다. 빈 리포트를 생성합니다.")
            
            aggregated_data = aggregator.aggregate_scan_results(
                nmap_file=str(nmap_file) if nmap_file and nmap_file.exists() else None,
                nuclei_file=str(nuclei_file) if nuclei_file and nuclei_file.exists() else None,
                zap_file=str(zap_file) if zap_file and zap_file.exists() else None
            )
            
            # 통합 리포트를 scan_output_dir에 저장 (부분 결과라도 저장)
            integrated_report_file = None
            try:
                integrated_report_file = scan_output_dir / "final_integrated_report.json"
                with open(integrated_report_file, 'w', encoding='utf-8') as f:
                    json.dump(aggregated_data, f, ensure_ascii=False, indent=2)
                
                # 부분 결과 여부 표시
                sources = aggregated_data.get('summary', {}).get('sources', {})
                successful_scans = sum([sources.get('nmap', False), sources.get('nuclei', False), sources.get('zap', False)])
                logger.info(f"✅ 통합 리포트 저장 완료: {integrated_report_file} (성공: {successful_scans}/3)")
                
            except Exception as e:
                logger.error(f"❌ 통합 리포트 저장 실패: {e}", exc_info=True)
                # 저장 실패해도 계속 진행 (다음 단계에서 재시도 가능)
            step_elapsed = time.time() - step_start_time
            if step_elapsed > 120:
                logger.warning(f"결과 통합 시간이 길었습니다 ({step_elapsed:.1f}초)")
            
            # Step 1-1: 취약점 PoC 검증 (스캔 완료 직후, 필요한 것만)
            # 제안된 워크플로우: PoC 검증을 스캔 직후에 수행하여 False Positive 확인
            if enable_poc_verification:
                try:
                    emit_scan_progress(scan_id, {
                        'stage': 'poc_verification',
                        'progress': 72,
                        'message': '취약점 PoC 검증 중 (ZAP Low/Medium Confidence 취약점만)...'
                    }, project_id=project_id)
                    
                    check_timeout("PoC 검증")
                    step_start_time = time.time()
                    
                    # PoC 생성기 초기화
                    poc_generator = AIPoCGenerator(
                        base_url=Config.OLLAMA_BASE_URL,
                        model=Config.OLLAMA_MODEL
                    )
                    
                    # 취약점 리스트 확인
                    vulnerabilities = aggregated_data.get('vulnerabilities', [])
                    if not vulnerabilities:
                        logger.info("⏭️ [PoC 검증] 검증할 취약점이 없습니다.")
                        print(f"[PoC 검증] ⏭️ 검증할 취약점이 없습니다.", flush=True)
                    else:
                        # Confidence 기반 필터링 (ZAP의 High/Critical + Low/Medium Confidence만)
                        poc_verification_targets = [
                            vuln for vuln in vulnerabilities 
                            if self._should_verify_with_poc(vuln)
                        ]
                        
                        if not poc_verification_targets:
                            logger.info("⏭️ [PoC 검증] PoC 검증 대상 취약점이 없습니다. (High Confidence ZAP 취약점은 결과 신뢰, Nuclei는 제외)")
                            print(f"[PoC 검증] ⏭️ PoC 검증 대상 취약점이 없습니다.", flush=True)
                        else:
                            logger.info(f"🔄 [PoC 검증] {len(poc_verification_targets)}개 ZAP Low/Medium Confidence 취약점에 대해 PoC 검증 시작")
                            print(f"[PoC 검증] 🔄 {len(poc_verification_targets)}개 ZAP 취약점 PoC 검증 시작", flush=True)
                            
                            verified_count = 0
                            failed_count = 0
                            manual_verification_count = 0
                            
                            for idx, vuln in enumerate(poc_verification_targets, 1):
                                try:
                                    vuln_name = vuln.get('name', 'Unknown')
                                    vuln_url = vuln.get('url', 'N/A')
                                    vuln_severity = vuln.get('severity', 'unknown')
                                    vuln_confidence = vuln.get('confidence', 'N/A')
                                    
                                    logger.info(f"🔄 [PoC 검증 {idx}/{len(poc_verification_targets)}] 검증 중: {vuln_name} ({vuln_severity}, Confidence: {vuln_confidence}) - {vuln_url}")
                                    print(f"[PoC 검증 {idx}/{len(poc_verification_targets)}] 🔄 검증 중: {vuln_name} ({vuln_severity})", flush=True)
                                    
                                    # PoC 생성 및 실행
                                    poc_result = poc_generator.generate_and_execute_poc(vuln)
                                    
                                    # 결과를 취약점 딕셔너리에 즉시 업데이트 (aggregated_data에 반영)
                                    if poc_result.get('poc_code'):
                                        vuln['poc_code'] = poc_result.get('poc_code')
                                    if poc_result.get('execution_result'):
                                        vuln['execution_result'] = poc_result.get('execution_result')
                                    
                                    # 상태별 카운트
                                    status = poc_result.get('status', 'failed')
                                    if status == 'success':
                                        verified_count += 1
                                        logger.info(f"✅ [PoC 검증 {idx}/{len(poc_verification_targets)}] 검증 성공: {vuln_name}")
                                        print(f"[PoC 검증 {idx}/{len(poc_verification_targets)}] ✅ 검증 성공: {vuln_name}", flush=True)
                                    elif status == 'manual_verification_needed':
                                        manual_verification_count += 1
                                        logger.info(f"⚠️ [PoC 검증 {idx}/{len(poc_verification_targets)}] 수동 검증 필요: {vuln_name}")
                                        print(f"[PoC 검증 {idx}/{len(poc_verification_targets)}] ⚠️ 수동 검증 필요: {vuln_name}", flush=True)
                                    else:
                                        failed_count += 1
                                        logger.warning(f"❌ [PoC 검증 {idx}/{len(poc_verification_targets)}] 검증 실패: {vuln_name}")
                                        print(f"[PoC 검증 {idx}/{len(poc_verification_targets)}] ❌ 검증 실패: {vuln_name}", flush=True)
                                    
                                except Exception as vuln_error:
                                    failed_count += 1
                                    logger.error(f"❌ [PoC 검증 {idx}/{len(poc_verification_targets)}] PoC 검증 중 오류: {vuln_error}", exc_info=True)
                                    print(f"[PoC 검증 {idx}/{len(poc_verification_targets)}] ❌ 오류 발생: {str(vuln_error)[:100]}", flush=True)
                                    # 개별 취약점 검증 실패해도 계속 진행
                                    continue
                            
                            # 최종 결과 로그
                            logger.info(f"✅ [PoC 검증] 검증 완료: 성공={verified_count}, 실패={failed_count}, 수동검증필요={manual_verification_count}")
                            print(f"[PoC 검증] ✅ 검증 완료: 성공={verified_count}, 실패={failed_count}, 수동검증필요={manual_verification_count}", flush=True)
                            
                            # PoC 검증 결과를 통합 리포트에 즉시 반영 (파일 재저장)
                            if integrated_report_file and integrated_report_file.exists():
                                try:
                                    with open(integrated_report_file, 'w', encoding='utf-8') as f:
                                        json.dump(aggregated_data, f, ensure_ascii=False, indent=2)
                                    logger.info(f"✅ [PoC 검증] PoC 검증 결과 반영 후 통합 리포트 재저장 완료: {integrated_report_file}")
                                except Exception as save_error:
                                    logger.error(f"❌ [PoC 검증] 통합 리포트 재저장 실패: {save_error}", exc_info=True)
                    
                    step_elapsed = time.time() - step_start_time
                    if step_elapsed > 300:
                        logger.warning(f"[PoC 검증] PoC 검증 시간이 길었습니다 ({step_elapsed:.1f}초)")
                    
                except requests.exceptions.ConnectionError as e:
                    logger.warning(f"Ollama 서버 연결 실패 (PoC 검증 스킵): {e}")
                    logger.info("Ollama 서버가 실행 중이지 않습니다. PoC 검증을 건너뜁니다.")
                    print(f"[PoC 검증] ⚠️ Ollama 서버 연결 실패, PoC 검증을 건너뜁니다.", flush=True)
                except requests.exceptions.Timeout as e:
                    logger.warning(f"PoC 검증 타임아웃 (선택적 단계): {e}")
                    print(f"[PoC 검증] ⚠️ 타임아웃 발생, PoC 검증을 건너뜁니다.", flush=True)
                except Exception as e:
                    logger.warning(f"PoC 검증 실패 (선택적 단계): {e}", exc_info=True)
                    print(f"[PoC 검증] ⚠️ 오류 발생, PoC 검증을 건너뜁니다: {str(e)[:100]}", flush=True)
                    # PoC 검증 실패해도 스캔 프로세스는 계속 진행
            else:
                logger.info("⏭️ [PoC 검증] PoC 검증이 비활성화되어 있습니다. (enable_poc_verification=false)")
                print(f"[PoC 검증] ⏭️ PoC 검증 비활성화", flush=True)
            
            # Step 4: CPE 파싱 및 NVD 매핑 (타임아웃: 10분)
            emit_scan_progress(scan_id, {
                'stage': 'nvd_mapping',
                'progress': 85,
                'message': 'NVD 데이터베이스와 매핑 중...'
            }, project_id=project_id)
            
            check_timeout("NVD 매핑")
            from app.core.processors.nvd_mapper import NVDMapper
            nvd_mapper = NVDMapper()
            
            # NVD 매핑 실행 (타임아웃: 10분)
            step_start_time = time.time()
            final_results = nvd_mapper.map_scan_results_to_cves(aggregated_data)
            step_elapsed = time.time() - step_start_time
            if step_elapsed > 600:
                logger.warning(f"NVD 매핑 시간이 길었습니다 ({step_elapsed:.1f}초)")
            
            # Step 4.5: CVE-Search API를 통한 NVD 상세 데이터 수집 및 병합
            emit_scan_progress(scan_id, {
                'stage': 'cve_enrichment',
                'progress': 87,
                'message': 'CVE-Search API에서 NVD 상세 데이터 수집 중...'
            }, project_id=project_id)
            
            check_timeout("CVE 상세 데이터 수집")
            step_start_time = time.time()
            aggregated_data = self._enrich_vulnerabilities_with_nvd_data(aggregated_data, scan_id=scan_id, project_id=project_id)
            step_elapsed = time.time() - step_start_time
            
            # Step 4.6: CPE 기반 CVE 역추적 (Infrastructure 버전 정보 활용)
            emit_scan_progress(scan_id, {
                'stage': 'cpe_enrichment',
                'progress': 88,
                'message': 'CPE 기반 CVE 역추적 중...'
            }, project_id=project_id)
            
            check_timeout("CPE 기반 CVE 역추적")
            step_start_time = time.time()
            aggregated_data = self._enrich_infrastructure_with_cpe_based_cves(aggregated_data)
            step_elapsed = time.time() - step_start_time
            
            # Step 4.7: CWE 기반 지식 데이터 보강
            emit_scan_progress(scan_id, {
                'stage': 'cwe_enrichment',
                'progress': 89,
                'message': 'CWE 지식 데이터 보강 중...'
            }, project_id=project_id)
            
            check_timeout("CWE 데이터 보강")
            step_start_time = time.time()
            aggregated_data = self._enrich_cwe_metadata(aggregated_data)
            step_elapsed = time.time() - step_start_time
            
            # CWE 병합 완료 알림
            try:
                emit_scan_progress(scan_id, {
                    'stage': 'cwe_enrichment_complete',
                    'progress': 85,
                    'message': 'CWE 지식 데이터 보강 완료'
                }, project_id=project_id)
            except Exception as e:
                logger.error(f"CWE 병합 완료 알림 전송 실패: {e}", exc_info=True)
            
            # NVD 데이터가 병합된 통합 리포트 다시 저장
            if integrated_report_file:
                try:
                    with open(integrated_report_file, 'w', encoding='utf-8') as f:
                        json.dump(aggregated_data, f, ensure_ascii=False, indent=2)
                    logger.info(f"✅ NVD 데이터 병합 후 통합 리포트 재저장 완료: {integrated_report_file}")
                except Exception as e:
                    logger.error(f"❌ 통합 리포트 재저장 실패: {e}", exc_info=True)
            
            if step_elapsed > 300:
                logger.warning(f"CVE 상세 데이터 수집 시간이 길었습니다 ({step_elapsed:.1f}초)")
            
            # Step 5: AI 공격 시나리오 생성 (타임아웃: 5분)
            try:
                emit_scan_progress(scan_id, {
                    'stage': 'ai_analysis',
                    'progress': 90,
                    'message': 'AI 분석 중 (약 1~2분 소요)...'
                }, project_id=project_id)
            except Exception as e:
                logger.error(f"AI 분석 시작 알림 전송 실패: {e}", exc_info=True)
            
            check_timeout("AI 분석")
            from app.core.processors.data_aggregator import DataAggregator
            refined_data = aggregator.refine_for_ai(aggregated_data)
            
            from app.core.ai.scenario_generator import ScenarioGenerator
            scenario_generator = ScenarioGenerator()
            
            # AI 분석 실행 (타임아웃: 5분, LlamaClient 내부에서 처리)
            step_start_time = time.time()
            ai_scenario = scenario_generator.generate_attack_scenario(
                refined_data,
                final_results.get('cpe_mapping', {})
            )
            step_elapsed = time.time() - step_start_time
            if step_elapsed > 300:
                logger.warning(f"AI 분석 시간이 길었습니다 ({step_elapsed:.1f}초)")
            
            # ✅ AI 시나리오 에러 체크 및 사용자 알림
            if isinstance(ai_scenario, dict) and ai_scenario.get('error'):
                error_msg = ai_scenario.get('error')
                logger.error(f"AI 시나리오 생성 에러: {error_msg}")
                emit_scan_progress(scan_id, {
                    'stage': 'ai_analysis',
                    'progress': 85,
                    'message': f'⚠️ AI 분석 실패: {error_msg}',
                    'warning': error_msg
                }, project_id=project_id)
            
            # [DEBUG] 공격 시나리오 생성 결과 디버깅
            logger.debug(f"공격 시나리오 생성 결과:")
            logger.debug(f"- ai_scenario 타입: {type(ai_scenario)}")
            logger.debug(f"- ai_scenario is None: {ai_scenario is None}")
            if ai_scenario:
                logger.debug(f"- ai_scenario 키: {list(ai_scenario.keys()) if isinstance(ai_scenario, dict) else 'N/A'}")
                selected_chains = ai_scenario.get('selected_chains', []) if isinstance(ai_scenario, dict) else []
                logger.debug(f"- selected_chains 개수: {len(selected_chains)}")
                if selected_chains:
                    logger.debug(f"- 첫 번째 체인 구조: {list(selected_chains[0].keys()) if isinstance(selected_chains[0], dict) else 'N/A'}")
                    if isinstance(selected_chains[0], dict):
                        steps = selected_chains[0].get('steps', [])
                        logger.debug(f"- 첫 번째 체인의 steps 개수: {len(steps)}")
                else:
                    logger.warning(f"⚠️ selected_chains가 비어있습니다!")
                    if isinstance(ai_scenario, dict) and 'error' in ai_scenario:
                        logger.warning(f"- 에러 메시지: {ai_scenario.get('error')}")
            
            # [DEBUG] 공격 시나리오를 파일로 저장
            try:
                debug_scenario_file = scan_output_dir / "debug_ai_scenario.json"
                with open(debug_scenario_file, 'w', encoding='utf-8') as f:
                    json.dump(ai_scenario, f, ensure_ascii=False, indent=2)
                logger.debug(f"✅ 공격 시나리오 디버깅 파일 저장: {debug_scenario_file}")
            except Exception as debug_error:
                logger.error(f"❌ 공격 시나리오 디버깅 파일 저장 실패: {debug_error}", exc_info=True)
            
            # Step 6: 공격 실행 (선택적, 타임아웃: 5분)
            attack_results = None
            
            # ✅ 공격 실행 전 ai_scenario 검증 및 사용자 알림
            if ai_scenario is None:
                error_msg = "AI 시나리오 생성 실패 (타입: None)"
                logger.error(error_msg)
                emit_scan_progress(scan_id, {
                    'stage': 'attack_execution',
                    'progress': 80,
                    'message': '⚠️ AI 시나리오 생성 실패로 공격 실행을 건너뜁니다.',
                    'warning': error_msg
                }, project_id=project_id)
                # ✅ 공격 결과에 에러 기록
                attack_results = {
                    'success': False,
                    'error': error_msg,
                    'results': [],
                    'loot': {'files': [], 'data': {}}
                }
            elif not isinstance(ai_scenario, dict):
                error_msg = f"AI 시나리오 생성 실패 (타입: {type(ai_scenario)})"
                logger.error(error_msg)
                emit_scan_progress(scan_id, {
                    'stage': 'attack_execution',
                    'progress': 80,
                    'message': '⚠️ AI 시나리오 생성 실패로 공격 실행을 건너뜁니다.',
                    'warning': error_msg
                }, project_id=project_id)
                # ✅ 공격 결과에 에러 기록
                attack_results = {
                    'success': False,
                    'error': error_msg,
                    'results': [],
                    'loot': {'files': [], 'data': {}}
                }
            else:
                selected_chains = ai_scenario.get('selected_chains', [])
                if not selected_chains:
                    logger.warning(f"⚠️ selected_chains가 비어있습니다. 공격 실행은 진행하지만 단계가 없을 수 있습니다.")
                    print(f"[DEBUG] ⚠️ selected_chains가 비어있습니다.", flush=True)
                else:
                    logger.info(f"✅ 공격 실행 준비 완료: {len(selected_chains)}개 체인, 총 {sum(len(c.get('steps', [])) for c in selected_chains)}개 단계")
                    print(f"[DEBUG] ✅ 공격 실행 준비 완료: {len(selected_chains)}개 체인", flush=True)
            
            try:
                check_timeout("공격 실행")
                from app.core.ai.attack_executor import AttackExecutor
                attack_executor = AttackExecutor()
                
                # 공격 실행 (타임아웃: 5분)
                step_start_time = time.time()
                logger.debug("공격 실행 시작...")
                print("[DEBUG] 공격 실행 시작...", flush=True)
                attack_results = attack_executor.execute_attack_scenario(
                    ai_scenario,
                    target_url
                )
                step_elapsed = time.time() - step_start_time
                
                # [DEBUG] 공격 실행 결과 디버깅
                if attack_results:
                    logger.debug(f"공격 실행 결과:")
                    logger.debug(f"- success: {attack_results.get('success')}")
                    logger.debug(f"- results 개수: {len(attack_results.get('results', []))}")
                    logger.debug(f"- loot data 키: {list(attack_results.get('loot', {}).get('data', {}).keys()) if attack_results.get('loot', {}).get('data') else '없음'}")
                    print(f"[DEBUG] 공격 실행 완료: success={attack_results.get('success')}, results={len(attack_results.get('results', []))}개", flush=True)
                else:
                    logger.warning("⚠️ attack_results가 None입니다!")
                    print("[DEBUG] ⚠️ attack_results가 None입니다!", flush=True)
                
                if step_elapsed > 300:
                    logger.warning(f"공격 실행 시간이 길었습니다 ({step_elapsed:.1f}초)")
            except TimeoutError as e:
                logger.warning(f"공격 실행 타임아웃 (선택적 단계): {e}")
                print(f"[DEBUG] ❌ 공격 실행 타임아웃: {e}", flush=True)
            except Exception as e:
                logger.warning(f"공격 실행 실패 (선택적 단계): {e}", exc_info=True)
                print(f"[DEBUG] ❌ 공격 실행 실패: {e}", flush=True)
            
            # Step 7: 최종 보고서 생성 (타임아웃: 2분)
            # 부분 결과라도 보고서 생성 시도
            final_report = None
            try:
                emit_scan_progress(scan_id, {
                    'stage': 'reporting',
                    'progress': 95,
                    'message': '최종 보고서 생성 중...'
                }, project_id=project_id)
                
                check_timeout("보고서 생성")
                from app.core.reporting.report_generator import ReportGenerator
                report_generator = ReportGenerator()
                
                # 보고서 생성 실행 (타임아웃: 2분)
                # aggregated_data가 비어있어도 최소한의 보고서는 생성
                step_start_time = time.time()
                try:
                    final_report = report_generator.generate_full_report(
                        aggregated_data,
                        final_results.get('cpe_mapping', {}),
                        ai_scenario,
                        attack_results
                    )
                    logger.info(f"✅ 최종 보고서 생성 성공")
                except Exception as report_error:
                    logger.error(f"❌ 보고서 생성 실패: {report_error}", exc_info=True)
                    # 보고서 생성 실패해도 계속 진행 (통합 리포트는 이미 생성됨)
                    integrated_exists = 'integrated_report_file' in locals() and integrated_report_file is not None and integrated_report_file.exists()
                    final_report = {
                        'error': str(report_error),
                        'partial_data_available': integrated_exists
                    }
                
                step_elapsed = time.time() - step_start_time
                if step_elapsed > 120:
                    logger.warning(f"보고서 생성 시간이 길었습니다 ({step_elapsed:.1f}초)")
            except Exception as e:
                logger.error(f"❌ 보고서 생성 단계 오류: {e}", exc_info=True)
                # 보고서 생성 실패해도 계속 진행
            
            # Step 7.5: AI 분석 (Red Team & Blue Team 리포트 생성)
            # 이 로직은 scan_test/test_ai_analyzer.py에서 검증됨
            ai_report_file = None
            try:
                emit_scan_progress(scan_id, {
                    'stage': 'ai_analysis',
                    'progress': 90,
                    'message': 'AI 보안 분석 중 (약 5~10분 소요)...'
                })
            except Exception as emit_error:
                logger.error(f"AI 분석 시작 알림 전송 실패: {emit_error}", exc_info=True)
            
            try:
                check_timeout("AI 분석")
                from app.core.processors.ai_analyzer import AIAnalyzer
                
                # AI 분석기 초기화 (llama3.1:8b 모델, 팩트 기반 리포트)
                # Docker 컨테이너 내부에서 호스트의 Ollama에 접근하기 위해 host.docker.internal 사용
                analyzer = AIAnalyzer(
                    base_url=Config.OLLAMA_BASE_URL,
                    model=Config.OLLAMA_MODEL  # llama3.1:8b (팩트 기반 리포트, Hallucination 방지)
                )
                
                # AI 분석 실행 (타임아웃: 10분)
                # 부분 결과 강화: ZAP 실패해도 Nmap/Nuclei 결과만으로 AI 분석 진행
                # integrated_report_file이 존재하거나 aggregated_data가 있으면 AI 분석 시도
                should_run_ai = False
                if integrated_report_file and integrated_report_file.exists():
                    should_run_ai = True
                    logger.info(f"✅ 통합 리포트 파일 발견: {integrated_report_file}")
                elif aggregated_data and (aggregated_data.get('vulnerabilities') or aggregated_data.get('infrastructure')):
                    should_run_ai = True
                    logger.info(f"✅ 통합 데이터 확인: 취약점 또는 인프라 정보 존재 (ZAP 실패해도 AI 분석 진행)")
                
                if should_run_ai:
                    step_start_time = time.time()
                    try:
                        logger.info(f"AI 분석 시작 (부분 결과 허용: ZAP 실패해도 진행)")
                        print(f"[AI ANALYSIS] 통합 리포트 경로: {integrated_report_file}", flush=True)
                        print(f"[AI ANALYSIS] Ollama URL: {Config.OLLAMA_BASE_URL}", flush=True)
                        print(f"[AI ANALYSIS] 모델: {Config.OLLAMA_MODEL}", flush=True)
                        sys.stdout.flush()
                        
                        # ZAP 결과 최적화: 상위 30개 핵심 취약점만 추출 (8B 모델 컨텍스트 한계 고려)
                        optimized_data = self._optimize_zap_data_for_ai(aggregated_data)
                        
                        # AI 리포트 생성 시 공격 실행 결과도 포함
                        ai_analysis_result = analyzer.analyze_scan_results(
                            optimized_data,
                            scan_output_dir,
                            attack_results=attack_results  # 공격 실행 결과 전달
                        )
                        step_elapsed = time.time() - step_start_time
                        
                        if ai_analysis_result.get('report_file'):
                            ai_report_file = Path(ai_analysis_result['report_file'])
                            logger.info(f"✅ AI 리포트 생성 완료: {ai_report_file} (소요 시간: {step_elapsed:.1f}초)")
                            print(f"[AI ANALYSIS] ✅ AI 리포트 생성 완료: {ai_report_file}", flush=True)
                        else:
                            logger.warning("⚠️ AI 리포트 파일이 생성되지 않았습니다.")
                            print(f"[AI ANALYSIS] ⚠️ AI 리포트 파일이 생성되지 않았습니다.", flush=True)
                        
                        if step_elapsed > 900:
                            logger.warning(f"AI 분석 시간이 길었습니다 ({step_elapsed:.1f}초, 권장: 900초 이하)")
                    except Exception as ai_error:
                        logger.error(f"❌ AI 분석 실행 중 오류: {ai_error}", exc_info=True)
                        print(f"[AI ANALYSIS] ❌ AI 분석 오류: {ai_error}", flush=True)
                        sys.stdout.flush()
                        # AI 분석 실패해도 계속 진행
                else:
                    logger.warning("⚠️ 통합 리포트 및 데이터가 없어 AI 분석을 건너뜁니다.")
                    print(f"[AI ANALYSIS] ⚠️ 통합 리포트 및 데이터가 없어 AI 분석을 건너뜁니다.", flush=True)
                    sys.stdout.flush()
                    
            except requests.exceptions.ConnectionError as e:
                logger.warning(f"Ollama 서버 연결 실패 (AI 분석 스킵): {e}")
                logger.info("Ollama 서버가 실행 중이지 않습니다. AI 분석을 건너뜁니다.")
            except requests.exceptions.Timeout as e:
                logger.warning(f"AI 분석 타임아웃 (선택적 단계): {e}")
            except Exception as e:
                logger.warning(f"AI 분석 실패 (선택적 단계): {e}", exc_info=True)
                # AI 분석 실패해도 스캔 프로세스는 계속 진행
            
            # Step 7.6: AI PoC Generation & Verification은 Step 1-1로 이동됨
            # (제안된 워크플로우: PoC 검증을 스캔 직후에 수행)
            
            # Step 8: 데이터베이스에 최종 결과 저장 (파일 경로 참조 방식)
            scan_result = ScanResult.query.get(scan_id)
            if scan_result:
                # 스캔 성공 여부 확인 (모든 파일이 생성되었는지)
                all_files_exist = all([nmap_file, nuclei_file, zap_file])
                scan_status = 'completed' if all_files_exist else 'partial_success'
                
                # DB에 저장할 데이터 (용량 최적화: 큰 데이터는 파일 경로만 저장)
                scan_result.data = {
                    'target_url': target_url,
                    'scan_output_dir': str(scan_output_dir.absolute()),  # 절대 경로
                    'integrated_report_path': str(integrated_report_file.absolute()) if integrated_report_file and integrated_report_file.exists() else None,
                    'nmap_file': str(nmap_file) if nmap_file else None,
                    'nuclei_file': str(nuclei_file) if nuclei_file else None,
                    'zap_file': str(zap_file) if zap_file else None,
                    # 요약 정보만 저장 (전체 데이터는 파일에서 읽기)
                    'summary': aggregated_data.get('summary', {}),
                    'partial_result': {
                        'nmap': nmap_file is None,
                        'nuclei': nuclei_file is None,
                        'zap': zap_file is None
                    },
                    # 메타데이터
                    'unified_schema_version': '2.0',
                    'report_generated': integrated_report_file is not None and integrated_report_file.exists(),
                    # AI 분석 리포트 경로 (이 로직은 scan_test/test_ai_analyzer.py에서 검증됨)
                    'ai_report_path': str(ai_report_file.absolute()) if ai_report_file and ai_report_file.exists() else None
                }
                scan_result.status = scan_status
                scan_result.completed_at = datetime.utcnow()
                db.session.commit()
                logger.info(f"DB 저장 완료: status={scan_status}, output_dir={scan_output_dir}")
            
            # 완료 알림 (project_id 포함)
            emit_scan_complete(scan_id, scan_result.data if scan_result else {}, project_id=project_id)
            
            logger.info(f"전체 스캔 완료: {target_url}")
            print(f"\n[ORCHESTRATOR DEBUG] ========== 전체 스캔 성공 완료 ==========", flush=True)
            print(f"[ORCHESTRATOR DEBUG] target_url: {target_url}, scan_id: {scan_id}", flush=True)
            sys.stdout.flush()
        
        except Exception as e:
            error_type = type(e).__name__
            error_msg = str(e)
            print(f"\n[ORCHESTRATOR DEBUG] ❌ ========== 전체 스캔 실패 ==========", flush=True)
            print(f"[ORCHESTRATOR DEBUG] ❌ 예외 타입: {error_type}", flush=True)
            print(f"[ORCHESTRATOR DEBUG] ❌ 예외 메시지: {error_msg}", flush=True)
            print(f"[ORCHESTRATOR DEBUG] ❌ scan_id: {scan_id}, target_url: {target_url}", flush=True)
            import traceback
            print(f"[ORCHESTRATOR DEBUG] ❌ Traceback:", flush=True)
            traceback.print_exc()
            sys.stdout.flush()
            
            logger.error(f"전체 스캔 실패: {e}", exc_info=True)
            # project_id는 이미 _run_full_scan_internal 시작 부분에서 가져옴
            emit_scan_error(scan_id, str(e), project_id=project_id)
            
            # 데이터베이스에 오류 상태 저장 (그때까지 생성된 경로라도 저장)
            try:
                scan_result = ScanResult.query.get(scan_id)
                if scan_result:
                    scan_result.status = 'failed'
                    
                    # 예외 처리: scan_output_dir가 정의되어 있으면 경로 저장
                    try:
                        error_data = {
                            'error': error_msg,
                            'error_type': error_type
                        }
                        # scan_output_dir가 정의되어 있으면 경로 저장
                        if 'scan_output_dir' in locals() and scan_output_dir:
                            error_data['scan_output_dir'] = str(scan_output_dir.absolute())
                            error_data['integrated_report_path'] = str((scan_output_dir / "final_integrated_report.json").absolute()) if (scan_output_dir / "final_integrated_report.json").exists() else None
                            print(f"[ORCHESTRATOR DEBUG] 오류 상태에 scan_output_dir 저장: {scan_output_dir}", flush=True)
                        
                        scan_result.data = error_data
                    except Exception as save_error:
                        print(f"[ORCHESTRATOR DEBUG] ❌ 오류 상태 저장 실패: {save_error}", flush=True)
                        logger.error(f"오류 상태 저장 실패: {save_error}")
                        scan_result.data = {'error': error_msg, 'error_type': error_type}
                    
                    scan_result.completed_at = datetime.utcnow()
                    db.session.commit()
                    print(f"[ORCHESTRATOR DEBUG] 오류 상태 DB 저장 완료: scan_id={scan_id}", flush=True)
                    logger.info(f"오류 상태 DB 저장 완료: scan_id={scan_id}")
                    sys.stdout.flush()
                else:
                    print(f"[ORCHESTRATOR DEBUG] ⚠️ scan_id={scan_id}에 해당하는 ScanResult를 찾을 수 없습니다", flush=True)
            except Exception as db_error:
                print(f"[ORCHESTRATOR DEBUG] ❌ DB 저장 중 예외 발생: {db_error}", flush=True)
                logger.error(f"DB 저장 중 예외 발생: {db_error}", exc_info=True)
                sys.stdout.flush()
        
        finally:
            # WebSocket 로깅 핸들러 정리 (성공/실패 여부와 관계없이)
            try:
                self._cleanup_websocket_logging(scan_id)
            except Exception as cleanup_error:
                logger.warning(f"WebSocket 로깅 핸들러 정리 중 오류 (무시): {cleanup_error}")
    
    def _run_docker_scans(self, target_url: str, scan_id: int, scan_output_dir: Path) -> Dict[str, Any]:
        """
        도커 컨테이너에서 스캔 실행
        
        Args:
            target_url: 타겟 URL
            scan_id: 스캔 ID (진행 상황 업데이트용)
            scan_output_dir: 스캔 결과 저장 디렉토리 (outputs/{target}_{timestamp}/)
        
        Returns:
            스캔 결과 딕셔너리
        """
        print(f"\n[RUN_DOCKER_SCANS DEBUG] _run_docker_scans 시작: target={target_url}, scan_id={scan_id}", flush=True)
        print(f"[RUN_DOCKER_SCANS DEBUG] scan_output_dir: {scan_output_dir}", flush=True)
        
        results = {}
        
        if self.docker_client is None:
            error_msg = "Docker 클라이언트가 초기화되지 않았습니다"
            print(f"[RUN_DOCKER_SCANS DEBUG] ❌ {error_msg}", flush=True)
            logger.error(error_msg)
            return results
        
        # Docker 클라이언트 ping 검증
        try:
            self.docker_client.ping()
            print(f"[RUN_DOCKER_SCANS DEBUG] ✅ Docker 데몬 연결 확인 (ping OK)", flush=True)
        except Exception as ping_err:
            error_msg = f"Docker 데몬 연결 실패: {ping_err}"
            print(f"[RUN_DOCKER_SCANS DEBUG] ❌ {error_msg}", flush=True)
            logger.error(error_msg)
            return results
        
        # 결과 저장 디렉토리 (호스트와 공유)
        scan_output_dir.mkdir(parents=True, exist_ok=True)
        
        # ✅ 호스트의 실제 절대 경로 계산 (Docker-in-Docker 환경에서 워커 컨테이너에 전달)
        # web 컨테이너 내부 경로(/app/scan_results/...)를 Windows 호스트 경로로 변환
        scan_output_dir_str = str(scan_output_dir.resolve())
        
        # 호스트 작업 디렉토리 확인 (docker-compose.yml의 context 기준)
        host_work_dir = os.environ.get('HOST_PWD')
        if not host_work_dir:
            # HOST_PWD가 없으면 Config.SCAN_RESULTS_DIR의 실제 호스트 경로 계산
            # Config.SCAN_RESULTS_DIR는 web 컨테이너 내부 경로일 수 있으므로 주의
            config_dir = Config.SCAN_RESULTS_DIR
            if config_dir.startswith('/app/scan_results'):
                # 컨테이너 내부 경로인 경우, 상위 디렉토리(프로젝트 루트) 계산
                # docker-compose.yml에서 ./scan_results:/app/scan_results로 마운트
                # 따라서 /app/scan_results의 상위는 /app이고, 호스트에서는 프로젝트 루트
                # 하지만 실제로는 HOST_PWD를 사용하는 것이 더 정확함
                # fallback: 현재 작업 디렉토리 사용 (일반적으로 /app)
                host_work_dir = os.getcwd()
                if host_work_dir.startswith('/app'):
                    # 컨테이너 내부이므로, 환경 변수나 다른 방법으로 호스트 경로 추정
                    # 가장 안전한 방법: 환경 변수 사용 강제
                    logger.warning(f"⚠️ HOST_PWD 환경 변수가 없고 컨테이너 내부 경로 감지됨")
                    logger.warning(f"⚠️ docker-compose.yml에 HOST_PWD 환경 변수 설정 필요")
                    # 임시 해결책: 상대 경로를 그대로 사용 (호스트에서 실행 시)
                    host_work_dir = os.path.dirname(os.path.dirname(config_dir)) if not config_dir.startswith('/') else '/tmp'
            else:
                # 이미 호스트 경로인 경우
                host_work_dir = os.path.dirname(config_dir)
        else:
            logger.info(f"✅ HOST_PWD 환경 변수 사용: {host_work_dir}")
        
        # 호스트의 실제 scan_results 경로 계산 (순수 문자열로 처리)
        # docker-compose.yml에서 ./scan_results:/app/scan_results로 마운트
        # 따라서 호스트 경로는 HOST_PWD/scan_results
        # Path 객체 사용 금지 - 컨테이너에서 실행 시 /app/ 접두사가 붙음
        host_scan_results_dir_str = host_work_dir.replace('\\', '/') + '/scan_results'
        
        # web 컨테이너 내부 경로인지 확인 (/app/scan_results로 시작)
        if scan_output_dir_str.startswith('/app/scan_results'):
            # 상대 경로 추출 (예: outputs/172_16_10_10_1768438769)
            relative_path = scan_output_dir_str.replace('/app/scan_results', '').lstrip('/')
            
            # 최종 호스트 경로 생성 (순수 문자열로 조합)
            # Path 객체나 resolve() 사용 금지 - 컨테이너에서 실행 시 경로가 엉망이 됨
            host_abs_path_str = host_scan_results_dir_str + '/' + relative_path
            
            logger.info(f"🔧 [경로 변환] 컨테이너 내부 -> 호스트:")
            logger.info(f"   컨테이너 경로: {scan_output_dir_str}")
            logger.info(f"   상대 경로: {relative_path}")
            logger.info(f"   호스트 작업 디렉토리: {host_work_dir}")
            logger.info(f"   호스트 scan_results: {host_scan_results_dir_str}")
            logger.info(f"   최종 호스트 경로: {host_abs_path_str}")
        else:
            # 이미 호스트 경로인 경우 (로컬 실행 시)
            host_abs_path_str = scan_output_dir_str
            logger.info(f"✅ 이미 호스트 경로로 인식: {host_abs_path_str}")
        
        # ✅ Windows 경로를 Docker 볼륨 마운트용 형식으로 변환
        # Windows: C:\Users\... -> /c/Users/... (Docker Desktop 형식)
        docker_mount_path = self._convert_windows_path_for_docker(host_abs_path_str)
        
        logger.info(f"🔧 [경로 변환] Windows -> Docker:")
        logger.info(f"   원본 경로: {host_abs_path_str}")
        logger.info(f"   Docker 경로: {docker_mount_path}")
        print(f"[DOCKER DEBUG] 원본 Windows 경로: {host_abs_path_str}", flush=True)
        print(f"[DOCKER DEBUG] 변환된 Docker 경로: {docker_mount_path}", flush=True)
        sys.stdout.flush()
        
        # 상대 경로 계산 (컨테이너 내부 경로용, fallback)
        base_dir = Path(Config.SCAN_RESULTS_DIR).resolve()
        try:
            rel_path = scan_output_dir.resolve().relative_to(base_dir)
            container_results_path = f"/app/scan_results/{rel_path.as_posix()}"
        except ValueError:
            container_results_path = '/app/results'
        
        # Docker 볼륨 마운트 설정
        # 호스트의 실제 절대 경로를 워커 컨테이너에 마운트
        volumes = {
            docker_mount_path: {
                'bind': '/app/results',
                'mode': 'rw'
            }
        }
        
        logger.info(f"📦 볼륨 마운트 설정 (Docker-in-Docker):")
        logger.info(f"   호스트 절대 경로 (Windows): {host_abs_path_str}")
        logger.info(f"   Docker 마운트 경로: {docker_mount_path}")
        logger.info(f"   컨테이너 마운트 포인트: /app/results")
        logger.info(f"   컨테이너 내부 경로 (fallback): {container_results_path}")
        print(f"[FINAL FIX] 📦 볼륨 마운트 설정:", flush=True)
        print(f"[FINAL FIX]   호스트 경로: {host_abs_path_str}", flush=True)
        print(f"[FINAL FIX]   Docker 경로: {docker_mount_path}", flush=True)
        print(f"[FINAL FIX]   컨테이너 경로: /app/results", flush=True)
        print(f"[RUN_DOCKER_SCANS DEBUG] 볼륨 마운트: {docker_mount_path} -> /app/results", flush=True)
        sys.stdout.flush()
        
        # ZAP 워커 컨테이너를 위한 환경 변수 (고정 IP로 직접 접근하여 DNS 해석 없음)
        # docker-compose에서 할당된 고정 IP 사용 (DNS 해석 지연 방지)
        zap_host = '172.18.0.5'  # 고정 IP (scanner-net 네트워크에서 DNS 없이 직접 접근)
        zap_port = 8080
        
        env_vars = {
            'TARGET_URL': target_url,
            'SCAN_ID': str(scan_id),
            'OUTPUT_DIR': '/app/results',  # 볼륨 마운트 포인트 사용 (항상 /app/results)
            'HOST_OUTPUT_DIR': host_abs_path_str,  # 호스트 경로 (올바르게 변환된 경로)
            'BASE_DIR': host_scan_results_dir_str,  # 기준 디렉토리 (디버깅용)
            'HOST_WORK_DIR': host_work_dir,  # 호스트 작업 디렉토리 (디버깅용)
            'PYTHONPATH': '/app',  # Python 모듈 검색 경로 설정
            'PYTHONUNBUFFERED': '1',  # 출력 버퍼링 해제 (실시간 로그용)
            # ZAP 워커를 위한 환경 변수 (고정 IP로 직접 접근하여 DNS 해석 없음)
            'ZAP_HOST': zap_host,  # '172.18.0.5' (고정 IP, scanner-net 네트워크에서 DNS 없이 직접 접근)
            'ZAP_PORT': str(zap_port),  # '8080'
            'ZAP_PROXY_HOST': zap_host,  # 호환성을 위해 추가 (고정 IP 사용)
            'ZAP_PROXY_PORT': str(zap_port)  # 호환성을 위해 추가
        }
        
        logger.info(f"환경 변수 설정:")
        logger.info(f"  TARGET_URL: {target_url}")
        logger.info(f"  SCAN_ID: {scan_id}")
        logger.info(f"  OUTPUT_DIR: /app/results")
        logger.info(f"  HOST_OUTPUT_DIR: {scan_output_dir.resolve()}")
        logger.info(f"  HOST_WORK_DIR: {host_work_dir}")
        logger.info(f"  ZAP_HOST: {zap_host} (docker-compose 서비스 이름)")
        logger.info(f"  ZAP_PORT: {zap_port}")
        logger.info(f"  PYTHONPATH: /app")
        logger.info(f"  PYTHONUNBUFFERED: 1")
        print(f"[RUN_DOCKER_SCANS DEBUG] OUTPUT_DIR: /app/results", flush=True)
        print(f"[RUN_DOCKER_SCANS DEBUG] HOST_OUTPUT_DIR: {scan_output_dir.resolve()}", flush=True)
        print(f"[RUN_DOCKER_SCANS DEBUG] ZAP_HOST: {zap_host} (동일 네트워크에서 'zap' 서비스로 접근)", flush=True)
        print(f"[RUN_DOCKER_SCANS DEBUG] ZAP_PORT: {zap_port}", flush=True)
        sys.stdout.flush()
        
        # 1. Nmap 스캔
        print(f"\n[RUN_DOCKER_SCANS DEBUG] ========== Nmap 스캔 시작 ==========", flush=True)
        # project_id 가져오기 (헬퍼 함수에서 사용)
        project_id = None
        try:
            scan_result = ScanResult.query.get(scan_id)
            if scan_result:
                project_id = scan_result.project_id
        except Exception:
            pass
        
        try:
            emit_scan_progress(scan_id, {
                'stage': 'nmap',
                'progress': 20,
                'message': 'Nmap 스캔 실행 중...'
            }, project_id=project_id)
            sys.stdout.flush()
            
            print(f"[RUN_DOCKER_SCANS DEBUG] Nmap 컨테이너 실행 호출 전...", flush=True)
            nmap_result = self._run_docker_container(
                image='security-scanner-nmap:latest',
                command=['python', '-u', '/app/worker.py', 'nmap'],  # -u 옵션 추가 (unbuffered)
                env_vars=env_vars,
                volumes=volumes,
                scan_id=scan_id,
                scan_output_dir=scan_output_dir
            )
            print(f"[RUN_DOCKER_SCANS DEBUG] Nmap 컨테이너 실행 완료, 결과: success={nmap_result.get('success', 'N/A')}", flush=True)
            results['nmap'] = nmap_result
        
        except Exception as e:
            error_msg = f"Nmap 스캔 실패: {e}"
            print(f"[RUN_DOCKER_SCANS DEBUG] ❌ {error_msg}", flush=True)
            logger.error(error_msg, exc_info=True)
            sys.stdout.flush()
            results['nmap'] = {'success': False, 'error': str(e), 'error_type': type(e).__name__}
        
        # 2. Nuclei 스캔
        print(f"\n[RUN_DOCKER_SCANS DEBUG] ========== Nuclei 스캔 시작 ==========", flush=True)
        # project_id 가져오기 (헬퍼 함수에서 사용)
        project_id = None
        try:
            scan_result = ScanResult.query.get(scan_id)
            if scan_result:
                project_id = scan_result.project_id
        except Exception:
            pass
        
        try:
            emit_scan_progress(scan_id, {
                'stage': 'nuclei',
                'progress': 40,
                'message': 'Nuclei 스캔 실행 중...'
            }, project_id=project_id)
            sys.stdout.flush()
            
            print(f"[RUN_DOCKER_SCANS DEBUG] Nuclei 컨테이너 실행 호출 전...", flush=True)
            print(f"[NUCLEI DEBUG] ========== Nuclei 컨테이너 실행 시작 ==========", flush=True)
            print(f"[NUCLEI DEBUG] 타겟 URL: {target_url}", flush=True)
            print(f"[NUCLEI DEBUG] 환경 변수: {env_vars}", flush=True)
            print(f"[NUCLEI DEBUG] 볼륨 마운트: {volumes}", flush=True)
            logger.info(f"[NUCLEI DEBUG] Nuclei 컨테이너 실행 시작: target_url={target_url}")
            
            nuclei_result = self._run_docker_container(
                image='security-scanner-nuclei:latest',
                command=['python', '-u', '/app/worker.py', 'nuclei'],  # -u 옵션 추가 (unbuffered)
                env_vars=env_vars,
                volumes=volumes,
                scan_id=scan_id,
                scan_output_dir=scan_output_dir
            )
            
            print(f"[NUCLEI DEBUG] ========== Nuclei 컨테이너 실행 완료 ==========", flush=True)
            print(f"[NUCLEI DEBUG] 실행 결과: success={nuclei_result.get('success', 'N/A')}", flush=True)
            if not nuclei_result.get('success'):
                print(f"[NUCLEI DEBUG] 에러 타입: {nuclei_result.get('error_type', 'N/A')}", flush=True)
                print(f"[NUCLEI DEBUG] 에러 메시지: {nuclei_result.get('error', 'N/A')}", flush=True)
                logger.warning(f"[NUCLEI DEBUG] Nuclei 컨테이너 실행 실패: {nuclei_result.get('error', 'N/A')}")
            
            print(f"[RUN_DOCKER_SCANS DEBUG] Nuclei 컨테이너 실행 완료, 결과: success={nuclei_result.get('success', 'N/A')}", flush=True)
            results['nuclei'] = nuclei_result
        
        except Exception as e:
            error_msg = f"Nuclei 스캔 실패: {e}"
            print(f"[RUN_DOCKER_SCANS DEBUG] ❌ {error_msg}", flush=True)
            logger.error(error_msg, exc_info=True)
            sys.stdout.flush()
            results['nuclei'] = {'success': False, 'error': str(e), 'error_type': type(e).__name__}
        
        # 3. ZAP 스캔 (정밀 스캔 모드: 활성화)
        print(f"\n[RUN_DOCKER_SCANS DEBUG] ========== ZAP 스캔 시작 ==========", flush=True)
        # project_id 가져오기 (헬퍼 함수에서 사용)
        project_id = None
        try:
            scan_result = ScanResult.query.get(scan_id)
            if scan_result:
                project_id = scan_result.project_id
        except Exception:
            pass
        
        try:
            emit_scan_progress(scan_id, {
                'stage': 'zap',
                'progress': 60,
                'message': 'ZAP 스캔 실행 중...'
            }, project_id=project_id)
            sys.stdout.flush()
            
            # Nuclei에서 발견한 URL 목록 전달 (최적화)
            discovered_urls = results.get('nuclei', {}).get('discovered_urls', [])
            if discovered_urls:
                env_vars['DISCOVERED_URLS'] = ','.join(discovered_urls)
                print(f"[RUN_DOCKER_SCANS DEBUG] Nuclei에서 발견한 URL {len(discovered_urls)}개 전달", flush=True)
            
            print(f"[RUN_DOCKER_SCANS DEBUG] ZAP 컨테이너 실행 호출 전...", flush=True)
            zap_result = self._run_docker_container(
                image='security-scanner-zap:latest',
                command=['python', '-u', '/app/worker.py', 'zap'],  # -u 옵션 추가 (unbuffered)
                env_vars=env_vars,
                volumes=volumes,
                scan_id=scan_id,
                scan_output_dir=scan_output_dir
            )
            print(f"[RUN_DOCKER_SCANS DEBUG] ZAP 컨테이너 실행 완료, 결과: success={zap_result.get('success', 'N/A')}", flush=True)
            results['zap'] = zap_result
        
        except Exception as e:
            error_msg = f"ZAP 스캔 실패: {e}"
            print(f"[RUN_DOCKER_SCANS DEBUG] ❌ {error_msg}", flush=True)
            logger.error(error_msg, exc_info=True)
            sys.stdout.flush()
            results['zap'] = {'success': False, 'error': str(e), 'error_type': type(e).__name__}
        
        print(f"\n[RUN_DOCKER_SCANS DEBUG] ========== _run_docker_scans 완료 ==========", flush=True)
        print(f"[RUN_DOCKER_SCANS DEBUG] 결과 요약: nmap={results.get('nmap', {}).get('success', 'N/A')}, "
              f"nuclei={results.get('nuclei', {}).get('success', 'N/A')}, "
              f"zap={results.get('zap', {}).get('success', 'N/A')}", flush=True)
        
        return results
    
    def _convert_windows_path_for_docker(self, windows_path: str) -> str:
        r"""
        Windows 경로를 Docker 볼륨 마운트용 경로로 변환
        
        Args:
            windows_path: Windows 절대 경로 (예: C:\Users\...)
        
        Returns:
            Docker 볼륨 마운트용 경로 (예: /c/Users/...)
        """
        # 순수 문자열로 처리 (Path.resolve() 사용 금지 - 컨테이너 경로로 변환됨)
        path_str = str(windows_path)
        
        # 백슬래시를 슬래시로 변환
        path_str = path_str.replace('\\', '/')
        
        # Windows 드라이브 문자 변환 (C: -> /c)
        if len(path_str) >= 2 and path_str[1] == ':':
            drive_letter = path_str[0].lower()
            path_str = f'/{drive_letter}{path_str[2:]}'
        
        return path_str
    
    def _convert_path_for_docker(self, path: Path, use_relative: bool = True) -> str:
        """
        경로를 Docker가 인식할 수 있는 경로로 변환
        
        Args:
            path: 변환할 경로 (Path 객체)
            use_relative: 상대 경로 사용 여부 (기본값: True, 권장)
        
        Returns:
            Docker가 인식할 수 있는 경로 문자열
        """
        abs_path = path.resolve()
        
        # 상대 경로 사용 시 (권장: Docker Compose 볼륨과 호환)
        if use_relative:
            try:
                # Config.SCAN_RESULTS_DIR 기준으로 상대 경로 계산
                base_dir = Path(Config.SCAN_RESULTS_DIR).resolve()
                try:
                    rel_path = abs_path.relative_to(base_dir)
                    # 이미 마운트된 /app/scan_results 경로 사용
                    docker_path = f"/app/scan_results/{rel_path.as_posix()}"
                    logger.info(f"상대 경로 변환: {abs_path} -> {docker_path} (기준: {base_dir})")
                    return docker_path
                except ValueError:
                    # base_dir의 하위 경로가 아닌 경우
                    logger.warning(f"상대 경로 변환 실패: {abs_path}는 {base_dir}의 하위 경로가 아닙니다")
            except Exception as e:
                logger.warning(f"상대 경로 변환 중 오류: {e}, 절대 경로 사용")
        
        # 절대 경로 사용 (상대 경로 변환 실패 시)
        abs_path = path.resolve()
        
        # Windows 환경인지 확인
        if platform.system() == 'Windows':
            path_str = str(abs_path)
            
            # Docker Desktop for Windows: 여러 경로 형식 시도
            if path_str.startswith('C:\\') or path_str.startswith('C:/'):
                # 방법 1: WSL2 스타일 (/mnt/c/...)
                docker_path_wsl = '/mnt/c' + path_str[2:].replace('\\', '/')
                # 방법 2: Docker Desktop 스타일 (시도)
                docker_path_dd = path_str.replace('\\', '/').replace('C:', '/host_mnt/c')
                
                logger.warning(f"절대 경로 사용 (Windows): {path_str}")
                logger.warning(f"  -> WSL2 스타일: {docker_path_wsl}")
                logger.warning(f"  -> Docker Desktop 스타일: {docker_path_dd}")
                logger.warning("절대 경로는 Docker Desktop에서 작동하지 않을 수 있습니다. 상대 경로 사용을 권장합니다.")
                
                # WSL2 스타일 반환 (일부 환경에서 작동)
                return docker_path_wsl
            elif path_str.startswith('/mnt/'):
                return path_str
        
        # Unix/Linux 환경 또는 이미 변환된 경로
        logger.info(f"절대 경로 사용 (Unix/Linux): {abs_path}")
        return str(abs_path)
    
    def _run_docker_container(
        self,
        image: str,
        command: list,
        env_vars: dict,
        volumes: dict,
        scan_id: int = None,
        scan_output_dir: Path = None
    ) -> Dict[str, Any]:
        """
        도커 컨테이너 실행
        
        Args:
            image: 도커 이미지 이름
            command: 실행할 명령어
            env_vars: 환경 변수
            volumes: 볼륨 마운트 설정
            scan_id: 스캔 ID (컨테이너 이름 생성용)
            scan_output_dir: 스캔 결과 저장 디렉토리 (web 컨테이너 경로)
        
        Returns:
            실행 결과
        """
        try:
            # 컨테이너 이름 생성 (중복 방지: 타임스탬프 포함)
            scan_id_param = scan_id if scan_id is not None else 0
            container_name = f"{image.replace(':', '_').replace('/', '_')}_{scan_id_param}_{int(time.time())}"
            
            # 기존 컨테이너가 있으면 강제 삭제
            try:
                existing_container = self.docker_client.containers.get(container_name)
                if existing_container:
                    logger.warning(f"기존 컨테이너 발견: {container_name}, 강제 삭제 중...")
                    existing_container.remove(force=True)
            except docker.errors.NotFound:
                pass  # 컨테이너가 없으면 정상
            except Exception as e:
                logger.warning(f"기존 컨테이너 삭제 시도 중 오류 (무시): {e}")
            
            # 컨테이너 실행 (에러 처리 강화)
            print(f"\n[DOCKER DEBUG] 컨테이너 실행 시도 시작: {image}", flush=True)
            print(f"[DOCKER DEBUG] 컨테이너 이름: {container_name}", flush=True)
            print(f"[DOCKER DEBUG] 명령어: {command}", flush=True)
            print(f"[DOCKER DEBUG] Docker 클라이언트 상태: {self.docker_client is not None}", flush=True)
            
            try:
                # Docker 클라이언트 ping 재검증
                if self.docker_client:
                    try:
                        self.docker_client.ping()
                        print(f"[DOCKER DEBUG] ✅ Docker 데몬 ping 성공 (컨테이너 실행 전 검증)", flush=True)
                    except Exception as ping_err:
                        print(f"[DOCKER DEBUG] ⚠️ Docker 데몬 ping 실패: {ping_err}", flush=True)
                        logger.warning(f"Docker ping 실패 (컨테이너 실행 시도 계속): {ping_err}")
                
                logger.info(f"🚀 컨테이너 실행 시도: {image}")
                logger.info(f"   컨테이너 이름: {container_name}")
                logger.info(f"   명령어: {command}")
                logger.info(f"   볼륨 마운트: {volumes}")
                logger.info(f"   환경 변수: {env_vars}")
                sys.stdout.flush()
                
                print(f"[DOCKER DEBUG] client.containers.run() 호출 직전...", flush=True)
                
                # 네트워크 설정: docker-compose의 네트워크 이름 사용
                # web, zap, worker가 동일한 네트워크에서 통신할 수 있도록 설정
                docker_network = Config.DOCKER_NETWORK  # 'security-scanner-net'
                logger.info(f"   네트워크: {docker_network}")
                print(f"[DOCKER DEBUG] 네트워크 설정: {docker_network}", flush=True)
                
                container = self.docker_client.containers.run(
                    image=image,
                    command=command,
                    environment=env_vars,
                    volumes=volumes,
                    network=docker_network,  # docker-compose의 scanner-net과 동일한 네트워크 사용
                    name=container_name,  # 고유한 이름 지정
                    working_dir='/app',  # 작업 디렉토리를 /app으로 설정
                    detach=True,  # 백그라운드 실행
                    auto_remove=False,  # 종료 시 자동 삭제 비활성화 (로그 확인을 위해)
                    stdout=True,
                    stderr=True
                )
                
                print(f"[DOCKER DEBUG] ✅ 컨테이너 생성 성공! Container ID: {container.id[:12]}", flush=True)
                logger.info(f"✅ 워커 컨테이너 실행 성공: {container.id[:12]} ({image})")
                logger.info(f"   컨테이너 이름: {container_name}")
                logger.info(f"   컨테이너 로그 확인: docker logs {container.id[:12]} -f")
                sys.stdout.flush()
                
                # [NUCLEI DEBUG] 컨테이너 네트워크 연결 상태 확인
                if 'nuclei' in image.lower():
                    try:
                        container.reload()  # 컨테이너 정보 갱신
                        networks = container.attrs.get('NetworkSettings', {}).get('Networks', {})
                        print(f"[NUCLEI DEBUG] 컨테이너 네트워크 연결 상태 확인:", flush=True)
                        print(f"[NUCLEI DEBUG]   - 연결된 네트워크: {list(networks.keys())}", flush=True)
                        logger.info(f"[NUCLEI DEBUG] 연결된 네트워크: {list(networks.keys())}")
                        
                        if docker_network in networks:
                            network_info = networks[docker_network]
                            ip_address = network_info.get('IPAddress', 'N/A')
                            print(f"[NUCLEI DEBUG]   - 네트워크 '{docker_network}' 연결 성공 (IP: {ip_address})", flush=True)
                            logger.info(f"[NUCLEI DEBUG] 네트워크 '{docker_network}' 연결 성공 (IP: {ip_address})")
                        else:
                            print(f"[NUCLEI DEBUG]   - ⚠️ 네트워크 '{docker_network}'에 연결되지 않음!", flush=True)
                            print(f"[NUCLEI DEBUG]   - 실제 연결된 네트워크: {list(networks.keys())}", flush=True)
                            logger.warning(f"[NUCLEI DEBUG] 네트워크 '{docker_network}'에 연결되지 않음! 실제: {list(networks.keys())}")
                    except Exception as net_err:
                        print(f"[NUCLEI DEBUG]   - ⚠️ 네트워크 상태 확인 실패: {net_err}", flush=True)
                        logger.warning(f"[NUCLEI DEBUG] 네트워크 상태 확인 실패: {net_err}")
                
            except docker.errors.APIError as e:
                error_msg = str(e)
                print(f"\n[DOCKER ERROR] ❌ 컨테이너 생성 실패 (API Error): {error_msg}", flush=True)
                print(f"[DOCKER ERROR] 이미지: {image}", flush=True)
                print(f"[DOCKER ERROR] 명령어: {command}", flush=True)
                print(f"[DOCKER ERROR] 볼륨: {volumes}", flush=True)
                print(f"[DOCKER ERROR] 환경 변수: {env_vars}", flush=True)
                
                logger.error(f"❌ 컨테이너 실행 실패 (API Error): {error_msg}")
                logger.error(f"   이미지: {image}")
                logger.error(f"   명령어: {command}")
                logger.error(f"   볼륨: {volumes}")
                logger.error(f"   환경 변수: {env_vars}")
                sys.stdout.flush()
                
                # 상세 에러 정보 출력
                if 'mount' in error_msg.lower() or 'volume' in error_msg.lower() or 'path' in error_msg.lower():
                    print(f"[DOCKER ERROR] 🔴 볼륨 마운트 오류 가능성 높음!", flush=True)
                    logger.error(f"   🔴 볼륨 마운트 오류 가능성 높음!")
                    logger.error(f"   Windows 환경에서는 절대 경로 마운트가 실패할 수 있습니다.")
                    logger.error(f"   해결 방법:")
                    logger.error(f"   1. docker-compose.yml에서 볼륨을 정의하고 이름으로 참조")
                    logger.error(f"   2. 상대 경로 사용 (현재: {env_vars.get('OUTPUT_DIR', 'N/A')})")
                    logger.error(f"   3. worker 컨테이너가 stdout으로 결과 출력하고 orchestrator가 파일로 저장")
                    sys.stdout.flush()
                
                return {
                    'success': False,
                    'error': f'컨테이너 실행 실패: {error_msg}',
                    'error_type': 'APIError',
                    'error_details': {
                        'image': image,
                        'command': command,
                        'volumes': volumes,
                        'env_vars': env_vars
                    }
                }
            except docker.errors.ImageNotFound as e:
                error_msg = str(e)
                print(f"\n[DOCKER ERROR] ❌ 이미지를 찾을 수 없음: {error_msg}", flush=True)
                print(f"[DOCKER ERROR] 이미지: {image}", flush=True)
                logger.error(f"❌ 이미지를 찾을 수 없습니다: {image} - {error_msg}")
                sys.stdout.flush()
                return {
                    'success': False,
                    'error': f'이미지를 찾을 수 없습니다: {image}',
                    'error_type': 'ImageNotFound',
                    'error_details': {
                        'image': image
                    }
                }
            except docker.errors.DockerException as e:
                error_msg = str(e)
                print(f"\n[DOCKER ERROR] ❌ Docker 예외 발생: {error_msg}", flush=True)
                logger.error(f"❌ Docker 예외 발생: {error_msg}", exc_info=True)
                sys.stdout.flush()
                return {
                    'success': False,
                    'error': f'Docker 예외: {error_msg}',
                    'error_type': 'DockerException',
                    'error_details': {
                        'image': image,
                        'exception': str(e)
                    }
                }
            except Exception as e:
                error_msg = str(e)
                error_type = type(e).__name__
                print(f"\n[DOCKER ERROR] ❌ 컨테이너 실행 실패 (기타 오류): {error_type}: {error_msg}", flush=True)
                logger.error(f"❌ 컨테이너 실행 실패 (기타 오류): {e}", exc_info=True)
                sys.stdout.flush()
                return {
                    'success': False,
                    'error': f'컨테이너 실행 실패: {error_msg}',
                    'error_type': error_type
                }
            
            # 실시간 로그 수집 및 진행률 모니터링을 위한 스레드
            logs_lines = []
            log_collection_done = threading.Event()
            progress_tracker = {
                'last_progress': None,
                'last_progress_time': None,
                'stuck_duration': 0,
                'progress_history': []
            }
            
            def extract_progress(log_text: str) -> Optional[float]:
                """
                로그에서 진행률(%) 추출
                Nmap: "Nmap done: X IP addresses (Y hosts up) scanned in Z seconds"
                Nuclei: "Progress: X%", "[INF] Templates loaded: X/Y"
                ZAP: API 기반으로 별도 처리
                """
                import re
                # Nuclei 진행률 패턴: "Progress: 45%" 또는 "[INF] Progress: 45%"
                progress_match = re.search(r'(?:Progress|progress|PROGRESS):\s*(\d+(?:\.\d+)?)\s*%', log_text)
                if progress_match:
                    return float(progress_match.group(1))
                
                # Nmap 완료 패턴: "Nmap done"이 나타나면 100%로 간주
                if 'nmap done' in log_text.lower() or 'scan complete' in log_text.lower():
                    return 100.0
                
                # 기타 진행률 패턴: "X/Y" 형식
                ratio_match = re.search(r'(\d+)/(\d+)', log_text)
                if ratio_match:
                    current = float(ratio_match.group(1))
                    total = float(ratio_match.group(2))
                    if total > 0:
                        return (current / total) * 100.0
                
                return None
            
            def collect_logs():
                """실시간 로그 수집 및 진행률 모니터링 스레드 (WebSocket 전송 포함)"""
                try:
                    # project_id 가져오기
                    project_id_for_logs = None
                    try:
                        scan_result = ScanResult.query.get(scan_id)
                        if scan_result:
                            project_id_for_logs = scan_result.project_id
                    except Exception:
                        pass
                    
                    # 실시간 로그 스트림 수집
                    for log_line in container.logs(stream=True, follow=True):
                        try:
                            log_text = log_line.decode('utf-8', errors='replace').strip()
                            if log_text:
                                logs_lines.append(log_text)
                                
                                # WebSocket으로 실시간 로그 전송
                                emit_log_update(scan_id, log_text, project_id=project_id_for_logs)
                                
                                # 진행률 추출 및 추적 (참고용, 더 이상 progress 계산하지 않음)
                                progress = extract_progress(log_text)
                                if progress is not None:
                                    current_time = time.time()
                                    progress_tracker['last_progress'] = progress
                                    progress_tracker['last_progress_time'] = current_time
                                    progress_tracker['progress_history'].append((current_time, progress))
                                    # 오래된 히스토리 정리 (최근 100개만 유지)
                                    if len(progress_tracker['progress_history']) > 100:
                                        progress_tracker['progress_history'] = progress_tracker['progress_history'][-100:]
                                    logger.info(f"[{image}] 진행률: {progress:.1f}%")
                                
                                # 중요한 메시지는 즉시 로깅
                                if any(keyword in log_text.upper() for keyword in ['ERROR', 'FAILED', 'COMPLETE', 'SUCCESS', 'START', 'WORKER']):
                                    logger.info(f"[{image}] {log_text}")
                        except Exception as e:
                            logger.warning(f"로그 디코딩 실패: {e}")
                except docker.errors.APIError as e:
                    # 409 Conflict 등 API 에러 처리
                    if '409' in str(e) or 'Conflict' in str(e):
                        logger.warning(f"⚠️ 로그 수집 중 컨테이너 충돌 발생 (무시): {e}")
                    else:
                        logger.error(f"❌ 로그 스트리밍 API 에러: {e}", exc_info=True)
                except Exception as e:
                    logger.error(f"❌ 로그 스트리밍 실패: {e}", exc_info=True)
                finally:
                    log_collection_done.set()
            
            def check_progress_timeout():
                """
                진행률 기반 타임아웃 체크
                300초(5분) 동안 진행률이 변하지 않으면 True 반환
                """
                if progress_tracker['last_progress_time'] is None:
                    return False  # 진행률이 아직 추적되지 않음
                
                current_time = time.time()
                stuck_duration = current_time - progress_tracker['last_progress_time']
                
                if stuck_duration >= 300:  # 300초 = 5분
                    logger.warning(f"⚠️ 진행률 기반 타임아웃 감지: {stuck_duration:.1f}초 동안 진행률 변화 없음 (마지막 진행률: {progress_tracker['last_progress']:.1f}%)")
                    return True
                
                return False
            
            # 로그 수집 스레드 시작
            log_thread = threading.Thread(target=collect_logs, daemon=True)
            log_thread.start()
            
            # 컨테이너 완료 대기 (진행률 기반 타임아웃 포함)
            exit_code = None
            container_stopped = False
            
            try:
                logger.info(f"⏳ 컨테이너 완료 대기 중... (최대 1시간, 진행률 변화 없으면 5분 후 종료)")
                wait_start_time = time.time()
                
                # 주기적으로 진행률 체크 (10초마다)
                while True:
                    # 컨테이너가 종료되었는지 확인 (논블로킹)
                    try:
                        container.reload()
                        if container.status == 'exited':
                            exit_code = container.attrs['State']['ExitCode']
                            logger.info(f"✅ 컨테이너 정상 종료: exit_code={exit_code}")
                            container_stopped = True
                            break
                    except Exception as e:
                        logger.debug(f"컨테이너 상태 확인 중 오류 (무시): {e}")
                    
                    # 진행률 기반 타임아웃 체크
                    if check_progress_timeout():
                        logger.warning(f"🛑 진행률 기반 타임아웃으로 컨테이너 강제 종료")
                        try:
                            container.stop(timeout=10)
                            container.reload()
                            exit_code = container.attrs['State']['ExitCode'] if container.status == 'exited' else -1
                            container_stopped = True
                            break
                        except Exception as e:
                            logger.error(f"컨테이너 강제 종료 실패: {e}")
                            exit_code = -1
                            container_stopped = True
                            break
                    
                    # 전체 타임아웃 체크 (1시간)
                    elapsed = time.time() - wait_start_time
                    if elapsed >= 3600:
                        logger.warning(f"🛑 전체 타임아웃 (1시간)으로 컨테이너 강제 종료")
                        try:
                            container.stop(timeout=10)
                            exit_code = -1
                            container_stopped = True
                            break
                        except Exception as e:
                            logger.error(f"컨테이너 강제 종료 실패: {e}")
                            exit_code = -1
                            container_stopped = True
                            break
                    
                    # 10초 대기 후 다시 체크
                    time.sleep(10)
                    
            except Exception as e:
                logger.error(f"❌ 컨테이너 대기 중 오류: {e}", exc_info=True)
                exit_code = -1
                # 타임아웃 또는 기타 오류 시 컨테이너 상태 확인
                try:
                    container.reload()
                    logger.error(f"   컨테이너 상태: {container.status}")
                except Exception as reload_error:
                    logger.error(f"   컨테이너 상태 확인 실패: {reload_error}")
            
            # 컨테이너가 아직 실행 중이면 강제 종료 시도
            if not container_stopped:
                logger.warning(f"⚠️ 컨테이너가 아직 실행 중입니다. 강제 종료 시도...")
                try:
                    container.stop(timeout=10)
                    exit_code = -1
                except Exception as e:
                    logger.error(f"컨테이너 강제 종료 실패: {e}")
                    exit_code = -1
            
            # 로그 수집 완료 대기 (최대 5초)
            log_collection_done.wait(timeout=5)
            
            # 최종 로그 수집 (스트리밍에서 놓친 부분 포함)
            try:
                final_logs_raw = container.logs(stdout=True, stderr=True)
                final_logs = final_logs_raw.decode('utf-8', errors='replace')
                
                if logs_lines:
                    logs = '\n'.join(logs_lines) + '\n' + '--- 최종 로그 ---\n' + final_logs
                else:
                    logs = final_logs
                
                # 로그에서 에러 메시지 추출 및 출력
                if exit_code != 0:
                    logger.error(f"❌ 컨테이너가 비정상 종료되었습니다 (exit_code={exit_code})")
                    logger.error(f"📋 상세 로그:")
                    for line in final_logs.split('\n')[-50:]:  # 마지막 50줄만 출력
                        if line.strip():
                            logger.error(f"   {line}")
                
            except docker.errors.APIError as e:
                # 409 Conflict 등 API 에러 처리
                if '409' in str(e) or 'Conflict' in str(e):
                    logger.warning(f"⚠️ 최종 로그 수집 중 컨테이너 충돌 발생 (무시): {e}")
                    logs = '\n'.join(logs_lines) if logs_lines else "로그를 수집할 수 없습니다 (컨테이너 충돌)"
                else:
                    logger.error(f"❌ 최종 로그 수집 API 에러: {e}", exc_info=True)
                    logs = '\n'.join(logs_lines) if logs_lines else f"로그를 수집할 수 없습니다: {e}"
            except Exception as e:
                logger.error(f"❌ 최종 로그 수집 실패: {e}", exc_info=True)
                logs = '\n'.join(logs_lines) if logs_lines else f"로그를 수집할 수 없습니다: {e}"
            
            # 결과 파일 경로는 나중에 _find_latest_result_file에서 찾음
            # 여기서는 성공 여부와 상세 로그 반환
            
            # 워커 종료 후 web 컨테이너 내부 경로에서 파일 존재 여부 체크
            # web 컨테이너 내부에서 실행 중이므로 컨테이너 경로 사용
            container_output_dir = env_vars.get('OUTPUT_DIR')  # 워커의 /app/results
            output_files_exist = False
            output_files_list = []
            
            # web 컨테이너에서 파일 확인 시에는 scan_output_dir 사용 (docker-compose 볼륨 마운트 덕분에 접근 가능)
            # docker-compose.yml: ./scan_results:/app/scan_results
            check_path = scan_output_dir  # web 컨테이너 내부 경로 (예: /app/scan_results/outputs/...)
            
            try:
                logger.info(f"🔍 파일 존재 여부 체크 (web 컨테이너 경로): {check_path}")
                print(f"[DOCKER DEBUG] 🔍 web 컨테이너 경로에서 파일 존재 여부 체크: {check_path}", flush=True)
                
                if check_path.exists():
                    logger.info(f"✅ 디렉토리 존재: {check_path}")
                    print(f"[DOCKER DEBUG] ✅ 디렉토리 존재: {check_path}", flush=True)
                    
                    # 디렉토리 내 파일 목록 확인
                    files = list(check_path.glob('*.json'))
                    if files:
                        output_files_exist = True
                        output_files_list = [str(f) for f in files]
                        logger.info(f"✅ 파일 발견: {len(files)}개 파일")
                        print(f"[DOCKER DEBUG] ✅ 파일 발견: {len(files)}개 파일", flush=True)
                        for f in files[:10]:  # 최대 10개만 출력
                            file_size = f.stat().st_size
                            logger.info(f"   - {f.name} ({file_size} bytes)")
                            print(f"[DOCKER DEBUG]    - {f.name} ({file_size} bytes)", flush=True)
                    else:
                        logger.warning(f"⚠️ 디렉토리는 존재하지만 JSON 파일이 없음: {check_path}")
                        print(f"[DOCKER DEBUG] ⚠️ 디렉토리는 존재하지만 JSON 파일이 없음", flush=True)
                else:
                    logger.warning(f"⚠️ 디렉토리가 존재하지 않음: {check_path}")
                    print(f"[DOCKER DEBUG] ⚠️ 디렉토리가 존재하지 않음: {check_path}", flush=True)
            except Exception as file_check_error:
                logger.error(f"❌ 파일 존재 여부 체크 중 오류: {file_check_error}", exc_info=True)
                print(f"[DOCKER DEBUG] ❌ 파일 존재 여부 체크 중 오류: {file_check_error}", flush=True)
            
            result = {
                'success': exit_code == 0,
                'exit_code': exit_code,
                'logs': logs,
                'container_name': container_name,
                'image': image,
                'output_dir': str(check_path),  # web 컨테이너 경로
                'files_exist': output_files_exist,
                'files_found': output_files_list,
                'files_count': len(output_files_list)
            }
            
            if exit_code != 0:
                result['error'] = f'컨테이너가 비정상 종료되었습니다 (exit_code={exit_code})'
                logger.error(f"📋 전체 로그 (최근 100줄):")
                for line in logs.split('\n')[-100:]:
                    if line.strip():
                        logger.error(f"   {line}")
            
            # 파일 존재 여부 요약 출력
            if output_files_exist:
                logger.info(f"✅ 워커 종료 후 파일 확인 성공: {len(output_files_list)}개 파일 발견")
                print(f"[DOCKER DEBUG] ✅ 워커 종료 후 파일 확인 성공: {len(output_files_list)}개 파일 발견", flush=True)
            else:
                logger.warning(f"⚠️ 워커 종료 후 파일 확인 실패: 호스트 경로에 파일이 없음")
                print(f"[DOCKER DEBUG] ⚠️ 워커 종료 후 파일 확인 실패: 호스트 경로에 파일이 없음", flush=True)
            
            return result
        
        except docker.errors.ImageNotFound:
            logger.error(f"도커 이미지를 찾을 수 없습니다: {image}")
            return {
                'success': False,
                'error': f'이미지를 찾을 수 없습니다: {image}'
            }
        except Exception as e:
            logger.error(f"도커 컨테이너 실행 실패: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _find_latest_result_file(
        self,
        results_dir: Path,
        scanner_type: str,
        target_url: str
    ) -> Optional[Path]:
        """
        결과 디렉토리에서 최신 스캔 결과 파일 찾기
        
        Args:
            results_dir: 결과 디렉토리 경로
            scanner_type: 스캐너 타입 ('nmap', 'nuclei', 'zap')
            target_url: 타겟 URL (파일명 필터링용)
        
        Returns:
            최신 결과 파일 경로 또는 None
        """
        try:
            from urllib.parse import urlparse
            
            # 1차 시도: target_url 기반 패턴
            safe_url = target_url.replace('://', '_').replace('/', '_').replace('.', '_').replace(':', '_')
            pattern = f"{scanner_type}_{safe_url}_*.json"
            
            # [NUCLEI DEBUG] 파일 찾기 디버깅
            if scanner_type == 'nuclei':
                print(f"[NUCLEI DEBUG] ========== 결과 파일 찾기 시작 ==========", flush=True)
                print(f"[NUCLEI DEBUG] 타겟 URL: {target_url}", flush=True)
                print(f"[NUCLEI DEBUG] Safe URL: {safe_url}", flush=True)
                print(f"[NUCLEI DEBUG] 검색 패턴: {pattern}", flush=True)
                print(f"[NUCLEI DEBUG] 결과 디렉토리: {results_dir}", flush=True)
                logger.info(f"[NUCLEI DEBUG] 파일 찾기: pattern={pattern}, dir={results_dir}")
            
            # 매칭되는 파일들 찾기
            matching_files = list(results_dir.glob(pattern))
            
            if scanner_type == 'nuclei':
                print(f"[NUCLEI DEBUG] 정확한 패턴 매칭 결과: {len(matching_files)}개 파일 발견", flush=True)
                for f in matching_files:
                    print(f"[NUCLEI DEBUG]   - {f.name}", flush=True)
            
            # 2차 시도: target_host 기반 패턴 (URL에서 호스트 추출)
            if not matching_files:
                try:
                    parsed = urlparse(target_url)
                    target_host = parsed.hostname or (parsed.netloc.split(':')[0] if parsed.netloc else '')
                    if target_host:
                        safe_host = target_host.replace('.', '_').replace(':', '_')
                        pattern = f"{scanner_type}_{safe_host}_*.json"
                        matching_files = list(results_dir.glob(pattern))
                        if matching_files:
                            logger.info(f"{scanner_type} 결과 파일 발견 (target_host 패턴): {len(matching_files)}개")
                except Exception as e:
                    logger.debug(f"target_host 패턴 시도 실패: {e}")
            
            # 3차 시도: scanner_type으로 시작하는 모든 파일 찾기
            if not matching_files:
                if scanner_type == 'nuclei':
                    print(f"[NUCLEI DEBUG] 정확한 패턴 매칭 실패, fallback 패턴 시도: {scanner_type}_*.json", flush=True)
                
                all_files = [f for f in results_dir.glob(f"{scanner_type}_*.json")]
                if scanner_type == 'nuclei':
                    print(f"[NUCLEI DEBUG] Fallback 패턴 매칭 결과: {len(all_files)}개 파일 발견", flush=True)
                    for f in all_files:
                        print(f"[NUCLEI DEBUG]   - {f.name} (수정 시간: {f.stat().st_mtime})", flush=True)
                
                if all_files:
                    # 수정 시간 기준으로 정렬하여 가장 최신 파일 반환
                    matching_files = sorted(all_files, key=lambda p: p.stat().st_mtime, reverse=True)
                    if matching_files:
                        if scanner_type == 'nuclei':
                            print(f"[NUCLEI DEBUG] 최신 파일 선택: {matching_files[0].name}", flush=True)
                        logger.info(f"{scanner_type} 결과 파일 발견 (fallback): {matching_files[0]}")
                        return matching_files[0]
            
            if matching_files:
                # 타임스탬프가 가장 큰 파일 (가장 최신) 반환
                latest_file = max(matching_files, key=lambda p: p.stat().st_mtime)
                if scanner_type == 'nuclei':
                    print(f"[NUCLEI DEBUG] 최신 파일 선택: {latest_file.name}", flush=True)
                    print(f"[NUCLEI DEBUG] 파일 크기: {latest_file.stat().st_size} bytes", flush=True)
                logger.info(f"{scanner_type} 결과 파일 발견: {latest_file}")
                return latest_file
            
            if scanner_type == 'nuclei':
                print(f"[NUCLEI DEBUG] ⚠️ 결과 파일을 찾을 수 없습니다!", flush=True)
                print(f"[NUCLEI DEBUG] 디렉토리 내 모든 파일:", flush=True)
                try:
                    all_files_in_dir = list(results_dir.iterdir())
                    for f in all_files_in_dir:
                        if f.is_file():
                            print(f"[NUCLEI DEBUG]   - {f.name} ({f.stat().st_size} bytes)", flush=True)
                except Exception as e:
                    print(f"[NUCLEI DEBUG]   - 디렉토리 읽기 실패: {e}", flush=True)
            
            logger.warning(f"{scanner_type} 결과 파일을 찾을 수 없습니다: {results_dir}")
            return None
        
        except Exception as e:
            logger.error(f"결과 파일 찾기 실패 ({scanner_type}): {e}")
            return None
    
    def _enrich_vulnerabilities_with_nvd_data(self, aggregated_data: Dict[str, Any], scan_id: int = None, project_id: int = None) -> Dict[str, Any]:
        """
        CVE-Search API를 통해 NVD 상세 데이터를 수집하여 vulnerabilities에 병합
        
        Args:
            aggregated_data: 통합된 스캔 결과 데이터
            scan_id: 스캔 ID (진행 상황 알림용)
            project_id: 프로젝트 ID (진행 상황 알림용)
        
        Returns:
            NVD 데이터가 병합된 데이터
        """
        import copy
        
        # 데이터 복사 (원본 보존)
        enriched_data = copy.deepcopy(aggregated_data)
        
        # Unified Schema인지 확인
        is_unified_schema = 'vulnerabilities' in enriched_data
        
        if not is_unified_schema:
            logger.warning("통합 스키마가 아니어서 CVE 상세 데이터 병합을 건너뜁니다.")
            return enriched_data
        
        vulnerabilities = enriched_data.get('vulnerabilities', [])
        
        # 데이터 정합성 확인: 취약점이 0개여도 시스템은 계속 진행
        if not vulnerabilities or len(vulnerabilities) == 0:
            logger.warning("⚠️ 발견된 취약점이 0개입니다. Nuclei 결과가 없거나 ZAP만 실행되었을 수 있습니다.")
            print(f"[CVE-SEARCH] ⚠️ 취약점 0개 발견 - ZAP 데이터만으로 진행하거나 CVE ID가 없는 경우 NVD 조회를 건너뜁니다.", flush=True)
            # 취약점이 없어도 데이터 구조는 유지 (AI 분석 시 빈 배열로 처리)
            enriched_data['vulnerabilities'] = []
            return enriched_data
        
        # 모든 CVE ID 수집 (중복 제거) - Nuclei 결과 강화 파싱
        all_cve_ids = set()
        for vuln in vulnerabilities:
            # Nuclei 결과에서 CVE ID 추출 (여러 필드명 지원: cve, cve-id, CVE-ID)
            cve_list = vuln.get('cve', []) or vuln.get('cve-id', []) or vuln.get('CVE-ID', [])
            
            # 문자열인 경우 리스트로 변환
            if isinstance(cve_list, str):
                cve_list = [cve_list]
            elif not isinstance(cve_list, list):
                cve_list = []
            
            # 각 CVE ID 처리 (CVE- 형식 검증 및 대문자 변환)
            import re
            cve_pattern = re.compile(r'^CVE-\d{4}-\d{4,7}$')
            
            for cve_id in cve_list:
                if cve_id and isinstance(cve_id, str):
                    # CVE- 접두사가 있으면 대문자로 변환하여 추가
                    cve_id_upper = cve_id.strip().upper()
                    
                    # ✅ 정규표현식 검증 추가
                    if cve_pattern.match(cve_id_upper):
                        all_cve_ids.add(cve_id_upper)
                    else:
                        logger.warning(f"⚠️ 잘못된 CVE 형식: {cve_id} (무시됨)")
        
        # CVE ID가 없어도 계속 진행 (ZAP 결과만 있어도 AI 분석 가능)
        if len(all_cve_ids) == 0:
            logger.info("⚠️ CVE ID가 발견되지 않았습니다. ZAP 결과만으로 AI 분석을 진행합니다.")
            print(f"[CVE-SEARCH] ⚠️ CVE ID 없음 - ZAP 데이터만으로 AI 분석 진행 (NVD 조회 건너뜀)", flush=True)
            enriched_data['vulnerabilities'] = vulnerabilities
            return enriched_data
        
        logger.info(f"CVE-Search API 호출 준비: {len(all_cve_ids)}개 고유 CVE ID 발견")
        print(f"[CVE-SEARCH] {len(all_cve_ids)}개 고유 CVE ID 발견: {sorted(list(all_cve_ids))[:10]}...", flush=True)
        
        # ✅ CVE 조회 통계 추적
        cve_stats = {
            'total': len(all_cve_ids),
            'success': 0,
            'failed': 0,
            'timeout': 0,
            'not_found': 0
        }
        
        # CVE ID별 NVD 데이터 수집
        cve_nvd_data_map = {}
        cve_search_url = Config.CVE_SEARCH_URL
        
        for cve_id in sorted(all_cve_ids):
            try:
                api_url = f"{cve_search_url}/api/cve/{cve_id}"
                logger.debug(f"CVE-Search API 호출: {api_url}")
                
                response = _make_cve_search_request(api_url, timeout=1800, max_retries=3)
                if response is None:
                    logger.warning(f"⚠️ CVE {cve_id} 조회 실패 (재시도 후에도 실패)")
                    cve_stats['failed'] += 1
                    continue
                
                if response.status_code == 200:
                    nvd_data = response.json()
                    if nvd_data and isinstance(nvd_data, dict):
                        # 필요한 필드만 추출 (CVSS 점수, Summary, CWE 등)
                        enriched_nvd_data = {
                            'cve_id': cve_id,
                            'summary': nvd_data.get('summary', ''),
                            'cvss': nvd_data.get('cvss', 0.0),
                            'cvss_v3': nvd_data.get('cvss-3', {}),
                            'cvss_v2': nvd_data.get('cvss-2', {}),
                            'cvss_score': self._extract_cvss_score(nvd_data),
                            # CVSS v3.1 상세 벡터 정보 추가
                            'cvss_v3_vector': self._extract_cvss_vector(nvd_data, 'v3'),
                            'cvss_v2_vector': self._extract_cvss_vector(nvd_data, 'v2'),
                            'cvss_v3_metrics': self._extract_cvss_metrics(nvd_data, 'v3'),
                            'cvss_v2_metrics': self._extract_cvss_metrics(nvd_data, 'v2'),
                            'cwe': nvd_data.get('cwe', ''),
                            'published': nvd_data.get('Published', ''),
                            'modified': nvd_data.get('Modified', ''),
                            'references': nvd_data.get('references', [])[:5]  # 최대 5개 참조
                        }
                        cve_nvd_data_map[cve_id] = enriched_nvd_data
                        cve_stats['success'] += 1
                        logger.debug(f"✅ CVE {cve_id} NVD 데이터 수집 완료 (CVSS: {enriched_nvd_data.get('cvss_score', 'N/A')})")
                elif response.status_code == 404:
                    logger.debug(f"⚠️ CVE {cve_id}가 CVE-Search 데이터베이스에 없습니다 (404)")
                    cve_stats['not_found'] += 1
                else:
                    logger.warning(f"⚠️ CVE-Search API 오류 (CVE: {cve_id}, Status: {response.status_code})")
                    cve_stats['failed'] += 1
                
                # API 호출 간격 조절 (서버 부하 방지 및 DNS 지연 대비)
                time.sleep(0.5)  # Nuclei가 많은 CVE를 찾을 경우를 대비하여 간격 조정
                
            except requests.exceptions.Timeout:
                logger.warning(f"⚠️ CVE-Search API 타임아웃 (CVE: {cve_id})")
                cve_stats['timeout'] += 1
            except requests.exceptions.ConnectionError:
                logger.error(f"❌ CVE-Search 서버 연결 실패: {cve_search_url}")
                print(f"[CVE-SEARCH] ❌ 서버 연결 실패: {cve_search_url}", flush=True)
                cve_stats['failed'] += 1
                break  # 서버가 없으면 더 이상 시도하지 않음
            except Exception as e:
                logger.error(f"❌ CVE {cve_id} 조회 중 오류: {e}", exc_info=True)
                cve_stats['failed'] += 1
        
        # ✅ 최종 통계 로깅 및 사용자 알림
        logger.info(f"NVD 조회 완료: {cve_stats['success']}/{cve_stats['total']} 성공 (실패: {cve_stats['failed']}, 타임아웃: {cve_stats['timeout']}, 없음: {cve_stats['not_found']})")
        print(f"[CVE-SEARCH] ✅ {cve_stats['success']}/{cve_stats['total']}개 CVE 조회 성공", flush=True)
        
        if cve_stats['failed'] > 0 or cve_stats['timeout'] > 0:
            warning_msg = f"{cve_stats['failed']}개 CVE 조회 실패"
            if cve_stats['timeout'] > 0:
                warning_msg += f", {cve_stats['timeout']}개 타임아웃"
            emit_scan_progress(scan_id, {
                'stage': 'nvd_mapping',
                'progress': 75,
                'message': f'NVD 조회 완료 ({cve_stats["success"]}/{cve_stats["total"]} 성공)',
                'warning': warning_msg
            }, project_id=project_id)
        
        logger.info(f"✅ CVE-Search API 데이터 수집 완료: {len(cve_nvd_data_map)}개 CVE 상세 정보 확보")
        print(f"[CVE-SEARCH] ✅ {len(cve_nvd_data_map)}개 CVE 상세 정보 수집 완료", flush=True)
        
        # vulnerabilities에 nvd_data 필드 병합
        enriched_count = 0
        for vuln in vulnerabilities:
            cve_list = vuln.get('cve', [])
            if isinstance(cve_list, str):
                cve_list = [cve_list]
            elif not isinstance(cve_list, list):
                cve_list = []
            
            # 해당 취약점의 첫 번째 CVE ID에 대한 NVD 데이터를 병합
            nvd_data_list = []
            for cve_id in cve_list:
                if cve_id and isinstance(cve_id, str) and cve_id.upper() in cve_nvd_data_map:
                    nvd_data_list.append(cve_nvd_data_map[cve_id.upper()])
            
            if nvd_data_list:
                vuln['nvd_data'] = nvd_data_list[0] if len(nvd_data_list) == 1 else nvd_data_list
                enriched_count += 1
                
                # CVSS 상세 정보 추가
                if isinstance(vuln['nvd_data'], dict):
                    vuln['cvss_v3_vector'] = vuln['nvd_data'].get('cvss_v3_vector')
                    vuln['cvss_v3_metrics'] = vuln['nvd_data'].get('cvss_v3_metrics', {})
                    # CVSS 상세 설명 추가
                    vuln = self._enrich_cvss_details(vuln)
        
        logger.info(f"✅ {enriched_count}개 취약점에 NVD 데이터 병합 완료")
        print(f"[CVE-SEARCH] ✅ {enriched_count}개 취약점에 NVD 데이터 병합 완료 (CVSS 상세 포함)", flush=True)
        
        enriched_data['vulnerabilities'] = vulnerabilities
        return enriched_data
    
    def _extract_cvss_score(self, nvd_data: Dict[str, Any]) -> float:
        """
        NVD 데이터에서 CVSS 점수 추출 (다양한 형식 지원, 유효성 검증 포함)
        
        Args:
            nvd_data: CVE-Search API에서 받은 NVD 데이터
        
        Returns:
            CVSS 점수 (없거나 유효하지 않으면 0.0)
        """
        if not isinstance(nvd_data, dict):
            return 0.0
        
        # 1. CVSS v3 점수 추출 (다양한 필드명 지원)
        cvss_v3_variants = [
            nvd_data.get('cvss-3', {}),
            nvd_data.get('cvss3', {}),
            nvd_data.get('cvss-3.0', {}),
            nvd_data.get('cvss-3.1', {}),
            nvd_data.get('cvss3.0', {}),
            nvd_data.get('cvss3.1', {})
        ]
        
        for cvss_v3 in cvss_v3_variants:
            if isinstance(cvss_v3, dict):
                # base_score 우선, 없으면 score
                score_v3 = cvss_v3.get('base_score') or cvss_v3.get('score')
                if score_v3 is not None:
                    try:
                        score = float(score_v3)
                        # 유효성 검증: 0.0 ~ 10.0 범위
                        if 0.0 <= score <= 10.0:
                            return score
                        else:
                            logger.warning(f"CVSS v3 점수가 유효 범위를 벗어남: {score}")
                    except (ValueError, TypeError):
                        pass
        
        # 2. CVSS v2 점수 추출 (다양한 필드명 지원)
        cvss_v2_variants = [
            nvd_data.get('cvss-2', {}),
            nvd_data.get('cvss2', {}),
            nvd_data.get('cvss-2.0', {}),
            nvd_data.get('cvss2.0', {})
        ]
        
        for cvss_v2 in cvss_v2_variants:
            if isinstance(cvss_v2, dict):
                score_v2 = cvss_v2.get('base_score') or cvss_v2.get('score')
                if score_v2 is not None:
                    try:
                        score = float(score_v2)
                        # 유효성 검증: 0.0 ~ 10.0 범위
                        if 0.0 <= score <= 10.0:
                            return score
                        else:
                            logger.warning(f"CVSS v2 점수가 유효 범위를 벗어남: {score}")
                    except (ValueError, TypeError):
                        pass
        
        # 3. 직접 cvss 필드 (v2 점수일 수 있음, 유효성 검증 필수)
        cvss = nvd_data.get('cvss')
        if cvss is not None:
            try:
                score = float(cvss)
                # 유효성 검증: 0.0 ~ 10.0 범위
                if 0.0 <= score <= 10.0:
                    return score
                else:
                    logger.warning(f"CVSS 점수가 유효 범위를 벗어남: {score} (무시됨)")
            except (ValueError, TypeError):
                pass
        
        # 4. cvss3, cvss2 직접 필드 (숫자 값)
        cvss3_direct = nvd_data.get('cvss3')
        if cvss3_direct is not None:
            try:
                score = float(cvss3_direct)
                if 0.0 <= score <= 10.0:
                    return score
            except (ValueError, TypeError):
                pass
        
        cvss2_direct = nvd_data.get('cvss2')
        if cvss2_direct is not None:
            try:
                score = float(cvss2_direct)
                if 0.0 <= score <= 10.0:
                    return score
            except (ValueError, TypeError):
                pass
        
        # 모든 방법 실패 시 0.0 반환
        return 0.0
    
    def _extract_cvss_vector(self, nvd_data: Dict[str, Any], version: str = 'v3') -> Optional[str]:
        """
        NVD 데이터에서 CVSS 벡터 문자열 추출
        
        Args:
            nvd_data: CVE-Search API에서 받은 NVD 데이터
            version: 'v3' 또는 'v2'
        
        Returns:
            CVSS 벡터 문자열 (없으면 None)
        """
        if version == 'v3':
            cvss_data = nvd_data.get('cvss-3', {})
            if isinstance(cvss_data, dict):
                return cvss_data.get('vector_string') or cvss_data.get('vectorString') or cvss_data.get('vector')
        elif version == 'v2':
            cvss_data = nvd_data.get('cvss-2', {})
            if isinstance(cvss_data, dict):
                return cvss_data.get('vector_string') or cvss_data.get('vectorString') or cvss_data.get('vector')
        return None
    
    def _extract_cvss_metrics(self, nvd_data: Dict[str, Any], version: str = 'v3') -> Dict[str, Any]:
        """
        NVD 데이터에서 CVSS 상세 지표 추출 (Attack Vector, Complexity 등)
        
        Args:
            nvd_data: CVE-Search API에서 받은 NVD 데이터
            version: 'v3' 또는 'v2'
        
        Returns:
            CVSS 메트릭 딕셔너리
        """
        metrics = {}
        if version == 'v3':
            cvss_data = nvd_data.get('cvss-3', {})
            if isinstance(cvss_data, dict):
                metrics = {
                    'attack_vector': cvss_data.get('attack_vector') or cvss_data.get('attackVector'),
                    'attack_complexity': cvss_data.get('attack_complexity') or cvss_data.get('attackComplexity'),
                    'privileges_required': cvss_data.get('privileges_required') or cvss_data.get('privilegesRequired'),
                    'user_interaction': cvss_data.get('user_interaction') or cvss_data.get('userInteraction'),
                    'scope': cvss_data.get('scope'),
                    'confidentiality_impact': cvss_data.get('confidentiality_impact') or cvss_data.get('confidentialityImpact'),
                    'integrity_impact': cvss_data.get('integrity_impact') or cvss_data.get('integrityImpact'),
                    'availability_impact': cvss_data.get('availability_impact') or cvss_data.get('availabilityImpact'),
                    'base_severity': cvss_data.get('base_severity') or cvss_data.get('baseSeverity'),
                    'exploitability_score': cvss_data.get('exploitability_score') or cvss_data.get('exploitabilityScore'),
                    'impact_score': cvss_data.get('impact_score') or cvss_data.get('impactScore')
                }
        elif version == 'v2':
            cvss_data = nvd_data.get('cvss-2', {})
            if isinstance(cvss_data, dict):
                metrics = {
                    'access_vector': cvss_data.get('access_vector') or cvss_data.get('accessVector'),
                    'access_complexity': cvss_data.get('access_complexity') or cvss_data.get('accessComplexity'),
                    'authentication': cvss_data.get('authentication'),
                    'confidentiality_impact': cvss_data.get('confidentiality_impact') or cvss_data.get('confidentialityImpact'),
                    'integrity_impact': cvss_data.get('integrity_impact') or cvss_data.get('integrityImpact'),
                    'availability_impact': cvss_data.get('availability_impact') or cvss_data.get('availabilityImpact'),
                    'exploitability_score': cvss_data.get('exploitability_score') or cvss_data.get('exploitabilityScore'),
                    'impact_score': cvss_data.get('impact_score') or cvss_data.get('impactScore')
                }
        # None 값 제거
        return {k: v for k, v in metrics.items() if v is not None}
    
    def _enrich_cvss_details(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """
        CVSS 벡터를 상세 설명으로 변환
        
        Args:
            vuln: 취약점 데이터 (cvss_v3_vector 또는 cvss_v3_metrics 포함)
        
        Returns:
            cvss_details가 추가된 취약점 데이터
        """
        # CVSS 벡터 또는 메트릭 확인
        cvss_vector = vuln.get('cvss_v3_vector', '') or vuln.get('cvss_vector', '')
        cvss_metrics = vuln.get('cvss_v3_metrics', {})
        
        if not cvss_vector and not cvss_metrics:
            return vuln
        
        # CVSS 메트릭 설명 매핑
        metrics_descriptions = {
            'attack_vector': {
                'NETWORK': 'Network (네트워크를 통해 공격 가능)',
                'ADJACENT_NETWORK': 'Adjacent Network (인접 네트워크에서 공격 가능)',
                'LOCAL': 'Local (로컬 접근 필요)',
                'PHYSICAL': 'Physical (물리적 접근 필요)',
                'N': 'Network',
                'A': 'Adjacent',
                'L': 'Local',
                'P': 'Physical'
            },
            'attack_complexity': {
                'LOW': 'Low (공격 난이도 낮음)',
                'HIGH': 'High (공격 난이도 높음)',
                'L': 'Low',
                'H': 'High'
            },
            'privileges_required': {
                'NONE': 'None (권한 불필요)',
                'LOW': 'Low (낮은 권한 필요)',
                'HIGH': 'High (높은 권한 필요)',
                'N': 'None',
                'L': 'Low',
                'H': 'High'
            },
            'user_interaction': {
                'NONE': 'None (사용자 조작 불필요)',
                'REQUIRED': 'Required (사용자 조작 필요)',
                'N': 'None',
                'R': 'Required'
            },
            'scope': {
                'UNCHANGED': 'Unchanged (영향 범위 변화 없음)',
                'CHANGED': 'Changed (영향 범위 변화)',
                'U': 'Unchanged',
                'C': 'Changed'
            },
            'confidentiality_impact': {
                'HIGH': 'High (기밀성 영향 높음 - 데이터 유출 가능)',
                'LOW': 'Low (기밀성 영향 낮음)',
                'NONE': 'None (기밀성 영향 없음)',
                'H': 'High',
                'L': 'Low',
                'N': 'None'
            },
            'integrity_impact': {
                'HIGH': 'High (무결성 영향 높음 - 데이터 변조 가능)',
                'LOW': 'Low (무결성 영향 낮음)',
                'NONE': 'None (무결성 영향 없음)',
                'H': 'High',
                'L': 'Low',
                'N': 'None'
            },
            'availability_impact': {
                'HIGH': 'High (가용성 영향 높음 - 서비스 중단 가능)',
                'LOW': 'Low (가용성 영향 낮음)',
                'NONE': 'None (가용성 영향 없음)',
                'H': 'High',
                'L': 'Low',
                'N': 'None'
            }
        }
        
        cvss_details = {
            'vector': cvss_vector
        }
        
        # CVSS 메트릭 설명 추가
        for metric_key, metric_value in cvss_metrics.items():
            if metric_value and metric_key in metrics_descriptions:
                value_upper = str(metric_value).upper()
                description = metrics_descriptions[metric_key].get(value_upper, str(metric_value))
                cvss_details[metric_key] = description
        
        vuln['cvss_details'] = cvss_details
        return vuln
    
    def _generate_vendor_variations(self, cpe: str) -> List[str]:
        """
        CPE 벤더명 변환을 통해 다양한 벤더명 변형 생성
        
        예: cpe:/a:igor_sysoev:nginx:1.19.0 -> 
            - cpe:/a:igor_sysoev:nginx:1.19.0 (원본)
            - cpe:/a:f5:nginx:1.19.0
            - cpe:/a:nginx:nginx:1.19.0
        
        Args:
            cpe: 원본 CPE 문자열
        
        Returns:
            벤더명 변형이 포함된 CPE 리스트
        """
        import re
        from urllib.parse import quote
        
        variations = [cpe]  # 원본 포함
        
        # CPE 형식 파싱: cpe:/a:vendor:product:version
        # cpe:/part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
        cpe_pattern = r'cpe:/a:([^:]+):([^:]+):([^:]+)'
        match = re.match(cpe_pattern, cpe)
        
        if not match:
            return variations
        
        vendor = match.group(1)
        product = match.group(2)
        version = match.group(3)
        
        # 벤더명 매핑 테이블 (일반적인 변환 규칙)
        vendor_mappings = {
            'igor_sysoev': ['f5', 'nginx'],  # Nginx의 경우
            'nginx': ['f5', 'igor_sysoev'],
            'f5': ['nginx', 'igor_sysoev'],
            'apache': ['apache_software_foundation'],
            'apache_software_foundation': ['apache'],
            'microsoft': ['ms', 'microsoft_corporation'],
            'oracle': ['oracle_corporation'],
            'mariadb': ['mariadb_ab'],
            'postgresql': ['postgresql_global_development_group']
        }
        
        # 벤더명 변형 생성
        if vendor in vendor_mappings:
            for alt_vendor in vendor_mappings[vendor]:
                alt_cpe = f"cpe:/a:{alt_vendor}:{product}:{version}"
                if alt_cpe not in variations:
                    variations.append(alt_cpe)
        
        # 제품명이 벤더명과 동일한 경우 (예: nginx:nginx) 추가
        if vendor != product:
            alt_cpe_same = f"cpe:/a:{product}:{product}:{version}"
            if alt_cpe_same not in variations:
                variations.append(alt_cpe_same)
        
        return variations
    
    def _enrich_infrastructure_with_cpe_based_cves(self, aggregated_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Infrastructure의 CPE 정보를 기반으로 NVD에서 잠재적 CVE 역추적 및 저장
        
        CPE 벤더명 변환을 통해 다양한 벤더명으로 검색하여 더 많은 CVE를 발굴합니다.
        예: igor_sysoev -> f5, nginx 등
        
        Args:
            aggregated_data: 통합된 스캔 결과 데이터
        
        Returns:
            CPE 기반 CVE가 추가된 데이터 (infrastructure_vulnerabilities 필드 추가)
        """
        import copy
        from urllib.parse import quote
        
        enriched_data = copy.deepcopy(aggregated_data)
        
        # Unified Schema인지 확인
        is_unified_schema = 'infrastructure' in enriched_data
        if not is_unified_schema:
            logger.warning("통합 스키마가 아니어서 CPE 기반 CVE 역추적을 건너뜁니다.")
            return enriched_data
        
        infrastructure = enriched_data.get('infrastructure', {})
        open_ports = infrastructure.get('open_ports', [])
        services = infrastructure.get('services', [])
        
        # 모든 CPE 수집 (중복 제거)
        all_cpes = set()
        cpe_to_context = {}  # CPE와 해당 서비스/포트 정보 매핑
        
        for port_data in open_ports:
            cpe_list = port_data.get('cpe', [])
            if isinstance(cpe_list, str):
                cpe_list = [cpe_list]
            elif not isinstance(cpe_list, list):
                cpe_list = []
            
            for cpe in cpe_list:
                if cpe and isinstance(cpe, str) and cpe.startswith('cpe:'):
                    all_cpes.add(cpe)
                    if cpe not in cpe_to_context:
                        cpe_to_context[cpe] = {
                            'port': port_data.get('port'),
                            'service': port_data.get('service'),
                            'product': port_data.get('product'),
                            'version': port_data.get('version')
                        }
        
        for service_data in services:
            cpe_list = service_data.get('cpe', [])
            if isinstance(cpe_list, str):
                cpe_list = [cpe_list]
            elif not isinstance(cpe_list, list):
                cpe_list = []
            
            for cpe in cpe_list:
                if cpe and isinstance(cpe, str) and cpe.startswith('cpe:'):
                    all_cpes.add(cpe)
                    if cpe not in cpe_to_context:
                        cpe_to_context[cpe] = {
                            'port': service_data.get('port'),
                            'service': service_data.get('name'),
                            'product': service_data.get('product'),
                            'version': service_data.get('version')
                        }
        
        if not all_cpes:
            logger.info("⚠️ Infrastructure에서 CPE 정보를 찾을 수 없습니다. CPE 기반 CVE 역추적을 건너뜁니다.")
            print(f"[CPE-BASED CVE] ⚠️ CPE 정보 없음 - CPE 기반 역추적 건너뜀", flush=True)
            enriched_data['infrastructure_vulnerabilities'] = []
            return enriched_data
        
        logger.info(f"CPE 기반 CVE 역추적 시작: {len(all_cpes)}개 고유 CPE 발견")
        print(f"[CPE-BASED CVE] {len(all_cpes)}개 고유 CPE 발견: {sorted(list(all_cpes))[:5]}...", flush=True)
        
        # CPE별 CVE 수집 (벤더명 변형 포함)
        infrastructure_vulnerabilities = []
        cve_search_url = Config.CVE_SEARCH_URL
        seen_cve_ids = set()  # 중복 CVE 제거용
        
        for original_cpe in sorted(all_cpes):
            # 벤더명 변형 생성
            cpe_variations = self._generate_vendor_variations(original_cpe)
            logger.info(f"CPE {original_cpe} -> {len(cpe_variations)}개 변형 생성: {cpe_variations}")
            
            for cpe in cpe_variations:
                try:
                    # CVE-Search API: /api/cvefor/{cpe} 엔드포인트 사용
                    cpe_encoded = quote(cpe, safe='')
                    api_url = f"{cve_search_url}/api/cvefor/{cpe_encoded}"
                    logger.debug(f"CPE 기반 CVE 검색: {api_url}")
                    
                    response = _make_cve_search_request(api_url, timeout=1800, max_retries=3)
                    if response is None:
                        logger.warning(f"⚠️ CPE {cpe} 기반 CVE 검색 실패 (재시도 후에도 실패)")
                        time.sleep(1.0)  # 실패해도 다음 CPE 조회 전 대기 (서버 부하 방지)
                        continue
                    
                    # API 호출 간격 조절 (서버 부하 방지 및 DNS 지연 대비)
                    time.sleep(1.0)
                    
                    if response.status_code == 200:
                        cve_list = response.json()
                        
                        # 응답 형식 처리 (리스트 또는 단일 객체)
                        if isinstance(cve_list, dict):
                            if 'id' in cve_list:  # 단일 CVE 객체
                                cve_list = [cve_list]
                            else:
                                cve_list = []
                        elif not isinstance(cve_list, list):
                            cve_list = []
                        
                        logger.info(f"✅ CPE {cpe} 기반 {len(cve_list)}개 CVE 발견")
                        
                        # 각 CVE에 대해 상세 정보 처리 (이미 상세 정보가 포함되어 있을 수 있음)
                        for cve_data in cve_list[:50]:  # 최대 50개 CVE 처리
                            if not isinstance(cve_data, dict):
                                continue
                            
                            cve_id = cve_data.get('id') or cve_data.get('cve_id') or cve_data.get('CVE-ID')
                            if not cve_id or not cve_id.startswith('CVE-'):
                                continue
                            
                            # 중복 CVE 제거 (같은 CVE가 여러 CPE 변형에서 나올 수 있음)
                            if cve_id in seen_cve_ids:
                                continue
                            seen_cve_ids.add(cve_id)
                            
                            # CVE 데이터가 이미 상세 정보를 포함하는지 확인
                            # /api/cvefor는 일반적으로 상세 정보를 반환하지만, 없으면 /api/cve/{cve_id}로 조회
                            nvd_data = cve_data
                            if not nvd_data.get('summary') and not nvd_data.get('cvss'):
                                # 상세 정보가 없으면 별도 조회
                                try:
                                    cve_detail_url = f"{cve_search_url}/api/cve/{cve_id}"
                                    detail_response = _make_cve_search_request(cve_detail_url, timeout=1800, max_retries=3)
                                    if detail_response is None:
                                        continue
                                    if detail_response.status_code == 200:
                                        nvd_data = detail_response.json()
                                    time.sleep(1.0)  # API 호출 간격 (서버 부하 방지)
                                except Exception as detail_e:
                                    logger.warning(f"⚠️ CVE {cve_id} 상세 정보 조회 실패: {detail_e}")
                                    continue
                            
                            # Infrastructure 취약점 데이터 구조 생성
                            infrastructure_vuln = {
                                'cve_id': cve_id,
                                'cpe': original_cpe,  # 원본 CPE 사용
                                'cpe_variations_searched': cpe_variations,  # 검색한 CPE 변형 기록
                                'matched_cpe': cpe,  # 매칭된 CPE 변형
                                'context': cpe_to_context.get(original_cpe, {}),
                                'nvd_data': {
                                    'cve_id': cve_id,
                                    'summary': nvd_data.get('summary', ''),
                                    'cvss_score': self._extract_cvss_score(nvd_data),
                                    'cvss_v3_vector': self._extract_cvss_vector(nvd_data, 'v3'),
                                    'cvss_v2_vector': self._extract_cvss_vector(nvd_data, 'v2'),
                                    'cvss_v3_metrics': self._extract_cvss_metrics(nvd_data, 'v3'),
                                    'cvss_v2_metrics': self._extract_cvss_metrics(nvd_data, 'v2'),
                                    'cwe': nvd_data.get('cwe', ''),
                                    'published': nvd_data.get('Published', '') or nvd_data.get('published', ''),
                                    'modified': nvd_data.get('Modified', '') or nvd_data.get('modified', ''),
                                    'references': nvd_data.get('references', [])[:5] if isinstance(nvd_data.get('references'), list) else []
                                }
                            }
                            infrastructure_vulnerabilities.append(infrastructure_vuln)
                            logger.debug(f"✅ CPE {cpe} 기반 CVE {cve_id} 발견 (CVSS: {infrastructure_vuln['nvd_data'].get('cvss_score', 'N/A')})")
                        
                    elif response.status_code == 404:
                        logger.debug(f"⚠️ CPE {cpe}에 대한 CVE가 없습니다 (404)")
                    else:
                        logger.warning(f"⚠️ CPE 기반 CVE 검색 API 오류 (CPE: {cpe}, Status: {response.status_code})")
                    
                    time.sleep(1.0)  # API 호출 간격 (서버 부하 방지 및 DNS 지연 대비)
                    
                except requests.exceptions.Timeout:
                    logger.warning(f"⚠️ CPE 기반 CVE 검색 타임아웃 (CPE: {cpe})")
                except requests.exceptions.ConnectionError:
                    logger.error(f"❌ CVE-Search 서버 연결 실패: {cve_search_url}")
                    print(f"[CPE-BASED CVE] ❌ 서버 연결 실패: {cve_search_url}", flush=True)
                    break  # 서버가 없으면 더 이상 시도하지 않음
                except Exception as e:
                    logger.error(f"❌ CPE {cpe} 기반 CVE 조회 중 오류: {e}", exc_info=True)
        
        # infrastructure_vulnerabilities 필드 추가
        enriched_data['infrastructure_vulnerabilities'] = infrastructure_vulnerabilities
        logger.info(f"✅ CPE 기반 CVE 역추적 완료: {len(infrastructure_vulnerabilities)}개 고유 CVE 발견")
        print(f"[CPE-BASED CVE] ✅ {len(infrastructure_vulnerabilities)}개 고유 CVE 발견 완료 (벤더명 변형 검색 포함)", flush=True)
        
        return enriched_data
    
    def _enrich_cwe_metadata(self, aggregated_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        CWE 기반 지식 데이터 보강 (CWE 설명 및 권장 대응 방안 수집)
        
        Args:
            aggregated_data: 통합된 스캔 결과 데이터
        
        Returns:
            CWE 메타데이터가 추가된 데이터
        """
        import copy
        enriched_data = copy.deepcopy(aggregated_data)
        
        # Unified Schema인지 확인
        is_unified_schema = 'vulnerabilities' in enriched_data
        if not is_unified_schema:
            logger.warning("통합 스키마가 아니어서 CWE 메타데이터 보강을 건너뜁니다.")
            return enriched_data
        
        vulnerabilities = enriched_data.get('vulnerabilities', [])
        infrastructure_vulnerabilities = enriched_data.get('infrastructure_vulnerabilities', [])
        
        # 모든 CWE 번호 수집 (중복 제거)
        all_cwe_ids = set()
        
        # vulnerabilities에서 CWE 추출
        for vuln in vulnerabilities:
            cwe_list = vuln.get('cwe', [])
            if isinstance(cwe_list, str):
                cwe_list = [cwe_list]
            elif not isinstance(cwe_list, list):
                cwe_list = []
            
            for cwe in cwe_list:
                if cwe:
                    cwe_str = str(cwe).strip()
                    # CWE-79, CWE79, 79 등 다양한 형식 처리
                    if cwe_str.startswith('CWE-'):
                        all_cwe_ids.add(cwe_str.upper())
                    elif cwe_str.startswith('CWE'):
                        all_cwe_ids.add(f"CWE-{cwe_str[3:]}")
                    elif cwe_str.isdigit():
                        all_cwe_ids.add(f"CWE-{cwe_str}")
        
        # infrastructure_vulnerabilities에서 CWE 추출
        for infra_vuln in infrastructure_vulnerabilities:
            nvd_data = infra_vuln.get('nvd_data', {})
            cwe = nvd_data.get('cwe', '')
            if cwe:
                cwe_str = str(cwe).strip()
                if cwe_str.startswith('CWE-'):
                    all_cwe_ids.add(cwe_str.upper())
                elif cwe_str.startswith('CWE'):
                    all_cwe_ids.add(f"CWE-{cwe_str[3:]}")
                elif cwe_str.isdigit():
                    all_cwe_ids.add(f"CWE-{cwe_str}")
        
        if not all_cwe_ids:
            logger.info("⚠️ CWE 번호를 찾을 수 없습니다. CWE 메타데이터 보강을 건너뜁니다.")
            print(f"[CWE ENRICHMENT] ⚠️ CWE 번호 없음 - CWE 메타데이터 보강 건너뜀", flush=True)
            return enriched_data
        
        logger.info(f"CWE 메타데이터 보강 시작: {len(all_cwe_ids)}개 고유 CWE 발견")
        print(f"[CWE ENRICHMENT] {len(all_cwe_ids)}개 고유 CWE 발견: {sorted(list(all_cwe_ids))[:10]}...", flush=True)
        
        # CWE별 메타데이터 수집 (로컬 JSON 파일 우선 사용)
        cwe_metadata_map = {}
        
        for cwe_id in sorted(all_cwe_ids):
            # 캐시에서 먼저 확인 (로컬 JSON 파일)
            if cwe_id in self.cwe_metadata_cache:
                cwe_metadata_map[cwe_id] = self.cwe_metadata_cache[cwe_id]
                logger.debug(f"✅ CWE {cwe_id} 메타데이터 로드 (캐시)")
            else:
                # 캐시에 없으면 플레이스홀더 사용
                cwe_metadata_map[cwe_id] = {
                    'cwe_id': cwe_id,
                    'name': f"CWE-{cwe_id.replace('CWE-', '')}",
                    'description': 'CWE 메타데이터를 찾을 수 없습니다.',
                    'extended_description': '',
                    'common_consequences': '',
                    'potential_mitigations': '',
                    'source': 'placeholder'
                }
                logger.debug(f"⚠️ CWE {cwe_id} 메타데이터 없음 (플레이스홀더 사용)")
        
        # vulnerabilities에 cwe_metadata 필드 병합
        enriched_count = 0
        for vuln in vulnerabilities:
            cwe_list = vuln.get('cwe', [])
            if isinstance(cwe_list, str):
                cwe_list = [cwe_list]
            elif not isinstance(cwe_list, list):
                cwe_list = []
            
            cwe_metadata_list = []
            for cwe in cwe_list:
                cwe_str = str(cwe).strip()
                if cwe_str.startswith('CWE-'):
                    cwe_normalized = cwe_str.upper()
                elif cwe_str.startswith('CWE'):
                    cwe_normalized = f"CWE-{cwe_str[3:]}"
                elif cwe_str.isdigit():
                    cwe_normalized = f"CWE-{cwe_str}"
                else:
                    continue
                
                if cwe_normalized in cwe_metadata_map:
                    cwe_metadata_list.append(cwe_metadata_map[cwe_normalized])
            
            if cwe_metadata_list:
                vuln['cwe_metadata'] = cwe_metadata_list[0] if len(cwe_metadata_list) == 1 else cwe_metadata_list
                enriched_count += 1
        
        logger.info(f"✅ {enriched_count}개 취약점에 CWE 메타데이터 병합 완료")
        print(f"[CWE ENRICHMENT] ✅ {enriched_count}개 취약점에 CWE 메타데이터 병합 완료", flush=True)
        
        # infrastructure_vulnerabilities에도 CWE 메타데이터 병합
        infrastructure_vulnerabilities = enriched_data.get('infrastructure_vulnerabilities', [])
        infra_enriched_count = 0
        
        for infra_vuln in infrastructure_vulnerabilities:
            nvd_data = infra_vuln.get('nvd_data', {})
            cwe = nvd_data.get('cwe', '')
            if cwe:
                cwe_str = str(cwe).strip()
                # CWE 정규화
                if cwe_str.startswith('CWE-'):
                    cwe_normalized = cwe_str.upper()
                elif cwe_str.startswith('CWE'):
                    cwe_normalized = f"CWE-{cwe_str[3:]}"
                elif cwe_str.isdigit():
                    cwe_normalized = f"CWE-{cwe_str}"
                else:
                    continue
                
                # 메타데이터가 있으면 병합
                if cwe_normalized in cwe_metadata_map:
                    if 'nvd_data' not in infra_vuln:
                        infra_vuln['nvd_data'] = {}
                    infra_vuln['nvd_data']['cwe_metadata'] = cwe_metadata_map[cwe_normalized]
                    infra_enriched_count += 1
        
        logger.info(f"✅ {enriched_count}개 취약점 + {infra_enriched_count}개 인프라 취약점에 CWE 메타데이터 병합 완료")
        print(f"[CWE ENRICHMENT] ✅ {enriched_count}개 취약점 + {infra_enriched_count}개 인프라 취약점에 CWE 메타데이터 병합 완료", flush=True)
        
        enriched_data['vulnerabilities'] = vulnerabilities
        enriched_data['infrastructure_vulnerabilities'] = infrastructure_vulnerabilities
        return enriched_data
    
    def _optimize_zap_data_for_ai(self, aggregated_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        스캔 결과를 AI 분석에 최적화 (8B 모델 컨텍스트 한계 고려)
        
        ZAP의 수백 KB짜리 JSON과 Nuclei의 대량 Info/Low 등급 취약점을 통째로 AI에게 주지 않고,
        상위 30-50개의 핵심 취약점만 추출하여 전달합니다.
        
        Args:
            aggregated_data: 통합된 스캔 결과 데이터
        
        Returns:
            최적화된 데이터 (ZAP 상위 30개, Nuclei Info/Low 상위 50개 포함)
        """
        import copy
        
        # 데이터 복사 (원본 보존)
        optimized_data = copy.deepcopy(aggregated_data)
        
        # Unified Schema인지 확인
        is_unified_schema = 'vulnerabilities' in optimized_data
        
        if is_unified_schema:
            vulnerabilities = optimized_data.get('vulnerabilities', [])
            
            # 취약점을 소스별로 분류
            zap_vulns = []
            nuclei_vulns = []
            nuclei_info_low_vulns = []  # Nuclei의 Info/Low 등급 취약점
            other_vulns = []
            
            for vuln in vulnerabilities:
                sources = vuln.get('sources', [])
                if isinstance(sources, str):
                    sources = [sources]
                
                severity = vuln.get('severity', '').lower() or vuln.get('risk', '').lower()
                
                # ZAP 취약점인지 확인
                if 'zap' in sources or vuln.get('source') == 'zap':
                    zap_vulns.append(vuln)
                # Nuclei 취약점인지 확인
                elif 'nuclei' in sources or vuln.get('source') == 'nuclei':
                    # Info/Low 등급은 별도로 분류
                    if severity in ['info', 'low', 'informational']:
                        nuclei_info_low_vulns.append(vuln)
                    else:
                        nuclei_vulns.append(vuln)
                else:
                    other_vulns.append(vuln)
            
            # Risk/Severity 레벨별 정렬 (Critical > High > Medium > Low > Info)
            severity_order = {
                'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1, 'informational': 1,
                'Critical': 5, 'High': 4, 'Medium': 3, 'Low': 2, 'Info': 1, 'Informational': 1
            }
            
            def get_severity_score(vuln):
                severity = vuln.get('severity', '') or vuln.get('risk', 'Low')
                return severity_order.get(severity, 0)
            
            # ZAP 취약점 상위 30개 추출 (등급 분포 유지)
            # 등급별로 골고루 선택하여 분포가 깨지지 않도록 함
            zap_vulns_sorted = sorted(zap_vulns, key=get_severity_score, reverse=True)
            
            # 등급별로 분류
            zap_by_severity = {
                'critical': [],
                'high': [],
                'medium': [],
                'low': [],
                'info': []
            }
            
            for vuln in zap_vulns_sorted:
                severity = (vuln.get('severity', '') or vuln.get('risk', '')).lower()
                if severity in zap_by_severity:
                    zap_by_severity[severity].append(vuln)
                else:
                    zap_by_severity['info'].append(vuln)  # 알 수 없는 등급은 info로 분류
            
            # 등급별 할당량 계산 (총 30개)
            # Critical/High 우선, 나머지는 등급별 비율 유지
            top_zap_vulns = []
            total_needed = 30
            
            # 1단계: Critical과 High는 최대한 많이 포함 (최대 15개)
            critical_high = zap_by_severity['critical'] + zap_by_severity['high']
            critical_high_count = min(len(critical_high), 15)
            top_zap_vulns.extend(critical_high[:critical_high_count])
            remaining = total_needed - len(top_zap_vulns)
            
            # 2단계: 나머지 등급에서 균등 분배
            other_severities = ['medium', 'low', 'info']
            other_vulns = []
            for sev in other_severities:
                other_vulns.extend(zap_by_severity[sev])
            
            # 등급별로 균등하게 선택
            per_severity = max(1, remaining // len(other_severities))
            for sev in other_severities:
                if len(top_zap_vulns) >= total_needed:
                    break
                count = min(per_severity, len(zap_by_severity[sev]), total_needed - len(top_zap_vulns))
                top_zap_vulns.extend(zap_by_severity[sev][:count])
            
            # 3단계: 아직 부족하면 나머지 등급에서 추가
            if len(top_zap_vulns) < total_needed:
                remaining_vulns = [v for v in zap_vulns_sorted if v not in top_zap_vulns]
                top_zap_vulns.extend(remaining_vulns[:total_needed - len(top_zap_vulns)])
            
            # 최적화된 취약점 객체 생성
            optimized_zap_vulns = []
            for vuln in top_zap_vulns:
                optimized_vuln = {
                    'name': vuln.get('name', ''),
                    'risk': vuln.get('risk', vuln.get('severity', 'info')),
                    'severity': vuln.get('severity', vuln.get('risk', 'info')),
                    'url': vuln.get('url', ''),
                    'evidence': vuln.get('evidence', '')[:500] if vuln.get('evidence') else '',
                    'description': vuln.get('description', '')[:300] if vuln.get('description') else '',
                    'sources': vuln.get('sources', ['zap']),
                    'cve': vuln.get('cve', [])[:3] if isinstance(vuln.get('cve'), list) else vuln.get('cve', []),
                    'cwe': vuln.get('cwe', [])[:3] if isinstance(vuln.get('cwe'), list) else vuln.get('cwe', [])
                }
                optimized_zap_vulns.append(optimized_vuln)
            
            top_zap_vulns = optimized_zap_vulns
            
            # Nuclei Info/Low 취약점 상위 50개 추출 (대량 데이터 처리, 등급 분포 유지)
            nuclei_info_low_sorted = sorted(nuclei_info_low_vulns, key=get_severity_score, reverse=True)
            
            # Info/Low 등급별로 분류
            nuclei_info_low_by_severity = {
                'low': [],
                'info': []
            }
            
            for vuln in nuclei_info_low_sorted:
                severity = (vuln.get('severity', '') or 'info').lower()
                if severity == 'low':
                    nuclei_info_low_by_severity['low'].append(vuln)
                else:
                    nuclei_info_low_by_severity['info'].append(vuln)
            
            # 등급별 균등 분배 (Low와 Info 모두 포함)
            top_nuclei_info_low = []
            total_needed = 50
            per_severity = max(1, total_needed // 2)  # Low와 Info 각각 최대 25개
            
            # Low 등급 우선 (위험도가 약간 높음)
            low_count = min(per_severity, len(nuclei_info_low_by_severity['low']))
            top_nuclei_info_low.extend(nuclei_info_low_by_severity['low'][:low_count])
            
            # Info 등급 추가
            info_count = min(total_needed - len(top_nuclei_info_low), len(nuclei_info_low_by_severity['info']))
            top_nuclei_info_low.extend(nuclei_info_low_by_severity['info'][:info_count])
            
            # 최적화된 취약점 객체 생성
            optimized_nuclei_info_low = []
            for vuln in top_nuclei_info_low:
                optimized_vuln = {
                    'name': vuln.get('name', ''),
                    'severity': vuln.get('severity', 'info'),  # 원본 severity 보존
                    'url': vuln.get('url', ''),
                    'description': vuln.get('description', '')[:200] if vuln.get('description') else '',  # Info/Low는 더 짧게
                    'sources': vuln.get('sources', ['nuclei']),
                    'cve': vuln.get('cve', [])[:2] if isinstance(vuln.get('cve'), list) else vuln.get('cve', []),  # Info/Low는 CVE 2개
                    'cwe': vuln.get('cwe', [])[:2] if isinstance(vuln.get('cwe'), list) else vuln.get('cwe', [])  # Info/Low는 CWE 2개
                }
                optimized_nuclei_info_low.append(optimized_vuln)
            
            top_nuclei_info_low = optimized_nuclei_info_low
            
            # 최적화된 취약점 리스트 구성 (ZAP 상위 30개 + Nuclei Medium/High/Critical 전부 + Nuclei Info/Low 상위 50개 + 기타)
            optimized_data['vulnerabilities'] = top_zap_vulns + nuclei_vulns + top_nuclei_info_low + other_vulns
            
            # 로깅
            total_zap_count = len(zap_vulns)
            optimized_zap_count = len(top_zap_vulns)
            total_nuclei_info_low_count = len(nuclei_info_low_vulns)
            optimized_nuclei_info_low_count = len(top_nuclei_info_low)
            
            if total_zap_count > optimized_zap_count:
                logger.info(f"✅ ZAP 결과 최적화: {total_zap_count}개 → {optimized_zap_count}개 (상위 30개 핵심 취약점만 AI에 전달)")
                print(f"[AI OPTIMIZATION] ZAP 취약점 최적화: {total_zap_count}개 → {optimized_zap_count}개", flush=True)
            
            if total_nuclei_info_low_count > optimized_nuclei_info_low_count:
                logger.info(f"✅ Nuclei Info/Low 결과 최적화: {total_nuclei_info_low_count}개 → {optimized_nuclei_info_low_count}개 (상위 50개만 AI에 전달)")
                print(f"[AI OPTIMIZATION] Nuclei Info/Low 취약점 최적화: {total_nuclei_info_low_count}개 → {optimized_nuclei_info_low_count}개", flush=True)
        
        return optimized_data
    
    def _wait_for_result_file(
        self,
        results_dir: Path,
        scanner_type: str,
        target_url: str,
        scan_id: int,
        timeout: int = 300,
        project_id: int = None
    ) -> Optional[Path]:
        """
        결과 파일이 생성될 때까지 대기 (무한루프 방지)
        
        Args:
            results_dir: 결과 디렉토리 경로
            scanner_type: 스캐너 타입 ('nmap', 'nuclei', 'zap')
            target_url: 타겟 URL
            scan_id: 스캔 ID (진행 상황 업데이트용)
            timeout: 최대 대기 시간 (초, 기본값: 5분)
            project_id: 프로젝트 ID (진행 상황 업데이트용)
        
        Returns:
            결과 파일 경로 또는 None (타임아웃 시)
        """
        start_time = time.time()
        check_interval = 2  # 2초마다 확인
        max_attempts = timeout // check_interval
        
        for attempt in range(max_attempts):
            elapsed = time.time() - start_time
            
            # 파일 찾기 시도
            result_file = self._find_latest_result_file(results_dir, scanner_type, target_url)
            if result_file and result_file.exists():
                logger.info(f"{scanner_type} 결과 파일 발견 (대기 시간: {elapsed:.1f}초): {result_file}")
                return result_file
            
            # 타임아웃 체크
            if elapsed >= timeout:
                logger.warning(f"{scanner_type} 결과 파일 대기 타임아웃 ({timeout}초 초과)")
                emit_scan_progress(scan_id, {
                    'stage': 'waiting_files',
                    'progress': 65,
                    'message': f'{scanner_type} 결과 파일 대기 타임아웃'
                }, project_id=project_id)
                return None
            
            # 진행 상황 업데이트 (10초마다)
            if attempt % 5 == 0:
                emit_scan_progress(scan_id, {
                    'stage': 'waiting_files',
                    'progress': 65,
                    'message': f'{scanner_type} 결과 파일 대기 중... ({int(elapsed)}/{timeout}초)'
                }, project_id=project_id)
            
            time.sleep(check_interval)
        
        logger.warning(f"{scanner_type} 결과 파일을 찾을 수 없습니다 (최대 시도 횟수 초과)")
        return None


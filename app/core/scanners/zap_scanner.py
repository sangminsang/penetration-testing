"""
ZAP 스캐너 모듈

OWASP ZAP를 사용하여 웹 애플리케이션 보안 스캔을 수행합니다.
도커 컨테이너에서 실행되며, 결과를 JSON 파일로 저장합니다.
"""

import time
import logging
import socket
from typing import Dict, List, Any, Optional
from pathlib import Path
from zapv2 import ZAPv2 as ZAPv2Client  # 변수 이름 충돌 방지를 위해 별칭 사용
from app.config import Config

logger = logging.getLogger(__name__)


class ZapScanner:
    """
    ZAP 스캐너 클래스
    
    OWASP ZAP API를 사용하여 웹 애플리케이션 보안 스캔을 수행합니다.
    """
    
    def __init__(
        self,
        target_url: str,
        output_dir: str = None,
        api_key: str = None,
        proxy_host: str = None,
        proxy_port: int = None,
        timeout: int = None
    ):
        """
        ZAP 스캐너 초기화
        
        Args:
            target_url: 스캔 대상 URL
            output_dir: 결과 파일 저장 디렉토리
            api_key: ZAP API 키
            proxy_host: ZAP 프록시 호스트
            proxy_port: ZAP 프록시 포트
            timeout: 스캔 타임아웃 (초)
        """
        self.target_url = target_url
        self.output_dir = output_dir or Config.SCAN_RESULTS_DIR
        self.api_key = api_key or Config.ZAP_API_KEY
        self.proxy_host = proxy_host or Config.ZAP_PROXY_HOST
        self.proxy_port = proxy_port or Config.ZAP_PROXY_PORT
        self.timeout = timeout or Config.ZAP_TIMEOUT
        
        # 출력 디렉토리 생성
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        
        # ZAP 클라이언트 초기화 (변수 이름 충돌 방지: zap_client 사용)
        self.zap_client = None
        self._init_zap_client()
    
    def _init_zap_client(self):
        """ZAP API 클라이언트 초기화"""
        try:
            # ZAP 프록시 설정
            zap_proxy_host = self.proxy_host  # 호스트 변수 (문자열)
            zap_proxy_port = self.proxy_port  # 포트 변수 (정수)
            
            proxies = {
                'http': f'http://{zap_proxy_host}:{zap_proxy_port}',
                'https': f'http://{zap_proxy_host}:{zap_proxy_port}'
            }
            
            # ZAPv2 클라이언트 생성 (변수 이름 충돌 방지: ZAPv2Client 사용)
            self.zap_client = ZAPv2Client(apikey=self.api_key, proxies=proxies)
            
            # 연결 테스트 (방어적 코드: callable 체크)
            zap_version_method = self.zap_client.core.version
            if callable(zap_version_method):
                zap_version = zap_version_method()
            else:
                # version이 메서드가 아닌 경우 (이상 케이스)
                zap_version = str(zap_version_method) if zap_version_method else "unknown"
                logger.warning(f"ZAP version이 callable이 아닙니다: {type(zap_version_method)}")
            
            logger.info(f"ZAP 클라이언트 초기화 완료 (버전: {zap_version})")
            logger.info(f"ZAP 프록시: {zap_proxy_host}:{zap_proxy_port}")
            print(f"[ZAP] 클라이언트 초기화 완료: {zap_proxy_host}:{zap_proxy_port} (버전: {zap_version})", flush=True)
        
        except Exception as e:
            logger.error(f"ZAP 클라이언트 초기화 실패: {e}", exc_info=True)
            print(f"[ZAP] ❌ 클라이언트 초기화 실패: {e}", flush=True)
            import traceback
            print(f"[ZAP] 트레이스백:\n{traceback.format_exc()}", flush=True)
            self.zap_client = None
    
    def run_scan(self, discovered_urls: List[str] = None) -> Dict[str, Any]:
        """
        ZAP 스캔 실행
        
        Args:
            discovered_urls: Katana/Nuclei로 발견한 URL 목록 (선택적)
                            제공되면 이 URL들만 스캔 (최적화)
        
        Returns:
            스캔 결과 딕셔너리
            {
                'alerts': [...],  # 발견된 보안 경고
                'spider_results': {...},  # 크롤링 결과
                'active_scan_results': {...}  # 공격 스캔 결과
            }
        """
        if self.zap_client is None:
            return {
                'success': False,
                'error': 'ZAP 클라이언트가 초기화되지 않았습니다',
                'alerts': []
            }
        
        logger.info(f"ZAP 스캔 시작: {self.target_url}")
        print(f"[ZAP] 스캔 시작: {self.target_url}", flush=True)
        print(f"[ZAP] ZAP 프록시: {self.proxy_host}:{self.proxy_port}", flush=True)
        
        try:
            # Step 1: 타겟 URL 접근 (ZAP이 인식하도록)
            print(f"[ZAP] Step 1: 타겟 URL 접근 중...", flush=True)
            if not self._access_target(self.target_url):
                print(f"[ZAP] ❌ 타겟 URL 접근 실패", flush=True)
                return {
                    'success': False,
                    'error': '타겟 URL에 접근할 수 없습니다',
                    'alerts': []
                }
            print(f"[ZAP] ✅ 타겟 URL 접근 성공", flush=True)
            
            # Step 2: Spider 크롤링 (URL 목록이 없을 때만)
            spider_results = {}
            if not discovered_urls:
                print(f"[ZAP] Step 2: Spider 크롤링 시작...", flush=True)
                logger.info("ZAP Spider 크롤링 시작")
                spider_results = self._run_spider()
                print(f"[ZAP] Step 2 완료: Spider 크롤링 완료", flush=True)
            else:
                print(f"[ZAP] Step 2 생략: {len(discovered_urls)}개 URL 사용 (Spider 불필요)", flush=True)
            
            # Step 3: Active Scan (공격 스캔)
            print(f"[ZAP] Step 3: Active Scan 시작...", flush=True)
            logger.info("ZAP Active Scan 시작")
            active_scan_results = self._run_active_scan(discovered_urls)
            print(f"[ZAP] Step 3 완료: Active Scan 완료", flush=True)
            
            # Step 4: 알림 수집
            print(f"[ZAP] Step 4: 알림 수집 중...", flush=True)
            alerts = self._get_alerts()
            print(f"[ZAP] Step 4 완료: {len(alerts)}개 경고 발견", flush=True)
            
            # 결과 저장
            result = {
                'success': True,
                'alerts': alerts,
                'spider_results': spider_results,
                'active_scan_results': active_scan_results
            }
            
            output_file = self._save_results(result)
            result['output_file'] = str(output_file)
            
            logger.info(f"ZAP 스캔 완료: {len(alerts)}개 경고 발견")
            print(f"[ZAP] ✅ 스캔 완료: {len(alerts)}개 경고 발견", flush=True)
            
            return result
        
        except Exception as e:
            logger.error(f"ZAP 스캔 오류: {e}", exc_info=True)
            print(f"[ZAP] ❌ 스캔 오류: {e}", flush=True)
            import traceback
            print(f"[ZAP] 트레이스백:\n{traceback.format_exc()}", flush=True)
            return {
                'success': False,
                'error': str(e),
                'alerts': []
            }
    
    def _access_target(self, url: str) -> bool:
        """
        타겟 URL 접근 (ZAP이 인식하도록)
        
        Args:
            url: 접근할 URL
            
        Returns:
            성공 여부
        """
        try:
            self.zap_client.core.access_url(url=url, followredirects=True)
            return True
        except Exception as e:
            logger.error(f"타겟 접근 실패: {e}")
            return False
    
    def _run_spider(self) -> Dict[str, Any]:
        """
        ZAP Spider 크롤링 실행 (진행률 기반 타임아웃 포함)
        
        Returns:
            크롤링 결과
        """
        try:
            scan_id = self.zap_client.spider.scan(
                url=self.target_url,
                maxchildren=100,
                recurse=True
            )
            
            # 크롤링 완료 대기 (진행률 기반 타임아웃)
            start_time = time.time()
            timeout = 1800  # 전체 타임아웃: 30분
            progress_timeout = 300  # 진행률 변화 없으면 5분 후 종료
            last_progress = None
            last_progress_time = None
            
            print(f"[ZAP] Spider 크롤링 진행률 모니터링 시작 (진행률 변화 없으면 {progress_timeout}초 후 종료)", flush=True)
            
            while True:
                try:
                    status = int(self.zap_client.spider.status(scan_id))
                    current_time = time.time()
                    
                    # 진행률 출력
                    if status != last_progress:
                        print(f"[ZAP] Spider 진행률: {status}%", flush=True)
                        last_progress = status
                        last_progress_time = current_time
                    elif last_progress_time:
                        # 진행률이 변하지 않은 시간 계산
                        stuck_duration = current_time - last_progress_time
                        if stuck_duration >= progress_timeout:
                            print(f"[ZAP] ⚠️ 진행률 기반 타임아웃: {stuck_duration:.1f}초 동안 진행률 변화 없음 (마지막 진행률: {status}%)", flush=True)
                            logger.warning(f"Spider 진행률 기반 타임아웃: {stuck_duration:.1f}초 동안 진행률 변화 없음")
                            self.zap_client.spider.stop(scan_id)
                            break
                    
                    # 완료 체크
                    if status >= 100:
                        print(f"[ZAP] ✅ Spider 크롤링 완료 (진행률: {status}%)", flush=True)
                        break
                    
                    # 전체 타임아웃 체크
                    if current_time - start_time > timeout:
                        print(f"[ZAP] ⚠️ 전체 타임아웃 ({timeout}초)으로 Spider 중단", flush=True)
                        logger.warning(f"Spider 전체 타임아웃: {timeout}초")
                        self.zap_client.spider.stop(scan_id)
                        break
                    
                    time.sleep(2)
                    
                except Exception as status_error:
                    logger.error(f"Spider 상태 확인 중 오류: {status_error}")
                    # 오류가 발생해도 계속 시도
                    time.sleep(2)
                    continue
            
            try:
                urls_found = self.zap_client.spider.results(scan_id)
                final_status = int(self.zap_client.spider.status(scan_id))
            except Exception as e:
                logger.warning(f"Spider 결과 수집 중 오류: {e}")
                urls_found = []
                final_status = status if 'status' in locals() else 0
            
            return {
                'scan_id': scan_id,
                'status': 'completed' if final_status >= 100 else 'partial',
                'urls_found': urls_found,
                'progress': final_status
            }
        
        except Exception as e:
            logger.error(f"Spider 크롤링 실패: {e}")
            print(f"[ZAP] ❌ Spider 크롤링 실패: {e}", flush=True)
            return {'status': 'failed', 'error': str(e)}
    
    def _run_active_scan(self, target_urls: List[str] = None) -> Dict[str, Any]:
        """
        Active Scan 실행 (공격 스캔)
        
        Args:
            target_urls: 스캔할 URL 목록 (없으면 타겟 URL만)
        
        Returns:
            스캔 결과
        """
        try:
            if target_urls:
                # URL 목록이 있으면 각각 스캔
                scanned_count = 0
                scan_ids_list = []  # 스캔 ID 목록 저장
                
                print(f"[ZAP] {len(target_urls[:50])}개 URL에 대한 Active Scan 시작...", flush=True)
                
                for url in target_urls[:50]:  # 최대 50개만 (성능 고려)
                    try:
                        scan_id = self.zap_client.ascan.scan(
                            url=url,
                            recurse=False,  # 하위 경로 탐색 안 함 (이미 Katana가 찾음)
                            inscopeonly=False
                        )
                        scan_ids_list.append(scan_id)
                        scanned_count += 1
                        if scanned_count % 10 == 0:
                            print(f"[ZAP] {scanned_count}개 URL 스캔 시작됨...", flush=True)
                    except Exception as e:
                        logger.warning(f"URL 스캔 실패 ({url}): {e}")
                        print(f"[ZAP] ⚠️ URL 스캔 실패 ({url}): {e}", flush=True)
                
                print(f"[ZAP] 총 {scanned_count}개 스캔 시작 완료, 완료 대기 중...", flush=True)
                
                # 모든 스캔 완료 대기 (진행률 기반 타임아웃 포함)
                if scan_ids_list:
                    self._wait_for_scans_to_finish_with_ids(scan_ids_list)
                else:
                    # 스캔 ID 목록이 없으면 기본 방법 사용
                    self._wait_for_scans_to_finish()
                
                return {
                    'status': 'completed',
                    'scanned_count': scanned_count,
                    'total_urls': len(target_urls)
                }
            else:
                # 타겟 URL만 스캔
                scan_id = self.zap_client.ascan.scan(
                    url=self.target_url,
                    recurse=True,
                    inscopeonly=False
                )
                
                # 스캔 완료 대기 (진행률 기반 타임아웃 포함)
                start_time = time.time()
                timeout = self.timeout  # 전체 타임아웃
                progress_timeout = 300  # 진행률 변화 없으면 5분 후 종료
                last_progress = None
                last_progress_time = None
                
                print(f"[ZAP] Active Scan 진행률 모니터링 시작 (진행률 변화 없으면 {progress_timeout}초 후 종료)", flush=True)
                
                while True:
                    try:
                        status = int(self.zap_client.ascan.status(scan_id))
                        current_time = time.time()
                        
                        # 진행률 출력
                        if status != last_progress:
                            print(f"[ZAP] Active Scan 진행률: {status}%", flush=True)
                            last_progress = status
                            last_progress_time = current_time
                        elif last_progress_time:
                            # 진행률이 변하지 않은 시간 계산
                            stuck_duration = current_time - last_progress_time
                            if stuck_duration >= progress_timeout:
                                print(f"[ZAP] ⚠️ 진행률 기반 타임아웃: {stuck_duration:.1f}초 동안 진행률 변화 없음 (마지막 진행률: {status}%)", flush=True)
                                logger.warning(f"Active Scan 진행률 기반 타임아웃: {stuck_duration:.1f}초 동안 진행률 변화 없음")
                                self.zap_client.ascan.stop(scan_id)
                                break
                        
                        # 완료 체크
                        if status >= 100:
                            print(f"[ZAP] ✅ Active Scan 완료 (진행률: {status}%)", flush=True)
                            break
                        
                        # 전체 타임아웃 체크
                        if current_time - start_time > timeout:
                            print(f"[ZAP] ⚠️ 전체 타임아웃 ({timeout}초)으로 Active Scan 중단", flush=True)
                            logger.warning(f"Active Scan 전체 타임아웃: {timeout}초")
                            self.zap_client.ascan.stop(scan_id)
                            break
                        
                        time.sleep(5)
                        
                    except Exception as status_error:
                        logger.error(f"Active Scan 상태 확인 중 오류: {status_error}")
                        # 오류가 발생해도 계속 시도
                        time.sleep(5)
                        continue
                
                try:
                    final_status = int(self.zap_client.ascan.status(scan_id))
                except Exception as e:
                    logger.warning(f"Active Scan 최종 상태 확인 중 오류: {e}")
                    final_status = status if 'status' in locals() else 0
                
                return {
                    'scan_id': scan_id,
                    'status': 'completed' if final_status >= 100 else 'partial',
                    'progress': final_status
                }
        
        except Exception as e:
            logger.error(f"Active Scan 실패: {e}")
            return {'status': 'failed', 'error': str(e)}
    
    def _wait_for_scans_to_finish_with_ids(self, scan_ids: List[str]):
        """
        특정 스캔 ID 목록에 대한 완료 대기 (진행률 기반 타임아웃 포함)
        
        Args:
            scan_ids: 대기할 스캔 ID 목록
        """
        if not scan_ids:
            logger.info("대기할 스캔이 없습니다")
            return
        
        logger.info(f"ZAP 스캔 완료 대기 중: {len(scan_ids)}개 스캔")
        print(f"[ZAP] Active Scan 완료 대기 중: {len(scan_ids)}개 스캔 (진행률 변화 없으면 300초 후 종료)", flush=True)
        
        start_time = time.time()
        timeout = self.timeout  # 전체 타임아웃
        progress_timeout = 300  # 진행률 변화 없으면 5분 후 종료
        last_total_progress = None
        last_progress_time = None
        
        while True:
            try:
                # 전체 진행률 계산 (모든 스캔의 평균 진행률)
                total_progress = 0
                active_scans = 0
                
                for scan_id in scan_ids:
                    try:
                        progress = int(self.zap_client.ascan.status(scan_id))
                        total_progress += progress
                        active_scans += 1
                        if progress >= 100:
                            # 완료된 스캔은 건너뛰기
                            continue
                    except Exception as e:
                        logger.debug(f"스캔 {scan_id} 진행률 확인 실패 (완료된 것으로 간주): {e}")
                        # 오류 발생 시 완료된 것으로 간주
                        total_progress += 100
                        active_scans += 1
                        continue
                
                if active_scans > 0:
                    avg_progress = total_progress / active_scans
                else:
                    avg_progress = 100
                
                current_time = time.time()
                
                # 진행률 출력
                if avg_progress != last_total_progress:
                    print(f"[ZAP] Active Scan 전체 진행률: {avg_progress:.1f}% (총 스캔: {active_scans}개)", flush=True)
                    last_total_progress = avg_progress
                    last_progress_time = current_time
                elif last_progress_time:
                    # 진행률이 변하지 않은 시간 계산
                    stuck_duration = current_time - last_progress_time
                    if stuck_duration >= progress_timeout:
                        print(f"[ZAP] ⚠️ 진행률 기반 타임아웃: {stuck_duration:.1f}초 동안 진행률 변화 없음 (평균 진행률: {avg_progress:.1f}%)", flush=True)
                        logger.warning(f"Active Scan 진행률 기반 타임아웃: {stuck_duration:.1f}초 동안 진행률 변화 없음")
                        # 모든 스캔 중단
                        for scan_id in scan_ids:
                            try:
                                self.zap_client.ascan.stop(scan_id)
                            except Exception as e:
                                logger.warning(f"스캔 {scan_id} 중단 실패: {e}")
                        break
                
                # 전체 타임아웃 체크
                if current_time - start_time > timeout:
                    print(f"[ZAP] ⚠️ 전체 타임아웃 ({timeout}초)으로 모든 Active Scan 중단", flush=True)
                    logger.warning(f"Active Scan 전체 타임아웃: {timeout}초")
                    # 모든 스캔 중단
                    for scan_id in scan_ids:
                        try:
                            self.zap_client.ascan.stop(scan_id)
                        except Exception as e:
                            logger.warning(f"스캔 {scan_id} 중단 실패: {e}")
                    break
                
                # 모든 스캔이 완료되었는지 확인
                all_complete = True
                for scan_id in scan_ids:
                    try:
                        progress = int(self.zap_client.ascan.status(scan_id))
                        if progress < 100:
                            all_complete = False
                            break
                    except Exception:
                        # 오류 발생 시 완료된 것으로 간주
                        continue
                
                if all_complete:
                    print(f"[ZAP] ✅ 모든 Active Scan 완료 (평균 진행률: 100%)", flush=True)
                    break
                
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"스캔 완료 대기 중 오류: {e}", exc_info=True)
                # 오류 발생 시 계속 시도
                time.sleep(5)
                continue
        
        logger.info("모든 ZAP 스캔 완료 대기 종료")
    
    def _wait_for_scans_to_finish(self):
        """
        모든 Active Scan 완료 대기 (기존 API 사용, 하위 호환성)
        """
        logger.info("모든 ZAP 스캔 완료 대기 중...")
        print(f"[ZAP] 모든 Active Scan 완료 대기 중 (진행률 변화 없으면 300초 후 종료)", flush=True)
        
        start_time = time.time()
        timeout = self.timeout  # 전체 타임아웃
        progress_timeout = 300  # 진행률 변화 없으면 5분 후 종료
        last_total_progress = None
        last_progress_time = None
        
        while True:
            try:
                # ZAP API를 통해 실행 중인 스캔 확인
                try:
                    scans = self.zap_client.ascan.scans
                except AttributeError:
                    # scans 속성이 없는 경우 scans_ids 시도
                    try:
                        scan_ids = self.zap_client.ascan.scans_ids
                        scans = [{'id': sid} for sid in scan_ids] if scan_ids else []
                    except Exception:
                        scans = []
                
                if not scans:
                    print(f"[ZAP] ✅ 모든 Active Scan 완료", flush=True)
                    break
                
                # 실행 중인 스캔만 필터링
                running_scans = [s for s in scans if s.get('state', '').upper() != 'FINISHED']
                if not running_scans:
                    print(f"[ZAP] ✅ 모든 Active Scan 완료", flush=True)
                    break
                
                # 전체 진행률 계산
                total_progress = 0
                active_count = 0
                for scan in running_scans:
                    scan_id = scan.get('id') or scan.get('scanId')
                    if scan_id:
                        try:
                            progress = int(self.zap_client.ascan.status(scan_id))
                            total_progress += progress
                            active_count += 1
                        except Exception as e:
                            logger.debug(f"스캔 {scan_id} 진행률 확인 실패: {e}")
                            continue
                
                if active_count > 0:
                    avg_progress = total_progress / active_count
                else:
                    avg_progress = 100
                
                current_time = time.time()
                
                # 진행률 출력
                if avg_progress != last_total_progress:
                    print(f"[ZAP] Active Scan 전체 진행률: {avg_progress:.1f}% (활성 스캔: {active_count}개)", flush=True)
                    last_total_progress = avg_progress
                    last_progress_time = current_time
                elif last_progress_time:
                    # 진행률이 변하지 않은 시간 계산
                    stuck_duration = current_time - last_progress_time
                    if stuck_duration >= progress_timeout:
                        print(f"[ZAP] ⚠️ 진행률 기반 타임아웃: {stuck_duration:.1f}초 동안 진행률 변화 없음 (평균 진행률: {avg_progress:.1f}%)", flush=True)
                        logger.warning(f"Active Scan 진행률 기반 타임아웃: {stuck_duration:.1f}초 동안 진행률 변화 없음")
                        # 모든 스캔 중단
                        for scan in running_scans:
                            scan_id = scan.get('id') or scan.get('scanId')
                            if scan_id:
                                try:
                                    self.zap_client.ascan.stop(scan_id)
                                except Exception as e:
                                    logger.warning(f"스캔 {scan_id} 중단 실패: {e}")
                        break
                
                # 전체 타임아웃 체크
                if current_time - start_time > timeout:
                    print(f"[ZAP] ⚠️ 전체 타임아웃 ({timeout}초)으로 모든 Active Scan 중단", flush=True)
                    logger.warning(f"Active Scan 전체 타임아웃: {timeout}초")
                    # 모든 스캔 중단
                    for scan in running_scans:
                        scan_id = scan.get('id') or scan.get('scanId')
                        if scan_id:
                            try:
                                self.zap_client.ascan.stop(scan_id)
                            except Exception as e:
                                logger.warning(f"스캔 {scan_id} 중단 실패: {e}")
                    break
                
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"스캔 완료 대기 중 오류: {e}", exc_info=True)
                # 오류 발생 시 계속 시도
                time.sleep(5)
                continue
        
        logger.info("모든 ZAP 스캔 완료 대기 종료")
    
    def _get_alerts(self, risk_levels: List[str] = None) -> List[Dict[str, Any]]:
        """
        보안 경고 수집 (개선: instancerefs, extracted-results 등 모든 필드 포함)
        
        Args:
            risk_levels: 수집할 위험도 목록 (예: ['High', 'Medium'])
        
        Returns:
            경고 목록 (모든 필드 포함)
        """
        if risk_levels is None:
            risk_levels = Config.ZAP_DEFAULT_RISK_LEVELS
        
        try:
            all_alerts = self.zap_client.core.alerts(baseurl=self.target_url)
            filtered_alerts = []
            
            for alert in all_alerts:
                if alert.get('risk') in risk_levels:
                    # 기본 필드
                    alert_data = {
                        'alert': alert.get('alert', ''),
                        'name': alert.get('alert', ''),
                        'risk': alert.get('risk', ''),
                        'riskcode': alert.get('riskcode', ''),
                        'url': alert.get('url', ''),
                        'uri': alert.get('uri', ''),
                        'description': alert.get('description', ''),
                        'desc': alert.get('desc', ''),
                        'solution': alert.get('solution', ''),
                        'evidence': alert.get('evidence', ''),
                        'confidence': alert.get('confidence', ''),
                        'reliability': alert.get('reliability', ''),
                        'cweid': alert.get('cweid', ''),
                        'wascid': alert.get('wascid', ''),
                        'pluginid': alert.get('pluginid', ''),
                        'id': alert.get('pluginid', ''),
                        # 🆕 추가 필드들
                        'instancerefs': alert.get('instancerefs', []),  # 인스턴스 참조 배열
                        'other': alert.get('other', ''),  # 기타 정보
                        'reference': alert.get('reference', ''),  # 참조 링크
                        'param': alert.get('param', ''),  # 취약한 파라미터
                        'attack': alert.get('attack', ''),  # 공격 페이로드
                        'messageId': alert.get('messageId', ''),  # 메시지 ID
                    }
                    
                    # instancerefs에서 상세 정보 추출
                    instancerefs = alert.get('instancerefs', [])
                    if instancerefs and isinstance(instancerefs, list):
                        instances_data = []
                        for instance in instancerefs:
                            instance_info = {
                                'method': instance.get('method', ''),
                                'uri': instance.get('uri', ''),
                                'parameter': instance.get('parameter', ''),
                                'attack': instance.get('attack', ''),
                                'evidence': instance.get('evidence', ''),
                                'other': instance.get('other', ''),
                                'requestHeader': instance.get('requestHeader', ''),
                                'requestBody': instance.get('requestBody', ''),
                                'responseHeader': instance.get('responseHeader', ''),
                                'responseBody': instance.get('responseBody', ''),
                                'extracted-results': instance.get('extracted-results', ''),  # 🆕 중요!
                            }
                            instances_data.append(instance_info)
                        alert_data['instances'] = instances_data
                    
                    filtered_alerts.append(alert_data)
            
            return filtered_alerts
        
        except Exception as e:
            logger.error(f"경고 수집 실패: {e}")
            return []
    
    def _save_results(self, data: Dict[str, Any]) -> Path:
        """
        스캔 결과를 파일로 저장
        
        Args:
            data: 저장할 데이터
            
        Returns:
            저장된 파일 경로
        """
        import time
        
        timestamp = int(time.time())
        safe_url = self.target_url.replace('://', '_').replace('/', '_').replace('.', '_').replace(':', '_')
        filename = f"zap_{safe_url}_{timestamp}.json"
        filepath = Path(self.output_dir) / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            import json
            json.dump({
                'target': self.target_url,
                'timestamp': timestamp,
                **data
            }, f, ensure_ascii=False, indent=2)
        
        logger.info(f"ZAP 결과 저장: {filepath}")
        return filepath


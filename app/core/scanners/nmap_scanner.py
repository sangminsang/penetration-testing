"""
Nmap 스캐너 모듈

네트워크 포트 및 서비스 탐지를 수행합니다.
도커 컨테이너에서 실행되며, 결과를 JSON 파일로 저장합니다.
"""

import subprocess
import json
import logging
import os
import xmltodict
import threading
import time
from typing import Dict, List, Any, Optional
from pathlib import Path
from app.config import Config

logger = logging.getLogger(__name__)


class NmapScanner:
    """
    Nmap 스캐너 클래스
    
    네트워크 포트 스캔, 서비스 버전 탐지, 취약점 스크립트 실행을 수행합니다.
    """
    
    def __init__(self, target_url: str, output_dir: str = None):
        """
        Nmap 스캐너 초기화
        
        Args:
            target_url: 스캔 대상 URL (예: https://example.com)
            output_dir: 결과 파일 저장 디렉토리
        """
        self.target_url = target_url
        self.output_dir = output_dir or Config.SCAN_RESULTS_DIR
        
        # 출력 디렉토리 생성
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        
        # URL에서 호스트명 추출
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        self.target_host = parsed.hostname or parsed.netloc.split(':')[0]
        
        # 진행률 기반 타임아웃 설정 (정밀 스캔 시 침묵이 길 수 있으므로 20분으로 대폭 증가)
        self.progress_timeout = int(os.environ.get('NMAP_PROGRESS_TIMEOUT', 1200))  # 기본 20분 (1200초)
    
    def run_scan(self) -> Dict[str, Any]:
        """
        Nmap 스캔 실행
        
        Returns:
            스캔 결과 딕셔너리
            {
                'hosts': [...],  # 발견된 호스트 정보
                'ports': [...],  # 열린 포트 정보
                'services': [...],  # 서비스 정보
                'vulnerabilities': [...]  # 발견된 취약점
            }
        """
        logger.info(f"Nmap 스캔 시작: {self.target_host}")
        print(f"[NMAP] 스캔 시작: {self.target_host}", flush=True)
        
        try:
            # Nmap 명령어 구성 (정밀 스캔 모드)
            # -sV: 서비스 버전 탐지
            # -sT: TCP 연결 스캔
            # -Pn: 호스트 발견 생략 (이미 알려진 호스트)
            # --script: 취약점 탐지 스크립트 실행 (vuln 포함)
            # --stats-every 30s: 30초마다 진행 상태 출력 (진행률 타임아웃 방지)
            nmap_args = Config.NMAP_ARGS.split()
            
            # --top-ports 옵션이 있으면 제거 (포트 범위를 명시적으로 지정하기 위해)
            nmap_args = [arg for arg in nmap_args if not arg.startswith('--top-ports') and arg != '20']
            
            # 포트 범위 추가 (1-10000)
            if '-p' not in nmap_args:
                nmap_args.extend(['-p', '1-10000'])
            
            nmap_args.extend([
                '--script', 'vuln,http-headers,http-server-header',  # 정밀 스캔: vuln 스크립트 포함
                '--stats-every', '30s',  # 30초마다 진행 상태 출력하여 타임아웃 방지
                '-oX', '-'  # XML 형식으로 출력 (더 안정적, JSON 변환은 파서에서 처리)
            ])
            
            # Nmap 실행
            cmd = ['nmap', self.target_host] + nmap_args
            logger.info(f"Nmap 명령어: {' '.join(cmd)}")
            print(f"[NMAP] 명령어 실행: {' '.join(cmd)}", flush=True)
            print(f"[NMAP] 타임아웃: {Config.NMAP_TIMEOUT}초", flush=True)
            
            import time
            scan_start = time.time()
            
            # 진행률 기반 타임아웃을 사용한 실행
            result = self._run_with_progress_timeout(
                cmd,
                timeout=Config.NMAP_TIMEOUT,
                progress_timeout=self.progress_timeout
            )
            
            scan_elapsed = time.time() - scan_start
            print(f"[NMAP] 스캔 실행 완료 (소요 시간: {scan_elapsed:.1f}초)", flush=True)
            
            if result.returncode != 0:
                error_msg = result.stderr or result.stdout or "Unknown error"
                logger.error(f"Nmap 실행 실패: {error_msg}")
                print(f"[NMAP] ❌ 실행 실패 (종료 코드: {result.returncode})", flush=True)
                print(f"[NMAP] 에러 메시지: {error_msg[:200]}", flush=True)
                return {
                    'success': False,
                    'error': error_msg,
                    'hosts': [],
                    'ports': [],
                    'services': []
                }
            
            print(f"[NMAP] ✅ 실행 성공 (출력 크기: {len(result.stdout)} bytes)", flush=True)
            
            # XML 결과 파싱 및 JSON 변환
            print(f"[NMAP] XML 결과 파싱 중...", flush=True)
            scan_data = self._parse_nmap_xml(result.stdout)
            
            hosts_count = len(scan_data.get('hosts', []))
            ports_count = len(scan_data.get('ports', []))
            services_count = len(scan_data.get('services', []))
            
            print(f"[NMAP] 파싱 완료: 호스트 {hosts_count}개, 포트 {ports_count}개, 서비스 {services_count}개", flush=True)
            
            # 결과 파일 저장
            print(f"[NMAP] 결과 파일 저장 중...", flush=True)
            output_file = self._save_results(scan_data)
            print(f"[NMAP] 결과 파일 저장 완료: {output_file}", flush=True)
            
            logger.info(f"Nmap 스캔 완료: {hosts_count}개 호스트 발견")
            print(f"[NMAP] ✅ 스캔 완료: {hosts_count}개 호스트, {ports_count}개 포트 발견", flush=True)
            
            return {
                'success': True,
                'output_file': str(output_file),
                **scan_data
            }
            
        except subprocess.TimeoutExpired:
            logger.error(f"Nmap 스캔 타임아웃: {Config.NMAP_TIMEOUT}초 초과")
            return {
                'success': False,
                'error': f'스캔 타임아웃 ({Config.NMAP_TIMEOUT}초)',
                'hosts': [],
                'ports': [],
                'services': []
            }
        except Exception as e:
            logger.error(f"Nmap 스캔 오류: {e}", exc_info=True)
            return {
                'success': False,
                'error': str(e),
                'hosts': [],
                'ports': [],
                'services': []
            }
    
    def _parse_nmap_xml(self, xml_output: str) -> Dict[str, Any]:
        """
        Nmap XML 출력 파싱 및 JSON 구조로 변환
        
        Args:
            xml_output: Nmap의 XML 형식 출력
            
        Returns:
            파싱된 스캔 데이터 (JSON 구조)
        """
        try:
            # XML을 딕셔너리로 변환
            xml_dict = xmltodict.parse(xml_output)
            
            hosts = []
            all_ports = []
            all_services = []
            
            # Nmap XML 구조: nmaprun -> host (리스트 또는 단일 객체)
            nmaprun = xml_dict.get('nmaprun', {})
            host_list = nmaprun.get('host', [])
            
            # host가 단일 객체인 경우 리스트로 변환
            if not isinstance(host_list, list):
                host_list = [host_list] if host_list else []
            
            for host in host_list:
                # IP 주소 추출
                addresses = host.get('address', [])
                if not isinstance(addresses, list):
                    addresses = [addresses] if addresses else []
                
                host_ip = ''
                for addr in addresses:
                    if isinstance(addr, dict) and addr.get('@addrtype') == 'ipv4':
                        host_ip = addr.get('@addr', '')
                        break
                
                # 호스트명 추출
                hostnames = host.get('hostnames', {})
                hostname = ''
                if hostnames:
                    hostname_list = hostnames.get('hostname', [])
                    if not isinstance(hostname_list, list):
                        hostname_list = [hostname_list] if hostname_list else []
                    if hostname_list:
                        hostname = hostname_list[0].get('@name', '')
                
                # 포트 정보 추출
                ports = []
                services = []
                
                ports_elem = host.get('ports', {})
                if ports_elem:
                    port_list = ports_elem.get('port', [])
                    if not isinstance(port_list, list):
                        port_list = [port_list] if port_list else []
                    
                    for port_elem in port_list:
                        if not isinstance(port_elem, dict):
                            continue
                        
                        port_id = port_elem.get('@portid', '')
                        protocol = port_elem.get('@protocol', 'tcp')
                        state_elem = port_elem.get('state', {})
                        state = state_elem.get('@state', '') if isinstance(state_elem, dict) else ''
                        
                        if state == 'open' and port_id:
                            port_data = {
                                'port': int(port_id),
                                'protocol': protocol,
                                'state': state
                            }
                            
                            # 서비스 정보 추출
                            service_elem = port_elem.get('service', {})
                            if service_elem and isinstance(service_elem, dict):
                                service_name = service_elem.get('@name', '')
                                product = service_elem.get('@product', '')
                                version = service_elem.get('@version', '')
                                
                                port_data['service'] = service_name
                                if product:
                                    port_data['product'] = product
                                if version:
                                    port_data['version'] = version
                                
                                # CPE 정보 추출 (있으면 추가, 없어도 에러 없이 진행)
                                cpe_list = service_elem.get('cpe', [])
                                if cpe_list:
                                    if not isinstance(cpe_list, list):
                                        cpe_list = [cpe_list]
                                    # CPE는 문자열 또는 딕셔너리 형태일 수 있음
                                    cpe_values = []
                                    for cpe in cpe_list:
                                        if isinstance(cpe, dict):
                                            cpe_text = cpe.get('#text', '') or cpe.get('@text', '')
                                            if cpe_text:
                                                cpe_values.append(cpe_text)
                                        elif isinstance(cpe, str):
                                            cpe_values.append(cpe)
                                    if cpe_values:
                                        port_data['cpe'] = cpe_values
                            
                            ports.append(port_data)
                            
                            # 서비스 정보 추가
                            if port_data.get('service'):
                                service_info = {
                                    'name': port_data['service'],
                                    'port': int(port_id),
                                    'protocol': protocol
                                }
                                if port_data.get('product'):
                                    service_info['product'] = port_data['product']
                                if port_data.get('version'):
                                    service_info['version'] = port_data['version']
                                if port_data.get('cpe'):
                                    service_info['cpe'] = port_data['cpe']
                                
                                all_services.append(service_info)
                            
                            all_ports.append(port_data)
                
                hosts.append({
                    'ip': host_ip,
                    'hostname': hostname,
                    'ports': ports
                })
            
            return {
                'hosts': hosts,
                'ports': all_ports,
                'services': all_services
            }
            
        except Exception as e:
            logger.error(f"XML 파싱 오류: {e}", exc_info=True)
            print(f"[NMAP] ❌ XML 파싱 실패: {e}", flush=True)
            return {
                'hosts': [],
                'ports': [],
                'services': []
            }
    
    def _run_with_progress_timeout(
        self,
        cmd: List[str],
        timeout: int,
        progress_timeout: int = 300
    ) -> subprocess.CompletedProcess:
        """
        진행률 기반 타임아웃을 사용하여 프로세스 실행
        
        일정 시간(progress_timeout) 동안 새로운 출력이 없으면
        프로세스를 강제 종료하고 그때까지 수집된 데이터를 반환합니다.
        
        Args:
            cmd: 실행할 명령어 리스트
            timeout: 전체 타임아웃 (초)
            progress_timeout: 진행률 타임아웃 (초, 기본 5분)
            
        Returns:
            subprocess.CompletedProcess 객체
        """
        process = None
        stdout_lines = []
        stderr_lines = []
        last_output_time = time.time()
        output_lock = threading.Lock()
        process_terminated = threading.Event()
        
        def read_output(pipe, output_list):
            """출력을 실시간으로 읽는 함수"""
            nonlocal last_output_time
            try:
                for line in iter(pipe.readline, ''):
                    if not line:
                        break
                    with output_lock:
                        output_list.append(line)
                        last_output_time = time.time()
            except Exception as e:
                logger.debug(f"출력 읽기 오류: {e}")
            finally:
                pipe.close()
        
        def monitor_progress():
            """진행률 모니터링 스레드"""
            nonlocal last_output_time, process
            while not process_terminated.is_set():
                time.sleep(10)  # 10초마다 체크
                
                if process is None or process.poll() is not None:
                    break
                
                elapsed_since_last_output = time.time() - last_output_time
                
                if elapsed_since_last_output > progress_timeout:
                    logger.warning(
                        f"[NMAP] 진행률 타임아웃: {progress_timeout}초 동안 출력 없음. "
                        f"프로세스 강제 종료 중..."
                    )
                    print(
                        f"[NMAP] ⚠️ 진행률 타임아웃: {progress_timeout}초 동안 출력 없음. "
                        f"프로세스 강제 종료 중...",
                        flush=True
                    )
                    try:
                        process.terminate()
                        time.sleep(5)  # 종료 대기
                        if process.poll() is None:
                            process.kill()  # 강제 종료
                    except Exception as e:
                        logger.error(f"프로세스 종료 오류: {e}")
                    break
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            # 출력 읽기 스레드 시작
            stdout_thread = threading.Thread(
                target=read_output,
                args=(process.stdout, stdout_lines),
                daemon=True
            )
            stderr_thread = threading.Thread(
                target=read_output,
                args=(process.stderr, stderr_lines),
                daemon=True
            )
            stdout_thread.start()
            stderr_thread.start()
            
            # 진행률 모니터링 스레드 시작
            monitor_thread = threading.Thread(target=monitor_progress, daemon=True)
            monitor_thread.start()
            
            # 프로세스 완료 대기
            process.wait(timeout=timeout)
            process_terminated.set()
            
            # 출력 스레드 종료 대기
            stdout_thread.join(timeout=2)
            stderr_thread.join(timeout=2)
            
            stdout_text = ''.join(stdout_lines)
            stderr_text = ''.join(stderr_lines)
            
            return subprocess.CompletedProcess(
                cmd,
                process.returncode,
                stdout=stdout_text,
                stderr=stderr_text
            )
            
        except subprocess.TimeoutExpired:
            process_terminated.set()
            if process:
                try:
                    process.terminate()
                    time.sleep(5)
                    if process.poll() is None:
                        process.kill()
                except Exception:
                    pass
            
            stdout_text = ''.join(stdout_lines)
            stderr_text = ''.join(stderr_lines)
            
            raise subprocess.TimeoutExpired(
                cmd,
                timeout,
                output=stdout_text,
                stderr=stderr_text
            )
        except Exception as e:
            process_terminated.set()
            if process:
                try:
                    process.terminate()
                    process.kill()
                except Exception:
                    pass
            raise
    
    def _save_results(self, data: Dict[str, Any]) -> Path:
        """
        스캔 결과를 파일로 저장
        
        Args:
            data: 저장할 데이터
            
        Returns:
            저장된 파일 경로
        """
        import time
        
        # 파일명 생성: nmap_타겟_타임스탬프.json
        timestamp = int(time.time())
        safe_host = self.target_host.replace('.', '_').replace(':', '_')
        filename = f"nmap_{safe_host}_{timestamp}.json"
        filepath = Path(self.output_dir) / filename
        
        # JSON 파일로 저장
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump({
                'target': self.target_url,
                'target_host': self.target_host,
                'timestamp': timestamp,
                **data
            }, f, ensure_ascii=False, indent=2)
        
        logger.info(f"Nmap 결과 저장: {filepath}")
        return filepath


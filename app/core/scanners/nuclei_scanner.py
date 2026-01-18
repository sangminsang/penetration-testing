"""
Nuclei 스캐너 모듈

Katana를 사용하여 URL을 수집하고, Nuclei로 취약점을 탐지합니다.
도커 컨테이너에서 실행되며, 결과를 JSON 파일로 저장합니다.
"""

import subprocess
import json
import logging
import os
import shutil
import threading
import time
from typing import Dict, List, Any, Optional
from pathlib import Path
from app.config import Config

logger = logging.getLogger(__name__)


class NucleiScanner:
    """
    Nuclei 스캐너 클래스
    
    Katana로 URL을 수집하고, Nuclei로 취약점을 탐지합니다.
    """
    
    def __init__(self, target_url: str, output_dir: str = None):
        """
        Nuclei 스캐너 초기화
        
        Args:
            target_url: 스캔 대상 URL
            output_dir: 결과 파일 저장 디렉토리 (워커 환경에서는 '/app/results' 권장)
        """
        self.target_url = target_url
        
        # 워커 환경에서는 항상 /app/results 사용 (볼륨 마운트 경로 보장)
        # output_dir이 전달되면 사용, 없으면 워커 환경 확인 후 적절한 경로 설정
        if output_dir:
            self.output_dir = output_dir
        else:
            # 워커 환경인지 확인 (컨테이너 내부 기준)
            # /app/results 디렉토리가 존재하면 워커 환경으로 간주
            if os.path.exists('/app/results') or os.path.exists('/app'):
                self.output_dir = '/app/results'
                logger.info(f"워커 환경 감지: output_dir을 '/app/results'로 설정")
            else:
                self.output_dir = Config.SCAN_RESULTS_DIR
        
        # 출력 디렉토리 생성
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        
        logger.info(f"NucleiScanner 초기화 완료: output_dir={self.output_dir}")
        
        # Katana와 Nuclei 경로 확인
        self.katana_path = shutil.which('katana') or '/usr/local/bin/katana'
        self.nuclei_path = shutil.which('nuclei') or '/usr/local/bin/nuclei'
        
        # 진행률 기반 타임아웃 설정
        self.progress_timeout = int(os.environ.get('NUCLEI_PROGRESS_TIMEOUT', 300))  # 기본 5분
    
    def run_scan(self) -> Dict[str, Any]:
        """
        전체 스캔 실행 (Katana + Nuclei)
        
        Returns:
            스캔 결과 딕셔너리
            {
                'discovered_urls': [...],  # Katana로 발견한 URL 목록
                'vulnerabilities': [...],  # Nuclei로 발견한 취약점
                'technologies': [...]  # 발견한 기술 스택
            }
        """
        logger.info(f"Nuclei 스캔 시작: {self.target_url}")
        print(f"[NUCLEI] 스캔 시작: {self.target_url}", flush=True)
        
        # # Step 1: Katana로 URL 수집 (파일 유지)
        print(f"[NUCLEI] Step 1: Katana URL 수집 시작...", flush=True)
        katana_result = self._run_katana()
        discovered_urls = katana_result.get('urls', [])
        katana_urls_file = katana_result.get('urls_file')  # Katana가 만든 파일 경로
        print(f"[NUCLEI] Step 1 완료: {len(discovered_urls)}개 URL 발견", flush=True)
        
        # Step 2: Nuclei로 취약점 탐지 (Katana 파일 직접 사용)
        print(f"[NUCLEI] Step 2: Nuclei 취약점 탐지 시작...", flush=True)
        vulnerabilities = self._run_nuclei(katana_urls_file)  # 파일 경로 직접 전달
        print(f"[NUCLEI] Step 2 완료: {len(vulnerabilities)}개 취약점 발견", flush=True)
        
        # Step 3: 기술 스택 탐지
        print(f"[NUCLEI] Step 3: 기술 스택 탐지 시작...", flush=True)
        technologies = self._detect_technologies()
        print(f"[NUCLEI] Step 3 완료: {len(technologies)}개 기술 발견", flush=True)
        
        # 결과 저장
        result = {
            'success': True,
            'discovered_urls': discovered_urls,
            'vulnerabilities': vulnerabilities,
            'technologies': technologies
        }
        
        output_file = self._save_results(result)
        result['output_file'] = str(output_file)
        
        # [NUCLEI DEBUG] 결과 파일 생성 확인
        print(f"[NUCLEI DEBUG] ========== 결과 파일 생성 확인 ==========", flush=True)
        print(f"[NUCLEI DEBUG] 결과 파일 경로: {output_file}", flush=True)
        print(f"[NUCLEI DEBUG] 파일 존재 여부: {output_file.exists() if output_file else 'N/A'}", flush=True)
        if output_file and output_file.exists():
            file_size = output_file.stat().st_size
            print(f"[NUCLEI DEBUG] 파일 크기: {file_size} bytes", flush=True)
            logger.info(f"[NUCLEI DEBUG] 결과 파일 생성 확인: {output_file} ({file_size} bytes)")
        else:
            print(f"[NUCLEI DEBUG] ⚠️ 결과 파일이 생성되지 않았습니다!", flush=True)
            logger.warning(f"[NUCLEI DEBUG] 결과 파일이 생성되지 않았습니다: {output_file}")
        
        logger.info(f"Nuclei 스캔 완료: {len(discovered_urls)}개 URL, {len(vulnerabilities)}개 취약점")
        
        return result
    
    def _run_katana(self) -> Dict[str, Any]:
        """
        Katana로 URL 수집 (파일 유지)
        
        Returns:
            {'urls': [URL 목록], 'urls_file': 파일 경로} 딕셔너리
        """
        logger.info("Katana URL 수집 시작")
        print(f"[KATANA] URL 수집 시작: {self.target_url}", flush=True)
        
        discovered_urls = [self.target_url]  # 기본값: 입력 URL
        katana_urls_file = None
        
        try:
            print(f"[KATANA] 실행 경로: {self.katana_path}", flush=True)
            # Katana 실행
            # -u: 타겟 URL
            # -silent: 조용한 모드
            # -jc: JavaScript 콘텐츠 크롤링
            # -kf: 모든 형태의 링크 추출
            # -o: 출력 파일
            
            # 워커 컨테이너 내부 기준 경로 강제 정규화 (파일명만 추출하여 워커 전용 경로와 조합)
            filename = f"katana_urls_{os.getpid()}.txt"
            # 워커 내부에서는 항상 /app/results 사용 (볼륨 마운트 보장)
            worker_output_dir = '/app/results'
            katana_urls_file = os.path.join(worker_output_dir, filename)
            
            # output_dir이 워커 경로가 아니면 경로 변환 로그 출력
            if self.output_dir and not self.output_dir.startswith('/app/results'):
                logger.warning(f"output_dir이 워커 경로가 아님: {self.output_dir}. 워커 경로로 변환: {katana_urls_file}")
                print(f"[KATANA] ⚠️ 경로 변환: {self.output_dir} -> {katana_urls_file}", flush=True)
            
            logger.info(f"Katana URL 파일 경로 (워커 기준): {katana_urls_file}")
            print(f"[KATANA] 파일 경로 (워커 기준): {katana_urls_file}", flush=True)
            
            cmd = [
                self.katana_path,
                '-u', self.target_url,
                '-silent',
                '-jc',  # JavaScript 콘텐츠 크롤링
                '-kf', 'all',  # 모든 형태의 링크
                '-d', str(Config.KATANA_MAX_DEPTH),  # 최대 깊이
                '-o', katana_urls_file
            ]
            
            logger.info(f"Katana 명령어: {' '.join(cmd)}")
            print(f"[KATANA] 명령어 실행: {' '.join(cmd)}", flush=True)
            print(f"[KATANA] 타임아웃: {Config.KATANA_TIMEOUT}초", flush=True)
            
            katana_start = time.time()
            result = self._run_with_progress_timeout(
                cmd,
                timeout=Config.KATANA_TIMEOUT,
                progress_timeout=self.progress_timeout
            )
            katana_elapsed = time.time() - katana_start
            print(f"[KATANA] 실행 완료 (소요 시간: {katana_elapsed:.1f}초, 종료 코드: {result.returncode})", flush=True)
            
            if result.returncode == 0 and os.path.exists(katana_urls_file):
                # 수집된 URL 읽기 (파일은 유지, Nuclei에서 사용)
                with open(katana_urls_file, 'r', encoding='utf-8') as f:
                    urls = [line.strip() for line in f if line.strip()]
                    discovered_urls = list(set(urls))  # 중복 제거
                    
                    # 타겟 URL이 없으면 추가
                    if self.target_url not in discovered_urls:
                        discovered_urls.insert(0, self.target_url)
                        # 파일에도 타겟 URL 추가 (Nuclei가 사용할 수 있도록)
                        with open(katana_urls_file, 'a', encoding='utf-8') as f_append:
                            f_append.write(f"{self.target_url}\n")
                
                logger.info(f"Katana로 {len(discovered_urls)}개 URL 발견 (파일: {katana_urls_file})")
                print(f"[KATANA] ✅ {len(discovered_urls)}개 URL 발견", flush=True)
                print(f"[KATANA] 파일 경로: {katana_urls_file} (Nuclei에서 사용 예정)", flush=True)
                if len(discovered_urls) <= 10:
                    for i, url in enumerate(discovered_urls, 1):
                        print(f"[KATANA]   {i}. {url}", flush=True)
            else:
                logger.warning(f"Katana 실행 실패 또는 결과 없음. 기본 URL만 사용합니다.")
                # 실패해도 기본 URL 파일 생성 (워커 경로로 정규화)
                if not katana_urls_file:
                    filename = f"katana_urls_{os.getpid()}.txt"
                    katana_urls_file = os.path.join('/app/results', filename)
                else:
                    # 파일명만 추출하여 워커 경로로 정규화
                    filename_only = os.path.basename(katana_urls_file)
                    katana_urls_file = os.path.join('/app/results', filename_only)
                with open(katana_urls_file, 'w', encoding='utf-8') as f:
                    f.write(f"{self.target_url}\n")
        
        except subprocess.TimeoutExpired:
            logger.warning(f"Katana 타임아웃. 기본 URL만 사용합니다.")
            # 타임아웃 시에도 기본 URL 파일 생성 (워커 경로로 정규화)
            if not katana_urls_file:
                filename = f"katana_urls_{os.getpid()}.txt"
                katana_urls_file = os.path.join('/app/results', filename)
            else:
                # 파일명만 추출하여 워커 경로로 정규화
                filename_only = os.path.basename(katana_urls_file)
                katana_urls_file = os.path.join('/app/results', filename_only)
            with open(katana_urls_file, 'w', encoding='utf-8') as f:
                f.write(f"{self.target_url}\n")
        except FileNotFoundError:
            logger.warning(f"Katana를 찾을 수 없습니다. 기본 URL만 사용합니다.")
            if not katana_urls_file:
                filename = f"katana_urls_{os.getpid()}.txt"
                katana_urls_file = os.path.join('/app/results', filename)
            else:
                # 파일명만 추출하여 워커 경로로 정규화
                filename_only = os.path.basename(katana_urls_file)
                katana_urls_file = os.path.join('/app/results', filename_only)
            with open(katana_urls_file, 'w', encoding='utf-8') as f:
                f.write(f"{self.target_url}\n")
        except Exception as e:
            logger.error(f"Katana 실행 오류: {e}")
            if not katana_urls_file:
                filename = f"katana_urls_{os.getpid()}.txt"
                katana_urls_file = os.path.join('/app/results', filename)
            else:
                # 파일명만 추출하여 워커 경로로 정규화
                filename_only = os.path.basename(katana_urls_file)
                katana_urls_file = os.path.join('/app/results', filename_only)
            with open(katana_urls_file, 'w', encoding='utf-8') as f:
                f.write(f"{self.target_url}\n")
        
        # 파일 경로 최종 정규화 (워커 기준 경로 보장, 모든 예외 처리 후에도 적용)
        if katana_urls_file and not katana_urls_file.startswith('/app/results'):
            filename_only = os.path.basename(katana_urls_file)
            katana_urls_file = os.path.join('/app/results', filename_only)
            logger.info(f"파일 경로 워커 기준으로 최종 정규화: {katana_urls_file}")
            print(f"[KATANA] 파일 경로 최종 정규화: {katana_urls_file}", flush=True)
        
        # 파일 경로와 URL 목록 모두 반환 (파일은 유지, 워커 기준 경로 보장)
        return {
            'urls': discovered_urls,
            'urls_file': katana_urls_file  # 워커 기준 경로: /app/results/katana_urls_*.txt
        }
    
    def _count_yaml_files(self, directory: str) -> int:
        """
        디렉토리 내 .yaml 파일을 재귀적으로 카운트 (이전 프로젝트 로직)
        
        Args:
            directory: 검색할 디렉토리 경로
        
        Returns:
            발견된 .yaml 파일 개수
        """
        count = 0
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if file.endswith('.yaml') or file.endswith('.yml'):
                        count += 1
        except (OSError, PermissionError) as e:
            logger.warning(f"템플릿 파일 카운트 중 오류: {e}")
        return count
    
    def _find_nuclei_templates(self) -> tuple:
        """
        Nuclei 템플릿 경로를 다중 경로에서 탐색하고 환경변수 설정 (이전 프로젝트 로직 강제 이식)
        
        Returns:
            (템플릿 경로, 환경변수 딕셔너리) 튜플
        """
        nuclei_env = dict(os.environ)
        
        # 가능한 템플릿 경로 목록 (실제 경로 최우선: /root/nuclei-templates가 컨테이너 내부 실제 경로)
        possible_template_paths = [
            '/root/nuclei-templates',  # 최우선: 컨테이너 내부 실제 템플릿 경로 (확인됨)
            '/root/.config/nuclei/templates',  # Docker에서 root 사용 시 표준 경로
            os.path.expanduser('~/.config/nuclei/templates'),  # Nuclei의 표준 기본 경로
            '/home/nuclei/nuclei-templates'  # 추가 호환성
        ]
        
        template_path = None
        template_found = False
        
        logger.info("Nuclei 템플릿 경로 탐색 시작 (4곳 확인)")
        print(f"[NUCLEI] 템플릿 경로 탐색 시작 (4곳 확인)...", flush=True)
        
        for path in possible_template_paths:
            if os.path.exists(path) and os.path.isdir(path):
                try:
                    # 실제 .yaml 템플릿 파일이 있는지 재귀적으로 확인
                    yaml_count = self._count_yaml_files(path)
                    if yaml_count > 0:
                        template_path = path
                        # 여러 가능한 환경변수 이름 모두 설정 (이전 프로젝트와 동일)
                        nuclei_env['NUCLEI_TEMPLATES_DIR'] = path
                        nuclei_env['NUCLEI_TEMPLATES'] = path
                        logger.info(f"✅ Nuclei 템플릿 발견: {path} ({yaml_count}개 .yaml 파일)")
                        print(f"[NUCLEI] ✅ 템플릿 발견: {path} ({yaml_count}개 .yaml 파일)", flush=True)
                        template_found = True
                        break
                    else:
                        # 디렉토리는 있지만 .yaml 파일이 없음
                        files = list(os.listdir(path))
                        logger.debug(f"디렉토리 존재하지만 .yaml 파일 없음: {path} ({len(files)}개 항목)")
                        print(f"[NUCLEI] ⚠️ 디렉토리 있으나 .yaml 파일 없음: {path}", flush=True)
                except OSError as e:
                    logger.warning(f"템플릿 경로 확인 중 오류: {path} - {e}")
                    print(f"[NUCLEI] ⚠️ 경로 확인 오류: {path} - {e}", flush=True)
                    continue
        
        # 템플릿을 찾지 못한 경우 다운로드 시도 (경로 강제 지정)
        if not template_found:
            logger.warning("Nuclei 템플릿을 찾을 수 없습니다. 다운로드 시도...")
            print(f"[NUCLEI] ⚠️ 템플릿을 찾을 수 없음. 다운로드 시도...", flush=True)
            
            # 실제 경로로 강제 설정 (컨테이너 내부 확인됨)
            default_template_dir = '/root/nuclei-templates'
            os.makedirs(default_template_dir, exist_ok=True)
            
            try:
                print(f"[NUCLEI] 템플릿 다운로드 중: {default_template_dir}...", flush=True)
                update_result = subprocess.run(
                    [
                        self.nuclei_path,
                        '-update-templates',  # 전체 명령어 사용
                        '-update-template-dir', default_template_dir  # 경로 명시적 지정 (엉뚱한 곳으로 가지 않도록)
                    ],
                    capture_output=True,
                    text=True,
                    timeout=300  # 5분 타임아웃
                )
                
                if update_result.returncode == 0:
                    # 다운로드 후 실제 .yaml 파일 확인
                    yaml_count = self._count_yaml_files(default_template_dir)
                    if yaml_count > 0:
                        template_path = default_template_dir
                        nuclei_env['NUCLEI_TEMPLATES_DIR'] = default_template_dir
                        nuclei_env['NUCLEI_TEMPLATES'] = default_template_dir
                        logger.info(f"✅ 템플릿 다운로드 성공: {default_template_dir} ({yaml_count}개 .yaml 파일)")
                        print(f"[NUCLEI] ✅ 템플릿 다운로드 성공: {default_template_dir} ({yaml_count}개 .yaml 파일)", flush=True)
                        template_found = True
                    else:
                        logger.warning("템플릿 다운로드 완료되었으나 .yaml 파일 없음")
                        print(f"[NUCLEI] ⚠️ 다운로드 완료되었으나 .yaml 파일 없음", flush=True)
                else:
                    logger.warning(f"템플릿 다운로드 실패: {update_result.stderr[:200]}")
                    print(f"[NUCLEI] ⚠️ 템플릿 다운로드 실패: {update_result.stderr[:200]}", flush=True)
            except subprocess.TimeoutExpired:
                logger.warning("템플릿 다운로드 타임아웃 (5분 초과)")
                print(f"[NUCLEI] ⚠️ 템플릿 다운로드 타임아웃", flush=True)
            except Exception as e:
                logger.error(f"템플릿 다운로드 중 오류: {e}", exc_info=True)
                print(f"[NUCLEI] ❌ 템플릿 다운로드 오류: {e}", flush=True)
        
        return template_path, nuclei_env
    
    def _update_nuclei_templates(self) -> tuple:
        """
        Nuclei 템플릿 강제 업데이트 및 경로 확인 (스캔 전 실행, 이전 프로젝트 로직 이식)
        
        Returns:
            (업데이트 성공 여부, 템플릿 경로, 환경변수 딕셔너리) 튜플
        """
        logger.info("Nuclei 템플릿 강제 업데이트 시작")
        print(f"[NUCLEI] 템플릿 업데이트 시작...", flush=True)
        
        # 템플릿 경로 강제 설정 (컨테이너 내부 실제 경로로 고정)
        default_template_dir = '/root/nuclei-templates'  # 컨테이너 내부 실제 경로 (확인됨)
        
        # 환경변수 딕셔너리 초기화 (기존 환경변수에 추가)
        nuclei_env = dict(os.environ)
        
        # 템플릿 경로를 실제 경로로 강제 설정 (확인된 실제 경로 사용)
        template_path = default_template_dir
        os.makedirs(default_template_dir, exist_ok=True)
        
        # 환경변수 강제 설정 (컨테이너 내부 실제 경로)
        nuclei_env['NUCLEI_TEMPLATES_DIR'] = default_template_dir
        nuclei_env['NUCLEI_TEMPLATES'] = default_template_dir
        
        logger.info(f"템플릿 경로 강제 설정: {default_template_dir} (컨테이너 내부 실제 경로)")
        print(f"[NUCLEI] 템플릿 경로 강제 설정: {default_template_dir}", flush=True)
        
        try:
            # 템플릿 업데이트 명령어 (경로 명시적 지정으로 엉뚱한 곳으로 가지 않도록)
            update_cmd = [
                self.nuclei_path,
                '-update-templates',  # 전체 명령어 사용
                '-update-template-dir', default_template_dir  # 실제 경로로 강제 지정 (엉뚱한 곳으로 가지 않도록)
            ]
            
            logger.info(f"Nuclei 템플릿 업데이트 명령어: {' '.join(update_cmd)}")
            print(f"[NUCLEI] 템플릿 업데이트 명령어: {' '.join(update_cmd)}", flush=True)
            print(f"[NUCLEI] 업데이트 대상 경로 (강제 지정): {default_template_dir}", flush=True)
            
            update_result = subprocess.run(
                update_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300  # 템플릿 업데이트는 최대 5분
            )
            
            # 업데이트 후 다시 확인 (실제 경로에서 확인)
            if update_result.returncode == 0:
                yaml_count = self._count_yaml_files(default_template_dir)
                if yaml_count > 0:
                    # 환경변수 강제 설정 (이미 설정했지만 재확인)
                    nuclei_env['NUCLEI_TEMPLATES_DIR'] = default_template_dir
                    nuclei_env['NUCLEI_TEMPLATES'] = default_template_dir
                    logger.info(f"✅ Nuclei 템플릿 업데이트 완료: {default_template_dir} ({yaml_count}개 .yaml 파일)")
                    print(f"[NUCLEI] ✅ 템플릿 업데이트 완료: {default_template_dir} ({yaml_count}개 .yaml 파일)", flush=True)
                    return True, default_template_dir, nuclei_env
                else:
                    logger.warning(f"⚠️ 업데이트 완료되었으나 .yaml 파일 없음: {default_template_dir}")
                    print(f"[NUCLEI] ⚠️ 업데이트 완료되었으나 .yaml 파일 없음: {default_template_dir}", flush=True)
                    # 그래도 경로와 환경변수는 설정된 채로 반환
                    return False, default_template_dir, nuclei_env
            else:
                logger.warning(f"⚠️ Nuclei 템플릿 업데이트 경고 (종료 코드: {update_result.returncode})")
                print(f"[NUCLEI] ⚠️ 템플릿 업데이트 경고 (종료 코드: {update_result.returncode})", flush=True)
                if update_result.stderr.strip():
                    logger.warning(f"템플릿 업데이트 오류 출력: {update_result.stderr[:500]}")
                    print(f"[NUCLEI] 오류: {update_result.stderr[:500]}", flush=True)
                # 업데이트 실패해도 실제 경로와 환경변수는 설정된 채로 반환
                return os.path.exists(default_template_dir), default_template_dir, nuclei_env
                
        except subprocess.TimeoutExpired:
            logger.warning("Nuclei 템플릿 업데이트 타임아웃 (5분 초과). 실제 경로 사용.")
            print(f"[NUCLEI] ⚠️ 템플릿 업데이트 타임아웃 (실제 경로 {default_template_dir} 사용)", flush=True)
            return os.path.exists(default_template_dir), default_template_dir, nuclei_env
        except Exception as e:
            logger.error(f"Nuclei 템플릿 업데이트 실패: {e}", exc_info=True)
            print(f"[NUCLEI] ❌ 템플릿 업데이트 실패: {e} (실제 경로 {default_template_dir} 사용)", flush=True)
            return os.path.exists(default_template_dir), default_template_dir, nuclei_env
    
    def _run_nuclei(self, katana_urls_file: str) -> List[Dict[str, Any]]:
        """
        Nuclei로 취약점 탐지 (Katana 파일 직접 사용: -list 파일 방식, 워커 경로 보장)
        
        Args:
            katana_urls_file: Katana가 생성한 URL 목록 파일 경로 (워커 기준으로 정규화됨)
            
        Returns:
            발견된 취약점 목록
        """
        logger.info(f"Nuclei 취약점 탐지 시작: Katana 파일 사용: {katana_urls_file}")
        print(f"[NUCLEI DEBUG] ========== Nuclei 취약점 탐지 시작 ==========", flush=True)
        print(f"[NUCLEI DEBUG] 입력 파일 경로: {katana_urls_file}", flush=True)
        
        # 워커 내부 기준 경로로 정규화 (파일명만 추출해서 /app/results와 재조합)
        if katana_urls_file:
            filename_only = os.path.basename(katana_urls_file)
            # 워커 내부에서는 항상 /app/results 사용 (볼륨 마운트 보장)
            urls_file = os.path.join('/app/results', filename_only)
            
            print(f"[NUCLEI DEBUG] 파일 경로 정규화:", flush=True)
            print(f"[NUCLEI DEBUG]   - 원본: {katana_urls_file}", flush=True)
            print(f"[NUCLEI DEBUG]   - 파일명만: {filename_only}", flush=True)
            print(f"[NUCLEI DEBUG]   - 정규화 후: {urls_file}", flush=True)
            
            # 기존 경로와 다르면 경로 변환 로그 출력
            if katana_urls_file != urls_file:
                logger.info(f"파일 경로 워커 기준으로 정규화: {katana_urls_file} -> {urls_file}")
                print(f"[NUCLEI] 파일 경로 정규화: {katana_urls_file} -> {urls_file}", flush=True)
        else:
            urls_file = None
            print(f"[NUCLEI DEBUG] ⚠️ katana_urls_file이 None입니다!", flush=True)
        
        # Katana 파일 확인 (워커 기준 경로)
        print(f"[NUCLEI DEBUG] Katana 파일 존재 확인:", flush=True)
        print(f"[NUCLEI DEBUG]   - 파일 경로: {urls_file}", flush=True)
        print(f"[NUCLEI DEBUG]   - 파일 존재 여부: {os.path.exists(urls_file) if urls_file else 'N/A'}", flush=True)
        
        if not urls_file or not os.path.exists(urls_file):
            logger.error(f"❌ Katana URL 파일을 찾을 수 없습니다 (워커 경로): {urls_file}")
            print(f"[NUCLEI] ❌ Katana URL 파일 없음 (워커 경로): {urls_file}", flush=True)
            
            # 디버깅: /app/results 디렉토리 내 파일 목록 확인
            try:
                print(f"[NUCLEI DEBUG] /app/results 디렉토리 상태 확인:", flush=True)
                print(f"[NUCLEI DEBUG]   - 디렉토리 존재: {os.path.exists('/app/results')}", flush=True)
                if os.path.exists('/app/results'):
                    files_in_results = os.listdir('/app/results')
                    logger.info(f"/app/results 디렉토리 내 파일: {files_in_results}")
                    print(f"[NUCLEI DEBUG]   - 디렉토리 내 파일 목록 ({len(files_in_results)}개):", flush=True)
                    for f in files_in_results:
                        file_path = os.path.join('/app/results', f)
                        file_size = os.path.getsize(file_path) if os.path.isfile(file_path) else 0
                        print(f"[NUCLEI DEBUG]     * {f} ({file_size} bytes)", flush=True)
                    
                    # katana 파일 패턴 검색
                    katana_files = [f for f in files_in_results if 'katana' in f.lower() and 'url' in f.lower()]
                    if katana_files:
                        print(f"[NUCLEI DEBUG]   - 발견된 Katana 파일: {katana_files}", flush=True)
                        logger.info(f"[NUCLEI DEBUG] 발견된 Katana 파일: {katana_files}")
                    else:
                        print(f"[NUCLEI DEBUG]   - ⚠️ Katana 파일을 찾을 수 없음!", flush=True)
            except Exception as e:
                logger.warning(f"/app/results 디렉토리 확인 실패: {e}")
                print(f"[NUCLEI DEBUG]   - 디렉토리 확인 실패: {e}", flush=True)
            
            return []
        
        # 파일에서 URL 개수 확인 (워커 기준 경로)
        try:
            with open(urls_file, 'r', encoding='utf-8') as f:
                url_count = len([line.strip() for line in f if line.strip()])
        except Exception as e:
            logger.error(f"Katana 파일 읽기 오류: {e}")
            url_count = 0
        
        logger.info(f"Nuclei 취약점 탐지 시작: {url_count}개 URL (파일: {urls_file})")
        print(f"[NUCLEI] 취약점 탐지 시작: {url_count}개 URL (Katana 파일 직접 사용, 워커 경로: {urls_file})", flush=True)
        
        # Step 0: 템플릿 강제 업데이트 및 경로 확인 (스캔 전 실행)
        update_success, template_path, nuclei_env = self._update_nuclei_templates()
        
        if not template_path:
            logger.error("❌ Nuclei 템플릿 경로를 찾을 수 없습니다. 스캔을 건너뜁니다.")
            print(f"[NUCLEI] ❌ 템플릿 경로 없음. 스캔 건너뜀", flush=True)
            return []
        
        vulnerabilities = []
        
        try:
            # 정규화된 워커 기준 경로 사용 (새 파일 생성하지 않음)
            logger.info(f"Katana URL 파일 직접 사용 (워커 경로): {urls_file}")
            print(f"[NUCLEI] Katana URL 파일 직접 사용 (워커 경로): {urls_file}", flush=True)
            
            # 템플릿 경로 강제 설정 (컨테이너 내부 실제 경로: /root/nuclei-templates로 고정)
            actual_template_path = '/root/nuclei-templates'  # 컨테이너 내부 실제 경로 (확인됨, 항상 이 경로 사용)
            
            # 환경변수 강제 설정 (컨테이너 내부 실제 경로)
            nuclei_env['NUCLEI_TEMPLATES_DIR'] = actual_template_path
            nuclei_env['NUCLEI_TEMPLATES'] = actual_template_path
            
            logger.info(f"템플릿 경로 강제 설정 (스캔 실행): {actual_template_path}")
            print(f"[NUCLEI] 템플릿 경로 강제 설정 (스캔 실행): {actual_template_path}", flush=True)
            
            # Nuclei 실행 (Katana 파일 직접 사용: -list 파일 방식, 워커 경로 보장, 템플릿 경로 명시)
            # 중요: -u 옵션은 절대 사용하지 않음 (충돌 방지, 오직 -list만 사용)
            # -list: Katana가 생성한 URL 목록 파일 사용 (워커 기준 경로: /app/results/katana_urls_*.txt)
            # -t: 템플릿 경로 명시적 지정 (컨테이너 내부 실제 경로: /root/nuclei-templates)
            # -jsonl: JSONL 형식 출력 (v3.3.5+ 지원)
            # -silent: 조용한 모드
            # -no-color: 색상 코드 제거
            # -severity: 모든 심각도 등급 탐지 (info,low,medium,high,critical)
            # -rate-limit: 서버 부하 방지 (50 요청/초)
            cmd = [
                self.nuclei_path,
                '-list', urls_file,  # 정규화된 워커 기준 경로: /app/results/katana_urls_*.txt (-u 옵션 절대 사용 안 함)
                '-t', actual_template_path,  # 템플릿 경로 명시적 지정: /root/nuclei-templates
                '-jsonl',  # v3.3.5+ 지원: -json 대신 -jsonl 사용
                '-silent',
                '-no-color',
                '-severity', 'info,low,medium,high,critical',  # 모든 등급 탐지 (tags info 제거)
                '-rate-limit', '50'  # 서버 보호: 초당 50개 요청 (워커 환경 최적화)
            ]
            
            # -u 옵션 완전 제거 확인 (중복 방지)
            if '-u' in cmd:
                logger.error("❌ 치명적 오류: -u 옵션이 명령어에 포함되어 있습니다. -list만 사용해야 합니다.")
                print(f"[NUCLEI] ❌ 오류: -u 옵션 제거 필요", flush=True)
                # -u 옵션 제거
                u_index = cmd.index('-u')
                cmd.pop(u_index)  # '-u' 제거
                if u_index < len(cmd):
                    cmd.pop(u_index)  # target_url 제거
            
            # 템플릿 경로 로깅
            logger.info(f"템플릿 경로 명시적 지정: {actual_template_path}")
            print(f"[NUCLEI] 템플릿 경로 명시적 지정: {actual_template_path}", flush=True)
            
            # 환경변수 확인 로그
            logger.info(f"환경변수 NUCLEI_TEMPLATES_DIR: {nuclei_env.get('NUCLEI_TEMPLATES_DIR', 'NOT SET')}")
            logger.info(f"환경변수 NUCLEI_TEMPLATES: {nuclei_env.get('NUCLEI_TEMPLATES', 'NOT SET')}")
            print(f"[NUCLEI] 환경변수 NUCLEI_TEMPLATES_DIR: {nuclei_env.get('NUCLEI_TEMPLATES_DIR', 'NOT SET')}", flush=True)
            print(f"[NUCLEI] 환경변수 NUCLEI_TEMPLATES: {nuclei_env.get('NUCLEI_TEMPLATES', 'NOT SET')}", flush=True)
            
            logger.info(f"Nuclei 명령어 (워커 기준): {' '.join(cmd)}")
            print(f"[NUCLEI] 명령어 실행 (워커 기준): {' '.join(cmd)}", flush=True)
            print(f"[NUCLEI] 워커 기준 파일 경로: {urls_file}", flush=True)
            print(f"[NUCLEI] 타임아웃: {Config.NUCLEI_TIMEOUT}초", flush=True)
            
            # 환경변수를 명시적으로 설정하여 실행 (이전 프로젝트와 동일)
            final_env = dict(os.environ)
            final_env.update(nuclei_env)
            final_env['GOGC'] = '20'  # Go 가비지 컬렉터 설정 (메모리 최적화)
            
            # [NUCLEI DEBUG] 실행 전 최종 확인
            print(f"[NUCLEI DEBUG] ========== Nuclei 실행 전 최종 확인 ==========", flush=True)
            print(f"[NUCLEI DEBUG] 명령어: {' '.join(cmd)}", flush=True)
            print(f"[NUCLEI DEBUG] 타임아웃: {Config.NUCLEI_TIMEOUT}초", flush=True)
            print(f"[NUCLEI DEBUG] 진행률 타임아웃: {self.progress_timeout}초", flush=True)
            print(f"[NUCLEI DEBUG] 환경변수 GOGC: {final_env.get('GOGC', 'NOT SET')}", flush=True)
            print(f"[NUCLEI DEBUG] 환경변수 NUCLEI_TEMPLATES_DIR: {final_env.get('NUCLEI_TEMPLATES_DIR', 'NOT SET')}", flush=True)
            print(f"[NUCLEI DEBUG] URL 파일 최종 확인: {urls_file} (존재: {os.path.exists(urls_file)})", flush=True)
            
            result = self._run_with_progress_timeout(
                cmd,
                timeout=Config.NUCLEI_TIMEOUT,
                progress_timeout=self.progress_timeout,
                env=final_env  # 환경변수 명시적 전달
            )
            
            # [NUCLEI DEBUG] 실행 결과 확인
            print(f"[NUCLEI DEBUG] ========== Nuclei 실행 결과 ==========", flush=True)
            print(f"[NUCLEI DEBUG] 종료 코드: {result.returncode}", flush=True)
            print(f"[NUCLEI DEBUG] stdout 길이: {len(result.stdout) if result.stdout else 0} bytes", flush=True)
            print(f"[NUCLEI DEBUG] stderr 길이: {len(result.stderr) if result.stderr else 0} bytes", flush=True)
            if result.stderr:
                print(f"[NUCLEI DEBUG] stderr 내용 (처음 500자): {result.stderr[:500]}", flush=True)
            logger.info(f"[NUCLEI DEBUG] 종료 코드: {result.returncode}, stdout: {len(result.stdout) if result.stdout else 0} bytes, stderr: {len(result.stderr) if result.stderr else 0} bytes")
            
            if result.returncode == 0 and result.stdout.strip():
                # JSONL 결과 파싱 (각 줄이 하나의 JSON 객체)
                # v3.3.5+ 버전에서는 -jsonl 플래그 사용
                for line in result.stdout.strip().split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        vuln_data = json.loads(line)
                        
                        vulnerability = {
                            'id': vuln_data.get('template-id', ''),
                            'name': vuln_data.get('info', {}).get('name', ''),
                            'severity': vuln_data.get('info', {}).get('severity', '').lower(),
                            'url': vuln_data.get('matched-at', ''),
                            'description': vuln_data.get('info', {}).get('description', ''),
                            'reference': vuln_data.get('info', {}).get('reference', []),
                            'cve': vuln_data.get('info', {}).get('classification', {}).get('cve-id', []),
                            'cwe': vuln_data.get('info', {}).get('classification', {}).get('cwe-id', []),
                            'tags': vuln_data.get('info', {}).get('tags', []),
                            'matcher_name': vuln_data.get('matcher-name', ''),
                            'extracted_results': vuln_data.get('extracted-results', [])
                        }
                        
                        vulnerabilities.append(vulnerability)
                    
                    except json.JSONDecodeError as e:
                        logger.debug(f"JSONL 파싱 스킵 (잘못된 줄): {line[:100]}... 에러: {e}")
                        continue
            elif result.returncode != 0:
                logger.warning(f"Nuclei 실행 실패 (종료 코드: {result.returncode})")
                print(f"[NUCLEI DEBUG] ⚠️ 실행 실패 상세 정보:", flush=True)
                print(f"[NUCLEI DEBUG]   - 종료 코드: {result.returncode}", flush=True)
                if result.stderr:
                    logger.warning(f"오류 출력: {result.stderr[:500]}")
                    print(f"[NUCLEI DEBUG]   - stderr 전체 내용:", flush=True)
                    print(f"[NUCLEI] {result.stderr}", flush=True)
                if result.stdout:
                    print(f"[NUCLEI DEBUG]   - stdout 내용 (처음 500자): {result.stdout[:500]}", flush=True)
                print(f"[NUCLEI] ⚠️ 실행 실패: {result.stderr[:500] if result.stderr else 'stderr 없음'}", flush=True)
            else:
                logger.info("Nuclei 실행 완료되었으나 결과 없음")
                print(f"[NUCLEI DEBUG] 실행 완료되었으나 결과 없음:", flush=True)
                print(f"[NUCLEI DEBUG]   - 종료 코드: {result.returncode}", flush=True)
                print(f"[NUCLEI DEBUG]   - stdout 비어있음: {not result.stdout.strip()}", flush=True)
                if result.stdout:
                    print(f"[NUCLEI DEBUG]   - stdout 내용 (처음 200자): {result.stdout[:200]}", flush=True)
                print(f"[NUCLEI] 실행 완료되었으나 결과 없음", flush=True)
            
            logger.info(f"Nuclei로 {len(vulnerabilities)}개 취약점 발견")
            print(f"[NUCLEI] ✅ {len(vulnerabilities)}개 취약점 발견", flush=True)
            
            # 결과 요약 출력
            if len(vulnerabilities) > 0 and len(vulnerabilities) <= 10:
                for i, vuln in enumerate(vulnerabilities[:10], 1):
                    print(f"[NUCLEI]   {i}. {vuln.get('name', 'Unknown')} ({vuln.get('severity', 'unknown')})", flush=True)
        
        except subprocess.TimeoutExpired as e:
            logger.warning("Nuclei 타임아웃")
            print(f"[NUCLEI DEBUG] ⚠️ 타임아웃 발생 상세:", flush=True)
            print(f"[NUCLEI DEBUG]   - 타임아웃 시간: {Config.NUCLEI_TIMEOUT}초", flush=True)
            print(f"[NUCLEI DEBUG]   - 진행률 타임아웃: {self.progress_timeout}초", flush=True)
            if hasattr(e, 'stdout') and e.stdout:
                print(f"[NUCLEI DEBUG]   - 타임아웃 시 stdout (처음 500자): {e.stdout[:500]}", flush=True)
            if hasattr(e, 'stderr') and e.stderr:
                print(f"[NUCLEI DEBUG]   - 타임아웃 시 stderr (처음 500자): {e.stderr[:500]}", flush=True)
            print(f"[NUCLEI] ⚠️ 타임아웃 발생", flush=True)
        except FileNotFoundError as e:
            logger.error(f"Nuclei를 찾을 수 없습니다")
            print(f"[NUCLEI DEBUG] ❌ Nuclei 경로 확인:", flush=True)
            print(f"[NUCLEI DEBUG]   - 설정된 경로: {self.nuclei_path}", flush=True)
            print(f"[NUCLEI DEBUG]   - 경로 존재 여부: {os.path.exists(self.nuclei_path)}", flush=True)
            print(f"[NUCLEI DEBUG]   - PATH 환경변수: {os.environ.get('PATH', 'NOT SET')}", flush=True)
            print(f"[NUCLEI] ❌ Nuclei를 찾을 수 없음", flush=True)
        except Exception as e:
            logger.error(f"Nuclei 실행 오류: {e}", exc_info=True)
            print(f"[NUCLEI DEBUG] ❌ 예외 발생 상세:", flush=True)
            print(f"[NUCLEI DEBUG]   - 예외 타입: {type(e).__name__}", flush=True)
            print(f"[NUCLEI DEBUG]   - 예외 메시지: {str(e)}", flush=True)
            import traceback
            print(f"[NUCLEI DEBUG]   - 스택 트레이스:", flush=True)
            for line in traceback.format_exc().split('\n'):
                print(f"[NUCLEI DEBUG]     {line}", flush=True)
            print(f"[NUCLEI] ❌ 실행 오류: {e}", flush=True)
        finally:
            # Katana 파일은 유지 (디버깅 및 확인용, 삭제하지 않음)
            if urls_file and os.path.exists(urls_file):
                file_size = os.path.getsize(urls_file)
                logger.debug(f"Katana URL 파일 유지: {urls_file} ({file_size} bytes)")
                print(f"[NUCLEI] Katana URL 파일 유지: {urls_file} ({file_size} bytes)", flush=True)
        
        return vulnerabilities
    
    def _detect_technologies(self) -> List[Dict[str, Any]]:
        """
        기술 스택 탐지 (Nuclei tech-detect 템플릿 사용)
        
        Returns:
            발견된 기술 목록
        """
        logger.info("기술 스택 탐지 시작")
        
        technologies = []
        
        try:
            cmd = [
                self.nuclei_path,
                '-u', self.target_url,
                '-tags', 'tech-detect',  # 기술 탐지 태그만 사용
                '-jsonl',  # v3.3.5+ 지원: -json 대신 -jsonl 사용
                '-silent',
                '-no-color'  # Windows 터미널 호환성
            ]
            
            result = self._run_with_progress_timeout(
                cmd,
                timeout=60,  # 기술 탐지는 빠르게
                progress_timeout=60  # 진행률 타임아웃도 60초
            )
            
            if result.returncode == 0 and result.stdout.strip():
                # JSONL 형식 파싱 (각 줄이 하나의 JSON 객체)
                for line in result.stdout.strip().split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                        tech_info = data.get('info', {})
                        
                        technology = {
                            'name': tech_info.get('name', ''),
                            'template_id': data.get('template-id', ''),
                            'tags': tech_info.get('tags', []),
                            'matched_at': data.get('matched-at', '')
                        }
                        
                        technologies.append(technology)
                    
                    except json.JSONDecodeError as e:
                        logger.debug(f"JSONL 파싱 스킵 (잘못된 줄): {line[:100]}... 에러: {e}")
                        continue
            
            logger.info(f"{len(technologies)}개 기술 발견")
        
        except Exception as e:
            logger.error(f"기술 탐지 오류: {e}")
        
        return technologies
    
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
        filename = f"nuclei_{safe_url}_{timestamp}.json"
        filepath = Path(self.output_dir) / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump({
                'target': self.target_url,
                'timestamp': timestamp,
                **data
            }, f, ensure_ascii=False, indent=2)
        
        logger.info(f"Nuclei 결과 저장: {filepath}")
        return filepath
    
    def _run_with_progress_timeout(
        self,
        cmd: List[str],
        timeout: int,
        progress_timeout: int = 300,
        env: Optional[Dict[str, str]] = None
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
                        f"[NUCLEI] 진행률 타임아웃: {progress_timeout}초 동안 출력 없음. "
                        f"프로세스 강제 종료 중..."
                    )
                    print(
                        f"[NUCLEI] ⚠️ 진행률 타임아웃: {progress_timeout}초 동안 출력 없음. "
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
            # 환경변수가 제공되면 사용, 없으면 기본 환경변수 사용
            process_env = env if env is not None else os.environ
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                env=process_env  # 환경변수 명시적 전달
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


#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nuclei 워커 스크립트

도커 컨테이너에서 실행되는 Nuclei 스캐너입니다.
Katana로 URL을 수집하고 Nuclei로 취약점을 탐지합니다.
"""

import os
import sys
import json
import time
import subprocess
from pathlib import Path

# 출력 버퍼링 해제 (실시간 로그를 위해)
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

# 앱 경로 추가
sys.path.insert(0, '/app')

def log(message, level='INFO'):
    """로그 출력 (즉시 플러시)"""
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] [{level}] [NUCLEI WORKER] {message}", flush=True)

def log_error(message):
    """에러 로그 출력"""
    log(message, 'ERROR')

def check_command(cmd_name, cmd_path):
    """명령어 존재 확인"""
    try:
        result = subprocess.run([cmd_path, '-version'], capture_output=True, timeout=5)
        if result.returncode == 0:
            version = result.stdout.decode('utf-8', errors='replace').strip().split('\n')[0]
            log(f"{cmd_name} 확인 완료: {version}")
            return True
        else:
            log_error(f"{cmd_name} 버전 확인 실패")
            return False
    except FileNotFoundError:
        log_error(f"{cmd_name}를 찾을 수 없음: {cmd_path}")
        return False
    except Exception as e:
        log_error(f"{cmd_name} 확인 중 오류: {e}")
        return False

def main():
    """메인 함수"""
    log("=" * 60)
    log("Nuclei 워커 시작")
    log("=" * 60)
    
    # 환경 변수 확인 (명시적으로 읽어오기)
    target_url = os.environ.get('TARGET_URL')
    scan_id = os.environ.get('SCAN_ID', 'unknown')
    output_dir_env = os.environ.get('OUTPUT_DIR')  # 환경변수에서 OUTPUT_DIR 읽기 (선택적)
    
    log(f"환경 변수 확인:")
    log(f"  - TARGET_URL: {target_url}")
    log(f"  - SCAN_ID: {scan_id}")
    log(f"  - OUTPUT_DIR (환경변수): {output_dir_env if output_dir_env else 'NOT SET'}")
    
    if not target_url:
        log_error("TARGET_URL 환경 변수가 설정되지 않았습니다")
        sys.exit(1)
    
    # 필수 도구 확인
    log("필수 도구 확인 중...")
    nuclei_path = '/usr/local/bin/nuclei'
    katana_path = '/usr/local/bin/katana'
    
    if not check_command('Nuclei', nuclei_path):
        log_error("Nuclei를 찾을 수 없습니다")
        sys.exit(1)
    
    if not check_command('Katana', katana_path):
        log_error("Katana를 찾을 수 없습니다")
        sys.exit(1)
    
    # 결과 저장 디렉토리 확인 (워커 볼륨 마운트 경로로 강제 고정)
    # 환경변수 OUTPUT_DIR이 있어도 워커 내부에서는 항상 /app/results 사용 (볼륨 마운트 보장)
    output_dir = '/app/results'  # 워커 컨테이너 내부 볼륨 마운트 경로 (강제 고정)
    
    if output_dir_env and output_dir_env != output_dir:
        log(f"⚠️ 환경변수 OUTPUT_DIR={output_dir_env}이 설정되었으나, 워커 내부에서는 {output_dir}로 강제 사용됩니다.")
    
    log(f"결과 저장 디렉토리 (워커 강제 경로): {output_dir}")
    log(f"⚠️ 중요: 모든 결과 파일은 워커 내부 기준 {output_dir} 경로에 저장됩니다.")
    
    try:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        log("디렉토리 생성/확인 완료")
        
        # 디렉토리 쓰기 권한 확인
        test_file = Path(output_dir) / '.test_write'
        try:
            test_file.write_text('test')
            test_file.unlink()
            log("디렉토리 쓰기 권한 확인 완료")
        except Exception as e:
            log_error(f"디렉토리 쓰기 권한 없음: {e}")
    except Exception as e:
        log_error(f"디렉토리 생성 실패: {e}")
        sys.exit(1)
    
    # Nuclei 스캐너 초기화 (워커 경로 강제 주입)
    log("Nuclei 스캐너 초기화 중...")
    log(f"⚠️ 중요: output_dir 파라미터를 명시적으로 '/app/results'로 강제 설정합니다.")
    try:
        from app.core.scanners.nuclei_scanner import NucleiScanner
        # output_dir을 명시적으로 '/app/results'로 강제 주입 (nuclei_scanner.py의 최신 로직 사용 보장)
        scanner = NucleiScanner(target_url, output_dir='/app/results')
        log("Nuclei 스캐너 초기화 완료")
        log(f"✅ NucleiScanner.output_dir = {scanner.output_dir} (워커 경로 강제 설정됨)")
        
        # 스캐너 내부 설정 확인 (디버깅)
        log(f"스캐너 내부 설정 확인:")
        log(f"  - target_url: {scanner.target_url}")
        log(f"  - output_dir: {scanner.output_dir}")
        log(f"  - katana_path: {scanner.katana_path}")
        log(f"  - nuclei_path: {scanner.nuclei_path}")
    except Exception as e:
        log_error(f"Nuclei 스캐너 초기화 실패: {e}")
        import traceback
        log_error(traceback.format_exc())
        sys.exit(1)
    
    # 스캔 실행 (nuclei_scanner.py의 최신 로직 강제 실행)
    log("=" * 60)
    log(f"스캔 시작: {target_url}")
    log(f"⚠️ 중요: scanner.run_scan()을 호출하여 nuclei_scanner.py의 모든 최신 로직이 실행됩니다.")
    log(f"  - 경로 정규화 로직: /app/results/katana_urls_*.txt")
    log(f"  - -list 파일 방식: Katana 파일 직접 사용")
    log(f"  - 템플릿 경로: /root/nuclei-templates")
    log(f"  - -u 옵션 제거: -list만 사용")
    log("=" * 60)
    
    # [NUCLEI DEBUG] 워커 환경 확인
    log("=" * 60)
    log("[NUCLEI DEBUG] 워커 환경 확인")
    log("=" * 60)
    try:
        import socket
        hostname = socket.gethostname()
        log(f"[NUCLEI DEBUG] 호스트명: {hostname}")
        
        # 네트워크 연결 테스트
        try:
            import urllib.request
            test_url = target_url.rstrip('/')
            log(f"[NUCLEI DEBUG] 타겟 URL 연결 테스트: {test_url}")
            req = urllib.request.Request(test_url, headers={'User-Agent': 'Nuclei-Scanner'})
            with urllib.request.urlopen(req, timeout=5) as response:
                log(f"[NUCLEI DEBUG] ✅ 타겟 URL 연결 성공 (HTTP {response.getcode()})")
        except Exception as conn_err:
            log_error(f"[NUCLEI DEBUG] ⚠️ 타겟 URL 연결 실패: {conn_err}")
        
        # /app/results 디렉토리 확인
        if os.path.exists('/app/results'):
            files_before = os.listdir('/app/results')
            log(f"[NUCLEI DEBUG] /app/results 디렉토리 존재 (파일 {len(files_before)}개)")
            if files_before:
                log(f"[NUCLEI DEBUG] 기존 파일 목록: {files_before[:10]}")
        else:
            log_error(f"[NUCLEI DEBUG] ⚠️ /app/results 디렉토리가 존재하지 않음!")
    except Exception as env_err:
        log_error(f"[NUCLEI DEBUG] 환경 확인 중 오류: {env_err}")
    
    start_time = time.time()
    try:
        # nuclei_scanner.py의 run_scan() 메서드 호출 (모든 최신 로직 실행 보장)
        # 내부적으로 _run_katana() -> _run_nuclei() 순서로 실행되며,
        # 경로 정규화, 파일 직접 사용, 템플릿 경로 지정 등 모든 로직이 적용됨
        result = scanner.run_scan()
        elapsed = time.time() - start_time
        
        log(f"스캔 완료 (소요 시간: {elapsed:.1f}초)")
        log(f"✅ nuclei_scanner.py의 모든 최신 로직이 정상적으로 실행되었습니다.")
        
        # 결과 확인
        if result.get('success'):
            output_file = result.get('output_file')
            urls_count = len(result.get('discovered_urls', []))
            vulns_count = len(result.get('vulnerabilities', []))
            techs_count = len(result.get('technologies', []))
            
            log("=" * 60)
            log("스캔 결과:")
            log(f"  - 결과 파일: {output_file}")
            log(f"  - 발견된 URL: {urls_count}개")
            log(f"  - 발견된 취약점: {vulns_count}개")
            log(f"  - 발견된 기술: {techs_count}개")
            log("=" * 60)
            
            # [NUCLEI DEBUG] 결과 파일 상세 확인
            log("=" * 60)
            log("[NUCLEI DEBUG] 결과 파일 상세 확인")
            log("=" * 60)
            if output_file:
                output_path = Path(output_file)
                log(f"[NUCLEI DEBUG] 결과 파일 경로: {output_file}")
                log(f"[NUCLEI DEBUG] 파일 존재 여부: {output_path.exists()}")
                if output_path.exists():
                    file_size = output_path.stat().st_size
                    log(f"[NUCLEI DEBUG] 파일 크기: {file_size} bytes")
                    log(f"[NUCLEI DEBUG] 파일 권한: {oct(output_path.stat().st_mode)}")
                    
                    # 파일 내용 일부 확인
                    try:
                        with open(output_path, 'r', encoding='utf-8') as f:
                            content_preview = f.read(500)
                            log(f"[NUCLEI DEBUG] 파일 내용 미리보기 (처음 500자): {content_preview}")
                    except Exception as read_err:
                        log_error(f"[NUCLEI DEBUG] 파일 읽기 실패: {read_err}")
                else:
                    log_error(f"[NUCLEI DEBUG] ⚠️ 결과 파일이 생성되지 않았습니다!")
                    log_error(f"[NUCLEI DEBUG] 예상 경로: {output_file}")
                    
                    # /app/results 디렉토리 재확인
                    if os.path.exists('/app/results'):
                        files_after = os.listdir('/app/results')
                        log(f"[NUCLEI DEBUG] /app/results 디렉토리 내 파일 ({len(files_after)}개):")
                        for f in files_after:
                            f_path = os.path.join('/app/results', f)
                            if os.path.isfile(f_path):
                                f_size = os.path.getsize(f_path)
                                log(f"[NUCLEI DEBUG]   - {f} ({f_size} bytes)")
            else:
                log_error(f"[NUCLEI DEBUG] ⚠️ output_file이 None입니다!")
            
            # 결과 파일 존재 확인
            if output_file and Path(output_file).exists():
                file_size = Path(output_file).stat().st_size
                log(f"결과 파일 확인 완료 (크기: {file_size} bytes)")
            else:
                log_error(f"결과 파일이 존재하지 않음: {output_file}")
            
            sys.exit(0)
        else:
            error_msg = result.get('error', 'Unknown error')
            log_error(f"스캔 실패: {error_msg}")
            sys.exit(1)
            
    except Exception as e:
        elapsed = time.time() - start_time
        log_error(f"스캔 실행 중 예외 발생 (소요 시간: {elapsed:.1f}초): {e}")
        import traceback
        log_error(traceback.format_exc())
        sys.exit(1)

if __name__ == '__main__':
    main()


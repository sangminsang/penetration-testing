#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nmap 워커 스크립트

도커 컨테이너에서 실행되는 Nmap 스캐너입니다.
환경 변수에서 타겟 URL을 받아 스캔을 수행하고 결과를 파일로 저장합니다.
"""

import os
import sys
import json
import time
from pathlib import Path

# 출력 버퍼링 해제 (실시간 로그를 위해)
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

# 앱 경로 추가
sys.path.insert(0, '/app')

def log(message, level='INFO'):
    """로그 출력 (즉시 플러시)"""
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] [{level}] [NMAP WORKER] {message}", flush=True)

def log_error(message):
    """에러 로그 출력"""
    log(message, 'ERROR')

def main():
    """메인 함수"""
    log("=" * 60)
    log("Nmap 워커 시작")
    log("=" * 60)
    
    # 환경 변수 확인
    target_url = os.environ.get('TARGET_URL')
    scan_id = os.environ.get('SCAN_ID', 'unknown')
    
    log(f"환경 변수 확인:")
    log(f"  - TARGET_URL: {target_url}")
    log(f"  - SCAN_ID: {scan_id}")
    
    if not target_url:
        log_error("TARGET_URL 환경 변수가 설정되지 않았습니다")
        sys.exit(1)
    
    # 결과 저장 디렉토리 확인
    output_dir = '/app/results'
    log(f"결과 저장 디렉토리: {output_dir}")
    
    try:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        log(f"디렉토리 생성/확인 완료")
        
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
    
    # Nmap 스캐너 초기화
    log("Nmap 스캐너 초기화 중...")
    try:
        from app.core.scanners.nmap_scanner import NmapScanner
        scanner = NmapScanner(target_url, output_dir=output_dir)
        log("Nmap 스캐너 초기화 완료")
    except Exception as e:
        log_error(f"Nmap 스캐너 초기화 실패: {e}")
        import traceback
        log_error(traceback.format_exc())
        sys.exit(1)
    
    # 스캔 실행
    log("=" * 60)
    log(f"스캔 시작: {target_url}")
    log("=" * 60)
    
    start_time = time.time()
    try:
        result = scanner.run_scan()
        elapsed = time.time() - start_time
        
        log(f"스캔 완료 (소요 시간: {elapsed:.1f}초)")
        
        # 결과 확인
        if result.get('success'):
            output_file = result.get('output_file')
            hosts_count = len(result.get('hosts', []))
            ports_count = len(result.get('ports', []))
            
            log("=" * 60)
            log("스캔 결과:")
            log(f"  - 결과 파일: {output_file}")
            log(f"  - 발견된 호스트: {hosts_count}개")
            log(f"  - 발견된 포트: {ports_count}개")
            log("=" * 60)
            
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


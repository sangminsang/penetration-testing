#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZAP 워커 스크립트

도커 컨테이너에서 실행되는 ZAP 스캐너입니다.
OWASP ZAP를 사용하여 웹 애플리케이션 보안 스캔을 수행합니다.
"""

import os
import sys
import json
import time
import socket
from pathlib import Path

# 출력 버퍼링 해제 (실시간 로그를 위해)
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

# 앱 경로 추가
sys.path.insert(0, '/app')

def log(message, level='INFO'):
    """로그 출력 (즉시 플러시)"""
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] [{level}] [ZAP WORKER] {message}", flush=True)

def log_error(message):
    """에러 로그 출력"""
    log(message, 'ERROR')

def check_connection(host, port, timeout=2):
    """연결 확인"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception as e:
        return False

def main():
    """메인 함수"""
    log("=" * 60)
    log("ZAP 워커 시작")
    log("=" * 60)
    
    # 환경 변수 확인
    target_url = os.environ.get('TARGET_URL')
    scan_id = os.environ.get('SCAN_ID', 'unknown')
    zap_host = os.environ.get('ZAP_HOST', 'zap')
    zap_port = int(os.environ.get('ZAP_PORT', 8080))
    
    log(f"환경 변수 확인:")
    log(f"  - TARGET_URL: {target_url}")
    log(f"  - SCAN_ID: {scan_id}")
    log(f"  - ZAP_HOST: {zap_host}")
    log(f"  - ZAP_PORT: {zap_port}")
    
    if not target_url:
        log_error("TARGET_URL 환경 변수가 설정되지 않았습니다")
        sys.exit(1)
    
    # ZAP 서버 연결 확인
    log("=" * 60)
    log(f"ZAP 서버 연결 확인: {zap_host}:{zap_port}")
    log("=" * 60)
    
    max_wait = 900  # 최대 15분 대기 (ZAP 부팅 시간 대폭 연장: 300초 → 900초)
    waited = 0
    connected = False
    
    log(f"ZAP 서버 연결 대기 시작 (최대 {max_wait}초 / 15분)")
    
    while waited < max_wait:
        if check_connection(zap_host, zap_port):
            log(f"✅ ZAP 서버 연결 성공! (대기 시간: {waited}초)")
            connected = True
            break
        
        time.sleep(2)
        waited += 2
        if waited % 30 == 0:  # 30초마다 로그 출력 (대기 시간이 길어졌으므로)
            minutes = waited // 60
            seconds = waited % 60
            log(f"ZAP 서버 대기 중... ({minutes}분 {seconds}초 / {max_wait}초)")
    
    if not connected:
        log_error(f"❌ ZAP 서버 연결 실패 (최대 대기 시간 {max_wait}초 / 15분 초과)")
        log_error(f"=" * 60)
        log_error(f"ZAP 연결 실패 - 네트워크 진단 정보:")
        log_error(f"  - ZAP 호스트: {zap_host}")
        log_error(f"  - ZAP 포트: {zap_port}")
        log_error(f"  - 대기 시간: {waited}초 ({waited // 60}분 {waited % 60}초)")
        log_error(f"  - 환경 변수 ZAP_PROXY_HOST: {os.environ.get('ZAP_PROXY_HOST', 'NOT SET')}")
        log_error(f"  - 환경 변수 ZAP_PROXY_PORT: {os.environ.get('ZAP_PROXY_PORT', 'NOT SET')}")
        log_error(f"")
        log_error(f"네트워크 진단 명령어:")
        log_error(f"  1. ZAP 컨테이너 상태: docker logs security-scanner-zap")
        log_error(f"  2. ZAP 컨테이너 실행 여부: docker ps -a | grep zap")
        log_error(f"  3. 네트워크 연결 테스트: nc -zv {zap_host} {zap_port} (또는 telnet {zap_host} {zap_port})")
        log_error(f"  4. DNS 해석 확인: ping {zap_host} (컨테이너 내부에서)")
        log_error(f"  5. 동일 네트워크 확인: docker network inspect security-scanner-net")
        log_error(f"=" * 60)
        sys.exit(1)
    
    # 결과 저장 디렉토리 확인
    output_dir = '/app/results'
    log(f"결과 저장 디렉토리: {output_dir}")
    
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
    
    # 발견된 URL 목록 확인
    discovered_urls = None
    discovered_urls_str = os.environ.get('DISCOVERED_URLS')
    if discovered_urls_str:
        discovered_urls = [url.strip() for url in discovered_urls_str.split(',') if url.strip()]
        log(f"발견된 URL 사용: {len(discovered_urls)}개")
        if len(discovered_urls) <= 10:
            for i, url in enumerate(discovered_urls, 1):
                log(f"  {i}. {url}")
        else:
            for i, url in enumerate(discovered_urls[:5], 1):
                log(f"  {i}. {url}")
            log(f"  ... 외 {len(discovered_urls) - 5}개")
    else:
        log("발견된 URL 없음 (기본 타겟 URL만 사용)")
    
    # ZAP 스캐너 초기화
    log("ZAP 스캐너 초기화 중...")
    try:
        from app.core.scanners.zap_scanner import ZapScanner
        scanner = ZapScanner(
            target_url,
            output_dir=output_dir,
            proxy_host=zap_host,
            proxy_port=zap_port
        )
        log("ZAP 스캐너 초기화 완료")
    except Exception as e:
        log_error(f"ZAP 스캐너 초기화 실패: {e}")
        import traceback
        log_error(traceback.format_exc())
        sys.exit(1)
    
    # 스캔 실행
    log("=" * 60)
    log(f"스캔 시작: {target_url}")
    log("=" * 60)
    
    start_time = time.time()
    try:
        result = scanner.run_scan(discovered_urls=discovered_urls)
        elapsed = time.time() - start_time
        
        log(f"스캔 완료 (소요 시간: {elapsed:.1f}초)")
        
        # 결과 확인
        if result.get('success'):
            output_file = result.get('output_file')
            alerts_count = len(result.get('alerts', []))
            
            log("=" * 60)
            log("스캔 결과:")
            log(f"  - 결과 파일: {output_file}")
            log(f"  - 발견된 경고: {alerts_count}개")
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


import requests
<<<<<<< HEAD
=======
import re
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642
import logging
import subprocess
import json
import shutil
<<<<<<< HEAD
import os
from typing import Dict, List, Any, Optional

=======
import sys
import os
from pathlib import Path
from typing import Dict, Any, List

# 로깅 설정
logging.basicConfig(level=logging.INFO)
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642
logger = logging.getLogger(__name__)

def collect_web_info(url):
    """
<<<<<<< HEAD
    이상적인 스캔 워크플로우:
    1. Katana 크롤링 (URL 수집)
    2. Nuclei 스캔 (취약점 후보 탐지)
    3. 필터링: 취약점 발견된 URL만 추출
    4. ZAP Targeted Scan (취약한 URL만 정밀 검증)
    5. VulnerabilityVerifier (실제 검증)
    
    Note: WhatWeb은 Nuclei의 tech-detect 태그로 대체 가능하지만,
          일부 메타데이터(IP, 국가 등)는 WhatWeb이 더 정확할 수 있음
    """
    results = {
        'headers': {}, 
        'webtechnologies': [], 
        'nuclei_vulns': [], 
        'zap_results': None,
        'verifications': []
    }
    
    # Step 0: 기본 헤더 수집 및 기술 스택 추출
    try:
        resp = requests.get(url, timeout=10, verify=False)
        results['headers'] = dict(resp.headers)
        
        # 헤더에서 기술 스택 정보 추출 (Nuclei/WhatWeb 실패 시 대비)
        server = resp.headers.get('Server', '')
        powered_by = resp.headers.get('X-Powered-By', '')
        
        if server:
            results['webtechnologies'].append({
                'name': server.split('/')[0] if '/' in server else server,
                'version': server.split('/')[1] if '/' in server else '',
                'source': 'HTTP-Header'
            })
        
        if powered_by:
            # PHP/5.6.40 형식 파싱
            if 'PHP' in powered_by:
                php_version = powered_by.replace('PHP/', '').split()[0] if 'PHP/' in powered_by else ''
                results['webtechnologies'].append({
                    'name': 'PHP',
                    'version': php_version,
                    'source': 'HTTP-Header'
                })
    except Exception as e:
        logger.warning(f"Failed to get headers: {e}")
        print(f"[STEP 0] ⚠️ 헤더 수집 실패: {e}")

    # Step 1: Katana 크롤링 (URL 수집)
    crawled_urls_file = f"urls_{os.getpid()}.txt"
    all_discovered_urls = [url]  # 기본 URL 포함
    
    try:
        katana_path = shutil.which('katana') or '/usr/local/bin/katana'
        if not os.path.exists(katana_path) and not shutil.which('katana'):
            print(f"[STEP 1] ⚠️ Katana를 찾을 수 없습니다. 기본 URL만 사용합니다.")
            logger.warning("Katana not found, using base URL only")
        else:
            print(f"[STEP 1] 🔍 Katana 크롤링 시작: {url}")
            result = subprocess.run(
                [katana_path, '-u', url, '-silent', '-o', crawled_urls_file], 
                timeout=60,
                errors='ignore',
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                print(f"[STEP 1] ⚠️ Katana 실행 실패 (코드: {result.returncode}): {result.stderr[:200]}")
                logger.warning(f"Katana failed with code {result.returncode}: {result.stderr}")
            
            if os.path.exists(crawled_urls_file):
                with open(crawled_urls_file, 'r') as f:
                    all_discovered_urls = [line.strip() for line in f if line.strip()]
                    all_discovered_urls = list(set(all_discovered_urls))  # 중복 제거
                    if url not in all_discovered_urls:
                        all_discovered_urls.insert(0, url)  # 기본 URL을 맨 앞에
                print(f"[STEP 1] ✅ {len(all_discovered_urls)}개 URL 발견")
            else:
                print(f"[STEP 1] ⚠️ Katana 결과 파일이 생성되지 않았습니다. 기본 URL만 사용합니다.")
                logger.warning("Katana output file not found")
    except Exception as e:
        logger.error(f"Katana crawling failed: {e}", exc_info=True)
        print(f"[STEP 1] ❌ Katana 크롤링 실패: {e}")
        all_discovered_urls = [url]  # 실패 시 기본 URL만 사용

    # Step 2: Nuclei 스캔 (취약점 + 기술 스택 탐지)
    nuclei_results_file = f"n_res_{os.getpid()}.json"
    vulnerable_urls = []  # 취약점 발견된 URL만 저장
    
    try:
        nuclei_path = shutil.which('nuclei') or '/usr/local/bin/nuclei'
        if not os.path.exists(nuclei_path) and not shutil.which('nuclei'):
            print(f"[STEP 2] ⚠️ Nuclei를 찾을 수 없습니다. 스캔을 건너뜁니다.")
            logger.warning("Nuclei not found, skipping scan")
        else:
            print(f"[STEP 2] 🎯 Nuclei 스캔 시작: {len(all_discovered_urls)}개 URL")
            
            # crawled_urls_file이 존재하는지 확인
            if not os.path.exists(crawled_urls_file):
                # 파일이 없으면 기본 URL만 파일에 작성
                with open(crawled_urls_file, 'w') as f:
                    f.write(url + '\n')
            
            # Nuclei 실행 (취약점 + 기술 스택 탐지)
            cmd = [
                nuclei_path, '-list', crawled_urls_file, '-silent',
                # '-tags', 'cve,vuln,tech,exposure,osint',  # 일단 제거
                '-severity', 'critical,high,medium,low,info',
                '-j', '-o', nuclei_results_file,
                '-c', '5', '-rl', '10'
            ]

            
            result = subprocess.run(
                cmd, 
                errors='ignore', 
                timeout=300,
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                print(f"[STEP 2] ⚠️ Nuclei 실행 실패 (코드: {result.returncode}): {result.stderr[:200]}")
                logger.warning(f"Nuclei failed with code {result.returncode}: {result.stderr}")
            
            if os.path.exists(nuclei_results_file):
                file_size = os.path.getsize(nuclei_results_file)
                if file_size == 0:
                    print(f"[STEP 2] ⚠️ Nuclei 결과 파일이 비어있습니다.")
                    logger.warning("Nuclei output file is empty")
                else:
                    with open(nuclei_results_file, 'r') as f:
                        for line in f:
                            if not line.strip():
                                continue
                            try:
                                res = json.loads(line)
                                vuln_info = {
                                    'name': res.get('info', {}).get('name', 'Unknown'),
                                    'severity': res.get('info', {}).get('severity', 'info'),
                                    'url': res.get('matched-at', ''),
                                    'template_id': res.get('template-id', ''),
                                    'tags': res.get('info', {}).get('tags', [])
                                }
                                results['nuclei_vulns'].append(vuln_info)
                                
                                # 취약점 발견된 URL 수집 (ZAP 검증용)
                                matched_url = vuln_info['url']
                                if matched_url and matched_url not in vulnerable_urls:
                                    vulnerable_urls.append(matched_url)
                                
                                # 기술 스택 정보 추출 (tech 태그가 있으면)
                                if 'tech' in str(res.get('info', {}).get('tags', [])).lower():
                                    tech_name = vuln_info['name']
                                    results['webtechnologies'].append({
                                        'name': tech_name,
                                        'version': '',  # Nuclei는 버전 정보를 잘 제공하지 않음
                                        'source': 'Nuclei'
                                    })
                            except json.JSONDecodeError as e:
                                logger.debug(f"JSON decode error: {e}")
                                continue
                    
                    print(f"[STEP 2] ✅ {len(results['nuclei_vulns'])}개 취약점 발견, {len(vulnerable_urls)}개 URL이 취약")
                    os.remove(nuclei_results_file)
            else:
                print(f"[STEP 2] ⚠️ Nuclei 결과 파일이 생성되지 않았습니다.")
                logger.warning("Nuclei output file not created")
    except Exception as e:
        logger.error(f"Nuclei scan failed: {e}", exc_info=True)
        print(f"[STEP 2] ❌ Nuclei 스캔 실패: {e}")

    # Step 3: WhatWeb 실행 (Nuclei 보완 - 메타데이터 및 정밀 버전 탐지)
    # Note: Nuclei의 tech-detect는 빠르지만, WhatWeb은 더 정밀한 버전 정보를 제공할 수 있음
    try:
        if shutil.which('whatweb'):
            print(f"[STEP 3] 🔎 WhatWeb 정밀 탐지 (Nuclei 보완): {url}")
            cmd = ['whatweb', '--log-json', '-', url]
            proc = subprocess.run(cmd, capture_output=True, text=True, errors='ignore', timeout=30)
            
            if proc.returncode != 0:
                print(f"[STEP 3] ⚠️ WhatWeb 실행 실패 (코드: {proc.returncode}): {proc.stderr[:200]}")
                logger.warning(f"WhatWeb failed with code {proc.returncode}: {proc.stderr}")
            elif proc.stdout:
                try:
                    data = json.loads(proc.stdout)
                    if data:
                        plugins = data[0].get('plugins', {})
                        for name, info in plugins.items():
                            # 중복 체크 (Nuclei에서 이미 발견한 기술은 제외)
                            existing = next((t for t in results['webtechnologies'] if t['name'] == name), None)
                            if not existing:
                                results['webtechnologies'].append({
                                    'name': name,
                                    'version': info.get('string', [''])[0] if isinstance(info.get('string'), list) else info.get('version', [''])[0] if isinstance(info.get('version'), list) else '',
                                    'source': 'WhatWeb'
                                })
                            elif existing['version'] == '' and info.get('version'):
                                # WhatWeb이 버전 정보를 제공하면 업데이트
                                version = info.get('version', [''])[0] if isinstance(info.get('version'), list) else info.get('version', '')
                                if version:
                                    existing['version'] = version
                                    existing['source'] = 'WhatWeb+Nuclei'
                        print(f"[STEP 3] ✅ WhatWeb 탐지 완료: {len(plugins)}개 기술 발견")
                except json.JSONDecodeError as e:
                    print(f"[STEP 3] ⚠️ WhatWeb JSON 파싱 실패: {e}")
                    logger.warning(f"WhatWeb JSON decode error: {e}")
        else:
            print(f"[STEP 3] ⏭️ WhatWeb이 설치되지 않았습니다. 건너뜁니다.")
            logger.debug("WhatWeb not installed, skipping")
    except Exception as e:
        logger.error(f"WhatWeb scan failed: {e}", exc_info=True)
        print(f"[STEP 3] ❌ WhatWeb 스캔 실패: {e}")

    # Step 4: ZAP Targeted Scan (취약점 발견된 URL만 정밀 검증)
    if vulnerable_urls:
        try:
            print(f"[STEP 4] 🛡️ ZAP Targeted Scan 시작: {len(vulnerable_urls)}개 취약 URL")
            from app.core.scanner.zap_scanner import ZapScanner
            from app.config import Config
            
            # Docker 환경 감지: 환경 변수로 ZAP 호스트 오버라이드 가능
            zap_host = os.getenv('ZAP_PROXY_HOST', Config.ZAP_PROXY_HOST)
            zap_port = int(os.getenv('ZAP_PROXY_PORT', Config.ZAP_PROXY_PORT))
            
            zap_scanner = ZapScanner(
                api_key=os.getenv('ZAP_API_KEY', Config.ZAP_API_KEY),
                proxy_host=zap_host,
                proxy_port=zap_port
            )
            
            # 취약점 발견된 URL만 ZAP으로 정밀 검증
            zap_result = zap_scanner.targeted_scan(vulnerable_urls)
            
            if zap_result and 'alerts' in zap_result:
                results['zap_results'] = {
                    'alerts': zap_result['alerts'],
                    'scanned_urls': len(vulnerable_urls)
                }
                print(f"[STEP 4] ✅ ZAP 검증 완료: {len(zap_result['alerts'])}개 알림 발견")
            else:
                print(f"[STEP 4] ⚠️ ZAP 스캔 실패 또는 알림 없음")
        except Exception as e:
            logger.warning(f"ZAP scan failed: {e}")
            print(f"[STEP 4] ⚠️ ZAP 스캔 실패: {e}")
    else:
        print(f"[STEP 4] ⏭️ 취약점 발견된 URL이 없어 ZAP 스캔 건너뜀")

    # Step 5: VulnerabilityVerifier (실제 검증)
    try:
        if results['nuclei_vulns']:
            print(f"[STEP 5] 🔬 VulnerabilityVerifier 검증 시작")
            from app.core.verifier import VulnerabilityVerifier
            
            # CVE 정보 추출 (Nuclei 결과에서)
            cves = []
            for vuln in results['nuclei_vulns']:
                # template-id나 name에서 CVE ID 추출 시도
                template_id = vuln.get('template_id', '')
                if 'cve' in template_id.lower():
                    cve_id = template_id.upper()
                    cves.append({
                        'id': cve_id,
                        'description': vuln.get('name', ''),
                        'severity': vuln.get('severity', 'medium')
                    })
            
            # VulnerabilityVerifier 실행
            verifier = VulnerabilityVerifier(
                target_url=url,
                endpoints=all_discovered_urls[:50],  # 최대 50개만 (성능 고려)
                cves=cves,
                technologies=results['webtechnologies']
            )
            
            verifications = verifier.verify_all()
            results['verifications'] = verifications
            print(f"[STEP 5] ✅ 검증 완료: {len(verifications)}개 검증 수행")
    except Exception as e:
        logger.warning(f"VulnerabilityVerifier failed: {e}")
        print(f"[STEP 5] ⚠️ 검증 실패: {e}")

    # Step 6: Nmap 전체 스캔 (네트워크 레벨 정보 수집)
    try:
        print(f"[STEP 6] 🔍 Nmap 전체 스캔 시작: {url}")
        from app.core.recon.network import run_recon
        
        # URL에서 호스트 추출
        from urllib.parse import urlparse
        parsed = urlparse(url)
        nmap_target = parsed.hostname or parsed.netloc.split(':')[0]
        
        if nmap_target:
            print(f"[STEP 6] 🎯 Nmap 타겟: {nmap_target}")
            nmap_result = run_recon(nmap_target, aggressive=True)
            
            if nmap_result:
                # Nmap 결과를 기술 스택에 추가
                for host in nmap_result:
                    for port_info in host.get('ports', []):
                        tech = {
                            'name': port_info.get('product', port_info.get('service', 'Unknown')),
                            'version': port_info.get('version', ''),
                            'source': 'Nmap',
                            'port': port_info.get('port'),
                            'service': port_info.get('service', '')
                        }
                        # 중복 체크
                        existing = next((t for t in results['webtechnologies'] 
                                        if t['name'] == tech['name'] and t.get('port') == tech.get('port')), None)
                        if not existing:
                            results['webtechnologies'].append(tech)
                
                # Nmap 결과를 별도 필드로 저장
                results['nmap_results'] = nmap_result
                print(f"[STEP 6] ✅ Nmap 스캔 완료: {len(nmap_result)}개 호스트, {sum(len(h.get('ports', [])) for h in nmap_result)}개 포트")
            else:
                print(f"[STEP 6] ⚠️ Nmap 스캔 결과 없음")
        else:
            print(f"[STEP 6] ⚠️ Nmap 타겟을 추출할 수 없습니다.")
    except ImportError as e:
        print(f"[STEP 6] ⚠️ Nmap 모듈을 import할 수 없습니다: {e}")
        logger.warning(f"Nmap import failed: {e}")
    except Exception as e:
        logger.error(f"Nmap scan failed: {e}", exc_info=True)
        print(f"[STEP 6] ❌ Nmap 스캔 실패: {e}")

    # 정리
=======
    통합 웹 정찰 함수 (Katana Crawling -> Nuclei Scan -> ZAP Targeted Scan)
    """
    results = {
        'headers': {},
        'wappalyzer': [],
        'whatweb': [],
        'webtechnologies': [],
        'nuclei_vulns': [],
        'zap_results': None
    }
    
    print("======================================================================")
    print(f"[WEB] Starting ENHANCED multi-tool web scan (Katana + Nuclei + ZAP)")
    print(f"[WEB] Target: {url}")
    print("======================================================================")

    # 1. HTTP Headers
    try:
        print("[WEB] Tool 1: HTTP Headers & HTML Analysis...")
        resp = requests.get(url, timeout=10, verify=False)
        results['headers'] = dict(resp.headers)
        if 'Server' in resp.headers:
            results['webtechnologies'].append({
                'name': resp.headers['Server'].split('/')[0],
                'version': resp.headers['Server'].split('/')[1] if '/' in resp.headers['Server'] else '',
                'source': 'Header Analysis',
                'evidence': f"Server Header: {resp.headers['Server']}",
                'confidence': 'High'
            })
    except Exception as e:
        print(f"[WEB] ❌ Tool 1 Error: {e}")

    # 2. WhatWeb
    try:
        print("[WEB] Tool 5: WhatWeb Analysis...")
        if shutil.which('whatweb'):
            cmd = ['whatweb', '--log-json', '-', '--color=never', url]
            subprocess.run(cmd, errors='ignore')
            if os.path.exists('nuclei_results.json'):
                with open('nuclei_results.json', 'r') as f: nuclei_out = f.read()
                os.remove('nuclei_results.json')
            else: nuclei_out = ''
            if nuclei_out:
                match = re.search(r'(\{.*"target\":.*\})', proc.stdout)
                if match:
                    try:
                        clean_json = match.group(1)
                        data = json.loads(clean_json)
                        plugins = data.get('plugins', {})
                        print(f"[WEB] ✅ WhatWeb found {len(plugins)} plugins")
                        for name, info in plugins.items():
                            ver = ''
                            if 'version' in info and info['version']: ver = info['version'][0]
                            elif 'string' in info and info['string']: ver = info['string'][0]
                            results['webtechnologies'].append({
                                'name': name,
                                'version': ver,
                                'source': 'WhatWeb',
                                'evidence': f"Plugin Match: {name}",
                                'confidence': 'Medium'
                            })
                    except: pass
    except Exception as e:
        print(f"[WEB] ❌ Tool 5 Error: {e}")

    # 3. Katana (Deep Crawling)
    crawled_urls_file = "crawled_urls.txt"
    try:
        print("[WEB] Tool 8: Katana Deep Crawling...")
        katana_path = shutil.which('katana') or '/usr/local/bin/katana'
        
        if os.path.exists(katana_path):
            # [FIXED] -kf 옵션에 'all' 명시하여 플래그 오류 수정
            cmd_katana = [
                katana_path, 
                '-u', url, 
                '-jc', 
                '-kf', 'all', 
                '-silent', 
                '-o', crawled_urls_file
            ]
            print(f"[DEBUG] Executing Katana: {' '.join(cmd_katana)}")
            subprocess.run(cmd_katana, timeout=60)
            
            url_count = 0
            if os.path.exists(crawled_urls_file):
                with open(crawled_urls_file, 'r') as f:
                    url_count = len(f.readlines())
            print(f"[WEB] ✅ Katana found {url_count} URLs")
        else:
            print("[WEB] ❌ Katana binary not found. Skipping deep crawl.")
            with open(crawled_urls_file, 'w') as f:
                f.write(url + "\n")
                
    except Exception as e:
        print(f"[WEB] ❌ Tool 8 (Katana) Error: {e}")
        with open(crawled_urls_file, 'w') as f:
            f.write(url + "\n")

    # 4. Nuclei (List Scan + ZAP Trigger)
    try:
        print("[WEB] Tool 9: Nuclei Vulnerability Scan (on crawled URLs)...")
        nuclei_path = shutil.which('nuclei') or '/usr/local/bin/nuclei'
        
        if os.path.exists(nuclei_path):
            cmd = [
                nuclei_path, 
                '-list', crawled_urls_file,
                '-tags', 'cve,vuln,tech',
                '-severity', 'critical,high,medium,low,info',
                '-j', '-o', 'nuclei_results.json', '-stats', '-si', '10', '-c', '50', '-rl', '100', '-bs', '10'
            ]
            print(f"[DEBUG] Executing Nuclei: {' '.join(cmd)}")
            
            subprocess.run(cmd, errors='ignore')
            if os.path.exists('nuclei_results.json'):
                with open('nuclei_results.json', 'r') as f: nuclei_out = f.read()
                os.remove('nuclei_results.json')
            else: nuclei_out = ''
            
            target_urls_for_zap = set()
            vuln_count = 0
            
            if nuclei_out:
                for line in nuclei_out.strip().split('\n'):
                    if not line: continue
                    try:
                        scan_res = json.loads(line)
                        info = scan_res.get('info', {})
                        severity = info.get('severity', 'info').lower()
                        name = info.get('name', 'Unknown')
                        matched_at = scan_res.get('matched-at', url)

                        # [TEST] Info 레벨도 ZAP 트리거
                        if severity in ['critical', 'high', 'medium', 'low', 'info']:
                             target_urls_for_zap.add(matched_at)
                            
                        if severity in ['critical', 'high', 'medium']:
                             results['nuclei_vulns'].append({
                                'name': name, 'severity': severity, 'url': matched_at,
                                'cve_id': info.get('classification', {}).get('cve-id')
                            })
                             vuln_count += 1
                        else:
                             if not any(t['name'] == name for t in results['webtechnologies']):
                                 results['webtechnologies'].append({
                                    'name': name, 'version': '', 'source': 'Nuclei',
                                    'confidence': 'High'
                                })

                    except: continue

            print(f"[WEB] ✅ Nuclei finished. Triggering ZAP for {len(target_urls_for_zap)} URLs.")

            if target_urls_for_zap:
                print(f"[WEB] 🚀 Triggering ZAP Targeted Scan...")
                try:
                    from app.core.scanner.zap_scanner import ZapScanner
                    zap = ZapScanner()
                    limited_targets = list(target_urls_for_zap)[:5]
                    zap_res = zap.targeted_scan(limited_targets)
                    results['zap_results'] = zap_res
                    print(f"[WEB] ✅ ZAP Targeted Scan completed with {len(zap_res.get('alerts', []))} alerts")
                except Exception as z_err:
                    print(f"[WEB] ❌ ZAP Error: {z_err}")
        else:
            print("[WEB] ❌ Nuclei binary not found")
            
    except Exception as e:
        print(f"[WEB] ❌ Tool 9 (Nuclei) Error: {e}")
>>>>>>> 6765f0338e4cc09c98a75bde603f7d50bbd85642
    finally:
        if os.path.exists(crawled_urls_file):
            os.remove(crawled_urls_file)

    return results

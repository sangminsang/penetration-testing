import requests
import re
import logging
import subprocess
import json
import shutil
import sys
import os
from pathlib import Path
from typing import Dict, Any, List

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def collect_web_info(url):
    """
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
            proc = subprocess.run(cmd, capture_output=True, text=True, errors='ignore')
            if proc.stdout:
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
                '-j', '-silent'
            ]
            print(f"[DEBUG] Executing Nuclei: {' '.join(cmd)}")
            
            proc = subprocess.run(cmd, capture_output=True, text=True, errors='ignore')
            
            target_urls_for_zap = set()
            vuln_count = 0
            
            if proc.stdout:
                for line in proc.stdout.strip().split('\n'):
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
    finally:
        if os.path.exists(crawled_urls_file):
            os.remove(crawled_urls_file)

    return results

import requests
import re
import logging
import subprocess
import json
import shutil
import sys
import os
from pathlib import Path

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def collect_web_info(url):
    """
    통합 웹 정찰 함수 (Final Fix: Nuclei Path & WhatWeb Regex)
    """
    results = {
        'headers': {},
        'wappalyzer': [],
        'whatweb': [],
        'sqli': {},
        'webtechnologies': [] 
    }
    
    print("======================================================================")
    print(f"[WEB] Starting ENHANCED multi-tool web scan (Final Fix)")
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
        print(f"[WEB] Tool 1: HTTP Status {resp.status_code}, Headers: {len(resp.headers)}")
    except Exception as e:
        print(f"[WEB] ❌ Tool 1 Error: {e}")

    # 2. WhatWeb (핀셋 파싱 적용)
    try:
        print("[WEB] Tool 5: WhatWeb Analysis...")
        if shutil.which('whatweb'):
            # --color=never 필수
            cmd = ['whatweb', '--log-json', '-', '--color=never', url]
            proc = subprocess.run(cmd, capture_output=True, text=True, errors='ignore')
            
            if proc.stdout:
                # 텍스트가 섞여 있어도 {"target":...} 패턴만 정확히 찾아냄
                match = re.search(r'(\{.*"target":.*\})', proc.stdout)
                
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
                    except json.JSONDecodeError:
                        print("[WEB] ⚠️ WhatWeb found JSON-like string but failed to decode")
                else:
                    print("[WEB] ⚠️ WhatWeb output did not contain valid JSON object")
            else:
                 print(f"[WEB] ⚠️ WhatWeb failed (No Output). Return: {proc.returncode}")
        else:
            print("[WEB] ❌ 'whatweb' binary not found in PATH")
    except Exception as e:
        print(f"[WEB] ❌ Tool 5 Error: {e}")

    # 3. Nuclei (경로 및 플래그 수정)
    try:
        print("[WEB] Tool 9: Nuclei Technology Detection...")
        
        nuclei_path = shutil.which('nuclei')
        if not nuclei_path and Path('/usr/local/bin/nuclei').exists():
            nuclei_path = '/usr/local/bin/nuclei'
            
        # 템플릿 경로 자동 탐지 (사용자 홈 디렉토리)
        home_dir = os.path.expanduser('~lsm') # lsm 사용자의 홈 강제 지정
        possible_paths = [
            f"{home_dir}/nuclei-templates/http/technologies",
            "/home/lsm/nuclei-templates/http/technologies",
            "http/technologies" # fallback
        ]
        
        template_path = "http/technologies"
        for p in possible_paths:
            if os.path.exists(p):
                template_path = p
                print(f"[DEBUG] Using Nuclei templates from: {template_path}")
                break
            
        if nuclei_path:
            # -json 대신 -j 사용, 템플릿 경로 명시
            cmd = [nuclei_path, '-u', url, '-t', template_path, '-j', '-silent']
            print(f"[DEBUG] Executing Nuclei: {' '.join(cmd)}")
            
            proc = subprocess.run(cmd, capture_output=True, text=True, errors='ignore')
            
            found_count = 0
            if proc.stdout:
                for line in proc.stdout.strip().split('\n'):
                    if not line: continue
                    try:
                        scan_res = json.loads(line)
                        info = scan_res.get('info', {})
                        tech_name = info.get('name', 'Unknown')
                        
                        results['webtechnologies'].append({
                            'name': tech_name,
                            'version': '',
                            'source': 'Nuclei',
                            'evidence': f"Template: {scan_res.get('template-id')}",
                            'confidence': 'High'
                        })
                        found_count += 1
                    except:
                        continue
            
            if found_count > 0:
                print(f"[WEB] ✅ Nuclei found {found_count} technologies")
            else:
                print(f"[WEB] ℹ️ Nuclei finished. Found 0 matches.")
                if proc.stderr:
                    print(f"[DEBUG] Nuclei Stderr: {proc.stderr[:100]}")
        else:
            print("[WEB] ❌ 'nuclei' binary not found")
    except Exception as e:
        print(f"[WEB] ❌ Tool 9 Error: {e}")

    return results

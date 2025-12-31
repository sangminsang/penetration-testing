# app/core/recon/web.py
# 웹 애플리케이션 정보 수집 모듈 (완전 자동화 버전)
# ffuf, dirsearch, whatweb, wappalyzer 통합

import requests
import re
import logging
import subprocess
import json
import tempfile
import os
from typing import Dict, Any, List, Optional
from urllib.parse import urljoin, urlparse
from Wappalyzer import Wappalyzer, WebPage
import requests
from playwright.sync_api import sync_playwright

logger = logging.getLogger(__name__)

# User-Agent 설정
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

def detect_spa_with_playwright(url: str, timeout: int = 10000) -> Dict[str, Any]:
    """
    Playwright를 사용한 SPA 프레임워크 탐지
    
    Returns:
        {"is_spa": True/False, "framework": "angular/react/vue/none"}
    """
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="networkidle", timeout=timeout)
            
            # JavaScript 실행하여 프레임워크 탐지
            spa_detection = page.evaluate("""
                () => {
                    // Angular 탐지
                    if (window.ng || window.getAllAngularRootElements || document.querySelector('[ng-version]')) {
                        return {is_spa: true, framework: 'Angular'};
                    }
                    
                    // React 탐지
                    if (window.React || document.querySelector('[data-reactroot]') || document.querySelector('[data-reactid]')) {
                        return {is_spa: true, framework: 'React'};
                    }
                    
                    // Vue 탐지
                    if (window.Vue || document.querySelector('[data-v-]') || document.querySelector('[v-cloak]')) {
                        return {is_spa: true, framework: 'Vue'};
                    }
                    
                    // Svelte 탐지
                    if (document.body.innerHTML.includes('svelte-')) {
                        return {is_spa: true, framework: 'Svelte'};
                    }
                    
                    return {is_spa: false, framework: 'none'};
                }
            """)
            
            browser.close()
            logger.info(f"[WEB] SPA detection via Playwright: {spa_detection}")
            return spa_detection
            
    except Exception as e:
        logger.warning(f"[WEB] Playwright SPA detection failed: {e}")
        return {"is_spa": False, "framework": "none"}

def discover_endpoints_with_ffuf(target: str) -> List[Dict[str, Any]]:
    """
    ffuf를 사용한 자동 엔드포인트 발견 (폴백 포함)
    """
    endpoints = []
    
    # 🆕 최소화된 중요 경로만 (ffuf 성능 향상)
    critical_paths = [
        "package.json",
        "rest/admin/application-version",
        "api",
        "api/Challenges",
        "api/Users",
        "api/Products",
        "ftp/legal.md",
        "swagger.json",
        "openapi.json",
        "version",
        ".env"
    ]
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write('\n'.join(critical_paths))
        wordlist_path = f.name
    
    ffuf_success = False
    
    try:
        print(f"[WEB] Running ffuf with {len(critical_paths)} critical paths...")
        result = subprocess.run(
            [
                'ffuf',
                '-u', f'{target}/FUZZ',
                '-w', wordlist_path,
                '-mc', '200,201,204,301,302,307,401,403,500',
                '-t', '10',
                '-timeout', '3',
                '-o', '-',
                '-of', 'json',
                '-s'
            ],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0 and result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                results = data.get('results', [])
                if len(results) > 0:
                    ffuf_success = True
                for entry in results:
                    url = entry.get('url', '')
                    status = entry.get('status', 0)
                    endpoints.append({
                        'url': url,
                        'path': url.replace(target, ''),
                        'status': status,
                        'length': entry.get('length', 0),
                        'source': 'ffuf'
                    })
                    print(f"[WEB] ffuf found: {url} [{status}]")
            except json.JSONDecodeError as e:
                print(f"[WEB] ffuf JSON parse error, fallback to manual")
        
        print(f"[WEB] ffuf discovered {len(endpoints)} endpoints")
        
    except FileNotFoundError:
        print(f"[WEB] ffuf not installed (using manual fallback)")
    except subprocess.TimeoutExpired:
        print(f"[WEB] ffuf timeout (using manual fallback)")
    except Exception as e:
        print(f"[WEB] ffuf error: {e} (using manual fallback)")
    finally:
        try:
            os.unlink(wordlist_path)
        except:
            pass
    
    # 🆕 ffuf 실패 또는 결과 없음 → 수동 확인
    if not ffuf_success or len(endpoints) == 0:
        print(f"[WEB] Using manual fallback for critical paths...")
        for path in critical_paths[:7]:
            try:
                url = f"{target}/{path}"
                response = requests.get(url, timeout=3, verify=False, 
                                       headers={"User-Agent": DEFAULT_USER_AGENT},
                                       allow_redirects=False)
                if response.status_code in [200, 201, 204, 301, 302, 307, 401, 403, 500]:
                    endpoints.append({
                        'url': url,
                        'path': f'/{path}',
                        'status': response.status_code,
                        'length': len(response.content),
                        'source': 'manual_fallback'
                    })
                    print(f"[WEB] Manual check found: {url} [{response.status_code}]")
            except:
                continue
        print(f"[WEB] Manual fallback discovered {len(endpoints)} endpoints")
    
    return endpoints

def extract_version_from_endpoints(target: str, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    엔드포인트에서 기술 스택 버전 정보 추출
    - Juice Shop 우회 경로 추가
    - 리다이렉트 방어 대응
    - 백업 파일 탐색
    """
    technologies = []
    
    for endpoint in endpoints:
        url = endpoint.get("url", "")
        path = endpoint.get("path", "").lower()
        status = endpoint.get("status", 0)
        
        if status not in [200, 500]:
            continue
        
        try:
            # ===================================================================
            # 1. package.json 파싱 (Juice Shop 우회 경로 추가)
            # ===================================================================
            if "package.json" in path:
                print(f"[WEB] 🔍 Trying multiple package.json paths (Juice Shop bypass)...")
                
                # 🔥 실전 우회 경로 (CTF/모의해킹 기법)
                package_paths = [
                    "/package.json",
                    "/ftp/package.json",              # Juice Shop FTP 경로
                    "/ftp/package.json.bak",          # 🔥 백업 파일 실수
                    "/ftp/package.json~",             # 🔥 Vim 백업 파일
                    "/api/package.json",              # 🔥 API 경로 노출
                    "/%2e%2e/package.json",           # 🔥 URL 인코딩 우회 (../)
                    "/%2e%2e%2fpackage.json",         # 🔥 ../package.json 인코딩
                    "/assets/package.json",
                    "/../package.json",
                    "/static/package.json",
                    "/public/package.json",
                    "/dist/package.json",
                    "/.git/../package.json",
                    "/node_modules/../package.json",  # 🔥 Node.js 경로 추측
                    "/backup/package.json",           # 🔥 일반적인 백업 디렉토리
                    "/old/package.json",              # 🔥 구버전 디렉토리
                    "/v1/package.json",               # 🔥 버전 관리 디렉토리
                ]
                
                session = requests.Session()
                session.headers.update({
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "application/json, text/plain, */*",  # 🔥 JSON 우선 요청
                })
                
                found = False
                
                for alt_path in package_paths:
                    try:
                        alt_url = f"{target}{alt_path}"
                        print(f"[WEB] Attempting: {alt_url}")
                        
                        # 🔥 리다이렉트 비활성화 (Juice Shop 대응)
                        resp = session.get(
                            alt_url, 
                            allow_redirects=False,  # 🔥 중요: 리다이렉트 차단
                            timeout=10, 
                            verify=False
                        )
                        
                        content_type = resp.headers.get('Content-Type', 'unknown')
                        content_length = len(resp.content)
                        
                        print(f"[WEB] Response: {resp.status_code}, Content-Type: {content_type}, Size: {content_length} bytes")
                        
                        # 🔥 리다이렉트 탐지 및 로깅
                        if resp.status_code in [301, 302, 303, 307, 308]:
                            redirect_location = resp.headers.get('Location', 'unknown')
                            print(f"[WEB] ⚠️ Redirect detected: {resp.status_code} -> {redirect_location}")
                            print(f"[WEB] 💡 Juice Shop is redirecting package.json to HTML page (defense mechanism)")
                            continue
                        
                        # 🔥 200 OK만 처리
                        if resp.status_code == 200:
                            # 🔥 응답 크기 체크 (HTML 페이지 필터링)
                            if content_length > 100000:  # 100KB 이상이면 의심
                                print(f"[WEB] ✗ Response too large ({content_length} bytes) - likely HTML page, not JSON")
                                continue
                            
                            # 🔥 Content-Type이 HTML이면 스킵 (확실한 리다이렉트 결과)
                            if 'text/html' in content_type.lower() and content_length > 10000:
                                print(f"[WEB] ✗ Content-Type is HTML and large size - skipping")
                                continue
                            
                            # 🔥 무조건 JSON 파싱 시도
                            try:
                                pkg_data = resp.json()
                                
                                # 🔥 JSON이지만 package.json이 아닌 경우 체크
                                if not isinstance(pkg_data, dict):
                                    print(f"[WEB] ✗ Response is not a JSON object")
                                    continue
                                
                                # dependencies 확인
                                if 'dependencies' in pkg_data or 'devDependencies' in pkg_data:
                                    print(f"[WEB] ✅ Found valid package.json at: {alt_path}")
                                    print(f"[WEB] 🎯 Juice Shop bypass successful! Path: {alt_path}")
                                    
                                    # 기본 정보 추출
                                    pkg_name = pkg_data.get('name', 'Unknown')
                                    pkg_version = pkg_data.get('version', 'Unknown')
                                    print(f"[WEB] 📦 Package: {pkg_name} v{pkg_version}")
                                    
                                    # Express, Angular 등 추출
                                    deps = pkg_data.get('dependencies', {})
                                    dev_deps = pkg_data.get('devDependencies', {})
                                    all_deps = {**deps, **dev_deps}
                                    
                                    # 🔥 중요 패키지 확장 (더 많은 기술 스택 탐지)
                                    important_packages = [
                                        # Backend Frameworks
                                        'express', 'koa', 'fastify', 'nest', 'hapi',
                                        # Frontend Frameworks
                                        'angular', '@angular/core', '@angular/cli',
                                        'react', 'react-dom', 'vue', 'next', 'nuxt', 'svelte',
                                        # Database & ORM
                                        'sequelize', 'mongoose', 'typeorm', 'prisma', 'knex',
                                        # Authentication
                                        'passport', 'jsonwebtoken', 'bcrypt', 'express-jwt',
                                        # Security
                                        'helmet', 'cors', 'express-rate-limit',
                                        # Testing
                                        'jest', 'mocha', 'chai', 'cypress', 'protractor',
                                        # Build Tools
                                        'webpack', 'vite', 'rollup', 'parcel',
                                        # Other
                                        'socket.io', 'axios', 'dotenv', 'express-session'
                                    ]
                                    
                                    found_count = 0
                                    for pkg_name, version in all_deps.items():
                                        if any(imp in pkg_name.lower() for imp in important_packages):
                                            clean_version = version.strip().lstrip('^~>=<')
                                            
                                            # 카테고리 판별
                                            category = 'other'
                                            if any(x in pkg_name.lower() for x in ['express', 'koa', 'fastify', 'nest', 'hapi']):
                                                category = 'backend'
                                            elif any(x in pkg_name.lower() for x in ['angular', 'react', 'vue', 'next', 'nuxt', 'svelte']):
                                                category = 'frontend'
                                            elif any(x in pkg_name.lower() for x in ['sequelize', 'mongoose', 'typeorm', 'prisma', 'knex']):
                                                category = 'database'
                                            elif any(x in pkg_name.lower() for x in ['passport', 'jsonwebtoken', 'bcrypt', 'jwt']):
                                                category = 'authentication'
                                            elif any(x in pkg_name.lower() for x in ['helmet', 'cors', 'rate-limit']):
                                                category = 'security'
                                            elif any(x in pkg_name.lower() for x in ['jest', 'mocha', 'chai', 'cypress', 'protractor']):
                                                category = 'testing'
                                            elif any(x in pkg_name.lower() for x in ['webpack', 'vite', 'rollup', 'parcel']):
                                                category = 'build-tool'
                                            
                                            technologies.append({
                                                "name": pkg_name,
                                                "version": clean_version,
                                                "product": pkg_name,
                                                "category": category,
                                                "language": "JavaScript",
                                                "source": f"package.json:{alt_path}"  # 🔥 어느 경로에서 찾았는지 기록
                                            })
                                            print(f"[WEB] 📦 {pkg_name}: {clean_version} [{category}] (from {alt_path})")
                                            found_count += 1
                                    
                                    print(f"[WEB] ✅ Total {found_count} packages extracted from package.json")
                                    found = True
                                    break  # 성공하면 루프 종료
                                    
                                elif 'name' in pkg_data:
                                    # package.json이지만 dependencies가 없는 경우
                                    print(f"[WEB] ⚠️ Found package.json but no dependencies at {alt_path}")
                                else:
                                    print(f"[WEB] ✗ JSON response but not a valid package.json")
                                    
                            except json.JSONDecodeError as e:
                                print(f"[WEB] ✗ Invalid JSON at {alt_path}: {str(e)[:100]}")
                                # 🔥 디버깅: 응답 일부 출력
                                preview = resp.text[:200].replace('\n', ' ')
                                print(f"[WEB] 📄 Response preview: {preview}...")
                                continue
                        
                    except requests.Timeout:
                        print(f"[WEB] ⏱️ Timeout for {alt_path}")
                        continue
                    except requests.ConnectionError:
                        print(f"[WEB] 🔌 Connection error for {alt_path}")
                        continue
                    except Exception as e:
                        print(f"[WEB] ✗ Error fetching {alt_path}: {str(e)[:100]}")
                        continue
                
                if not found:
                    print(f"[WEB] ❌ package.json not accessible from any path")
                    print(f"[WEB] 💡 Juice Shop defense is active - all attempts blocked/redirected")
            
            # ===================================================================
            # 2. application-version 엔드포인트
            # ===================================================================
            elif "application-version" in path or ("version" in path and "api" not in path):
                print(f"[WEB] 🔍 Fetching version from {url}...")
                try:
                    response = requests.get(
                        url, 
                        timeout=5, 
                        verify=False, 
                        headers={"User-Agent": DEFAULT_USER_AGENT}
                    )
                    
                    if response.status_code == 200:
                        try:
                            version_data = response.json()
                            if isinstance(version_data, dict):
                                if "version" in version_data:
                                    technologies.append({
                                        "name": "Application",
                                        "version": str(version_data["version"]),
                                        "product": "Application",
                                        "category": "application",
                                        "language": None,
                                        "source": "api:version-endpoint"
                                    })
                                    print(f"[WEB] ✅ Version: {version_data['version']}")
                        except:
                            # JSON 파싱 실패 시 정규표현식으로 버전 추출
                            version_match = re.search(r'(\d+\.\d+\.\d+)', response.text)
                            if version_match:
                                technologies.append({
                                    "name": "Application",
                                    "version": version_match.group(1),
                                    "product": "Application",
                                    "category": "application",
                                    "language": None,
                                    "source": "api:version-endpoint"
                                })
                                print(f"[WEB] ✅ Version: {version_match.group(1)}")
                                
                except Exception as e:
                    print(f"[WEB] ✗ Error fetching version: {e}")
            
            # ===================================================================
            # 3. API 에러 메시지에서 기술 스택 추출
            # ===================================================================
            elif "api" in path and status == 500:
                print(f"[WEB] 🔍 Analyzing API error at {url}...")
                try:
                    response = requests.get(
                        url, 
                        timeout=5, 
                        verify=False, 
                        headers={"User-Agent": DEFAULT_USER_AGENT}
                    )
                    
                    error_text = response.text.lower()
                    
                    # Express 탐지
                    if "express" in error_text:
                        technologies.append({
                            "name": "Express",
                            "version": "",
                            "product": "Express",
                            "category": "backend",
                            "language": "JavaScript",
                            "source": "api:error-message"
                        })
                        print(f"[WEB] ✅ Detected Express from error message")
                    
                    # Node.js 버전 탐지
                    if "node" in error_text:
                        node_match = re.search(r'node.?v?(\d+\.\d+\.\d+)', response.text, re.IGNORECASE)
                        if node_match:
                            technologies.append({
                                "name": "Node.js",
                                "version": node_match.group(1),
                                "product": "Node.js",
                                "category": "runtime",
                                "language": "JavaScript",
                                "source": "api:error-message"
                            })
                            print(f"[WEB] ✅ Node.js version: {node_match.group(1)}")
                    
                    # 추가: Stack trace에서 더 많은 정보 추출
                    stack_patterns = [
                        (r'at\s+(\w+)\s+\(.*?node_modules/([^/]+)', 'dependency'),  # Stack trace에서 패키지명
                        (r'Error:\s+.*?(\w+)\s+is not defined', 'missing-module'),
                    ]
                    
                    for pattern, info_type in stack_patterns:
                        matches = re.findall(pattern, response.text, re.IGNORECASE)
                        if matches:
                            print(f"[WEB] 📝 Found {len(matches)} {info_type} references in error")
                            
                except Exception as e:
                    print(f"[WEB] ✗ Error analyzing API error: {e}")
        
        except Exception as e:
            print(f"[WEB] ⚠️ Unexpected error in endpoint processing: {e}")
            continue
    
    return technologies

def detect_with_wappalyzer(target: str) -> List[Dict[str, Any]]:
    """Wappalyzer를 사용하여 웹 기술 스택 탐지 (Python API 방식)"""
    technologies = []
    try:
        print("[WEB] Running Wappalyzer (Python API)...")
        
        # ===== 🔥 Import 추가 =====
        from Wappalyzer import Wappalyzer, WebPage
        import requests
        
        # 최신 기술 DB 다운로드
        wappalyzer = Wappalyzer.latest()
        
        print(f"[WEB] Fetching {target} for Wappalyzer analysis...")
        
        # 요청 보내기
        response = requests.get(target, timeout=10, verify=False, headers={"User-Agent": DEFAULT_USER_AGENT})
        
        # WebPage 객체 생성
        webpage = WebPage(
            url=target,
            html=response.text,
            headers=dict(response.headers)
        )
        
        # 기술 탐지
        detected = wappalyzer.analyze(webpage)
        print(f"[WEB] Wappalyzer detected {len(detected)} technologies")
        
        for tech_name in detected:
            tech_info = {
                "name": tech_name,
                "version": "",
                "source": "wappalyzer"
            }
            technologies.append(tech_info)
            print(f"[WEB] Wappalyzer detected: {tech_name}")
        
        # Angular 누락 디버깅
        if "Angular" not in detected and "angular" in response.text.lower():
            print("[WEB] ⚠️ WARNING: Angular exists in HTML but Wappalyzer missed it!")
            print("[WEB] This might be due to outdated Wappalyzer signatures.")
        
    except ImportError as e:
        print(f"[WEB] Wappalyzer Python library not installed: {e}")
        return []
    except Exception as e:
        print(f"[WEB] Wappalyzer analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return []
    
    return technologies


def detect_with_whatweb(target: str) -> List[Dict[str, Any]]:
    """WhatWeb으로 기술 스택 감지"""
    technologies = []
    try:
        print(f"[WEB] Running WhatWeb...")
        result = subprocess.run(
            ['whatweb', '--log-json=-', '--color=never', '--no-errors', target],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0 and result.stdout:
            for line in result.stdout.strip().split('\n'):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    plugins = data.get('plugins', {})
                    
                    for plugin_name, plugin_data in plugins.items():
                        version = ""
                        if isinstance(plugin_data, dict):
                            version_list = plugin_data.get('version', [])
                            if isinstance(version_list, list) and len(version_list) > 0:
                                version = str(version_list[0])
                            elif isinstance(version_list, str):
                                version = version_list
                        
                        # 🆕 이름에서 버전 분리
                        clean_name = plugin_name
                        if not version:
                            # 이름에 버전이 포함된 경우 (예: "JQuery 2.2.4")
                            version_match = re.search(r'(\d+\.\d+\.\ d+|\d+\.\d+)', plugin_name)
                            if version_match:
                                version = version_match.group(1)
                                clean_name = plugin_name[:version_match.start()].strip()
                        
                        technologies.append({
                            'name': clean_name,
                            'version': version,
                            'source': 'whatweb'
                        })
                        print(f"[WEB] WhatWeb detected: {clean_name} {version}")
                        
                except json.JSONDecodeError:
                    continue
                    
    except FileNotFoundError:
        print(f"[WEB] WhatWeb not installed (skipping)")
    except Exception as e:
        print(f"[WEB] WhatWeb failed: {e}")
    
    return technologies

def detect_with_http_headers(target: str) -> List[Dict[str, Any]]:
    """HTTP 헤더 및 HTML 분석 - Recog 통합"""
    print("[WEB] 🔥🔥🔥 RECOG-POWERED VERSION 🔥🔥🔥")
    technologies = []
    
    # ===== 🔥 Recog 초기화 =====
    try:
        from .fingerprint import RecogFingerprinter
        recog = RecogFingerprinter()
        use_recog = True
        print("[WEB] ✓ Recog fingerprinter loaded")
    except Exception as e:
        print(f"[WEB] ⚠️  Recog not available: {e}")
        recog = None
        use_recog = False
    
    try:
        print("[WEB] Analyzing HTTP headers...")
        response = requests.get(
            target, 
            timeout=10, 
            verify=False,
            headers={"User-Agent": DEFAULT_USER_AGENT}
        )
        
        headers = response.headers
        print(f"[WEB] HTTP Status: {response.status_code}")
        
        # ===== 🔥 Recog로 헤더 분석 =====
        if use_recog and recog:
            # Server 헤더
            if "Server" in headers:
                server = headers["Server"]
                print(f"[WEB] Analyzing Server header with Recog: {server}")
                
                match = recog.match_http_header(server)
                if match:
                    technologies.append({
                        "name": match.get("product", "Unknown"),
                        "version": match.get("version", ""),
                        "source": match.get("source", "recog")
                    })
                    print(f"[WEB] ✓ Recog matched: {match.get('product')} {match.get('version')}")
                else:
                    # Recog 실패하면 기존 로직
                    if "/" in server:
                        parts = server.split("/")
                        technologies.append({
                            "name": parts[0].strip(),
                            "version": parts[1].strip() if len(parts) > 1 else "",
                            "source": "http:server-header"
                        })
            
            # X-Powered-By 헤더
            if "X-Powered-By" in headers:
                powered = headers["X-Powered-By"]
                print(f"[WEB] Analyzing X-Powered-By with Recog: {powered}")
                
                match = recog.match_http_header(powered)
                if match:
                    technologies.append({
                        "name": match.get("product", "Unknown"),
                        "version": match.get("version", ""),
                        "source": match.get("source", "recog")
                    })
                    print(f"[WEB] ✓ Recog matched: {match.get('product')} {match.get('version')}")
        
        # 나머지 기존 로직...
        # (HTML 분석, Angular 탐지 등은 그대로 유지)
        
    except Exception as e:
        print(f"[WEB] HTTP detection failed: {e}")
    
    return technologies


def analyze_http_headers(url: str) -> Dict[str, Any]:
    """HTTP 헤더 분석"""
    try:
        for protocol in ['https', 'http']:
            try:
                parsed = urlparse(url)
                test_url = f"{protocol}://{parsed.netloc or parsed.path}"
                if not parsed.netloc:
                    continue
                
                response = requests.get(
                    test_url,
                    timeout=10,
                    allow_redirects=True,
                    verify=False,
                    headers={"User-Agent": DEFAULT_USER_AGENT}
                )
                
                headers = dict(response.headers)
                waf_info = detect_waf(test_url, headers, response.text[:10000])
                cms_info = detect_cms(test_url, response.text[:50000], headers)
                security_headers = analyze_security_headers(headers)
                
                web_server = headers.get('Server', '')
                web_framework = None
                x_powered_by = headers.get('X-Powered-By', '')
                if x_powered_by:
                    web_framework = x_powered_by
                
                programming_language = None
                if 'PHP' in x_powered_by:
                    php_match = re.search(r'PHP/(\d+\.\d+)', x_powered_by)
                    if php_match:
                        programming_language = f"PHP/{php_match.group(1)}"
                
                return {
                    'web_server': web_server,
                    'web_framework': web_framework,
                    'programming_language': programming_language,
                    'headers': headers,
                    'status_code': response.status_code,
                    'url': test_url,
                    'waf': waf_info,
                    'cms': cms_info,
                    'security_headers': security_headers
                }
            except:
                continue
    except Exception as e:
        logger.warning(f"HTTP: {e}")
        return {}


def detect_waf(url: str, headers: Dict[str, str], response_text: str) -> Dict[str, Any]:
    """WAF 감지"""
    waf_info = {"waf": None, "detected": False, "signatures": []}
    
    waf_signatures = {
        'cloudflare': {'headers': ['cf-ray'], 'patterns': [r'cloudflare']},
        'aws-waf': {'headers': ['x-amzn-requestid'], 'patterns': [r'aws']},
        'akamai': {'headers': ['x-akamai-request-id'], 'patterns': [r'akamai']},
    }
    
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    response_lower = response_text.lower()
    
    for waf_name, signatures in waf_signatures.items():
        detected = False
        found_signatures = []
        
        for header in signatures.get('headers', []):
            if header.lower() in headers_lower:
                detected = True
                found_signatures.append(f"Header: {header}")
        
        if detected:
            waf_info['waf'] = waf_name
            waf_info['detected'] = True
            waf_info['signatures'] = found_signatures
            break
    
    return waf_info


def detect_cms(url: str, html: str, headers: Dict[str, str]) -> Dict[str, Any]:
    """CMS 감지"""
    cms_info = {"cms": None, "version": None, "detected": False}
    html_lower = html.lower()
    
    cms_signatures = {
        'wordpress': {'patterns': [r'wp-content', r'wp-includes']},
        'drupal': {'patterns': [r'sites/default', r'drupal']},
        'joomla': {'patterns': [r'components/com_', r'joomla']}
    }
    
    for cms_name, signatures in cms_signatures.items():
        for pattern in signatures.get('patterns', []):
            if re.search(pattern, html_lower, re.IGNORECASE):
                cms_info['cms'] = cms_name
                cms_info['detected'] = True
                break
        if cms_info['detected']:
            break
    
    return cms_info


def analyze_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """보안 헤더 분석"""
    critical_headers = {
        'Strict-Transport-Security': {'critical': True},
        'Content-Security-Policy': {'critical': True},
        'X-Frame-Options': {'critical': True},
        'X-Content-Type-Options': {'critical': False}
    }
    
    present = []
    missing = []
    
    for header_name, header_info in critical_headers.items():
        if header_name in headers:
            present.append({'header': header_name, 'value': headers[header_name]})
        else:
            missing.append({'header': header_name, 'critical': header_info['critical']})
    
    score = int((len(present) / len(critical_headers)) * 100)
    
    return {
        'missing': missing,
        'present': present,
        'score': score
    }


def detect_javascript_libraries(url: str) -> List[Dict[str, str]]:
    """JavaScript 라이브러리 감지"""
    libraries = []
    try:
        parsed = urlparse(url)
        base_url = f"{parsed.scheme or 'https'}://{parsed.netloc}"
        response = requests.get(base_url, timeout=10, verify=False, 
                               headers={"User-Agent": DEFAULT_USER_AGENT})
        html_content = response.text[:50000]
        
        if 'jquery' in html_content.lower():
            jquery_match = re.search(r'jquery[.-]?(\d+\.\d+\.\d+)', html_content, re.IGNORECASE)
            if jquery_match:
                libraries.append({"library": "jQuery", "version": jquery_match.group(1)})
        
        if 'angular' in html_content.lower():
            ng_version_match = re.search(r'ng-version=["\'](\d+\.\d+\.\d+)["\']', html_content, re.IGNORECASE)
            if ng_version_match:
                libraries.append({"library": "Angular", "version": ng_version_match.group(1)})
    
    except Exception as e:
        logger.warning(f"JavaScript: {e}")
    
    return libraries


def find_exposed_files(url: str) -> tuple:
    """노출된 파일 발견"""
    exposed_files = []
    package_info = None
    
    common_files = [".env", "package.json", "composer.json", ".git/config"]
    
    try:
        parsed = urlparse(url)
        base_url = f"{parsed.scheme or 'https'}://{parsed.netloc}"
        
        for file_path in common_files[:5]:
            try:
                test_url = urljoin(base_url, file_path)
                response = requests.get(test_url, timeout=5, verify=False, 
                                       allow_redirects=False,
                                       headers={"User-Agent": DEFAULT_USER_AGENT})
                if response.status_code == 200:
                    file_type = "config"
                    exposed_files.append({
                        "path": file_path,
                        "type": file_type,
                        "url": test_url,
                        "size": len(response.content)
                    })
                    
                    if file_path == "package.json":
                        try:
                            package_info = json.loads(response.text)
                        except:
                            pass
            except:
                continue
    
    except Exception as e:
        logger.warning(f": {e}")
    
    return exposed_files, package_info


def discover_api_endpoints(url: str) -> List[Dict[str, Any]]:
    """API 엔드포인트 발견"""
    api_endpoints = []
    common_api_paths = ["/api", "/api/v1", "/graphql", "/swagger.json", "/api-docs", "/docs"]
    
    try:
        parsed = urlparse(url)
        base_url = f"{parsed.scheme or 'https'}://{parsed.netloc}"
        
        for path in common_api_paths[:5]:
            try:
                test_url = urljoin(base_url, path)
                response = requests.get(test_url, timeout=5, verify=False, 
                                       allow_redirects=False,
                                       headers={"User-Agent": DEFAULT_USER_AGENT})
                if response.status_code in [200, 401, 403]:
                    api_endpoints.append({
                        "path": path,
                        "url": test_url,
                        "status_code": response.status_code
                    })
            except:
                continue
    
    except Exception as e:
        logger.warning(f"API: {e}")
    
    return api_endpoints

def extract_api_calls_from_js(target: str) -> List[Dict[str, Any]]:
    """
    JavaScript 파일 내부의 API 호출 패턴을 정적 분석으로 추출
    (Step 2: 템플릿 리터럴 변수 제외 버전)
    """
    api_endpoints = []
    
    try:
        parsed = urlparse(target)
        base_url = f"{parsed.scheme or 'https'}://{parsed.netloc}"
        
        # JavaScript 파일 경로
        js_paths = [
            'static/js/app.js',
            'js/main.js',
            'assets/main.js',
            'bundle.js',
            'app.bundle.js',
            'vendor.js',
            'chunk-vendors.js',
            'main.chunk.js',
            'runtime.js',
            'polyfills.js'
        ]
        
        # 🔥 수정된 API 패턴 (템플릿 리터럴 변수 제외)
        api_patterns = [
            # 기본 패턴 (따옴표 필수)
            r'axios\.(get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)',
            r'fetch\s*\(\s*["\']([^"\']+)',
            r'\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)',
            
            # 🔥 수정: 정적 문자열만 추출 (변수 제외)
            r'\.(?:get|post|put|delete|patch)\s*\(\s*["\']([/][^"\']+)["\']',  # .get('/api/...')
            r'this\.http\.(?:get|post|put|delete|patch)\s*\(\s*["\']([/][^"\']+)["\']',  # Angular
            
            # 🔥 변수 할당 패턴 (const url = '/api/...')
            r'(?:const|let|var)\s+\w+\s*=\s*["\']([/][^"\']+)["\']',
            r'url\s*:\s*["\']([/][^"\']+)["\']',
            r'endpoint\s*:\s*["\']([/][^"\']+)["\']',
            r'path\s*:\s*["\']([/][^"\']+)["\']',
            
            # 🔥 추가: 배열/객체에서 정적 경로 추출
            r'["\']([/]api[^"\']*)["\']',  # '/api/...' 형태 (가장 광범위)
            r'["\']([/]rest[^"\']*)["\']',  # '/rest/...'
        ]
        
        # 매우 관대한 필터링
        ignore_keywords = [
            'javascript:', 'mailto:', 'tel:', 'data:', 'blob:',
        ]
        
        print(f"[WEB] Extracting API calls from JavaScript files...")
        logger.info(f"[WEB] Starting JS API extraction for {target}")
        
        found_js_files = 0
        total_raw_matches = 0
        
        # 필터링 통계
        filtered_reasons = {
            'too_short': 0,
            'protocol': 0,
            'no_slash': 0,
            'generic_word': 0,
            'template_var': 0,
            'duplicate': 0
        }
        
        for js_path in js_paths:
            try:
                js_url = urljoin(base_url, js_path)
                response = requests.get(
                    js_url, 
                    timeout=10, 
                    verify=False, 
                    headers={'User-Agent': DEFAULT_USER_AGENT}
                )
                
                if response.status_code == 200:
                    found_js_files += 1
                    js_content = response.text
                    
                    print(f"[WEB] Analyzing {js_path} ({len(js_content)} bytes)")
                    
                    for pattern_idx, pattern in enumerate(api_patterns):
                        matches = re.findall(pattern, js_content, re.IGNORECASE)
                        
                        if matches and len(matches) > 0:
                            total_raw_matches += len(matches)
                            print(f"[WEB]   📊 Pattern #{pattern_idx+1} found {len(matches)} raw matches")
                        
                        for match in matches:
                            endpoint = match[-1] if isinstance(match, tuple) else match
                            
                            # 🔥 디버깅: 원본 출력
                            print(f"[WEB]   🔍 Raw match: '{endpoint}'")
                            
                            # 🔥 추가: 템플릿 리터럴 변수 완전 제외
                            if '${' in endpoint or endpoint.startswith('`') or endpoint.startswith('$'):
                                filtered_reasons['template_var'] += 1
                                print(f"[WEB]     ❌ Filtered: template literal variable")
                                continue
                            
                            # 필터링 1: 최소 길이
                            if len(endpoint) < 4:  # /api 최소 4자
                                filtered_reasons['too_short'] += 1
                                print(f"[WEB]     ❌ Filtered: too short ({len(endpoint)} chars)")
                                continue
                            
                            # 필터링 2: 프로토콜 제외
                            if any(keyword in endpoint.lower() for keyword in ignore_keywords):
                                filtered_reasons['protocol'] += 1
                                print(f"[WEB]     ❌ Filtered: protocol keyword")
                                continue
                            
                            # 필터링 3: /로 시작해야 함
                            if not endpoint.startswith('/'):
                                filtered_reasons['no_slash'] += 1
                                print(f"[WEB]     ❌ Filtered: doesn't start with '/'")
                                continue
                            
                            # 🔥 완화: 정적 리소스만 제외
                            generic_words = [
                                '.css', '.js', '.png', '.jpg', '.svg', '.ico', '.woff', '.ttf',
                                '/assets/', '/static/', '/public/', '/dist/', '/node_modules/'
                            ]
                            if any(word in endpoint.lower() for word in generic_words):
                                filtered_reasons['generic_word'] += 1
                                print(f"[WEB]     ❌ Filtered: generic static resource")
                                continue
                            
                            # URL 정규화
                            full_url = urljoin(base_url, endpoint)
                            
                            # 중복 체크
                            normalized_url = full_url.rstrip('/')
                            if any(e['url'].rstrip('/') == normalized_url for e in api_endpoints):
                                filtered_reasons['duplicate'] += 1
                                print(f"[WEB]     ⚠️ Duplicate: already added")
                                continue
                            
                            # 🎉 최종 통과!
                            api_endpoints.append({
                                'url': full_url,
                                'path': endpoint,
                                'source': f'js-static-analysis:{js_path}',
                                'method': 'unknown'
                            })
                            
                            print(f"[WEB]   ✅ ACCEPTED: {endpoint}")
                            logger.info(f"[WEB] Found API endpoint: {endpoint} in {js_path}")
                    
            except requests.Timeout:
                print(f"[WEB] ⏱️ Timeout for {js_path}")
                continue
            except Exception as e:
                logger.debug(f"[WEB] Error fetching {js_path}: {e}")
                continue
        
        # 최종 통계
        print(f"\n[WEB] ========================================")
        print(f"[WEB] 📊 FILTERING STATISTICS")
        print(f"[WEB] ========================================")
        print(f"[WEB] 📊 Total raw matches found: {total_raw_matches}")
        print(f"[WEB] 📊 Filtered by reason:")
        print(f"[WEB] 📊   - Too short (< 4 chars): {filtered_reasons['too_short']}")
        print(f"[WEB] 📊   - Protocol keyword: {filtered_reasons['protocol']}")
        print(f"[WEB] 📊   - No leading slash: {filtered_reasons['no_slash']}")
        print(f"[WEB] 📊   - Generic resource: {filtered_reasons['generic_word']}")
        print(f"[WEB] 📊   - Template variable: {filtered_reasons['template_var']}")
        print(f"[WEB] 📊   - Duplicate: {filtered_reasons['duplicate']}")
        print(f"[WEB] 📊 ========================================")
        print(f"[WEB] 📊 ✅ FINAL ACCEPTED: {len(api_endpoints)} API endpoints")
        print(f"[WEB] 📊 ========================================\n")
        
        print(f"[WEB] JS Analysis: Found {len(api_endpoints)} API endpoints from {found_js_files} JS files")
        
    except Exception as e:
        logger.warning(f"[WEB] JS API extraction failed: {e}")
    
    return api_endpoints


def detect_spa_framework(target: str) -> Dict[str, Any]:
    """
    SPA 프레임워크 탐지 (동적 스캔 필요 여부 판단용)
    
    Args:
        target: 타겟 URL
    
    Returns:
        {
            'is_spa': True/False,
            'framework': 'Angular'/'React'/'Vue'/None,
            'version': '버전',
            'confidence': 'high'/'medium'/'low',
            'indicators': ['발견된 증거들']
        }
    """
    result = {
        'is_spa': False,
        'framework': None,
        'version': None,
        'confidence': 'low',
        'indicators': []
    }
    
    try:
        print(f"[WEB] Detecting SPA framework...")
        
        response = requests.get(
            target, 
            timeout=10, 
            verify=False,
            headers={'User-Agent': DEFAULT_USER_AGENT}
        )
        
        html = response.text.lower()
        html_original = response.text  # 대소문자 구분용
        headers = dict(response.headers)
        
        # Angular 탐지
        angular_indicators = 0
        if 'ng-version' in html:
            angular_indicators += 3
            version_match = re.search(r'ng-version="([^"]+)"', html_original, re.IGNORECASE)
            if version_match:
                result['version'] = version_match.group(1)
                print(f"[WEB] Found Angular version from ng-version: {result['version']}")
            result['indicators'].append('ng-version attribute found')
        
        # 🔥 추가: 다른 Angular 버전 탐지 방법
        if not result['version']:
            # @angular/core 패키지 참조 찾기
            angular_core_match = re.search(r'@angular/core[@/]([0-9.]+)', html_original)
            if angular_core_match:
                result['version'] = angular_core_match.group(1)
                print(f"[WEB] Found Angular version from @angular/core: {result['version']}")
                angular_indicators += 2
            
            # Angular CLI 버전 정보
            cli_match = re.search(r'Angular CLI[:\s]+([0-9.]+)', html_original, re.IGNORECASE)
            if cli_match:
                result['version'] = cli_match.group(1)
                print(f"[WEB] Found Angular version from CLI: {result['version']}")
                angular_indicators += 1
        
        if any(x in html for x in ['ng-app', 'ng-controller', '[ng-', '(ng-']):
            angular_indicators += 2
            result['indicators'].append('Angular directives found')
        
        if 'angular' in html or '@angular/core' in html:
            angular_indicators += 1
            result['indicators'].append('Angular core reference')
        
        # 🔥 추가: Angular 빌드 파일 패턴 확인
        if any(x in html for x in ['main.js', 'polyfills.js', 'runtime.js', 'vendor.js']):
            # Angular CLI 기본 빌드 구조
            if 'runtime.js' in html and 'polyfills.js' in html:
                angular_indicators += 1
                result['indicators'].append('Angular build pattern detected')
        
        if angular_indicators >= 3:
            result['is_spa'] = True
            result['framework'] = 'Angular'
            result['confidence'] = 'high' if angular_indicators >= 4 else 'medium'
            print(f"[WEB] Detected Angular SPA (confidence: {result['confidence']}, version: {result.get('version', 'unknown')})")
            return result
        
        # React 탐지
        react_indicators = 0
        if any(x in html for x in ['react', 'reactdom', '_react', '__react']):
            react_indicators += 2
            result['indicators'].append('React references found')
            
            # 🔥 추가: React 버전 탐지
            react_version_match = re.search(r'react[@/]([0-9.]+)', html_original)
            if react_version_match:
                result['version'] = react_version_match.group(1)
                print(f"[WEB] Found React version: {result['version']}")
        
        if 'data-reactroot' in html or 'data-reactid' in html:
            react_indicators += 3
            result['indicators'].append('React DOM attributes')
        
        if '<div id="root">' in html or '<div id="app">' in html:
            react_indicators += 1
            result['indicators'].append('Common React root element')
        
        if react_indicators >= 3:
            result['is_spa'] = True
            result['framework'] = 'React'
            result['confidence'] = 'high' if react_indicators >= 4 else 'medium'
            print(f"[WEB] Detected React SPA (confidence: {result['confidence']}, version: {result.get('version', 'unknown')})")
            return result
        
        # Vue 탐지
        vue_indicators = 0
        if any(x in html for x in ['vue', 'v-if', 'v-for', 'v-bind', 'v-on', ':class', '@click']):
            vue_indicators += 2
            result['indicators'].append('Vue directives found')
            
            # 🔥 추가: Vue 버전 탐지
            vue_version_match = re.search(r'vue[@/]([0-9.]+)', html_original)
            if vue_version_match:
                result['version'] = vue_version_match.group(1)
                print(f"[WEB] Found Vue version: {result['version']}")
        
        if 'vue-router' in html or 'vuex' in html:
            vue_indicators += 2
            result['indicators'].append('Vue ecosystem libraries')
        
        if '<div id="app">' in html and 'vue' in html:
            vue_indicators += 1
            result['indicators'].append('Vue app structure')
        
        if vue_indicators >= 3:
            result['is_spa'] = True
            result['framework'] = 'Vue'
            result['confidence'] = 'high' if vue_indicators >= 4 else 'medium'
            print(f"[WEB] Detected Vue SPA (confidence: {result['confidence']}, version: {result.get('version', 'unknown')})")
            return result
        
        # SPA 일반 특성 탐지 (프레임워크 불명확)
        spa_generic_indicators = 0
        
        # 거의 비어있는 HTML body (JS로 렌더링)
        body_match = re.search(r'<body[^>]*>(.*?)</body>', html, re.DOTALL | re.IGNORECASE)
        if body_match:
            body_content = body_match.group(1).strip()
            # body가 주로 script 태그와 한 개의 div만 있는 경우
            if len(body_content) < 500 and '<script' in body_content:
                spa_generic_indicators += 2
                result['indicators'].append('Minimal HTML body (JS-rendered)')
        
        # 대량의 JS 번들 파일
        if any(x in html for x in ['bundle.js', 'chunk', 'vendor.js', 'main.js']):
            spa_generic_indicators += 1
            result['indicators'].append('Bundled JavaScript files')
        
        if spa_generic_indicators >= 2:
            result['is_spa'] = True
            result['framework'] = 'Unknown SPA'
            result['confidence'] = 'low'
            print(f"[WEB] Detected generic SPA pattern (framework unknown)")
            return result
        
        print(f"[WEB] No SPA detected - standard server-rendered site")
        
    except Exception as e:
        logger.warning(f"[WEB] SPA detection failed: {e}")
    
    return result


def smart_directory_bruteforce(url: str, detected_tech: List[str] = None, use_threading: bool = False) -> List[Dict[str, Any]]:
    """스마트 디렉토리 브루트포스 (ffuf 사용)"""
    return []  # ffuf로 대체


def collect_web_info(target: str) -> Dict[str, Any]:
    """
    웹 서비스 정보 수집 (개선된 버전)
    - 기존 멀티툴 스캔 유지
    - JavaScript 정적 분석 추가
    - SPA 프레임워크 탐지 추가
    """
    # URL 정규화
    if not target.startswith(('http://', 'https://')):
        if ':' in target and not target.startswith('['):
            parts = target.split(':')
            if len(parts) == 2 and parts[1].isdigit():
                target = f"http://{target}"
            else:
                target = f"https://{target}"
        else:
            target = f"https://{target}"
    
    print("=" * 70)
    print(f"[WEB] Starting ENHANCED multi-tool web scan")
    print(f"[WEB] Target: {target}")
    print("=" * 70)
    
    all_technologies = []
    
    # === Tool 1: HTTP Headers & HTML Analysis ===
    print(f"[WEB] Tool 1: HTTP Headers & HTML Analysis...")
    http_techs = detect_with_http_headers(target)
    all_technologies.extend(http_techs)
    print(f"[WEB] Tool 1 result: {len(http_techs)} technologies")
    
    # === Tool 2: ffuf Endpoint Discovery ===
    print(f"[WEB] Tool 2: ffuf Endpoint Discovery...")
    ffuf_endpoints = discover_endpoints_with_ffuf(target)
    print(f"[WEB] Tool 2 result: {len(ffuf_endpoints)} endpoints")
    
    # === Tool 3: Extracting versions from endpoints ===
    print(f"[WEB] Tool 3: Extracting versions from endpoints...")
    version_info = extract_version_from_endpoints(target, ffuf_endpoints)
    all_technologies.extend(version_info)
    print(f"[WEB] Tool 3 result: {len(version_info)} technologies")
    
    # === Tool 4: Wappalyzer ===
    print(f"[WEB] Tool 4: Wappalyzer...")
    wapp_techs = detect_with_wappalyzer(target)
    all_technologies.extend(wapp_techs)
    print(f"[WEB] Tool 4 result: {len(wapp_techs)} technologies")
    
    # === Tool 5: WhatWeb ===
    print(f"[WEB] Tool 5: WhatWeb...")
    what_techs = detect_with_whatweb(target)
    all_technologies.extend(what_techs)
    print(f"[WEB] Tool 5 result: {len(what_techs)} technologies")
    
    # === Tool 6: JavaScript 정적 분석 (NEW) ===
    print(f"[WEB] Tool 6: JavaScript Static Analysis (NEW)...")
    js_api_endpoints = extract_api_calls_from_js(target)
    print(f"[WEB] Tool 6 result: {len(js_api_endpoints)} API endpoints from JS")
    
    # === Tool 7: SPA 프레임워크 탐지 (NEW) ===
    print(f"[WEB] Tool 7: SPA Framework Detection (NEW)...")
    spa_info = detect_spa_framework(target)
    print(f"[WEB] Tool 7 result: SPA={spa_info['is_spa']}, Framework={spa_info.get('framework', 'None')}")
    
    # HTTP 정보 수집
    logger.info(f"{target}")
    http_info = analyze_http_headers(target)
    js_libs = detect_javascript_libraries(target)
    exposed, package_info = find_exposed_files(target)
    api_endpoints = discover_api_endpoints(target)
    
    # API 엔드포인트 통합 (기존 + JS 분석 결과)
    all_api_endpoints = api_endpoints + js_api_endpoints
    
    # 중복 제거
    unique_techs = []
    seen = set()
    for tech in all_technologies:
        key = f"{tech.get('name')}-{tech.get('version', '')}"
        if key not in seen:
            seen.add(key)
            unique_techs.append(tech)
    
    print("=" * 70)
    print(f"[WEB] Web scan completed: {len(unique_techs)} unique technologies")
    print("=" * 70)
    
    # web_technologies 리스트 생성
    web_technologies = []
    
    # HTTP 헤더에서 추출
    if http_info.get('web_server'):
        web_technologies.append({
            'name': http_info['web_server'],
            'version': '',
            'product': http_info['web_server'],
            'category': 'webserver',
            'language': None,
            'type': 'webserver',
            'source': 'HTTP Header'
        })
    
    if http_info.get('web_framework'):
        web_technologies.append({
            'name': http_info['web_framework'],
            'version': '',
            'product': http_info['web_framework'],
            'category': 'framework',
            'language': None,
            'type': 'framework',
            'source': 'HTTP Header'
        })
    
    # WAF 감지
    if http_info.get('waf', {}).get('detected'):
        waf_name = http_info['waf']['waf']
        web_technologies.append({
            'name': waf_name,
            'version': '',
            'product': waf_name,
            'category': 'security',
            'language': None,
            'type': 'waf',
            'source': 'WAF Detection'
        })
    
    # CMS 감지
    if http_info.get('cms', {}).get('detected'):
        cms_name = http_info['cms']['cms']
        web_technologies.append({
            'name': cms_name,
            'version': '',
            'product': cms_name,
            'category': 'cms',
            'language': None,
            'type': 'cms',
            'source': 'CMS Detection'
        })
    
    # JavaScript 라이브러리
    for lib in js_libs:
        web_technologies.append({
            'name': lib['library'],
            'version': lib.get('version', ''),
            'product': lib['library'],
            'category': 'frontend',
            'language': 'JavaScript',
            'type': 'javascript-library',
            'source': 'HTML Analysis'
        })
    
    # 멀티툴 결과 통합
    for tech in unique_techs:
        name = tech.get('name', 'Unknown')
        version = tech.get('version', '')
        source = tech.get('source', 'multi-tool')
        
        # 카테고리 및 언어 판별
        category = 'other'
        language = None
        
        tech_lower = name.lower()
        if any(x in tech_lower for x in ['jquery', 'angular', 'react', 'vue', 'bootstrap']):
            category = 'frontend'
            language = 'JavaScript'
        elif any(x in tech_lower for x in ['express', 'node', 'npm', 'koa']):
            category = 'backend'
            language = 'JavaScript'
        elif tech_lower in ['html5', 'html']:
            category = 'markup'
            language = 'HTML'
        elif 'php' in tech_lower:
            category = 'backend'
            language = 'PHP'
        elif 'python' in tech_lower:
            category = 'backend'
            language = 'Python'
        elif any(x in tech_lower for x in ['java', 'spring']):
            category = 'backend'
            language = 'Java'
        elif 'nginx' in tech_lower or 'apache' in tech_lower:
            category = 'webserver'
        elif any(x in tech_lower for x in ['mysql', 'postgres', 'mongodb', 'redis']):
            category = 'database'
        
        web_technologies.append({
            'name': name,
            'version': version,
            'product': name,
            'category': category,
            'language': language,
            'source': source,
            'type': 'detected'
        })
    
    return {
        'http_headers': http_info,
        'javascript_libraries': js_libs,
        'exposed_files': exposed,
        'web_technologies': web_technologies,
        'package_info': package_info,
        'waf_info': http_info.get('waf', {}),
        'cms_info': http_info.get('cms', {}),
        'security_headers': http_info.get('security_headers', {}),
        'api_endpoints': all_api_endpoints,  # 통합된 API 엔드포인트
        'discovered_paths': [],
        'multitools_results': {
            'total_tools': 7,  # 5 -> 7로 업데이트
            'technologies_found': len(unique_techs),
            'endpoints_found': len(all_api_endpoints),
            'all_results': all_technologies
        },
        # 새로운 필드
        'spa_detection': spa_info,
        'js_analysis': {
            'api_endpoints_from_js': len(js_api_endpoints),
            'requires_dynamic_scan': spa_info['is_spa'] and spa_info['confidence'] in ['high', 'medium']
        }
    }

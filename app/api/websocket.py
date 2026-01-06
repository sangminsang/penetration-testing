from flask_socketio import emit
from app.models import Project
from app import db
import traceback
import subprocess
import os
import shutil
from app.core.distributor import spawn_workers

class ScanProgressEmitter:
    def __init__(self, socketio):
        self.socketio = socketio

    def emit_log(self, msg, stage='info', progress=0):
        self.socketio.emit('scan_progress', {'stage': stage, 'progress': progress, 'current_item': msg})

def register_socketio_handlers(socketio, scan_emitter):
    @socketio.on('start_scan')
    def handle_start_scan(data):
        target = data.get('target')
        project = Project.query.filter_by(target=target).first()
        socketio.start_background_task(run_integrated_scan, target, project.id if project else None, scan_emitter)

def run_integrated_scan(target, project_id, emitter):
    import time
    import glob
    import json
    from pathlib import Path
    
    try:
        emitter.emit_log(f"🔍 1단계: 마스터 정찰(Katana) 시작 - {target}", 'recon', 10)
        
        # 1. 메인 서버에서 Katana를 먼저 실행하여 전체 URL 수집
        katana_path = shutil.which('katana') or '/usr/local/bin/katana'
        temp_urls_file = f"temp_urls_{int(os.getpid())}.txt"
        
        katana_cmd = [katana_path, '-u', target, '-silent', '-jc', '-kf', 'all', '-o', temp_urls_file]
        subprocess.run(katana_cmd, timeout=120)

        # 2. 수집된 URL 리스트 읽기
        discovered_urls = []
        if os.path.exists(temp_urls_file):
            with open(temp_urls_file, 'r') as f:
                discovered_urls = [line.strip() for line in f if line.strip()]
            os.remove(temp_urls_file)

        if not discovered_urls:
            discovered_urls = [target] # 추출 실패 시 입력값이라도 사용

        emitter.emit_log(f"📦 2단계: {len(discovered_urls)}개 URL 발견. 6개 워커로 분산 스캔 시작!", 'analysis', 30)

        # 3. 발견된 모든 URL을 6개 워커에게 배분 (진정한 분산 처리)
        spawn_workers(discovered_urls, worker_count=6)
        
        emitter.emit_log(f"🚀 6개 워커가 동시에 Nuclei/ZAP 스캔 중입니다...", 'crawling', 70)
        
        # 4. 결과 파일을 모니터링하며 대시보드로 전송
        # 프로젝트 루트 기준으로 경로 계산 (작업 디렉토리 문제 해결)
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        result_dir = os.path.join(base_dir, "scan_results")
        
        # 디렉토리가 없으면 생성
        os.makedirs(result_dir, exist_ok=True)
        
        domain_part = target.split("://")[-1].split("/")[0].replace(".", "_")
        pattern = os.path.join(result_dir, f"*{domain_part}*.json")
        
        # 워커가 결과를 생성할 때까지 대기 (최대 10분)
        max_wait_time = 600
        start_time = time.time()
        processed_files = set()
        
        while time.time() - start_time < max_wait_time:
            # 결과 파일 찾기
            result_files = glob.glob(pattern)
            
            for file_path in result_files:
                if file_path in processed_files:
                    continue
                    
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        result_data = json.load(f)
                    
                    # 기술 스택을 대시보드 형식으로 변환하여 전송
                    webtechnologies = result_data.get('webtechnologies', [])
                    nuclei_vulns = result_data.get('nuclei_vulns', [])
                    
                    # 기술별로 취약점 그룹화
                    tech_vuln_map = {}
                    for vuln in nuclei_vulns:
                        # 취약점을 CVE 형식으로 변환
                        cve_obj = {
                            'cve_id': vuln.get('template_id', vuln.get('name', 'Unknown')),
                            'severity': vuln.get('severity', 'medium').upper(),
                            'description': vuln.get('name', ''),
                            'url': vuln.get('url', '')
                        }
                        
                        # 기술과 연결 (첫 번째 기술에 연결하거나, URL 기반으로 매칭)
                        tech_name = 'Unknown'
                        if webtechnologies:
                            tech_name = webtechnologies[0].get('name', 'Unknown')
                        
                        if tech_name not in tech_vuln_map:
                            tech_vuln_map[tech_name] = []
                        tech_vuln_map[tech_name].append(cve_obj)
                    
                    # 기술 스택 전송 (취약점 포함)
                    for tech in webtechnologies:
                        tech_name = tech.get('name', 'Unknown')
                        tech_obj = {
                            'name': tech_name,
                            'version': tech.get('version', ''),
                            'source': tech.get('source', 'Unknown'),
                            'cves': tech_vuln_map.get(tech_name, [])
                        }
                        emitter.socketio.emit('technology_detected', tech_obj)
                    
                    # 취약점만 있고 기술 스택이 없는 경우도 처리
                    if not webtechnologies and nuclei_vulns:
                        for vuln in nuclei_vulns:
                            cve_obj = {
                                'cve_id': vuln.get('template_id', vuln.get('name', 'Unknown')),
                                'severity': vuln.get('severity', 'medium').upper(),
                                'description': vuln.get('name', ''),
                                'url': vuln.get('url', '')
                            }
                            tech_obj = {
                                'name': 'Vulnerability',
                                'version': '',
                                'source': 'Nuclei',
                                'cves': [cve_obj]
                            }
                            emitter.socketio.emit('technology_detected', tech_obj)
                    
                    processed_files.add(file_path)
                    emitter.emit_log(f"✅ 결과 파일 처리 완료: {os.path.basename(file_path)}", 'success', 85)
                    
                except Exception as e:
                    emitter.emit_log(f"⚠️ 결과 파일 처리 실패: {e}", 'error')
            
            # 모든 워커가 완료되었는지 확인 (파일 수가 안정화되면)
            if len(result_files) >= len(discovered_urls) * 0.8:  # 80% 이상 완료
                time.sleep(5)  # 마지막 파일들이 완료될 시간
                break
                
            time.sleep(2)  # 2초마다 체크
        
        emitter.emit_log(f"✅ 모든 워커 배정 완료. {len(processed_files)}개 결과 파일 처리됨.", 'completed', 90)
        
        # 5. CVE 매칭 및 AI 시나리오 생성
        emitter.emit_log(f"🔍 3단계: CVE 매칭 및 AI 시나리오 생성 시작...", 'analysis', 92)
        
        try:
            # 모든 결과 파일에서 기술 스택 수집
            all_technologies = []
            all_cves_from_nuclei = []
            
            for file_path in processed_files:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        result_data = json.load(f)
                    
                    # 기술 스택 수집
                    webtechnologies = result_data.get('webtechnologies', [])
                    for tech in webtechnologies:
                        tech_dict = {
                            'product': tech.get('name', 'unknown'),
                            'version': tech.get('version', ''),
                            'source': tech.get('source', 'Unknown')
                        }
                        if tech_dict not in all_technologies:
                            all_technologies.append(tech_dict)
                    
                    # Nuclei 취약점 수집
                    nuclei_vulns = result_data.get('nuclei_vulns', [])
                    for vuln in nuclei_vulns:
                        cve_id = vuln.get('template_id', vuln.get('name', ''))
                        if cve_id and cve_id.startswith('CVE-'):
                            all_cves_from_nuclei.append({
                                'id': cve_id,
                                'description': vuln.get('name', ''),
                                'severity': vuln.get('severity', 'medium'),
                                'url': vuln.get('url', '')
                            })
                except Exception as e:
                    continue
            
            # CVE 매칭 수행 (기술 스택 기반)
            if all_technologies:
                emitter.emit_log(f"📊 {len(all_technologies)}개 기술 스택에 대한 CVE 검색 중...", 'analysis', 94)
                
                from app.core.cve.cpe_generator import batch_generate_cpes
                from app.core.cve.async_nvd_client import AsyncNvdClient
                from app.core.cve.cache_manager import get_cache_manager
                import asyncio
                from app.config import Config
                
                # CVE 매칭 함수 import
                try:
                    from app.core.cve.matcher import search_cves_for_technologies as search_cves_func
                except ImportError:
                    try:
                        from app.core.cve.matcher import search_cves_universal as search_cves_func
                    except ImportError:
                        search_cves_func = None
                
                if search_cves_func:
                    # CPE 생성
                    technologies_with_cpe = batch_generate_cpes(all_technologies)
                    cpe_techs = [t for t in technologies_with_cpe if t.get('cpe')]
                    
                    # NVD 클라이언트 초기화 (설정값 직접 사용)
                    nvd_client = AsyncNvdClient(
                        api_key=getattr(Config, 'NVD_API_KEY', None),
                        base_url=getattr(Config, 'NVD_BASE_URL', "https://services.nvd.nist.gov/rest/json/cves/2.0")
                    )
                    cache_manager = get_cache_manager()
                    
                    # 비동기 CVE 검색
                    async def search_all_cves():
                        all_cves = []
                        for tech in cpe_techs:
                            prod = tech.get('product')
                            ver = tech.get('version')
                            try:
                                cves = await search_cves_func(prod, ver, nvd_client=nvd_client, cache_manager=cache_manager)
                                if cves:
                                    all_cves.extend(cves)
                            except Exception:
                                pass
                        return all_cves
                    
                    # 이벤트 루프 실행
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        matched_cves = loop.run_until_complete(search_all_cves())
                        # Nuclei에서 발견한 CVE와 병합
                        matched_cves.extend(all_cves_from_nuclei)
                        # 중복 제거
                        unique_cves = {}
                        for cve in matched_cves:
                            cve_id = cve.get('id') or cve.get('cve_id')
                            if cve_id:
                                unique_cves[cve_id] = cve
                        matched_cves = list(unique_cves.values())
                        
                        emitter.emit_log(f"✅ {len(matched_cves)}개 CVE 발견!", 'success', 96)
                    finally:
                        loop.close()
                else:
                    matched_cves = all_cves_from_nuclei
                    emitter.emit_log(f"⚠️ CVE 매칭 함수를 사용할 수 없습니다. Nuclei 결과만 사용합니다.", 'warning', 96)
            else:
                matched_cves = all_cves_from_nuclei
                emitter.emit_log(f"⚠️ 기술 스택이 없습니다. Nuclei 결과만 사용합니다.", 'warning', 96)
            
            # AI 시나리오 생성
            if matched_cves or all_technologies:
                emitter.emit_log(f"🤖 AI 기반 공격 시나리오 생성 중...", 'analysis', 97)
                
                try:
                    from app.core.scenario.generator import call_ollama
                    from flask import current_app
                    
                    # Flask 애플리케이션 컨텍스트 설정 (Ollama 호출을 위해 필요)
                    from app import create_app
                    app, _ = create_app()
                    
                    with app.app_context():
                        # 프롬프트 생성
                        prompt_lines = [f"Analyze the security posture of {target}."]
                        
                        if all_technologies:
                            tech_names = [t.get('product', 'unknown') for t in all_technologies]
                            prompt_lines.append(f"Technologies: {', '.join(set(tech_names))}.")
                        
                        if matched_cves:
                            prompt_lines.append(f"Vulnerabilities: {len(matched_cves)} found.")
                            sorted_cves = sorted(matched_cves, key=lambda x: float(x.get('cvss', 0) or 0), reverse=True)
                            for cve in sorted_cves[:5]:
                                cve_id = cve.get('id', cve.get('cve_id', 'Unknown'))
                                desc = cve.get('description', '')[:100].replace('\n', ' ')
                                prompt_lines.append(f"- {cve_id}: {desc}...")
                        
                        prompt_lines.append("Based on this, create a short penetration testing scenario.")
                        final_prompt = " ".join(prompt_lines)
                        
                        # Ollama 호출
                        scenario_text = call_ollama(final_prompt)
                    
                    # 시나리오를 대시보드로 전송
                    if isinstance(scenario_text, str):
                        scenario_object = {
                            "title": f"Penetration Test Scenario for {target}",
                            "summary": scenario_text[:200] + "..." if len(scenario_text) > 200 else scenario_text,
                            "content": scenario_text,
                            "steps": [
                                {"name": "Reconnaissance", "details": f"Found {len(all_technologies)} tech stacks"},
                                {"name": "Scanning", "details": f"Detected {len(matched_cves)} CVEs"},
                                {"name": "Analysis", "details": "High risk vulnerabilities identified"}
                            ]
                        }
                    else:
                        scenario_object = scenario_text
                    
                    emitter.socketio.emit('ai_scenario_ready', scenario_object)
                    emitter.emit_log(f"✅ AI 시나리오 생성 완료!", 'success', 99)
                    
                except Exception as e:
                    emitter.emit_log(f"⚠️ AI 시나리오 생성 실패: {str(e)}", 'warning', 99)
                    # 폴백 시나리오
                    fallback_scenario = {
                        "title": f"Penetration Test Scenario for {target}",
                        "summary": f"Found {len(all_technologies)} technologies and {len(matched_cves)} CVEs.",
                        "content": f"Attack Scenario for {target}:\n1. Reconnaissance: Discovered {len(all_technologies)} technologies.\n2. Vulnerability Analysis: Identified {len(matched_cves)} potential vulnerabilities.",
                        "steps": [
                            {"name": "Reconnaissance", "details": f"Found {len(all_technologies)} tech stacks"},
                            {"name": "Scanning", "details": f"Detected {len(matched_cves)} CVEs"}
                        ]
                    }
                    emitter.socketio.emit('ai_scenario_ready', fallback_scenario)
        
        except Exception as e:
            emitter.emit_log(f"⚠️ CVE 매칭/AI 시나리오 생성 중 오류: {str(e)}", 'warning', 99)
            traceback.print_exc()
        
        emitter.emit_log(f"✅ 스캔 완료!", 'completed', 100)
        emitter.socketio.emit('scan_completed', {})

    except Exception as e:
        traceback.print_exc()
        emitter.emit_log(f"❌ 분산 처리 중 오류: {str(e)}", 'error')

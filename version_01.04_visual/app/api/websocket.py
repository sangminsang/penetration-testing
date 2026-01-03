from flask_socketio import emit
from flask import request
from app.models import ScanResult, Project
from app import db, create_app
import traceback
import requests
import re

class ScanProgressEmitter:
    def __init__(self, socketio):
        self.socketio = socketio

    def emit_log(self, msg, stage='info', progress=0):
        self.socketio.emit('scan_progress', {'stage': stage, 'progress': progress, 'current_item': msg})

    def emit_tech(self, name, version=None, source="Recon", evidence=""):
        # 실무자를 위한 상세 증거(evidence)를 포함하여 전송
        self.socketio.emit('technology_detected', {
            'name': name, 
            'version': version, 
            'source': source,
            'evidence': evidence
        })

    def emit_url(self, url, status_code=None):
        self.socketio.emit('url_discovered', {'url': url, 'status_code': status_code})

def register_socketio_handlers(socketio, scan_emitter):
    @socketio.on('start_scan')
    def handle_start_scan(data):
        target = data.get('target')
        project = Project.query.filter_by(target=target).first()
        socketio.start_background_task(run_integrated_scan, target, project.id if project else None, scan_emitter)

def run_integrated_scan(target, project_id, emitter):
    scan_data = {'technologies': [], 'urls': []}
    try:
        emitter.emit_log(f"🕵️ 정찰 분석 개시: {target}", 'init', 5)
        
        # 1. L4 정찰: Nmap 포트 분석 및 서비스 배너 추출
        from app.nmap_recon import run_recon
        clean_host = re.sub(r'^https?://', '', target).split('/')[0].split(':')[0]
        emitter.emit_log("📡 [Network] 포트 스캔 및 서비스 배너 수집 중...", 'recon', 20)
        nmap_res = run_recon(clean_host)
        if nmap_res:
            for host in nmap_res:
                for port in host.get('ports', []):
                    if port.get('product'):
                        evidence = f"Port {port['port']}/{port['protocol']} open. Banner: {port['product']} {port.get('version', '')}"
                        emitter.emit_tech(port['product'], port.get('version'), 'Nmap Scan', evidence)

        # 2. L7 정찰: HTTP 응답 헤더 심층 분석
        emitter.emit_log("🌐 [HTTP] 헤더 메타데이터 및 기술 스택 분석 중...", 'recon', 45)
        try:
            resp = requests.get(target, timeout=10, verify=False)
            # 서버가 보낸 모든 헤더를 증거로 활용
            raw_headers = "\n".join([f"{k}: {v}" for k, v in resp.headers.items()])
            
            # 특정 헤더에서 기술 정보 추출 (Server, X-Powered-By 등)
            for header_key in ['Server', 'X-Powered-By', 'X-AspNet-Version', 'Via']:
                val = resp.headers.get(header_key)
                if val:
                    emitter.emit_tech(val, source=f"Header: {header_key}", evidence=raw_headers)
        except: pass

        # 3. Fingerprinting: Wappalyzer 기반의 고정밀 분석 (ActiveX, PHP 등 탐지)
        from app.core.recon.web import detect_with_wappalyzer
        emitter.emit_log("🔍 [App] 사이트 지문(Fingerprint) 매칭 중...", 'recon', 70)
        wapp_results = detect_with_wappalyzer(target)
        if wapp_results:
            for tech in wapp_results:
                # Wappalyzer가 찾은 기술들은 특정 HTML 패턴을 근거로 함
                evidence = f"Detected via internal pattern matching rules for '{tech['name']}'"
                emitter.emit_tech(tech['name'], tech.get('version'), "Wappalyzer Engine", evidence)

        # 4. 크롤링 및 결과 저장
        from app.core.recon.crawler import WebCrawler
        emitter.emit_log("🕸️ [Structure] 사이트 내부 경로 수집 및 저장 중...", 'crawling', 90)
        crawler = WebCrawler(target, max_depth=1)
        crawl_res = crawler.crawl()
        for u in crawl_res.get('urls', []):
            url_str = u['url'] if isinstance(u, dict) else u
            scan_data['urls'].append(url_str)
            emitter.emit_url(url_str, 200)

        if project_id:
            app, _ = create_app()
            with app.app_context():
                db.session.add(ScanResult(project_id=project_id, data=scan_data))
                db.session.commit()

        emitter.emit_log("✅ 모든 정찰 작업이 완료되었습니다.", 'completed', 100)
        emitter.socketio.emit('scan_completed', {})

    except Exception as e:
        traceback.print_exc()
        emitter.emit_log(f"❌ 오류 발생: {str(e)}", 'error')

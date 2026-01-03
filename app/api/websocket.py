from flask_socketio import emit
from flask import request
from app.models import ScanResult, Project
from app import db, create_app
import traceback
import requests
import re
import time

class ScanProgressEmitter:
    def __init__(self, socketio):
        self.socketio = socketio

    def emit_log(self, msg, stage='info', progress=0):
        self.socketio.emit('scan_progress', {'stage': stage, 'progress': progress, 'current_item': msg})

    def emit_tech(self, name, version=None, source="Recon", evidence=""):
        self.socketio.emit('technology_detected', {
            'name': name, 
            'version': version or 'N/A', 
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
        emitter.emit_log(f"🕵️ 통합 정찰 분석 개시: {target}", 'init', 5)
        
        # 1. L4 레이어: Nmap 기본 정찰
        from app.nmap_recon import run_recon
        clean_host = re.sub(r'^https?://', '', target).split('/')[0].split(':')[0]
        emitter.emit_log("📡 [L4] 포트 스캔 및 서비스 배너 수집 중...", 'recon', 15)
        nmap_res = run_recon(clean_host)
        if nmap_res:
            for host in nmap_res:
                for port in host.get('ports', []):
                    if port.get('product'):
                        evidence = f"Port {port['port']}/{port['protocol']} open. Banner: {port['product']} {port.get('version', '')}"
                        emitter.emit_tech(port['product'], port.get('version'), 'Nmap Scan', evidence)

        # 2. 강력한 통합 엔진(collect_web_info) 호출
        from app.core.recon.web import collect_web_info
        emitter.emit_log("🚀 [Deep Recon] 16개 기술 탐지 엔진 가동 중...", 'recon', 40)
        
        all_techs = collect_web_info(target)
        
        seen_techs = set()
        if all_techs:
            for tech in all_techs:
                # tech가 문자열인 경우와 딕셔너리인 경우 모두 대응
                if isinstance(tech, str):
                    name = tech
                    version = 'N/A'
                    source = 'Integrated Scanner'
                    evidence = 'Detected via pattern matching'
                else:
                    name = tech.get('name', 'Unknown')
                    version = tech.get('version', 'N/A')
                    source = tech.get('source', 'Integrated Scanner')
                    evidence = tech.get('evidence') or f"Detected via {source}"
                
                if not name or name in seen_techs: continue
                
                emitter.emit_tech(name, version, source, evidence)
                scan_data['technologies'].append({'name': name, 'version': version, 'source': source, 'evidence': evidence})
                seen_techs.add(name)

        # 3. 크롤링 및 구조 분석
        from app.core.recon.crawler import WebCrawler
        emitter.emit_log("🕸️ [Structure] 사이트 내부 경로 수집 중...", 'crawling', 85)
        crawler = WebCrawler(target, max_depth=1)
        crawl_res = crawler.crawl()
        for u in crawl_res.get('urls', []):
            url_str = u['url'] if isinstance(u, dict) else u
            scan_data['urls'].append(url_str)
            emitter.emit_url(url_str, 200)

        # 4. 결과 저장
        if project_id:
            app, _ = create_app()
            with app.app_context():
                # 데이터가 이미 존재하면 업데이트, 없으면 추가
                db.session.add(ScanResult(project_id=project_id, data=scan_data))
                db.session.commit()

        emitter.emit_log("✅ 모든 통합 정찰 작업이 완료되었습니다.", 'completed', 100)
        emitter.socketio.emit('scan_completed', {})

    except Exception as e:
        traceback.print_exc()
        emitter.emit_log(f"❌ 오류 발생: {str(e)}", 'error')

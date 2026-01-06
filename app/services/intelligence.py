import re

class IntelligenceEngine:
    """
    스캔 데이터 정제 및 검증 힌트 생성 엔진
    """

    def __init__(self):
        self.tech_stack = {} 

    def _normalize_name(self, name):
        return str(name).lower().strip()

    def _generate_manual_hint(self, tech_name, category, version, url="TARGET_URL"):
        """
        기술 스택에 따른 실무자용 수동 검증 명령어 생성
        """
        tech_lower = tech_name.lower()
        cat_lower = category.lower()
        hints = []

        # 1. 웹 서버 / 언어 관련 (HTTP 헤더 검증)
        if cat_lower in ['web server', 'language', 'operating system']:
            hints.append(f"curl -I -v {url}")
            hints.append(f"whatweb -v {url}")

        # 2. 데이터베이스 (SQL Injection 검증)
        if 'sql' in tech_lower or cat_lower == 'database':
            hints.append(f"sqlmap -u \"{url}\" --batch --dbs")
            hints.append("Manual Check: Add ' OR 1=1 -- to input fields")

        # 3. CMS (WordPress, Drupal 등)
        if 'wordpress' in tech_lower:
            hints.append(f"wpscan --url {url} --enumerate u,p,t")
        elif 'joomla' in tech_lower:
            hints.append(f"joomscan -u {url}")

        # 4. Nginx/Apache 구체적 버전
        if 'nginx' in tech_lower:
            hints.append(f"nikto -h {url} -Tuning b")
        
        # 5. PHP
        if 'php' in tech_lower:
            hints.append(f"curl -X GET {url} -H 'X-Powered-By: verify'")

        if not hints:
            hints.append(f"nuclei -u {url} -t http/technologies")

        return hints

    def add_finding(self, tech_name, version, category, source_tool, evidence, confidence="High"):
        if not tech_name or tech_name.lower() == 'unknown':
            return

        key = self._normalize_name(tech_name)
        
        if version and version.lower() in ['n/a', 'unknown', 'none']:
            version = ""
            
        evidence_str = f"[{source_tool}] {evidence}" if evidence else f"[{source_tool}] Detected"

        if key not in self.tech_stack:
            self.tech_stack[key] = {
                "name": tech_name,
                "version": version,
                "category": category,
                "sources": [source_tool],
                "evidence": [evidence_str],
                "confidence": confidence,
                "hints": [] # 힌트 리스트 초기화
            }
        else:
            existing = self.tech_stack[key]
            if source_tool not in existing["sources"]:
                existing["sources"].append(source_tool)
            if evidence_str not in existing["evidence"]:
                existing["evidence"].append(evidence_str)
            if not existing["version"] and version:
                existing["version"] = version
            elif version and len(version) > len(existing["version"]):
                existing["version"] = version

    def refine_data(self, scan_results, target_url="http://localhost"):
        """
        데이터 정제 메인 함수
        """
        self.tech_stack = {} 

        # 1. 헤더 분석
        headers = scan_results.get('headers', {})
        if isinstance(headers, dict):
            if 'server' in headers:
                self.add_finding("Web Server", headers['server'], "Web Server", "Header", f"Server: {headers['server']}")
            if 'x-powered-by' in headers:
                self.add_finding("Language", headers['x-powered-by'], "Language", "Header", f"X-Powered-By: {headers['x-powered-by']}")

        # 2. 통합 리스트 (Nuclei, WhatWeb 등)
        tech_list = scan_results.get('webtechnologies', [])
        if isinstance(tech_list, list):
            for tech in tech_list:
                if not isinstance(tech, dict): continue
                self.add_finding(
                    tech.get('name'), 
                    tech.get('version', ''), 
                    tech.get('category', 'Generic'), 
                    tech.get('source', 'Scanner'),
                    tech.get('evidence')
                )

        # 3. 데이터 후처리 (힌트 생성)
        final_list = []
        for tech in self.tech_stack.values():
            # 힌트 생성 (현재 타겟 URL 기준)
            tech['hints'] = self._generate_manual_hint(tech['name'], tech['category'], tech['version'], target_url)
            final_list.append(tech)
            
        return final_list

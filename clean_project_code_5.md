# Project Code Extract (Part 5/5)
- **Root:** `d:\3차 프로젝트\6트\12.26 app`
- **Files included:** 16 (Total: 92)

---

## File 77: projects.html
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\templates\projects.html`

```html
<!DOCTYPE html>
<html>
<head>
    <title>Security Scanner - Projects</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <style>
        body { background-color: #f8f9fa; }
        .container { max-width: 900px; }
        .project-card { border-radius: 10px; transition: transform 0.2s; }
        .project-card:hover { transform: translateY(-5px); box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
    </style>
</head>
<body class="container py-5">
    <h2 class="mb-4">🛡️ Project Management</h2>
    
    <div class="card p-4 mb-5 shadow-sm">
        <h5 class="card-title">Create New Target</h5>
        <form action="/project/new" method="POST" class="row g-3">
            <div class="col-md-5">
                <input type="text" name="name" class="form-control" placeholder="Project Name" required>
            </div>
            <div class="col-md-5">
                <input type="text" name="target" class="form-control" placeholder="http://example.com" required>
            </div>
            <div class="col-md-2">
                <button type="submit" class="btn btn-primary w-100">Add</button>
            </div>
        </form>
    </div>

    <div class="row g-4">
        {% for p in projects %}
        <div class="col-12">
            <div class="card project-card p-3 shadow-sm border-0">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h5 class="mb-1 text-primary">{{ p.name }}</h5>
                        <code class="text-secondary">{{ p.target }}</code>
                    </div>
                    <div class="btn-group">
                        <a href="/live-scan/{{ p.id }}" class="btn btn-success btn-sm px-3">Scan</a>
                        <form action="/project/delete/{{ p.id }}" method="POST" onsubmit="return confirm('진짜 삭제할까요? 스캔 데이터도 모두 사라집니다.');">
                            <button type="submit" class="btn btn-outline-danger btn-sm ms-2">Delete</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        {% endfor %}
    </div>
</body>
</html>
```
---

## File 78: socket_test.html
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\templates\socket_test.html`

```html
<!DOCTYPE html>
<html>
<head>
    <title>Live Scan Dashboard</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <style>
        body { font-family: monospace; background: #1a1a1a; color: #0f0; padding: 20px; }
        #log-box { 
            border: 1px solid #333; 
            background: #000; 
            height: 300px; 
            overflow-y: scroll; 
            padding: 10px; 
            margin-bottom: 20px;
        }
        .log-entry { margin: 2px 0; }
        .success { color: #0f0; font-weight: bold; }
        .info { color: #aaa; }
    </style>
</head>
<body>
    <h1>🚀 Live Scan Dashboard</h1>

    <div style="margin-bottom: 20px;">
        <input type="text" id="target-url" value="http://testphp.vulnweb.com" 
               style="padding: 10px; width: 300px; background: #333; color: #fff; border: 1px solid #555;">
        <button onclick="startScan()" 
                style="padding: 10px 20px; background: #0f0; color: #000; border: none; cursor: pointer; font-weight: bold;">
            START SCAN 🚀
        </button>
    </div>

    <!-- 로그 박스 -->
    <div id="log-box"></div>
    
    <!-- 기술 스택 카드 영역 -->
    <div id="tech-stack"></div>

    <script>
        // 소켓 연결
        var socket = io();

        socket.on('connect', function() {
            addLog('Connected to server!', 'success');
        });

        // 로그 수신 ('scan_log' 이벤트)
        socket.on('scan_log', function(data) {
            addLog(data.message, data.level);
        });

        // 기술 업데이트 수신 ('tech_update' 이벤트)
        socket.on('tech_update', function(data) {
            addLog(`[TECH] ${data.name} updated (Confidence: ${data.confidence}%)`, 'success');
            // 여기에 나중에 게이지 바 업데이트 로직 추가
        });

        function addLog(msg, level) {
            var box = document.getElementById('log-box');
            var div = document.createElement('div');
            div.className = 'log-entry ' + level;
            div.innerText = `> ${msg}`;
            box.appendChild(div);
            box.scrollTop = box.scrollHeight; // 자동 스크롤
        }

        function startScan() {
            var target = document.getElementById('target-url').value;
            addLog(`Requesting scan for ${target}...`, 'info');
            
            // 백엔드로 스캔 시작 이벤트 전송
            socket.emit('start_scan', {target: target});
        }
    </script>
</body>
</html>
```
---

## File 79: url_tree.html
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\templates\url_tree.html`

```html
<!DOCTYPE html>
<html>
<head>
    <title>URL Tree Viewer</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: #0a0a0a; color: #fff; margin: 0; overflow: hidden; font-family: 'Inter', sans-serif; }
        .node circle { fill: #00ff41; stroke: #fff; stroke-width: 2px; }
        /* 텍스트 스타일 대폭 강화 */
        .node text { 
            font-size: 14px; 
            font-weight: 500;
            fill: #ffffff !important; 
            text-shadow: 2px 2px 4px #000, -1px -1px 0 #000, 1px -1px 0 #000, -1px 1px 0 #000, 1px 1px 0 #000;
            pointer-events: none;
        }
        .link { fill: none; stroke: #444; stroke-width: 1.5px; opacity: 0.6; }
        #canvas { width: 100vw; height: 100vh; }
        .info-panel { position: fixed; top: 20px; left: 20px; z-index: 100; background: rgba(20, 20, 20, 0.9); padding: 15px; border-radius: 8px; border: 1px solid #00ff41; }
    </style>
</head>
<body>
    <div class="info-panel">
        <h5 class="text-success mb-2">🌳 URL_NODE_MAP</h5>
        <div class="small mb-3">Target: <span class="text-info">{{ project.target }}</span></div>
        <a href="/live-scan/{{ project.id }}" class="btn btn-xs btn-outline-light py-1 w-100">BACK_TO_LOG</a>
    </div>
    <div id="canvas"></div>

    <script>
        const projectId = "{{ project.id }}";
        const width = window.innerWidth;
        const height = window.innerHeight;

        const svg = d3.select("#canvas").append("svg")
            .attr("width", width).attr("height", height);
        const g = svg.append("g");

        const zoom = d3.zoom().on("zoom", (e) => g.attr("transform", e.transform));
        svg.call(zoom);

        d3.json(`/api/project/${projectId}/tree-data`).then(data => {
            const root = d3.hierarchy(data);
            const treeLayout = d3.tree().nodeSize([40, 220]); // 가로 간격 확보
            treeLayout(root);

            svg.call(zoom.transform, d3.zoomIdentity.translate(100, height/2).scale(0.9));

            g.selectAll(".link")
                .data(root.links()).enter().append("path")
                .attr("class", "link")
                .attr("d", d3.linkHorizontal().x(d => d.y).y(d => d.x));

            const node = g.selectAll(".node")
                .data(root.descendants()).enter().append("g")
                .attr("class", "node")
                .attr("transform", d => `translate(${d.y},${d.x})`);

            node.append("circle").attr("r", 6);

            // 텍스트를 나중에 추가하여 선보다 위에 오게 함
            node.append("text")
                .attr("dy", "0.35em")
                .attr("x", d => d.children ? -12 : 12)
                .attr("text-anchor", d => d.children ? "end" : "start")
                .text(d => d.data.name);
        });
    </script>
</body>
</html>
```
---

## File 80: test.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\test.py`

```python
# test.py (수정된 버전)
import sys
import os
from pathlib import Path

# test.py의 위치: app/test.py
# matcher.py의 위치: app/core/cve/matcher.py
# test.py에서 matcher.py를 직접 import하기 위해 app 디렉토리를 path에 추가
current_dir = Path(__file__).parent  # app/
sys.path.insert(0, str(current_dir))

# 이제 app 패키지를 거치지 않고 core 모듈을 직접 import
# app/__init__.py를 실행하지 않으므로 Flask 의존성 문제 없음
from core.cve.matcher import (
    parse_complex_version_string,
    normalize_product_name,
    parse_and_normalize_version
)

# ===========================
# 테스트 1: parse_complex_version_string
# ===========================
print("=" * 60)
print("Test 1: parse_complex_version_string")
print("=" * 60)

test_cases = [
    "Apache/2.4.66",
    "mysql 5.7.35",
    "nginx 1.19.0",
    "Werkzeug/3.1.4 Python/3.11.14",
    "Apache httpd 2.4.41 (Ubuntu)",
    "PostgreSQL 13.4",
    "OpenSSH_7.4",
]

for test in test_cases:
    result = parse_complex_version_string(test)
    print(f"Input:  {test}")
    print(f"Output: product='{result['product']}', version='{result['version']}'")
    print()

# ===========================
# 테스트 2: extract_tech_info_from_scanner (network.py 출력)
# ===========================
print("=" * 60)
print("Test 2: extract_tech_info_from_scanner (network.py)")
print("=" * 60)

# 간단한 추출 함수 (routes.py 로직 재현)
def extract_tech_info_from_scanner(tech_item):
    # Case 1: network.py 출력 (full_version 필드 우선 사용)
    if "full_version" in tech_item and tech_item.get("full_version"):
        parsed = parse_complex_version_string(tech_item["full_version"])
        return {"product": parsed["product"], "version": parsed["version"]}
    
    # Case 2: network.py 출력 (product + version 필드)
    if "product" in tech_item and "version" in tech_item:
        return {
            "product": normalize_product_name(tech_item["product"]),
            "version": tech_item["version"]
        }
    
    # Case 3: web.py, database.py 출력 ("name" 필드)
    if "name" in tech_item:
        parsed = parse_complex_version_string(tech_item["name"])
        return {"product": parsed["product"], "version": parsed["version"]}
    
    return {"product": "", "version": ""}

network_outputs = [
    {"full_version": "nginx 1.19.0", "product": "nginx", "version": "1.19.0"},
    {"product": "mysql", "version": "5.7.35"},
]

for output in network_outputs:
    result = extract_tech_info_from_scanner(output)
    print(f"Input:  {output}")
    print(f"Output: {result}")
    print()

# ===========================
# 테스트 3: extract_tech_info_from_scanner (web.py 출력)
# ===========================
print("=" * 60)
print("Test 3: extract_tech_info_from_scanner (web.py)")
print("=" * 60)

web_outputs = [
    {"name": "Apache/2.4.66", "type": "web_server"},
    {"name": "Werkzeug/3.1.4", "type": "framework"},
    {"name": "Django/4.2", "type": "framework"},
]

for output in web_outputs:
    result = extract_tech_info_from_scanner(output)
    print(f"Input:  {output}")
    print(f"Output: {result}")
    print()

# ===========================
# 테스트 4: extract_tech_info_from_scanner (database.py 출력)
# ===========================
print("=" * 60)
print("Test 4: extract_tech_info_from_scanner (database.py)")
print("=" * 60)

db_outputs = [
    {"name": "mysql 5.7.35", "type": "database", "port": 3306},
    {"name": "PostgreSQL 13.4", "type": "database", "port": 5432},
    {"name": "redis 6.2.0", "type": "database", "port": 6379},
]

for output in db_outputs:
    result = extract_tech_info_from_scanner(output)
    print(f"Input:  {output}")
    print(f"Output: {result}")
    print()

print("=" * 60)
print("All tests completed!")
print("=" * 60)
```
---

## File 81: __init__.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\utils\__init__.py`

```python
# Utility modules

```
---

## File 82: exploit.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\app\utils\exploit.py`

```python
import json
import subprocess
import logging
import platform
from typing import Dict, Any, List, Union

logger = logging.getLogger(__name__)


def _build_searchsploit_cmd(args: List[str]) -> List[str]:
    """
    OS에 따라 searchsploit 실행 커맨드를 만들어 준다.
    - Windows  : WSL 안의 searchsploit 사용 -> ["wsl", "searchsploit", ...]
    - Linux/WSL: 로컬 searchsploit 사용     -> ["searchsploit", ...]
    """
    system = platform.system().lower()
    if system.startswith("windows"):
        # Windows에서 WSL 안의 searchsploit 실행
        return ["wsl", "searchsploit", *args]
    else:
        # Linux / WSL 내부
        return ["searchsploit", *args]


def search_exploits_for_single_cve(cveid: str, maxpercve: int = 5) -> List[Dict[str, Any]]:
    """
    단일 CVE ID에 대한 exploit 검색
    - 우선 --json 사용
    - 실패 시 텍스트 출력 파싱으로 fallback
    """
    exploits: List[Dict[str, Any]] = []

    if not cveid or not isinstance(cveid, str) or not cveid.startswith("CVE-"):
        logger.warning(f"search_exploits_for_single_cve: Invalid CVE ID: {cveid!r}")
        return exploits

    try:
        logger.info(f"EXPLOIT: Searching exploits for {cveid}")

        # --------------------------------------------------
        # 1차 시도: JSON 출력 사용
        # --------------------------------------------------
        cmd = _build_searchsploit_cmd(["--json", cveid])
        logger.debug(f"EXPLOIT: Running command (JSON): {' '.join(cmd)}")

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        if proc.returncode == 0 and proc.stdout.strip():
            try:
                data = json.loads(proc.stdout)
                results = data.get("RESULTS_EXPLOIT", []) or []

                for item in results[:maxpercve]:
                    title = item.get("Title") or item.get("title")
                    edb_id = item.get("EDB-ID") or item.get("id")
                    if not title or not edb_id:
                        continue

                    exploits.append(
                        {
                            "title": str(title),
                            "id": str(edb_id),
                        }
                    )
                    logger.debug(f"EXPLOIT(JSON): {title} (EDB-{edb_id})")

                if exploits:
                    logger.info(
                        f"EXPLOIT: Found {len(exploits)} exploits for {cveid} (JSON)"
                    )
                    return exploits

            except json.JSONDecodeError:
                logger.debug(
                    f"EXPLOIT: JSON parsing failed for {cveid}, falling back to text"
                )
        else:
            if proc.stderr:
                logger.debug(
                    f"EXPLOIT(JSON): non-zero return code {proc.returncode}, stderr={proc.stderr[:200]!r}"
                )

        # --------------------------------------------------
        # 2차 시도: 텍스트 출력 파싱
        # --------------------------------------------------
        cmd = _build_searchsploit_cmd([cveid])
        logger.debug(f"EXPLOIT: Running command (TEXT): {' '.join(cmd)}")

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        if proc.returncode != 0:
            logger.warning(
                f"EXPLOIT(TEXT): searchsploit returned code {proc.returncode} for {cveid}"
            )
            if proc.stderr:
                logger.debug(
                    f"EXPLOIT(TEXT): stderr for {cveid}: {proc.stderr[:200]!r}"
                )
            return exploits

        if not proc.stdout:
            logger.debug(f"EXPLOIT(TEXT): No output for {cveid}")
            return exploits

        count = 0
        for line in proc.stdout.strip().split("\n"):
            if count >= maxpercve:
                break

            line = line.strip()
            # 헤더/구분선/타이틀 행 스킵
            if (
                not line
                or "----" in line
                or line.lower().startswith("exploit title")
                or line.lower().startswith("shellcodes")
            ):
                continue

            # "Title | EDB-ID | Path" 형식
            parts = [p.strip() for p in line.split("|")]
            if len(parts) < 2:
                continue

            title = parts[0]
            edb_id = None

            # 뒷부분에서 숫자인 덩어리를 EDB ID로 추출
            for part in parts[1:]:
                token = part.split()[0] if part else ""
                if token.isdigit():
                    edb_id = token
                    break

            if not title or not edb_id:
                continue

            exploits.append(
                {
                    "title": title,
                    "id": edb_id,
                }
            )
            logger.debug(f"EXPLOIT(TEXT): {title} (EDB-{edb_id})")
            count += 1

        if exploits:
            logger.info(
                f"EXPLOIT: Found {len(exploits)} exploits for {cveid} (TEXT)"
            )
        else:
            logger.warning(f"EXPLOIT: No exploits found for {cveid}")

    except FileNotFoundError as e:
        logger.error(
            f"EXPLOIT: searchsploit command not found. "
            f"Ensure WSL and searchsploit are installed. Error: {e}"
        )
    except subprocess.TimeoutExpired:
        logger.warning(f"EXPLOIT: searchsploit timeout for {cveid}")
    except Exception as e:
        logger.exception(f"EXPLOIT: Unexpected error for {cveid}: {e}")

    return exploits


def search_exploits_for_cves(
    cves: List[Union[str, Dict[str, Any]]], maxpercve: int = 5
) -> Dict[str, List[Dict[str, Any]]]:
    """
    여러 CVE에 대해 exploit 검색.
    - 입력 형식 둘 다 지원:
      * ["CVE-2020-11023", "CVE-2019-11358", ...]
      * [{"cveid": "CVE-2020-11023", ...}, {...}, ...]
    """
    results: Dict[str, List[Dict[str, Any]]] = {}

    for cve in cves:
        # 1) CVE ID 추출
        if isinstance(cve, str):
            cveid = cve
        elif isinstance(cve, dict):
            cveid = (
                cve.get("cveid")
                or cve.get("id")
                or cve.get("CVE")
                or cve.get("cve_id")
                or ""
            )
        else:
            logger.warning(
                f"search_exploits_for_cves: Unsupported CVE type: {type(cve)}"
            )
            continue

        if not cveid or not isinstance(cveid, str) or not cveid.startswith("CVE-"):
            logger.warning(
                f"search_exploits_for_cves: Invalid CVE ID value: {cveid!r}"
            )
            continue

        # 2) 실제 검색
        exploits = search_exploits_for_single_cve(cveid, maxpercve)
        if exploits:
            results[cveid] = exploits
            logger.info(
                f"search_exploits_for_cves: {cveid} -> {len(exploits)} exploits found"
            )

    return results
```
---

## File 83: dashboard.html
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\backup_20260103\dashboard.html`

```html
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e0e0e0;
            line-height: 1.6;
        }

        .container {
            max-width: 1600px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            text-align: center;
            padding: 40px 0 20px;
            border-bottom: 2px solid #0f3460;
            margin-bottom: 30px;
        }

        h1 {
            font-size: 2.5em;
            color: #00d4ff;
            text-shadow: 0 0 10px rgba(0, 212, 255, 0.5);
            margin-bottom: 10px;
        }

        .scan-section {
            margin-bottom: 30px;
            background: rgba(15, 52, 96, 0.5);
            border: 1px solid #0f3460;
            border-radius: 8px;
            padding: 20px;
            backdrop-filter: blur(10px);
        }

        .scan-controls {
            display: flex;
            gap: 15px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }

        input[type="text"],
        input[type="url"] {
            flex: 1;
            min-width: 300px;
            padding: 12px 15px;
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid #0f3460;
            border-radius: 6px;
            color: #e0e0e0;
            font-size: 14px;
        }

        input[type="text"]:focus,
        input[type="url"]:focus {
            outline: none;
            border-color: #00d4ff;
            box-shadow: 0 0 10px rgba(0, 212, 255, 0.3);
        }

        button {
            padding: 12px 30px;
            background: linear-gradient(135deg, #00d4ff 0%, #0099cc 100%);
            border: none;
            border-radius: 6px;
            color: #000;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s ease;
            font-size: 14px;
        }

        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0, 212, 255, 0.3);
        }

        button:disabled {
            background: #666;
            cursor: not-allowed;
            opacity: 0.6;
        }

        .loading {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            padding: 20px;
            color: #00d4ff;
        }

        .spinner {
            border: 3px solid rgba(0, 212, 255, 0.2);
            border-top: 3px solid #00d4ff;
            border-radius: 50%;
            width: 30px;
            height: 30px;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .section-title {
            font-size: 1.5em;
            color: #00d4ff;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #0f3460;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }

        .stat-card {
            background: rgba(0, 212, 255, 0.1);
            border: 1px solid #00d4ff;
            border-radius: 6px;
            padding: 15px;
            text-align: center;
        }

        .stat-label {
            font-size: 0.9em;
            color: #aaa;
            margin-bottom: 8px;
        }

        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #00d4ff;
        }

        .severity-high {
            color: #ff4444;
        }

        .severity-medium {
            color: #ffaa00;
        }

        .severity-low {
            color: #00ff88;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }

        thead {
            background: rgba(0, 212, 255, 0.15);
        }

        th {
            padding: 12px;
            text-align: left;
            color: #00d4ff;
            font-weight: bold;
            border-bottom: 2px solid #0f3460;
        }

        td {
            padding: 12px;
            border-bottom: 1px solid rgba(0, 212, 255, 0.1);
        }

        tr:hover {
            background: rgba(0, 212, 255, 0.05);
        }

        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            margin-right: 5px;
        }

        .badge-high {
            background: rgba(255, 68, 68, 0.3);
            color: #ff4444;
            border: 1px solid #ff4444;
        }

        .badge-medium {
            background: rgba(255, 170, 0, 0.3);
            color: #ffaa00;
            border: 1px solid #ffaa00;
        }

        .badge-low {
            background: rgba(0, 255, 136, 0.3);
            color: #00ff88;
            border: 1px solid #00ff88;
        }

        .badge-info {
            background: rgba(0, 212, 255, 0.3);
            color: #00d4ff;
            border: 1px solid #00d4ff;
        }

        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            border-bottom: 2px solid #0f3460;
            flex-wrap: wrap;
        }

        .tab-button {
            padding: 10px 20px;
            background: transparent;
            border: none;
            border-bottom: 3px solid transparent;
            color: #aaa;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.3s ease;
        }

        .tab-button.active {
            color: #00d4ff;
            border-bottom-color: #00d4ff;
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        .cve-item {
            background: rgba(0, 0, 0, 0.3);
            border-left: 4px solid #00d4ff;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 4px;
        }

        .cve-id {
            font-weight: bold;
            color: #00d4ff;
            font-family: monospace;
        }

        .cve-description {
            margin-top: 8px;
            color: #bbb;
            font-size: 0.95em;
        }

        .alert-item {
            background: rgba(0, 0, 0, 0.3);
            border-left: 4px solid #ffaa00;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 4px;
        }

        .alert-item.high {
            border-left-color: #ff4444;
        }

        .alert-item.low {
            border-left-color: #00ff88;
        }

        .tech-list {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }

        .tech-card {
            background: rgba(0, 212, 255, 0.1);
            border: 1px solid #00d4ff;
            border-radius: 6px;
            padding: 15px;
        }

        .tech-name {
            font-weight: bold;
            color: #00d4ff;
            margin-bottom: 8px;
        }

        .tech-version {
            color: #aaa;
            font-size: 0.9em;
            margin-bottom: 5px;
        }

        .tech-source {
            font-size: 0.85em;
            color: #888;
        }

        .scenario-box {
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid #0f3460;
            border-radius: 6px;
            padding: 20px;
            white-space: pre-wrap;
            word-wrap: break-word;
            font-family: 'Courier New', monospace;
            font-size: 0.95em;
            color: #00ff88;
            max-height: 500px;
            overflow-y: auto;
        }

        .error-message {
            background: rgba(255, 68, 68, 0.2);
            border: 1px solid #ff4444;
            border-radius: 6px;
            padding: 15px;
            color: #ff8888;
            margin-bottom: 20px;
        }

        .success-message {
            background: rgba(0, 255, 136, 0.2);
            border: 1px solid #00ff88;
            border-radius: 6px;
            padding: 15px;
            color: #00ff88;
            margin-bottom: 20px;
        }

        .empty-state {
            text-align: center;
            padding: 40px;
            color: #aaa;
        }

        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            border-top: 2px solid #0f3460;
            margin-top: 40px;
        }

        .severity-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }

        .severity-indicator.high {
            background: #ff4444;
        }

        .severity-indicator.medium {
            background: #ffaa00;
        }

        .severity-indicator.low {
            background: #00ff88;
        }

        .scroll-table {
            overflow-x: auto;
        }

        .json-viewer {
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid #0f3460;
            border-radius: 6px;
            padding: 15px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            color: #00d4ff;
            max-height: 400px;
            overflow-y: auto;
        }

        .filter-buttons {
            margin-bottom: 15px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        .filter-btn {
            padding: 8px 16px;
            background: rgba(0, 212, 255, 0.3);
            color: #00d4ff;
            border: 1px solid #00d4ff;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .filter-btn.active {
            background: #00d4ff;
            color: #000;
        }

        .filter-btn:hover {
            background: rgba(0, 212, 255, 0.5);
        }

        @media (max-width: 768px) {
            h1 {
                font-size: 1.8em;
            }

            .scan-controls {
                flex-direction: column;
            }

            input[type="text"],
            input[type="url"] {
                min-width: auto;
            }

            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }

            .tech-list {
                grid-template-columns: 1fr;
            }

            .tabs {
                flex-wrap: wrap;
            }
        }
    </style>
</head>
<body>
    <!-- Deep Fingerprinting Trace Section -->
    <div class="scan-section" id="deep-fingerprint-section" style="display: none;">
        <h2 class="section-title">🔍 Deep Fingerprinting Trace</h2>
        <p style="color: #aaa; margin-bottom: 20px;">
            Multi-layer technology detection with progressive confidence building
        </p>

        <!-- Timeline Visualization -->
        <div id="fingerprint-timeline" style="margin-bottom: 30px;">
            <!-- Layer cards will be dynamically inserted here -->
        </div>

        <!-- Summary Stats -->
        <div class="stats-grid" style="margin-top: 20px;">
            <div class="stat-card">
                <div class="stat-label">Total Layers</div>
                <div class="stat-value" id="fp-total-layers">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Technologies Found</div>
                <div class="stat-value" id="fp-total-techs">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Total Duration</div>
                <div class="stat-value" id="fp-duration">0s</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Avg Confidence</div>
                <div class="stat-value" id="fp-avg-confidence">0%</div>
            </div>
        </div>
    </div>

    <!-- CSS Styles for Deep Fingerprinting -->
    <style>
    .layer-card {
        background: rgba(0, 0, 0, 0.3);
        border-left: 4px solid #00d4ff;
        border-radius: 8px;
        padding: 20px;
        margin-bottom: 20px;
        transition: all 0.3s ease;
        position: relative;
    }

    .layer-card.analyzing {
        border-left-color: #ffaa00;
        animation: pulse 1.5s infinite;
    }

    .layer-card.completed {
        border-left-color: #00ff88;
    }

    .layer-card.failed {
        border-left-color: #ff4444;
    }

    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.7; }
    }

    .layer-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 15px;
    }

    .layer-title {
        font-size: 1.3em;
        color: #00d4ff;
        font-weight: bold;
    }

    .layer-status {
        display: inline-block;
        padding: 5px 15px;
        border-radius: 20px;
        font-size: 0.85em;
        font-weight: bold;
    }

    .layer-status.analyzing {
        background: rgba(255, 170, 0, 0.2);
        color: #ffaa00;
        border: 1px solid #ffaa00;
    }

    .layer-status.completed {
        background: rgba(0, 255, 136, 0.2);
        color: #00ff88;
        border: 1px solid #00ff88;
    }

    .layer-status.failed {
        background: rgba(255, 68, 68, 0.2);
        color: #ff4444;
        border: 1px solid #ff4444;
    }

    .layer-description {
        color: #aaa;
        font-size: 0.95em;
        margin-bottom: 15px;
    }

    .layer-metrics {
        display: flex;
        gap: 20px;
        margin-bottom: 15px;
        flex-wrap: wrap;
    }

    .layer-metric {
        display: flex;
        align-items: center;
        gap: 8px;
    }

    .layer-metric-label {
        color: #888;
        font-size: 0.9em;
    }

    .layer-metric-value {
        color: #00d4ff;
        font-weight: bold;
    }

    .tech-list-horizontal {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        margin-top: 15px;
    }

    .tech-badge {
        background: rgba(0, 212, 255, 0.15);
        border: 1px solid #00d4ff;
        border-radius: 6px;
        padding: 8px 15px;
        display: flex;
        flex-direction: column;
        gap: 5px;
        min-width: 150px;
    }

    .tech-badge.verified {
        border-color: #00ff88;
        background: rgba(0, 255, 136, 0.15);
    }

    .tech-badge-name {
        color: #00d4ff;
        font-weight: bold;
        font-size: 0.95em;
    }

    .tech-badge.verified .tech-badge-name {
        color: #00ff88;
    }

    .tech-badge-meta {
        color: #888;
        font-size: 0.8em;
    }

    .tech-badge-version {
        color: #ffaa00;
        font-size: 0.85em;
        font-weight: bold;
    }

    .confidence-bar-container {
        background: rgba(255, 255, 255, 0.1);
        border-radius: 10px;
        height: 8px;
        overflow: hidden;
        margin-top: 5px;
    }

    .confidence-bar {
        height: 100%;
        background: linear-gradient(90deg, #ff4444 0%, #ffaa00 50%, #00ff88 100%);
        transition: width 0.3s ease;
        border-radius: 10px;
    }

    .layer-timeline-connector {
        width: 2px;
        height: 30px;
        background: linear-gradient(180deg, #00d4ff 0%, transparent 100%);
        margin: 0 auto;
    }
    </style>
    <div class="container">
        <header>
            <h1>🔐 Security Scan Dashboard</h1>
            <p>Comprehensive vulnerability assessment and analysis</p>
        </header>

        <!-- Scan Controls -->
        <div class="scan-section">
            <div class="scan-controls">
                <input type="url" id="targetInput" placeholder="Enter target URL (e.g., http://127.0.0.1:3000)" value="http://127.0.0.1:3000">
                <button id="scanButton" onclick="startScan()">🚀 Start Scan</button>
            </div>
            <div id="loadingIndicator" class="loading" style="display: none;">
                <div class="spinner"></div>
                <span>Scanning in progress... This may take several minutes</span>
            </div>
            <div id="errorMessage" class="error-message" style="display: none;"></div>
            <div id="successMessage" class="success-message" style="display: none;"></div>
        </div>

        <!-- Summary Stats -->
        <div class="scan-section" id="statsSection" style="display: none;">
            <h2 class="section-title">📊 Scan Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">Technologies Detected</div>
                    <div class="stat-value" id="techCount">0</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">CVEs Found</div>
                    <div class="stat-value" id="cveCount">0</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">ZAP Alerts</div>
                    <div class="stat-value" id="zapCount">0</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Vulnerabilities Verified</div>
                    <div class="stat-value" id="verifyCount">0</div>
                </div>
            </div>

            <!-- Alert Breakdown -->
            <div style="margin-top: 20px;">
                <h3 style="color: #00d4ff; margin-bottom: 10px;">Alert Severity Breakdown</h3>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-label">High Risk</div>
                        <div class="stat-value severity-high" id="highCount">0</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Medium Risk</div>
                        <div class="stat-value severity-medium" id="mediumCount">0</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Low Risk</div>
                        <div class="stat-value severity-low" id="lowCount">0</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Results Tabs -->
        <div class="scan-section" id="resultsSection" style="display: none;">
            <div class="tabs">
                <button class="tab-button active" onclick="switchTab(event, 'technologies')">🔧 Technologies</button>
                <button class="tab-button" onclick="switchTab(event, 'cves')">🚨 CVEs</button>
                <button class="tab-button" onclick="switchTab(event, 'zap-alerts')">⚠️ ZAP Alerts</button>
                <button class="tab-button" onclick="switchTab(event, 'verification')">✅ Verification</button>
                <button class="tab-button" onclick="switchTab(event, 'scenario')">🤖 AI Scenario</button>
                <button class="tab-button" onclick="switchTab(event, 'raw-data')">📋 Raw Data</button>
            </div>

            <!-- Technologies Tab -->
            <div id="technologies" class="tab-content active">
                <h2 class="section-title">Detected Technologies</h2>
                <div id="techContainer" class="tech-list"></div>
            </div>

            <!-- CVEs Tab -->
            <div id="cves" class="tab-content">
                <h2 class="section-title">CVE Vulnerabilities</h2>
                <div class="scroll-table">
                    <table>
                        <thead>
                            <tr>
                                <th>CVE ID</th>
                                <th>CVSS</th>
                                <th>Description</th>
                                <th>Product</th>
                            </tr>
                        </thead>
                        <tbody id="cveTable"></tbody>
                    </table>
                </div>
            </div>

            <!-- ZAP Alerts Tab -->
            <div id="zap-alerts" class="tab-content">
                <h2 class="section-title">OWASP ZAP Security Alerts</h2>
                
                <!-- Filter Buttons -->
                <div class="filter-buttons">
                    <button class="filter-btn active" onclick="filterZapAlerts(event, 'all')">All</button>
                    <button class="filter-btn" onclick="filterZapAlerts(event, 'High')">High</button>
                    <button class="filter-btn" onclick="filterZapAlerts(event, 'Medium')">Medium</button>
                    <button class="filter-btn" onclick="filterZapAlerts(event, 'Low')">Low</button>
                </div>

                <div id="zapContainer"></div>
            </div>

            <!-- Verification Tab -->
            <div id="verification" class="tab-content">
                <h2 class="section-title">Vulnerability Verification Results</h2>
                <div class="scroll-table">
                    <table>
                        <thead>
                            <tr>
                                <th>CVE ID</th>
                                <th>Endpoint</th>
                                <th>Status</th>
                                <th>Confidence</th>
                                <th>Exploitable</th>
                            </tr>
                        </thead>
                        <tbody id="verificationTable"></tbody>
                    </table>
                </div>
            </div>

            <!-- AI Scenario Tab -->
            <div id="scenario" class="tab-content">
                <h2 class="section-title">🤖 AI-Powered Attack Scenario</h2>
                <div id="scenarioContainer" class="scenario-box"></div>
            </div>

            <!-- Raw Data Tab -->
            <div id="raw-data" class="tab-content">
                <h2 class="section-title">Raw API Response</h2>
                <div id="rawDataContainer" class="json-viewer"></div>
            </div>
        </div>

        <footer class="footer">
            <p>Security Scan Dashboard | Powered by Nmap, CVE Database, and OWASP ZAP</p>
        </footer>
    </div>

    <script>
        let currentScanData = null;
        let allZapAlerts = [];
        let currentZapFilter = 'all';

        async function startScan() {
            const target = document.getElementById('targetInput').value.trim();
            
            if (!target) {
                showError('Please enter a target URL');
                return;
            }

            const scanButton = document.getElementById('scanButton');
            scanButton.disabled = true;
            document.getElementById('loadingIndicator').style.display = 'flex';
            document.getElementById('errorMessage').style.display = 'none';
            document.getElementById('successMessage').style.display = 'none';

            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ target })
                });

                if (!response.ok) {
                    throw new Error(`HTTP Error: ${response.status}`);
                }

                const data = await response.json();
                currentScanData = data;
                allZapAlerts = data.zap_scan?.alerts || [];

                displayResults(data);
                showSuccess('✅ Scan completed successfully!');
            } catch (error) {
                console.error('Scan error:', error);
                showError(`❌ Scan failed: ${error.message}`);
            } finally {
                scanButton.disabled = false;
                document.getElementById('loadingIndicator').style.display = 'none';
            }
        }

        function displayResults(data) {
            // Show sections
            document.getElementById('statsSection').style.display = 'block';
            document.getElementById('resultsSection').style.display = 'block';

            // Update stats
            document.getElementById('techCount').textContent = data.technologies?.length || 0;
            document.getElementById('cveCount').textContent = data.cves?.length || 0;
            document.getElementById('zapCount').textContent = data.zap_scan?.alerts?.length || 0;
            document.getElementById('verifyCount').textContent = data.verifications?.length || 0;

            // Severity breakdown
            const zapAlerts = data.zap_scan?.alerts || [];
            const highCount = zapAlerts.filter(a => a.risk === 'High').length;
            const mediumCount = zapAlerts.filter(a => a.risk === 'Medium').length;
            const lowCount = zapAlerts.filter(a => a.risk === 'Low').length;

            document.getElementById('highCount').textContent = highCount;
            document.getElementById('mediumCount').textContent = mediumCount;
            document.getElementById('lowCount').textContent = lowCount;

            // Display technologies
            displayTechnologies(data.technologies || []);

            // Display CVEs
            displayCVEs(data.cves || []);

            // Display ZAP Alerts
            displayZapAlerts(data.zap_scan?.alerts || []);

            // Display Verification Results
            displayVerification(data.verifications || []);

            // Display AI Scenario
            displayScenario(data.scenario || []);

            // Display Raw Data
            displayRawData(data);
        }

        function displayTechnologies(techs) {
            const container = document.getElementById('techContainer');
            
            if (techs.length === 0) {
                container.innerHTML = '<div class="empty-state">No technologies detected</div>';
                return;
            }

            container.innerHTML = techs.map(tech => `
                <div class="tech-card">
                    <div class="tech-name">${tech.product || 'Unknown'}</div>
                    <div class="tech-version">Version: ${tech.version || 'N/A'}</div>
                    <div class="tech-source">Source: <span class="badge badge-info">${tech.source || 'unknown'}</span></div>
                    ${tech.cpe ? `<div class="tech-source" style="margin-top: 10px; word-break: break-all;"><strong>CPE:</strong> <code style="color: #00ff88; font-size: 0.85em;">${tech.cpe}</code></div>` : ''}
                </div>
            `).join('');
        }

        function displayCVEs(cves) {
            const table = document.getElementById('cveTable');
            
            if (cves.length === 0) {
                table.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 20px;">No CVEs found</td></tr>';
                return;
            }

            table.innerHTML = cves.map(cve => `
                <tr>
                    <td><span class="cve-id">${cve.cve_id || 'N/A'}</span></td>
                    <td><span class="badge ${cve.cvss >= 7 ? 'badge-high' : cve.cvss >= 4 ? 'badge-medium' : 'badge-low'}">${cve.cvss || 'N/A'}</span></td>
                    <td>${truncate(cve.description || '', 100)}</td>
                    <td>${cve.product || 'N/A'}</td>
                </tr>
            `).join('');
        }

        function displayZapAlerts(alerts) {
            const container = document.getElementById('zapContainer');
            
            let filteredAlerts = alerts;
            if (currentZapFilter !== 'all') {
                filteredAlerts = alerts.filter(a => a.risk === currentZapFilter);
            }

            if (filteredAlerts.length === 0) {
                container.innerHTML = `<div class="empty-state">No ZAP alerts found for filter: ${currentZapFilter}</div>`;
                return;
            }

            container.innerHTML = filteredAlerts.slice(0, 50).map(alert => `
                <div class="alert-item ${alert.risk?.toLowerCase() || 'low'}">
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                        <span class="severity-indicator ${alert.risk?.toLowerCase() || 'low'}"></span>
                        <strong>${alert.name || 'Unknown Alert'}</strong>
                        <span class="badge ${alert.risk === 'High' ? 'badge-high' : alert.risk === 'Medium' ? 'badge-medium' : 'badge-low'}">${alert.risk || 'Unknown'}</span>
                    </div>
                    <div style="color: #bbb; font-size: 0.9em; margin-bottom: 5px; word-break: break-all;">
                        <strong>URL:</strong> ${alert.url || 'N/A'}
                    </div>
                    <div style="color: #999; font-size: 0.85em;">
                        ${truncate(alert.description || '', 200)}
                    </div>
                </div>
            `).join('');

            if (filteredAlerts.length > 50) {
                container.innerHTML += `<div style="text-align: center; color: #aaa; padding: 20px;">... and ${filteredAlerts.length - 50} more alerts</div>`;
            }
        }

        function displayVerification(verifications) {
            const table = document.getElementById('verificationTable');
            
            if (verifications.length === 0) {
                table.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 20px;">No verification results</td></tr>';
                return;
            }

            table.innerHTML = verifications.map(v => `
                <tr>
                    <td><span class="cve-id">${v.cve_id || 'N/A'}</span></td>
                    <td>${v.endpoint || 'N/A'}</td>
                    <td><span class="badge badge-info">${v.status || 'N/A'}</span></td>
                    <td>
                        <span class="badge ${v.confidence === 'high' ? 'badge-high' : v.confidence === 'medium' ? 'badge-medium' : 'badge-low'}">
                            ${v.confidence || 'N/A'}
                        </span>
                    </td>
                    <td>${v.exploitable ? '<span class="badge badge-high">Yes</span>' : '<span class="badge badge-low">No</span>'}</td>
                </tr>
            `).join('');
        }

        function displayScenario(scenario) {
            const container = document.getElementById('scenarioContainer');
            
            if (!scenario || scenario.length === 0) {
                container.textContent = 'No AI scenario generated';
                return;
            }

            container.textContent = Array.isArray(scenario) ? scenario.join('\n') : scenario;
        }

        function displayRawData(data) {
            const container = document.getElementById('rawDataContainer');
            container.textContent = JSON.stringify(data, null, 2);
        }

        function switchTab(event, tabName) {
            // Remove active class from all tab buttons
            document.querySelectorAll('.tab-button').forEach(btn => {
                btn.classList.remove('active');
            });

            // Remove active class from all tab contents
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });

            // Add active class to clicked button and corresponding content
            event.target.classList.add('active');
            document.getElementById(tabName).classList.add('active');
        }

        function filterZapAlerts(event, severity) {
            currentZapFilter = severity;
            
            // Update button styles
            document.querySelectorAll('.filter-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            event.target.classList.add('active');

            // Display filtered alerts
            displayZapAlerts(allZapAlerts);
        }

        function showError(message) {
            const errorDiv = document.getElementById('errorMessage');
            errorDiv.textContent = message;
            errorDiv.style.display = 'block';
        }

        function showSuccess(message) {
            const successDiv = document.getElementById('successMessage');
            successDiv.textContent = message;
            successDiv.style.display = 'block';
        }

        function truncate(str, length) {
            if (str.length <= length) return str;
            return str.substring(0, length) + '...';
        }

        console.log('🔐 Security Dashboard loaded and ready for scanning');
    </script>
</body>
</html>
```
---

## File 84: dashboard.js
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\backup_20260103\dashboard.js`

```javascript
// ===================================================================
// CVE Attack Simulation Dashboard - Main JavaScript (v3 - Fixed)
// ===================================================================

document.addEventListener('DOMContentLoaded', () => {
    console.log('[INIT] Dashboard initializing...');
    const scanBtn = document.getElementById('scan-btn');
    const targetInput = document.getElementById('target-input');
    
    console.log('[INIT] Scan button:', scanBtn ? '✅ Found' : '❌ NOT FOUND');
    console.log('[INIT] Target input:', targetInput ? '✅ Found' : '❌ NOT FOUND');
    
    if (!scanBtn || !targetInput) {
        console.error('[ERROR] Required elements not found!');
        console.error('Required IDs: scan-btn, target-input');
        alert('❌ UI 요소를 찾을 수 없습니다.\n\nHTML에서 다음 ID가 있는지 확인하세요:\n- id="scan-btn"\n- id="target-input"');
        return;
    }

    // 스캔 버튼 클릭 이벤트
    scanBtn.addEventListener('click', async () => {
        const target = targetInput.value.trim();
        console.log('[CLICK] Scan button clicked');
        console.log('[CLICK] Target:', target);

        if (!target) {
            alert('타겟 URL을 입력하세요!');
            return;
        }

        // UI 업데이트
        scanBtn.disabled = true;
        scanBtn.textContent = '스캔 중... ⏳';

        // 기존 결과 초기화
        console.log('[CLEAR] Clearing all sections...');
        clearAllSections();

        try {
            console.log('[FETCH] Starting fetch to /api/scan');
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ target })
            });

            console.log('[FETCH] Response status:', response.status);

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            console.log('[FETCH] Response received, data keys:', Object.keys(data));

            // ========== 전역 변수에 저장 (NEW) ==========
            window.currentScanData = data;

            // 각 섹션 렌더링
            console.log('[RENDER] Starting to render results...');
            renderRecon(data.technologies || [], data.categorized?.recon || {});
            renderCVEs(data.cves || [], data.verifications || []);
            
            // ========== ZAP 결과 렌더링 추가 (NEW) ==========
            renderZapResults(data.zap_scan);
            
            renderScenario(data.scenario || []);
            renderLoot(data.verifications || []);

            // 전체 기술 스택 모달 설정
            setupTechModal(data.categorized?.recon || {}, data.technologies || []);

            console.log('[SUCCESS] All rendering complete!');

        } catch (error) {
            console.error('[ERROR] Scan failed:', error);
            console.error('[ERROR] Stack:', error.stack);
            alert('❌ 스캔 실패:\n\n' + error.message);

            // 에러 메시지 표시
            const reconSection = document.getElementById('recon-section');
            if (reconSection) {
                reconSection.innerHTML = `<p class="info-text">❌ 스캔 실패: ${error.message}</p>`;
            }
        } finally {
            // 버튼 복원
            scanBtn.disabled = false;
            scanBtn.textContent = 'Scan & Analyze';
        }
    });

    console.log('[INIT] Dashboard initialization complete');
});


// ===================================================================
// 1️⃣ 정찰 결과 렌더링 (Recon)
// ===================================================================
function renderRecon(technologies, categorized) {
    console.log('[RECON] renderRecon called with', technologies.length, 'technologies');
    
    const reconSection = document.getElementById('recon-section');
    const showAllBtn = document.getElementById('show-all-tech-btn');
    
    if (!reconSection) {
        console.error('[RECON] ❌ recon-section NOT found');
        return;
    }
    console.log('[RECON] ✅ recon-section found');
    
    if (technologies.length === 0) {
        reconSection.innerHTML = '<p style="color: #95a5a6;">정찰 결과가 없습니다.</p>';
        if (showAllBtn) showAllBtn.style.display = 'none';
        return;
    }

    // CPE가 있는 핵심 기술만 표시
    const coreTechs = technologies.filter(t => t.cpe && !t.filtered);
    
    console.log('[RECON] Core technologies (with CPE):', coreTechs.length);
    
    let html = `<p style="font-size: 0.9em; color: #95a5a6;">
        <span style="color: #3498db; font-weight: bold;">핵심 기술: ${coreTechs.length}개</span> 
        <span> | 전체: ${technologies.length}개</span>
    </p>`;
    
    html += '<ul style="list-style: none; padding: 0; margin: 0;">';
    
    coreTechs.forEach(tech => {
        const version = tech.version && tech.version !== 'N/A' ? `v${tech.version}` : '';
        const source = tech.source ? `(${tech.source})` : '';
        
        html += `
            <li style="padding: 8px; margin: 5px 0; background: #2c3e50; border-radius: 5px; border-left: 3px solid #3498db;">
                <span style="color: #3498db; font-weight: bold;">📦 ${tech.product}</span> 
                <span style="color: #e74c3c;">${version}</span> 
                <span style="color: #95a5a6;">${source}</span>
            </li>
        `;
    });
    
    html += '</ul>';
    reconSection.innerHTML = html;
    
    // 전체 보기 버튼
    if (showAllBtn) {
        if (technologies.length > coreTechs.length) {
            showAllBtn.style.display = 'block';
            showAllBtn.textContent = `📋 전체 기술 스택 보기 (${technologies.length}개)`;
        } else {
            showAllBtn.style.display = 'none';
        }
    }
    
    console.log('[RECON] ✅ Recon rendering complete');
}


// ===================================================================
// 2️⃣ CVE 렌더링
// ===================================================================
function renderCVEs(cves, verifications) {
    console.log('[CVE] renderCVEs called with', cves.length, 'CVEs');
    
    const tableBody = document.getElementById('cve-table-body');
    
    if (!tableBody) {
        console.error('[CVE] ❌ cve-table-body NOT found');
        return;
    }
    console.log('[CVE] ✅ cve-table-body found');
    
    if (cves.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: #95a5a6; padding: 20px;">CVE가 발견되지 않았습니다.</td></tr>';
        return;
    }

    let html = '';
    
    cves.forEach(cve => {
        const cveId = cve.cve_id || 'N/A';
        const cvss = cve.cvss_score || 'N/A';
        const service = cve.service || 'N/A';
        const version = cve.version || 'N/A';
        const description = cve.description || 'N/A';
        
        // ✅ 검증 상태
        const verified = verifications.filter(v => v.cve_id === cveId);
        const exploitable = verified.filter(v => v.exploitable === true);
        
        let verificationBadge = '';
        
        if (exploitable.length > 0) {
            verificationBadge = `<span style="background: #e74c3c; color: white; padding: 4px 10px; border-radius: 12px; font-size: 0.85em; white-space: nowrap;">🚨 검증됨 (${exploitable.length})</span>`;
        } else if (verified.length > 0) {
            verificationBadge = `<span style="background: #2ecc71; color: white; padding: 4px 10px; border-radius: 12px; font-size: 0.85em; white-space: nowrap;">✅ 안전</span>`;
        } else {
            verificationBadge = `<span style="background: #95a5a6; color: white; padding: 4px 10px; border-radius: 12px; font-size: 0.85em; white-space: nowrap;">⚪ 미검증</span>`;
        }
        
        const desc = truncateText(description, 100);
        
        html += `
            <tr style="${exploitable.length > 0 ? 'background: rgba(231, 76, 60, 0.1);' : ''}">
                <td><a href="https://nvd.nist.gov/vuln/detail/${cveId}" target="_blank" style="color: #3498db; text-decoration: none;">${cveId}</a></td>
                <td style="color: #e74c3c; font-weight: bold;">${cvss}</td>
                <td>${service}</td>
                <td>${version}</td>
                <td>${verificationBadge}</td>
                <td style="font-size: 0.9em; color: #bdc3c7;">${desc}</td>
            </tr>
        `;
    });
    
    tableBody.innerHTML = html;
    console.log('[CVE] ✅ CVE rendering complete');
}


// ===================================================================
// 3️⃣ AI 공격 시나리오 렌더링
// ===================================================================
function renderScenario(scenarioLines) {
    console.log('[SCENARIO] renderScenario called with', scenarioLines.length, 'lines');
    
    const scenarioSection = document.getElementById('scenario-section');
    
    if (!scenarioSection) {
        console.error('[SCENARIO] ❌ scenario-section NOT found');
        return;
    }
    console.log('[SCENARIO] ✅ scenario-section found');
    
    if (scenarioLines.length === 0) {
        scenarioSection.innerHTML = '<p style="color: #95a5a6;">AI 시나리오가 생성되지 않았습니다.</p>';
        return;
    }
    
    if (scenarioLines[0].includes('실패') || scenarioLines[0].includes('❌')) {
        scenarioSection.innerHTML = `<p style="color:#e74c3c;">${scenarioLines[0]}</p>`;
        return;
    }

    const markdownText = scenarioLines.join('\n');
    
    try {
        // ✅ marked.js가 있으면 사용
        if (typeof marked !== 'undefined') {
            console.log('[SCENARIO] ✅ marked.js available, using for parsing');
            const htmlContent = marked.parse(markdownText);
            scenarioSection.innerHTML = htmlContent;
        } else {
            // ⚠️ marked.js가 없으면 단순 포맷팅
            console.log('[SCENARIO] ⚠️ marked.js NOT available, using fallback');
            const htmlContent = simpleFallbackMarkdown(markdownText);
            scenarioSection.innerHTML = htmlContent;
        }
        
        console.log('[SCENARIO] ✅ Scenario rendering complete');
        
    } catch (error) {
        console.error('[SCENARIO] ❌ Error:', error);
        scenarioSection.innerHTML = `<pre style="background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto;">${escapeHtml(markdownText)}</pre>`;
    }
}


// ===================================================================
// 4️⃣ Loot 섹션 렌더링
// ===================================================================
function renderLoot(verifications) {
    console.log('[LOOT] renderLoot called with', verifications.length, 'verifications');
    
    const sensitiveFilesList = document.getElementById('sensitive-files-list');
    
    if (!sensitiveFilesList) {
        console.error('[LOOT] ❌ sensitive-files-list NOT found');
        return;
    }
    console.log('[LOOT] ✅ sensitive-files-list found');
    
    const sensitiveKeywords = [
        '/.env', '/.git', '/admin', '/backup', 
        '/config', '/phpmyadmin', '/web.config',
        '/.aws', '/.ssh', '/credentials'
    ];
    
    const sensitiveFiles = verifications.filter(v => {
        if (!v.endpoint) return false;
        const endpoint = v.endpoint.toLowerCase();
        return sensitiveKeywords.some(keyword => endpoint.includes(keyword));
    });
    
    console.log('[LOOT] Found sensitive files:', sensitiveFiles.length);
    
    if (sensitiveFiles.length === 0) {
        sensitiveFilesList.innerHTML = '<li style="color: #2ecc71;">✅ 민감 파일이 발견되지 않았습니다.</li>';
        return;
    }

    let html = '';
    
    sensitiveFiles.forEach(file => {
        const status = file.exploitable ? '🚨 접근 가능' : '⚠️ 발견됨';
        const evidence = file.evidence || '추가 조사 필요';
        
        html += `
            <li style="padding: 8px; margin: 5px 0; background: #2c3e50; border-radius: 5px; border-left: 3px solid ${file.exploitable ? '#e74c3c' : '#f39c12'};">
                <span style="color: #3498db; font-weight: bold;">${file.endpoint}</span>
                <span style="color: ${file.exploitable ? '#e74c3c' : '#f39c12'}; margin-left: 10px;">${status}</span>
                <br>
                <span style="color: #95a5a6; font-size: 0.9em; margin-left: 10px;">💡 ${evidence}</span>
            </li>
        `;
    });
    
    sensitiveFilesList.innerHTML = html;
    console.log('[LOOT] ✅ Loot rendering complete');
}


// ===================================================================
// 5️⃣ ZAP 스캔 결과 렌더링 (NEW)
// ===================================================================
function renderZapResults(zapScan) {
    console.log('[ZAP] renderZapResults called');
    
    const scenarioSection = document.getElementById('scenario-section');
    
    if (!scenarioSection) {
        console.error('[ZAP] ❌ scenario-section NOT found');
        return;
    }
    
    const existingZap = document.getElementById('zap-section');
    if (existingZap) {
        existingZap.remove();
    }
    
    const zapSection = document.createElement('div');
    zapSection.id = 'zap-section';
    zapSection.className = 'section';
    
    zapSection.innerHTML = displayZapResults(zapScan);
    
    scenarioSection.insertAdjacentElement('afterend', zapSection);
    
    console.log('[ZAP] ✅ ZAP section rendered');
}


// ===================================================================
// 6️⃣ 모달 설정
// ===================================================================
function setupTechModal(categorized, allTechnologies) {
    console.log('[MODAL] setupTechModal called');
    
    const modal = document.getElementById('tech-modal');
    const btn = document.getElementById('show-all-tech-btn');
    const span = document.getElementsByClassName('close')[0];
    
    if (!btn) {
        console.error('[MODAL] ❌ show-all-tech-btn NOT found');
        return;
    }
    if (!modal) {
        console.error('[MODAL] ❌ tech-modal NOT found');
        return;
    }
    if (!span) {
        console.error('[MODAL] ❌ close button NOT found');
        return;
    }
    
    console.log('[MODAL] ✅ All modal elements found');
    
    btn.onclick = function() {
        console.log('[MODAL] Opening modal');
        populateModal(categorized, allTechnologies);
        modal.style.display = 'block';
    };
    
    span.onclick = function() {
        console.log('[MODAL] Closing modal (X button)');
        modal.style.display = 'none';
    };
    
    window.onclick = function(event) {
        if (event.target == modal) {
            console.log('[MODAL] Closing modal (outside click)');
            modal.style.display = 'none';
        }
    };
    
    console.log('[MODAL] ✅ Modal setup complete');
}


function populateModal(categorized, allTechnologies) {
    console.log('[MODAL] Populating modal with categorized data');
    
    const categories = ['web', 'network', 'database', 'os', 'cloud', 'container'];
    
    categories.forEach(cat => {
        const listEl = document.getElementById(`${cat}-tech-list`);
        
        if (!listEl) {
            console.warn(`[MODAL] ⚠️ Element not found: ${cat}-tech-list`);
            return;
        }
        
        const techs = categorized[cat] || [];
        
        console.log(`[MODAL] ${cat}:`, techs.length, 'technologies');
        
        if (techs.length === 0) {
            listEl.innerHTML = '<li style="color: #95a5a6;">발견된 기술이 없습니다.</li>';
            return;
        }
        
        let html = '';
        
        techs.forEach(tech => {
            const version = tech.version && tech.version !== 'N/A' ? tech.version : '버전 미상';
            const source = tech.source || '알 수 없음';
            
            html += `
                <li style="padding: 8px; margin: 5px 0; background: #2c3e50; border-radius: 5px; border-left: 3px solid #3498db;">
                    <span style="color: #3498db; font-weight: bold;">${tech.product}</span>
                    <span style="color: #e74c3c; margin-left: 10px;">v${version}</span>
                    <span style="color: #95a5a6; font-size: 0.9em; margin-left: 10px;">(${source})</span>
                </li>
            `;
        });
        
        listEl.innerHTML = html;
    });
    
    console.log('[MODAL] ✅ Population complete');
}


// ===================================================================
// 유틸리티 함수
// ===================================================================
function clearAllSections() {
    console.log('[CLEAR] Clearing all sections');
    
    const sections = [
        'recon-section',
        'cve-section',
        'scenario-section',
        'sensitive-files-list',
        'zap-section'
    ];

    sections.forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            element.innerHTML = '<p class="info-text">스캔을 시작하세요...</p>';
        }
    });

    const showAllBtn = document.getElementById('show-all-tech-btn');
    if (showAllBtn) {
        showAllBtn.style.display = 'none';
    }
}


function truncateText(text, maxLength) {
    if (!text) return 'N/A';
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
}


function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}


function simpleFallbackMarkdown(text) {
    let html = escapeHtml(text);
    
    html = html.replace(/^### (.*?)$/gm, '<h3 style="color: #2ecc71; margin-top: 15px;">$1</h3>');
    html = html.replace(/^## (.*?)$/gm, '<h2 style="color: #3498db; border-bottom: 1px solid #3498db; padding-bottom: 8px; margin-top: 18px;">$1</h2>');
    html = html.replace(/^# (.*?)$/gm, '<h1 style="color: #e74c3c; border-bottom: 2px solid #e74c3c; padding-bottom: 10px; margin-top: 20px;">$1</h1>');
    
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong style="color: #e74c3c;">$1</strong>');
    html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');
    html = html.replace(/``````/gs, '<pre style="background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto;"><code>$1</code></pre>');
    html = html.replace(/`(.*?)`/g, '<code style="background: #2c3e50; color: #e74c3c; padding: 2px 6px; border-radius: 3px;">$1</code>');
    
    html = html.replace(/\n\n/g, '</p><p style="margin-top: 15px;">');
    html = '<p style="line-height: 1.6;">' + html + '</p>';
    
    return html;
}


// ===================================================================
// ZAP 관련 함수들
// ===================================================================
function displayZapResults(zapScan) {
    if (!zapScan || !zapScan.alerts || zapScan.alerts.length === 0) {
        return `
        <div class="section">
            <h2>🔒 OWASP ZAP Security Scan</h2>
            <div class="info-text" style="color: #95a5a6;">
                No ZAP scan results available or ZAP scan was not performed.
            </div>
        </div>
        `;
    }
    
    const summary = zapScan.summary || {};
    const alerts = zapScan.alerts || [];
    const riskBreakdown = zapScan.risk_breakdown || {};
    
    let html = `
    <div class="section">
        <h2>🔒 OWASP ZAP Security Scan</h2>
        <div class="info-text">
            <span class="highlight">Total Alerts: ${summary.total_alerts || 0}</span> | 
            <span style="color:#e74c3c;font-weight:bold;">🔴 High: ${summary.high || 0}</span> | 
            <span style="color:#e67e22;font-weight:bold;">🟠 Medium: ${summary.medium || 0}</span> | 
            <span style="color:#f39c12;font-weight:bold;">🟡 Low: ${summary.low || 0}</span> | 
            <span style="color:#3498db;">ℹ️ Info: ${summary.informational || 0}</span>
        </div>
        
        <h3 style="color:#e74c3c;margin-top:20px;">High Risk Alerts</h3>
        <table>
            <thead>
                <tr>
                    <th>Risk</th>
                    <th>Alert Type</th>
                    <th>URL</th>
                    <th>CWE ID</th>
                    <th>Solution</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    const highAlerts = (riskBreakdown.high || []).slice(0, 10);
    if (highAlerts.length > 0) {
        highAlerts.forEach(alert => {
            html += `
                <tr class="exploitable-row">
                    <td><span style="color:#e74c3c;font-weight:bold;">🔴 High</span></td>
                    <td style="font-weight:bold;">${alert.alert || 'N/A'}</td>
                    <td style="font-size:0.85em;max-width:200px;overflow:hidden;text-overflow:ellipsis;">
                        ${alert.url ? alert.url.substring(0, 60) : 'N/A'}
                    </td>
                    <td>${alert.cweid || '-'}</td>
                    <td style="font-size:0.85em;max-width:300px;">
                        ${alert.solution ? alert.solution.substring(0, 100) + '...' : 'N/A'}
                    </td>
                </tr>
            `;
        });
    } else {
        html += `
            <tr>
                <td colspan="5" style="text-align:center;color:#2ecc71;">
                    ✅ No high risk vulnerabilities found!
                </td>
            </tr>
        `;
    }
    
    html += `
            </tbody>
        </table>
        
        <h3 style="color:#e67e22;margin-top:20px;">Medium Risk Alerts</h3>
        <table>
            <thead>
                <tr>
                    <th>Risk</th>
                    <th>Alert Type</th>
                    <th>URL</th>
                    <th>CWE ID</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    const mediumAlerts = (riskBreakdown.medium || []).slice(0, 10);
    if (mediumAlerts.length > 0) {
        mediumAlerts.forEach(alert => {
            html += `
                <tr>
                    <td><span style="color:#e67e22;font-weight:bold;">🟠 Medium</span></td>
                    <td>${alert.alert || 'N/A'}</td>
                    <td style="font-size:0.85em;max-width:200px;overflow:hidden;text-overflow:ellipsis;">
                        ${alert.url ? alert.url.substring(0, 60) : 'N/A'}
                    </td>
                    <td>${alert.cweid || '-'}</td>
                    <td style="font-size:0.85em;max-width:300px;">
                        ${alert.description ? alert.description.substring(0, 120) + '...' : 'N/A'}
                    </td>
                </tr>
            `;
        });
        
        if ((riskBreakdown.medium || []).length > 10) {
            html += `
                <tr>
                    <td colspan="5" style="text-align:center;color:#95a5a6;font-style:italic;">
                        ... and ${(riskBreakdown.medium || []).length - 10} more medium risk alerts
                    </td>
                </tr>
            `;
        }
    } else {
        html += `
            <tr>
                <td colspan="5" style="text-align:center;color:#2ecc71;">
                    ✅ No medium risk vulnerabilities found!
                </td>
            </tr>
        `;
    }
    
    html += `
            </tbody>
        </table>
        
        <button class="secondary-btn" onclick="showAllZapAlerts()">
            📋 View All ${alerts.length} ZAP Alerts
        </button>
    </div>
    `;
    
    return html;
}


function showAllZapAlerts() {
    const zapScan = window.currentScanData?.zap_scan;
    if (!zapScan || !zapScan.alerts) {
        alert('No ZAP scan data available');
        return;
    }
    
    const alerts = zapScan.alerts;
    let modalContent = `
        <h2>🔒 All OWASP ZAP Alerts (${alerts.length})</h2>
        <table style="width:100%;margin-top:20px;">
            <thead>
                <tr>
                    <th>Risk</th>
                    <th>Alert</th>
                    <th>URL</th>
                    <th>CWE</th>
                    <th>Confidence</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    alerts.forEach(alert => {
        const riskColor = {
            'High': '#e74c3c',
            'Medium': '#e67e22',
            'Low': '#f39c12',
            'Informational': '#3498db'
        }[alert.risk] || '#95a5a6';
        
        modalContent += `
            <tr>
                <td><span style="color:${riskColor};font-weight:bold;">${alert.risk}</span></td>
                <td>${alert.alert}</td>
                <td style="font-size:0.8em;max-width:250px;overflow:hidden;text-overflow:ellipsis;">
                    ${alert.url}
                </td>
                <td>${alert.cweid || '-'}</td>
                <td>${alert.confidence || 'N/A'}</td>
            </tr>
        `;
    });
    
    modalContent += `
            </tbody>
        </table>
    `;
    
    showModal(modalContent);
}


function showModal(content) {
    let modal = document.getElementById('generic-modal');
    if (modal) {
        modal.remove();
    }
    
    modal = document.createElement('div');
    modal.id = 'generic-modal';
    modal.className = 'modal';
    modal.style.display = 'block';
    
    modal.innerHTML = `
        <div class="modal-content" style="max-width: 90%; max-height: 80vh; overflow-y: auto;">
            <span class="close" style="float:right;font-size:28px;font-weight:bold;cursor:pointer;">&times;</span>
            ${content}
        </div>
    `;
    
    document.body.appendChild(modal);
    
    const closeBtn = modal.querySelector('.close');
    closeBtn.onclick = function() {
        modal.style.display = 'none';
        modal.remove();
    };
    
    modal.onclick = function(event) {
        if (event.target === modal) {
            modal.style.display = 'none';
            modal.remove();
        }
    };
}


console.log('[DASHBOARD] ✅ JavaScript loaded and ready');


// ==========================================
// Deep Fingerprinting Trace JavaScript
// dashboard.js에 추가하거나 별도 파일로 생성
// ==========================================

/**
 * Deep Fingerprinting 스캔 시작
 */
async function startDeepFingerprint(target) {
    console.log('[DEEP-FP] Starting deep fingerprint scan for:', target);

    // UI 초기화
    const section = document.getElementById('deep-fingerprint-section');
    section.style.display = 'block';

    const timeline = document.getElementById('fingerprint-timeline');
    timeline.innerHTML = '<div class="loading"><div class="spinner"></div><span>Initializing Deep Fingerprint Analysis...</span></div>';

    try {
        const response = await fetch('/api/deep-fingerprint', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ target })
        });

        if (!response.ok) {
            throw new Error(`HTTP Error: ${response.status}`);
        }

        const data = await response.json();
        console.log('[DEEP-FP] Response received:', data);

        // 결과 렌더링
        renderDeepFingerprint(data);

        return data;

    } catch (error) {
        console.error('[DEEP-FP] Error:', error);
        timeline.innerHTML = `
            <div class="error-message">
                ❌ Deep Fingerprint scan failed: ${error.message}
            </div>
        `;
        throw error;
    }
}

/**
 * Deep Fingerprinting 결과 렌더링
 */
function renderDeepFingerprint(data) {
    console.log('[DEEP-FP] Rendering results...');

    const timeline = document.getElementById('fingerprint-timeline');
    timeline.innerHTML = '';

    // 각 레이어 렌더링
    data.layers.forEach((layer, index) => {
        const layerCard = createLayerCard(layer);
        timeline.appendChild(layerCard);

        // 마지막 레이어가 아니면 커넥터 추가
        if (index < data.layers.length - 1) {
            const connector = document.createElement('div');
            connector.className = 'layer-timeline-connector';
            timeline.appendChild(connector);
        }
    });

    // Summary 통계 업데이트
    updateFingerprintSummary(data);
}

/**
 * 레이어 카드 생성
 */
function createLayerCard(layer) {
    const card = document.createElement('div');
    card.className = `layer-card ${layer.status}`;

    // 상태별 아이콘
    const statusIcons = {
        'completed': '✅',
        'analyzing': '🔄',
        'failed': '❌'
    };

    const icon = statusIcons[layer.status] || '❓';

    // 평균 confidence 계산
    const avgConfidence = layer.technologies && layer.technologies.length > 0
        ? layer.technologies.reduce((sum, t) => sum + (t.confidence || 0), 0) / layer.technologies.length
        : 0;

    card.innerHTML = `
        <div class="layer-header">
            <div class="layer-title">
                ${icon} Layer ${layer.id}: ${layer.name}
            </div>
            <span class="layer-status ${layer.status}">
                ${layer.status.toUpperCase()}
            </span>
        </div>

        <div class="layer-description">
            ${layer.description}
        </div>

        <div class="layer-metrics">
            <div class="layer-metric">
                <span class="layer-metric-label">⏱️ Duration:</span>
                <span class="layer-metric-value">${layer.duration}s</span>
            </div>
            <div class="layer-metric">
                <span class="layer-metric-label">🎯 Technologies:</span>
                <span class="layer-metric-value">${layer.count}</span>
            </div>
            <div class="layer-metric">
                <span class="layer-metric-label">📊 Avg Confidence:</span>
                <span class="layer-metric-value">${(avgConfidence * 100).toFixed(0)}%</span>
            </div>
            ${layer.endpoints_discovered ? `
            <div class="layer-metric">
                <span class="layer-metric-label">🔗 Endpoints:</span>
                <span class="layer-metric-value">${layer.endpoints_discovered}</span>
            </div>
            ` : ''}
        </div>

        ${layer.technologies && layer.technologies.length > 0 ? `
        <div class="tech-list-horizontal">
            ${layer.technologies.map(tech => createTechBadge(tech)).join('')}
        </div>
        ` : '<div style="color: #888; font-style: italic; margin-top: 10px;">No technologies detected in this layer</div>'}

        ${layer.error ? `
        <div class="error-message" style="margin-top: 15px;">
            Error: ${layer.error}
        </div>
        ` : ''}
    `;

    return card;
}

/**
 * 기술 배지 생성
 */
function createTechBadge(tech) {
    const verified = tech.verified ? ' verified' : '';
    const verifiedIcon = tech.verified ? ' ✓' : '';

    return `
        <div class="tech-badge${verified}">
            <div class="tech-badge-name">${tech.name}${verifiedIcon}</div>
            ${tech.version ? `<div class="tech-badge-version">v${tech.version}</div>` : ''}
            <div class="tech-badge-meta">${tech.method || tech.source}</div>
            ${tech.confidence ? `
            <div class="confidence-bar-container">
                <div class="confidence-bar" style="width: ${tech.confidence * 100}%"></div>
            </div>
            ` : ''}
        </div>
    `;
}

/**
 * Summary 통계 업데이트
 */
function updateFingerprintSummary(data) {
    document.getElementById('fp-total-layers').textContent = data.layers.length;
    document.getElementById('fp-total-techs').textContent = data.summary.total_technologies;
    document.getElementById('fp-duration').textContent = `${data.summary.total_duration}s`;

    // 평균 confidence 계산
    let totalConfidence = 0;
    let techCount = 0;

    data.layers.forEach(layer => {
        if (layer.technologies) {
            layer.technologies.forEach(tech => {
                if (tech.confidence) {
                    totalConfidence += tech.confidence;
                    techCount++;
                }
            });
        }
    });

    const avgConfidence = techCount > 0 ? (totalConfidence / techCount * 100).toFixed(0) : 0;
    document.getElementById('fp-avg-confidence').textContent = `${avgConfidence}%`;
}

/**
 * 기존 startScan 함수에 통합
 */
async function startScan() {
    const target = document.getElementById('targetInput').value.trim();

    if (!target) {
        showError('Please enter a target URL');
        return;
    }

    const scanButton = document.getElementById('scanButton');
    scanButton.disabled = true;
    document.getElementById('loadingIndicator').style.display = 'flex';

    try {
        // Deep Fingerprinting 먼저 실행
        console.log('[SCAN] Starting Deep Fingerprint...');
        await startDeepFingerprint(target);

        // 기존 스캔 계속 진행
        console.log('[SCAN] Starting full scan...');
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ target })
        });

        if (!response.ok) {
            throw new Error(`HTTP Error: ${response.status}`);
        }

        const data = await response.json();
        currentScanData = data;

        displayResults(data);
        showSuccess('Scan completed successfully!');

    } catch (error) {
        console.error('[SCAN] Error:', error);
        showError(`Scan failed: ${error.message}`);
    } finally {
        scanButton.disabled = false;
        document.getElementById('loadingIndicator').style.display = 'none';
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        startDeepFingerprint,
        renderDeepFingerprint
    };
}

console.log('[DEEP-FP] Module loaded successfully');
```
---

## File 85: routes.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\backup_20260103\routes.py`

```python
# app/api/routes.py - Import Section

from flask import Blueprint, render_template, request, jsonify, current_app  # type: ignore
import nmap  # type: ignore
import re
import asyncio
import logging
import importlib.util
import os
from typing import List, Dict, Any
from pathlib import Path

# ========== Core Imports ==========
from ..core.cve.cpe_generator import batch_generate_cpes
from ..core.recon.network import run_recon, collect_network_info
from ..core.recon.web import collect_web_info
from ..core.recon.os import collect_os_info
from ..core.recon.database import collect_database_info
from ..core.recon.cloud import collect_cloud_info
from ..core.recon.container import collect_container_info
from ..core.scenario.generator import build_prompt, call_ollama
from ..core.scenario.reporter import enrich_loot
from ..core.cve.async_nvd_client import AsyncNvdClient
from ..core.cve.cache_manager import CacheManager
from ..core.cve.matcher import (
    extract_cve_summary,
    deduplicate_cves,
    parse_and_normalize_version,
    parse_complex_version_string,
    normalize_product_name,
    extract_product_from_version_string,
    map_product_to_vendor_product,
    build_cpe_string,
    search_cves_universal
)
from ..utils.exploit import search_exploits_for_cves
from app.core.verifier import VulnerabilityVerifier

# ========== Scanner Import (지연 로딩) ==========
# run_network_scan은 app/core/scanner.py에 있음
# Circular import 방지를 위해 함수 레벨에서 import
def get_run_network_scan():
    """지연 import로 run_network_scan 함수 가져오기"""
    scanner_path = os.path.join(
        os.path.dirname(__file__), 
        '..',
        'core', 
        'scanner.py'
    )
    
    if not os.path.exists(scanner_path):
        raise ImportError(f"scanner.py not found at {scanner_path}")
    
    spec = importlib.util.spec_from_file_location("core_scanner", scanner_path)
    scanner_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scanner_module)
    
    return scanner_module.run_network_scan

# ========== Logger ==========
logger = logging.getLogger(__name__)

# ========== Blueprint ==========
bp = Blueprint('main', __name__)


# 전역 캐시 매니저 (앱 시작 시 한 번만 초기화)
cache_manager = None


def get_cache_manager():
    """캐시 매니저 싱글톤"""
    global cache_manager
    if cache_manager is None:
        # 프로젝트 루트 계산 (api/routes.py 기준으로 app/의 부모 = 프로젝트 루트)
        project_root = Path(__file__).parent.parent.parent
        data_dir = project_root / "data"
        data_dir.mkdir(exist_ok=True)
        
        cache_manager = CacheManager(
            backend="sqlite",
            ttl=86400,  # 24시간
            db_path=str(data_dir / "cve_cache.db")  # 절대 경로
        )
        # 앱 시작 시 만료된 캐시 정리
        cache_manager.clear_expired()
    return cache_manager



# ========================================
# 🆕 헬퍼 함수: 스캐너 출력 파싱
# ========================================


def extract_tech_info_from_scanner(tech_item: Dict[str, Any]) -> Dict[str, str]:
    """
    스캐너 출력에서 product와 version 추출 (다양한 형식 지원)
    
    Args:
        tech_item: 스캐너 출력 항목
    
    Returns:
        {"product": "nginx", "version": "1.19.0"}
    """
    # Case 1: network.py 출력 (full_version 필드 우선 사용)
    if "full_version" in tech_item and tech_item.get("full_version"):
        full_version = tech_item["full_version"]
        
        # parse_complex_version_string 사용
        parsed = parse_complex_version_string(full_version)
        
        return {
            "product": parsed.get("product", ""),
            "version": parsed.get("version", "")
        }
    
    # Case 2: network.py 출력 (product + version 필드)
    if "product" in tech_item and "version" in tech_item:
        product = tech_item.get("product", "")
        version = tech_item.get("version", "")
        
        return {
            "product": normalize_product_name(product),
            "version": parse_and_normalize_version(version) or version
        }
    
    # Case 3: web.py, database.py 출력 ("name" 필드)
    if "name" in tech_item:
        name = tech_item["name"]
        
        # parse_complex_version_string 사용
        parsed = parse_complex_version_string(name)
        
        return {
            "product": parsed.get("product", ""),
            "version": parsed.get("version", "")
        }
    
    # Case 4: 알 수 없는 형식
    logger.warning(f"Unknown tech_item format: {tech_item}")
    return {
        "product": "",
        "version": ""
    }



def extract_tech_info_from_recon(host: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    recon 결과 (network.py)에서 기술 정보 추출
    
    Args:
        host: run_recon() 반환값의 개별 호스트
    
    Returns:
        [{"product": "nginx", "version": "1.19.0", "port": 80, "host_ip": "192.168.1.x"}, ...]
    """
    technologies = []
    
    for port in host.get("ports", []):
        # full_version 필드 우선 사용
        tech_info = extract_tech_info_from_scanner(port)
        
        if tech_info["product"]:
            technologies.append({
                "product": tech_info["product"],
                "version": tech_info["version"],
                "port": port.get("port"),
                "host_ip": host.get("ip"),
                "source": "network_scan",
                "service": port.get("service"),
                # NSE 스크립트 취약점도 추가
                "nse_vulnerabilities": port.get("nse_scripts", []),
                "has_vulnerabilities": port.get("has_vulnerabilities", False)
            })
    
    return technologies


def extract_tech_info_from_web(web_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    web.py 출력에서 기술 정보 추출
    Returns:
        [{\"product\": \"apache\", \"version\": \"2.4.66\", \"source\": \"web_scan\"}, ...]
    """
    technologies = []
    
    # 🆕 디버깅: 입력 데이터 확인
    print("\n" + "="*70)
    print("[DEBUG-ROUTES] extract_tech_info_from_web() 호출됨")
    print(f"[DEBUG-ROUTES] web_info 키: {list(web_info.keys())}")
    
    web_technologies = web_info.get('webtechnologies', [])  # ⭐ 밑줄 제거!
    print(f"DEBUG: Type of web_technologies: {type(web_technologies)}")
    print(f"WORKFLOW: Web recon completed - Found {len(web_technologies)} technologies")
    
    for idx, tech in enumerate(web_technologies):
        # 🆕 디버깅: 각 기술 정보 출력
        print(f"\n[DEBUG-ROUTES] Tech #{idx+1}:")
        print(f"  - name: {tech.get('name', 'N/A')}")
        print(f"  - version: {tech.get('version', 'N/A')}")
        print(f"  - product: {tech.get('product', 'N/A')}")
        print(f"  - category: {tech.get('category', 'N/A')}")
        print(f"  - language: {tech.get('language', 'N/A')}")
        print(f"  - source: {tech.get('source', 'N/A')}")
        
        # 🆕 안전한 값 추출
        name = tech.get('name', '')
        version = tech.get('version', '')
        product = tech.get('product', name)
        
        # 🆕 빈 문자열 처리
        if not name or name.strip() == '':
            name = 'Unknown'
        if not version or version.strip() == '':
            version = 'N/A'
        if not product or product.strip() == '':
            product = name
        
        tech_info = extract_tech_info_from_scanner(tech)
        if tech_info["product"]:
            # 🆕 extract_tech_info_from_scanner 결과도 빈 문자열 체크
            final_product = tech_info["product"] or product or "Unknown"
            final_version = tech_info["version"] or version or "N/A"
            
            tech_obj = {
                "product": final_product,
                "version": final_version,
                "source": "web_scan",
                "tech_type": tech.get("type"),
                "original_name": tech.get("name")
            }
            
            # 🆕 디버깅: 생성된 객체 확인
            print(f"[DEBUG-ROUTES] 생성된 tech_obj: {tech_obj}")
            
            technologies.append(tech_obj)
    
    print(f"\n[DEBUG-ROUTES] 총 {len(technologies)}개 기술 추출됨")
    print("="*70 + "\n")
    
    return technologies


def extract_tech_info_from_database(db_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    database.py 출력에서 기술 정보 추출
    
    Returns:
        [{"product": "mysql", "version": "5.7.35", "source": "database_scan"}, ...]
    """
    technologies = []
    
    for tech in db_info.get("database_technologies", []):
        tech_info = extract_tech_info_from_scanner(tech)
        
        if tech_info["product"]:
            technologies.append({
                "product": tech_info["product"],
                "version": tech_info["version"],
                "source": "database_scan",
                "port": tech.get("port"),
                "db_type": tech.get("db_type"),
                # 위험 정보 태깅
                "anonymous_access": tech.get("anonymous_access", False),
                "dangerous": tech.get("dangerous", False),
                "weak_credentials": tech.get("weak_credentials", []),
                "original_name": tech.get("name")  # 디버깅용
            })
    
    return technologies



def extract_tech_info_from_os(os_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    os.py 출력에서 기술 정보 추출
    
    Returns:
        [{"product": "linux", "version": "4.15", "source": "os_scan"}, ...]
    """
    technologies = []
    
    for tech in os_info.get("os_technologies", []):
        tech_info = extract_tech_info_from_scanner(tech)
        
        if tech_info["product"]:
            technologies.append({
                "product": tech_info["product"],
                "version": tech_info["version"],
                "source": "os_scan",
                "original_name": tech.get("name")
            })
    
    return technologies



def extract_tech_info_from_cloud(cloud_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    cloud.py 출력에서 기술 정보 추출
    
    Returns:
        [{"product": "aws", "version": "", "source": "cloud_scan"}, ...]
    """
    technologies = []
    
    for tech in cloud_info.get("cloud_technologies", []):
        tech_info = extract_tech_info_from_scanner(tech)
        
        if tech_info["product"]:
            technologies.append({
                "product": tech_info["product"],
                "version": tech_info["version"],
                "source": "cloud_scan",
                "original_name": tech.get("name")
            })
    
    return technologies



def extract_tech_info_from_container(container_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    container.py 출력에서 기술 정보 추출
    
    Returns:
        [{"product": "docker", "version": "20.10", "source": "container_scan"}, ...]
    """
    technologies = []
    
    for tech in container_info.get("container_technologies", []):
        tech_info = extract_tech_info_from_scanner(tech)
        
        if tech_info["product"]:
            technologies.append({
                "product": tech_info["product"],
                "version": tech_info["version"],
                "source": "container_scan",
                "original_name": tech.get("name")
            })
    
    return technologies

def deduplicate_technologies(technologies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    기술 목록에서 중복 제거 (같은 product는 버전 있는 것 우선)
    
    Args:
        technologies: 기술 정보 리스트
        
    Returns:
        중복 제거된 기술 리스트
    """
    seen_products = {}
    
    for tech in technologies:
        product = tech.get('product', '').lower()
        version = tech.get('version', 'N/A')
        
        if not product:
            continue
            
        # 첫 등장이거나, 기존 항목이 버전 없고 현재 항목에 버전 있으면 교체
        if product not in seen_products:
            seen_products[product] = tech
        else:
            existing_version = seen_products[product].get('version', 'N/A')
            
            # 버전이 있는 것으로 우선 선택
            if existing_version == 'N/A' and version != 'N/A':
                seen_products[product] = tech
                print(f"[DEDUP] 교체: {product} (N/A -> {version})")
                logger.info(f"[DEDUP] Replaced {product}: N/A -> {version}")
            elif existing_version != 'N/A' and version == 'N/A':
                # 기존에 버전 있으면 유지
                print(f"[DEDUP] 유지: {product} (버전 있음: {existing_version})")
                logger.info(f"[DEDUP] Kept {product} with version: {existing_version}")
            else:
                # 둘 다 버전 있거나 둘 다 없으면 먼저 발견된 것 유지
                print(f"[DEDUP] 중복 무시: {product} ({version})")
                logger.debug(f"[DEDUP] Duplicate ignored: {product}")
    
    result = list(seen_products.values())
    print(f"[DEDUP] ✅ {len(technologies)}개 -> {len(result)}개로 중복 제거 완료")
    logger.info(f"[DEDUP] Deduplicated: {len(technologies)} -> {len(result)}")
    
    return result

# ========================================
# CVE 관련 함수
# ========================================


def score_cve_exploitability(cve_item: dict, exploit_map: dict) -> int:
    """
    CVE의 실제 공격 가능성 점수 계산
    
    Args:
        cve_item: CVE 정보
        exploit_map: Exploit 매핑 정보
    
    Returns:
        공격 가능성 점수 (높을수록 우선순위 높음)
    """
    score = 0
    
    # 1. CVSS 기본 점수
    cvss = cve_item.get("cvss", 0)
    if cvss >= 9.0:
        score += 10
    elif cvss >= 7.0:
        score += 5
    elif cvss >= 4.0:
        score += 2
    
    # 2. Searchsploit에 실제 exploit 있으면 대폭 가산
    if cve_item.get("cve_id") in exploit_map:
        score += 20
    
    # 3. 매칭 신뢰도
    confidence = cve_item.get("match_confidence", "none")
    if confidence == "high":
        score += 10
    elif confidence == "medium":
        score += 5
    elif confidence == "low":
        score += 2
    
    # 4. 최근 CVE일수록 높은 점수
    try:
        cve_id = cve_item.get("cve_id", "CVE-2000-0000")
        year = int(cve_id.split("-")[1])
        if year >= 2024:
            score += 15
        elif year >= 2022:
            score += 10
        elif year >= 2020:
            score += 5
    except:
        pass
    
    return score



def build_attack_chains(recon_result, all_cves, exploit_map):
    """
    여러 CVE를 엮은 공격 체인 후보 생성
    
    Args:
        recon_result: 정찰 결과
        all_cves: 전체 CVE 리스트
        exploit_map: Exploit 매핑
    
    Returns:
        공격 체인 리스트
    """
    chains = []
    chain_id = 1
    
    # CVE들을 공격 가능성 점수로 정렬
    scored_cves = [
        (cve, score_cve_exploitability(cve, exploit_map)) 
        for cve in all_cves
    ]
    scored_cves.sort(key=lambda x: x[1], reverse=True)
    
    # 역할별로 분류
    initial = [c for c, s in scored_cves if c.get("cvss", 0) >= 7.0]
    privesc = [
        c for c, s in scored_cves
        if "privilege" in (c.get("description") or "").lower()
    ]
    exfil = [
        c for c, s in scored_cves
        if any(keyword in (c.get("description") or "").lower() 
               for keyword in ["sql", "information disclosure", "data leak", "file read"])
    ]
    
    logger.info(f"Attack chain candidates - Initial: {len(initial)}, Privesc: {len(privesc)}, Exfil: {len(exfil)}")
    
    if not initial:
        return chains
    
    max_chain = 3
    for i, init_cve in enumerate(initial[:max_chain]):
        chain_steps = []
        
        host_ip = init_cve.get("host_ip") or (
            recon_result[0].get("ip") if recon_result else "127.0.0.x"
        )
        service = init_cve.get("service") or init_cve.get("technology") or "unknown"
        port = init_cve.get("port")
        
        # 1단계: initial_access
        chain_steps.append({
            "step": 1,
            "role": "initial_access",
            "cve_id": init_cve.get("cve_id"),
            "cvss": init_cve.get("cvss"),
            "service": service,
            "port": port,
            "confidence": init_cve.get("match_confidence", "none")
        })
        
        step_num = 2
        
        # 2단계: privilege_escalation
        if privesc:
            pe = privesc[i % len(privesc)]
            chain_steps.append({
                "step": step_num,
                "role": "privilege_escalation",
                "cve_id": pe.get("cve_id"),
                "cvss": pe.get("cvss"),
                "service": pe.get("service") or pe.get("technology") or "unknown",
                "port": pe.get("port"),
                "confidence": pe.get("match_confidence", "none")
            })
            step_num += 1
        
        # 3단계: data_exfiltration
        if exfil:
            de = exfil[i % len(exfil)]
            chain_steps.append({
                "step": step_num,
                "role": "data_exfiltration",
                "cve_id": de.get("cve_id"),
                "cvss": de.get("cvss"),
                "service": de.get("service") or de.get("technology") or "unknown",
                "port": de.get("port"),
                "confidence": de.get("match_confidence", "none")
            })
        
        chains.append({
            "chain_id": chain_id,
            "host_ip": host_ip,
            "steps": chain_steps,
        })
        chain_id += 1
    
    logger.info(f"Generated {len(chains)} attack chains")
    return chains



async def search_cves_parallel(technologies: List[Dict[str, Any]], max_pages: int = 1) -> List[Dict[str, Any]]:
    """
    CVE 병렬 검색 (CPE 자동 발견 포함)
    
    Args:
        technologies: [{"product": "nginx", "version": "1.19.0", ...}, ...]
        max_pages: 최대 페이지 수
    
    Returns:
        CVE 리스트
    """
    nvd_client = AsyncNvdClient(max_concurrent=10, cache_size=2000)
    
    # 제품 리스트 생성
    products = []
    for tech in technologies:
        product = tech.get("product", "")
        version = tech.get("version", "")
        
        if not product:
            continue
        
        products.append({
            "product": product,
            "version": version,
            "tech_info": tech  # 원본 정보 보존
        })
    
    if not products:
        return []
    
    logger.info(f"Starting parallel CVE search for {len(products)} products")
    
    # 병렬 CVE 검색 (CPE 자동 발견 포함)
    all_cves = []
    
    # asyncio.gather로 병렬 실행
    tasks = []
    for prod in products:
        task = search_cves_universal(
            tech_name=prod["product"],
            tech_version=prod["version"],
            nvd_client=nvd_client
        )
        tasks.append((task, prod))  # task와 제품 정보를 함께 저장
    
    # 모든 검색 병렬 실행
    results = await asyncio.gather(*[t[0] for t in tasks], return_exceptions=True)
    
    # 결과 처리
    for idx, (result, prod) in enumerate(zip(results, [t[1] for t in tasks])):
        if isinstance(result, Exception):
            logger.error(f"CVE search failed for {prod['product']}: {result}")
            continue
        
        tech_info = prod["tech_info"]
        
        # CVE 정보에 기술 스택 정보 추가
        for cve_summary in result:
            if cve_summary.get("is_vulnerable"):
                # 기술 정보 추가
                cve_summary["technology"] = f"{prod['product']} {prod['version']}".strip()
                cve_summary["product"] = prod["product"]
                cve_summary["version"] = prod["version"]
                cve_summary["source"] = tech_info.get("source", "unknown")
                cve_summary["port"] = tech_info.get("port")
                cve_summary["host_ip"] = tech_info.get("host_ip")
                
                # 추가 정보
                if tech_info.get("anonymous_access"):
                    cve_summary["anonymous_access"] = True
                if tech_info.get("dangerous"):
                    cve_summary["dangerous"] = True
                if tech_info.get("nse_vulnerabilities"):
                    cve_summary["nse_vulnerabilities"] = tech_info["nse_vulnerabilities"]
                
                all_cves.append(cve_summary)
    
    # 통계 출력
    stats = nvd_client.get_stats()
    logger.info(f"CVE search completed. Stats: {stats}")
    
    return all_cves



# ========================================
# 라우트
# ========================================


@bp.route("/")
def index():
    """대시보드 페이지"""
    return render_template("dashboard.html")



@bp.route("/api/scan", methods=["POST"])
def api_scan():
    """통합 스캔 API"""
    data = request.get_json() or {}
    target = data.get("target")
    
    if not target:
        return jsonify({"error": "target is required"}), 400
    
    # localhost를 127.0.0.1로 변환
    if "localhost" in target.lower():
        target = target.lower().replace("localhost", "127.0.0.1")
        logger.info(f"[DEBUG] Converted target to: {target}")
    
    # 비동기 실행
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        result = loop.run_until_complete(async_scan_workflow(target))
        return jsonify(result)
    except Exception as e:
        logger.exception(f"Scan failed: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        loop.close()

async def search_cves_for_technologies(
    technologies: List[Dict[str, Any]],
    nvd_client,
    cache_manager
) -> List[Dict[str, Any]]:
    """
    기술 정보 리스트에서 CVE 검색
    """
    all_cves = []
    
    print(f"\n[CVE-SEARCH] Starting CVE search for {len(technologies)} technologies...")
    logger.info(f"[CVE-SEARCH] Starting CVE search for {len(technologies)} technologies")
    
    for idx, tech in enumerate(technologies, 1):
        product = tech.get("product", "")
        version = tech.get("version", "")
        cpe = tech.get("cpe", "")
        filtered = tech.get("filtered", False)  # 🆕 필터링 여부 확인
        
        print(f"[CVE-SEARCH] [{idx}/{len(technologies)}] Searching: {product} v{version}")
        logger.info(f"[CVE-SEARCH] [{idx}/{len(technologies)}] Product: {product}, Version: {version}")
        
        if not product:
            print(f"[CVE-SEARCH] ⚠️ Skipping (no product name)")
            logger.warning(f"[CVE-SEARCH] Skipping empty product")
            continue
        
        # 🆕 필터링된 항목은 CVE 검색 건너뛰기
        if filtered:
            print(f"[CVE-SEARCH] ⚠️ Skipping filtered product: {product}")
            logger.info(f"[CVE-SEARCH] Skipping filtered: {product}")
            continue
        
        try:
            # CPE가 있으면 CPE로 검색, 없으면 키워드 검색
            if cpe:
                print(f"[CVE-SEARCH]   Using CPE: {cpe}")
                logger.info(f"[CVE-SEARCH]   CPE: {cpe}")
                
                # 캐시 확인
                cached = cache_manager.get(cpe)
                if cached is not None:
                    print(f"[CVE-SEARCH]   ✓ Cache hit: {len(cached)} CVEs")
                    logger.info(f"[CVE-SEARCH]   Cache hit: {len(cached)} CVEs")
                    cves = cached
                else:
                    # NVD API 호출
                    cves = await nvd_client.search_cves_by_cpe(cpe, max_results=100)
                    
                    print(f"[CVE-SEARCH]   ✓ API returned: {len(cves)} CVEs")
                    logger.info(f"[CVE-SEARCH]   API returned: {len(cves)} CVEs")
                    
                    # 캐시 저장
                    if cves:
                        cache_manager.set(cpe, cves)
            else:
                # 🆕 CPE 없으면 건너뛰기 (키워드 검색 하지 않음)
                print(f"[CVE-SEARCH]   ⚠️ No CPE, skipping CVE search for: {product}")
                logger.info(f"[CVE-SEARCH]   No CPE: {product}")
                continue
            
            # CVE 요약 정보 생성
            for cve_raw in cves:
                cve_summary = extract_cve_summary(cve_raw)
                
                # 기술 정보 추가
                cve_summary["host_ip"] = tech.get("host_ip", "N/A")
                cve_summary["port"] = tech.get("port", "N/A")
                cve_summary["service"] = tech.get("service", product)
                cve_summary["product"] = product
                cve_summary["version"] = version
                cve_summary["source"] = tech.get("source", "unknown")
                
                # 추가 플래그
                if tech.get("anonymous_access"):
                    cve_summary["anonymous_access"] = True
                if tech.get("dangerous"):
                    cve_summary["dangerous"] = True
                if tech.get("nse_vulnerabilities"):
                    cve_summary["nse_vulnerabilities"] = tech.get("nse_vulnerabilities")
                
                all_cves.append(cve_summary)
        
        except Exception as e:
            print(f"[CVE-SEARCH] ❌ Error searching CVEs for {product}: {e}")
            logger.exception(f"[CVE-SEARCH] Exception for {product}: {e}")
            continue
    
    print(f"\n[CVE-SEARCH] ✅ Total CVEs found: {len(all_cves)}")
    logger.info(f"[CVE-SEARCH] Total CVEs found: {len(all_cves)}")
    
    # 중복 제거
    unique_cves = deduplicate_cves(all_cves)
    
    print(f"[CVE-SEARCH] ✅ After deduplication: {len(unique_cves)} unique CVEs")
    logger.info(f"[CVE-SEARCH] After deduplication: {len(unique_cves)} unique CVEs")
    
    return unique_cves

async def async_scan_workflow(target: str):
    """
    통합 취약점 스캔 워크플로우 (최종 완벽 호환 버전)
    - Fix: AI 시나리오를 문자열(text)과 객체(object) 두 가지 형태로 모두 제공
    - Result: 프론트엔드 호환성 100% 보장
    """
    from ..core.recon.network import run_recon
    from ..core.recon.web import collect_web_info
    from ..core.cve.cpe_generator import batch_generate_cpes
    from ..core.cve.async_nvd_client import AsyncNvdClient
    from ..core.verifier import VulnerabilityVerifier
    from ..core.scenario.generator import call_ollama 
    from ..utils.exploit import search_exploits_for_cves
    from ..core.scanner.zap_scanner import ZapScanner, format_alerts_for_dashboard
    import json
    
    cache_manager = get_cache_manager()
    
    # CVE 매처 가져오기
    search_cves_func = None
    try:
        from ..core.cve.matcher import search_cves_for_technologies
        search_cves_func = search_cves_for_technologies
    except ImportError:
        try:
            from ..core.cve.matcher import search_cves_universal
            search_cves_func = search_cves_universal
        except ImportError:
            logger.warning("CVE Matcher functions not found!")

    logger.info("="*70)
    logger.info(f"WORKFLOW: Starting comprehensive scan for {target}")

    # ========== Step 1: Nmap 스캔 ==========
    print(f"WORKFLOW: Step 1 - Running Nmap scan on {target}...")
    recon_result = run_recon(target)
    print(f"WORKFLOW: Found {len(recon_result)} hosts")

    # ========== Step 2: Web Recon ==========
    print(f"WORKFLOW: Step 2 - Running web reconnaissance...")
    web_info = {}
    try:
        web_info = collect_web_info(target)
        print(f"WORKFLOW: Web recon completed")
    except Exception:
        pass

    # ========== Step 3: 인프라 (안전 모드) ==========
    print(f"WORKFLOW: Step 3 - Infrastructure info...")
    cloud_info = {}
    try:
        from ..core.recon.cloud import discover_cloud_assets
        cloud_info = discover_cloud_assets(target)
    except Exception:
        pass

    # ========== Step 4: CPE 생성 ==========
    print(f"WORKFLOW: Step 4 - Generating CPE identifiers...")
    technologies_with_cpe = []
    
    if isinstance(recon_result, list):
        for host in recon_result:
            for port in host.get("ports", []):
                tech = {
                    "product": port.get("product", "unknown"),
                    "version": port.get("version", ""),
                    "service": port.get("service", "unknown"),
                    "port": port.get("port"),
                    "ip": host.get("ip"),
                    "source": "nmap",
                    "category": "detected"
                }
                technologies_with_cpe.append(tech)
    
    if web_info and 'webtechnologies' in web_info:
        for tech_info in web_info['webtechnologies']:
            tech = {
                'product': tech_info.get('name', tech_info.get('product', 'unknown')),
                'version': tech_info.get('version', ''),
                'service': 'web',
                'source': 'web_recon',
                'category': 'other'
            }
            technologies_with_cpe.append(tech)

    technologies_with_cpe = batch_generate_cpes(technologies_with_cpe)
    cpe_techs = [t for t in technologies_with_cpe if t.get("cpe")]
    print(f"WORKFLOW: Generated CPE for {len(cpe_techs)} technologies")

    # ========== Step 5: CVE 검색 ==========
    print(f"WORKFLOW: Step 5 - Searching for CVEs...")
    nvd_client = AsyncNvdClient(
        api_key=current_app.config.get("NVD_API_KEY"),
        base_url=current_app.config.get("NVD_BASE_URL")
    )
    all_cves = []
    
    if search_cves_func:
        print(f"WORKFLOW: Searching CVEs for {len(cpe_techs)} technologies...")
        for tech in cpe_techs:
            prod = tech.get('product')
            ver = tech.get('version')
            try:
                cves = await search_cves_func(
                    prod, 
                    ver,
                    nvd_client=nvd_client,
                    cache_manager=cache_manager
                )
                if cves: 
                    all_cves.extend(cves)
            except Exception:
                pass 

    unique_cves = {}
    for cve in all_cves:
        if cve and isinstance(cve, dict) and cve.get('id'):
            unique_cves[cve.get('id')] = cve
    all_cves = list(unique_cves.values())
    print(f"WORKFLOW: Found {len(all_cves)} CVEs")

    # ========== Step 6.5: ZAP 스캔 ==========
    print(f"WORKFLOW: Step 6.5 - Running OWASP ZAP security scan...")
    zap_alerts = []
    try:
        zap_scanner = ZapScanner(
            api_key=current_app.config.get('ZAP_API_KEY'),
            proxy_host=current_app.config.get('ZAP_PROXY_HOST'),
            proxy_port=current_app.config.get('ZAP_PROXY_PORT')
        )
        scan_result = zap_scanner.full_scan(target)
        if scan_result and 'alerts' in scan_result:
            zap_alerts = format_alerts_for_dashboard(scan_result['alerts'])
    except Exception:
        print("WORKFLOW: ZAP scan skipped")

    # ========== Step 7: 검증 ==========
    print(f"WORKFLOW: Step 7 - Verifying vulnerabilities...")
    verifications = []
    try:
        endpoints = web_info.get('apiendpoints', [])
        verifier = VulnerabilityVerifier(
            target, endpoints, all_cves, technologies_with_cpe
        )
        if hasattr(verifier, 'verify_vulnerabilities'):
            try:
                verifications = verifier.verify_vulnerabilities()
            except TypeError:
                verifications = verifier.verify_vulnerabilities(all_cves, web_info)
        elif hasattr(verifier, 'verify'):
            verifications = verifier.verify()
    except Exception:
        pass

    # ========== Step 8: 익스플로잇 ==========
    print(f"WORKFLOW: Step 8 - Searching for exploits...")
    exploits = []
    try:
        exploits = search_exploits_for_cves(all_cves)
        print(f"WORKFLOW: Found {len(exploits)} exploits")
    except Exception:
        pass

    # ========== Step 9: AI 시나리오 (객체 호환성 강화) ==========
    print(f"WORKFLOW: Step 9 - Generating AI-powered attack scenario...")
    scenario_text = ""
    scenario_object = {} # 프론트엔드를 위한 객체 형태
    
    try:
        prompt_lines = [f"Analyze the security posture of {target}."]
        
        if technologies_with_cpe:
            tech_names = [t.get('product', 'unknown') for t in technologies_with_cpe]
            prompt_lines.append(f"\nDetected Technologies: {', '.join(set(tech_names))}")
            
        if all_cves:
            prompt_lines.append(f"\nCritical Vulnerabilities ({len(all_cves)} found):")
            sorted_cves = sorted(all_cves, key=lambda x: float(x.get('cvss', 0) or 0), reverse=True)
            for cve in sorted_cves[:5]:
                cve_id = cve.get('id', 'Unknown')
                desc = cve.get('description', '')[:100].replace('\n', ' ')
                prompt_lines.append(f"- {cve_id}: {desc}...")

        prompt_lines.append("\nBased on this, create a short penetration testing scenario.")
        final_prompt = "\n".join(prompt_lines)
        
        print("WORKFLOW: Calling Ollama API...")
        try:
            scenario_text = call_ollama(final_prompt)
        except Exception:
            # Ollama 호출 실패 시 기본 텍스트 제공 (프로그램 죽지 않게)
            scenario_text = f"**Attack Scenario for {target}**\n\n"
            scenario_text += f"1. **Reconnaissance**: Discovered {len(technologies_with_cpe)} technologies.\n"
            scenario_text += f"2. **Vulnerability Analysis**: Identified {len(all_cves)} potential vulnerabilities.\n"
            scenario_text += f"3. **Exploitation**: Found {len(exploits)} public exploits.\n\n"
            scenario_text += "*(Note: AI generation service is currently unavailable, this is a generated summary)*"

        # ⭐ 중요: 프론트엔드가 객체를 원할 경우를 대비해 구조화된 데이터도 준비
        scenario_object = {
            "title": f"Penetration Test Scenario for {target}",
            "summary": scenario_text[:200] + "...",
            "content": scenario_text,
            "steps": [
                {"step": 1, "name": "Reconnaissance", "details": f"Found {len(technologies_with_cpe)} tech stacks"},
                {"step": 2, "name": "Scanning", "details": f"Detected {len(all_cves)} CVEs"},
                {"step": 3, "name": "Analysis", "details": "High risk vulnerabilities identified"}
            ]
        }
            
        print("WORKFLOW: AI scenario generated successfully")
            
    except Exception as e:
        logger.warning(f"AI generation failed: {e}")
        scenario_text = "AI scenario generation failed."
        scenario_object = {"content": scenario_text}

    logger.info("="*70)
    print("="*70)
    print("WORKFLOW: SCAN COMPLETED")
    
    recon_by_category = {"web": [], "network": [], "os": [], "database": [], "cloud": [], "container": []}
    cves_by_category = {"web": [], "network": [], "os": [], "database": [], "cloud": [], "container": []}
    
    for tech in technologies_with_cpe:
        recon_by_category["web"].append(tech)
    for cve in all_cves:
        cves_by_category["web"].append(cve)

    return {
        "target": target,
        "technologies": technologies_with_cpe,
        "cves": all_cves,
        "zap_alerts": zap_alerts,
        "verifications": verifications,
        "exploits": exploits,
        
        # ⭐ 핵심 수정: 단순 텍스트와 객체 모두 제공 (프론트엔드가 골라 쓸 수 있게) ⭐
        "scenario": scenario_text,          # 1. 예전 방식 (문자열)
        "ai_scenario": scenario_object,     # 2. 새로운 방식 (객체)
        "report_summary": scenario_text,    # 3. 비상용
        
        "recon": {
            "nmap": recon_result,
            "web": web_info,
            "os": {},
            "cloud": cloud_info,
            "by_category": recon_by_category
        },
        "cves_by_category": cves_by_category
    }


@bp.route("/api/cache/stats", methods=["GET"])
def api_cache_stats():
    """캐시 통계 조회"""
    stats = get_cache_manager().get_stats()
    return jsonify(stats)

@bp.route("/api/cache/clear", methods=["POST"])
def api_cache_clear():
    """캐시 초기화"""
    data = request.get_json() or {}
    clear_type = data.get("type", "expired")  # "expired", "all"
    
    cache_mgr = get_cache_manager()
    
    if clear_type == "all":
        cache_mgr.clear_all()
        return jsonify({"message": "All cache cleared"})
    else:
        deleted = cache_mgr.clear_expired()
        return jsonify({"message": f"{deleted} expired entries cleared"})

@bp.route('/api/scan/network', methods=['POST'])
def scan_network():
    """
    네트워크 스캔 API
    
    Request Body:
        network_cidr: "192.168.1.0/24"
        max_concurrent: 5
    """
    data = request.get_json()
    network_cidr = data.get('network_cidr')
    max_concurrent = data.get('max_concurrent', 5)
    
    if not network_cidr:
        return jsonify({"error": "network_cidr is required"}), 400
    
    try:
        # 지연 import로 함수 가져오기
        run_network_scan = get_run_network_scan()
        
        result = run_network_scan(network_cidr, max_concurrent)
        return jsonify(result), 200
    except Exception as e:
        logger.exception(f"Network scan failed: {e}")
        return jsonify({"error": str(e)}), 500


@bp.route('/api/zap_scan', methods=['POST'])
def api_zap_scan():
    """
    OWASP ZAP 스캔 실행 API
    
    Request Body:
        {
            "target": "http://localhost:3000",
            "run_spider": true,
            "run_active": true,
            "risk_levels": ["High", "Medium"],
            "zap_api_key": "change-me-9203935709",
            "zap_host": "127.0.0.1",
            "zap_port": 8080
        }
    
    Response:
        {
            "status": "success",
            "target": "http://localhost:3000",
            "spider_result": {...},
            "active_scan_result": {...},
            "alerts": [...],
            "summary": {
                "total_alerts": 15,
                "high": 3,
                "medium": 8,
                "low": 4
            }
        }
    """
    try:
        data = request.get_json() or {}
        target = data.get('target')
        
        if not target:
            return jsonify({'error': 'target URL is required'}), 400
        
        # ZAP 설정
        zap_api_key = data.get('zap_api_key', 'change-me-9203935709')
        zap_host = data.get('zap_host', '127.0.0.1')
        zap_port = data.get('zap_port', 8080)
        
        # 스캔 옵션
        run_spider = data.get('run_spider', True)
        run_active = data.get('run_active', True)
        risk_levels = data.get('risk_levels', ['High', 'Medium'])
        
        logger.info(f"ZAP Scan requested for target: {target}")
        
        # ZAP Scanner 초기화
        from ..core.scanner.zap_scanner import ZapScanner
        
        scanner = ZapScanner(
            api_key=zap_api_key,
            proxy_host=zap_host,
            proxy_port=zap_port,
            timeout=600  # 10분
        )
        
        # 전체 스캔 실행
        result = scanner.full_scan(
            target_url=target,
            run_spider=run_spider,
            run_active=run_active,
            risk_levels=risk_levels
        )
        
        if 'error' in result:
            return jsonify({
                'status': 'error',
                'message': result['error'],
                'result': result
            }), 500
        
        return jsonify({
            'status': 'success',
            'result': result
        })
        
    except Exception as e:
        logger.exception(f"ZAP scan failed: {e}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/zap_alerts', methods=['GET'])
def api_zap_alerts():
    """
    ZAP Alert 조회 API (스캔 후 별도 조회)
    
    Query Parameters:
        ?base_url=http://localhost:3000&risk_levels=High,Medium
    
    Response:
        {
            "alerts": [...],
            "total": 15,
            "by_risk": {...}
        }
    """
    try:
        base_url = request.args.get('base_url')
        risk_levels_str = request.args.get('risk_levels', 'High,Medium')
        risk_levels = [r.strip() for r in risk_levels_str.split(',')]
        
        from ..core.scanner.zap_scanner import ZapScanner, format_alerts_for_dashboard
        
        scanner = ZapScanner()
        alerts = scanner.get_alerts(base_url=base_url, risk_levels=risk_levels)
        
        formatted = format_alerts_for_dashboard(alerts)
        
        return jsonify({
            'status': 'success',
            'alerts': alerts,
            'formatted': formatted
        })
        
    except Exception as e:
        logger.exception(f"Failed to fetch ZAP alerts: {e}")
        return jsonify({'error': str(e)}), 500
    
# ==========================================
# routes.py에 추가할 코드
# ==========================================

from flask import jsonify, request
from ..core.recon.web import detectWithHttpHeaders, detectJavascriptLibraries, collectWebInfo
from ..core.verifier import VulnerabilityVerifier
from ..core.exploit.advanced_verification import AdvancedVerification
import time
import asyncio

@bp.route('/api/deep-fingerprint', methods=['POST'])
async def api_deep_fingerprint():
    """
    Deep Fingerprinting Trace API
    레이어별로 순차적으로 기술을 탐지하고 각 단계의 결과를 반환
    """
    data = request.get_json() or {}
    target = data.get('target')

    if not target:
        return jsonify({'error': 'target is required'}), 400

    try:
        result = {
            'target': target,
            'timestamp': time.time(),
            'layers': []
        }

        # ===================================
        # Layer 1: HTTP Header Analysis
        # ===================================
        layer1_start = time.time()
        logger.info(f"[DEEP-FP] Layer 1: HTTP Header Analysis started for {target}")

        try:
            from ..core.recon.web import analyzehttpheaders
            header_analysis = analyzehttpheaders(target)

            layer1_techs = []
            if header_analysis:
                # Server 헤더 정보
                if 'webserver' in header_analysis and header_analysis['webserver']:
                    layer1_techs.append({
                        'name': header_analysis['webserver'],
                        'confidence': 0.7,
                        'source': 'Server Header',
                        'method': 'HTTP Response Header'
                    })

                # X-Powered-By 정보
                if 'webframework' in header_analysis and header_analysis['webframework']:
                    layer1_techs.append({
                        'name': header_analysis['webframework'],
                        'confidence': 0.8,
                        'source': 'X-Powered-By Header',
                        'method': 'HTTP Response Header'
                    })

                # Programming Language
                if 'programminglanguage' in header_analysis and header_analysis['programminglanguage']:
                    layer1_techs.append({
                        'name': header_analysis['programminglanguage'],
                        'confidence': 0.75,
                        'source': 'X-Powered-By Analysis',
                        'method': 'HTTP Response Header'
                    })

            layer1_duration = time.time() - layer1_start

            result['layers'].append({
                'id': 1,
                'name': 'HTTP Header Analysis',
                'description': 'Basic technology detection from HTTP response headers',
                'duration': round(layer1_duration, 2),
                'technologies': layer1_techs,
                'count': len(layer1_techs),
                'status': 'completed'
            })

            logger.info(f"[DEEP-FP] Layer 1 completed: {len(layer1_techs)} technologies found")

        except Exception as e:
            logger.error(f"[DEEP-FP] Layer 1 failed: {e}")
            result['layers'].append({
                'id': 1,
                'name': 'HTTP Header Analysis',
                'duration': 0,
                'technologies': [],
                'count': 0,
                'status': 'failed',
                'error': str(e)
            })

        # ===================================
        # Layer 2: File Structure & Path Analysis
        # ===================================
        layer2_start = time.time()
        logger.info(f"[DEEP-FP] Layer 2: File Structure Analysis started")

        try:
            from ..core.recon.web import discoverendpointswithffuf, extractversionfromendpoints

            # 중요 경로 탐색
            endpoints = discoverendpointswithffuf(target)

            # 버전 정보 추출
            layer2_techs = extractversionfromendpoints(target, endpoints)

            # 형식 통일
            layer2_formatted = []
            for tech in layer2_techs:
                layer2_formatted.append({
                    'name': tech.get('name', 'Unknown'),
                    'version': tech.get('version', ''),
                    'confidence': 0.85,
                    'source': tech.get('source', 'File Structure'),
                    'method': 'Path Enumeration & File Analysis'
                })

            layer2_duration = time.time() - layer2_start

            result['layers'].append({
                'id': 2,
                'name': 'File Structure & Path Analysis',
                'description': 'Deep analysis of file paths, package.json, version endpoints',
                'duration': round(layer2_duration, 2),
                'technologies': layer2_formatted,
                'endpoints_discovered': len(endpoints),
                'count': len(layer2_formatted),
                'status': 'completed'
            })

            logger.info(f"[DEEP-FP] Layer 2 completed: {len(layer2_formatted)} technologies found")

        except Exception as e:
            logger.error(f"[DEEP-FP] Layer 2 failed: {e}")
            result['layers'].append({
                'id': 2,
                'name': 'File Structure & Path Analysis',
                'duration': 0,
                'technologies': [],
                'count': 0,
                'status': 'failed',
                'error': str(e)
            })

        # ===================================
        # Layer 3: Deep Verification
        # ===================================
        layer3_start = time.time()
        logger.info(f"[DEEP-FP] Layer 3: Deep Verification started")

        try:
            # 모든 기술 정보 수집
            all_techs = []
            for layer in result['layers']:
                if layer['status'] == 'completed':
                    all_techs.extend(layer['technologies'])

            # VulnerabilityVerifier를 사용한 검증
            verifier = VulnerabilityVerifier(
                targeturl=target,
                endpoints=[],
                cves=[],
                technologies=all_techs
            )

            # 서버 컨텍스트 탐지
            server_context = verifier.detectServerContext()

            layer3_techs = []

            # 검증된 OS 정보
            if server_context.get('os') != 'unknown':
                layer3_techs.append({
                    'name': server_context['os'].upper(),
                    'category': 'Operating System',
                    'confidence': 0.95,
                    'source': 'Context-Aware Detection',
                    'method': 'Multi-Source Verification',
                    'verified': True
                })

            # 검증된 웹서버 정보
            if server_context.get('webserver') != 'unknown':
                layer3_techs.append({
                    'name': server_context['webserver'].capitalize(),
                    'category': 'Web Server',
                    'confidence': 0.95,
                    'source': 'Context-Aware Detection',
                    'method': 'Multi-Source Verification',
                    'verified': True
                })

            # 검증된 언어 정보
            if server_context.get('language') != 'unknown':
                layer3_techs.append({
                    'name': server_context['language'].upper(),
                    'category': 'Programming Language',
                    'confidence': 0.95,
                    'source': 'Context-Aware Detection',
                    'method': 'Multi-Source Verification',
                    'verified': True
                })

            layer3_duration = time.time() - layer3_start

            result['layers'].append({
                'id': 3,
                'name': 'Deep Verification',
                'description': 'Context-aware verification using AdvancedVerification engine',
                'duration': round(layer3_duration, 2),
                'technologies': layer3_techs,
                'count': len(layer3_techs),
                'server_context': server_context,
                'status': 'completed'
            })

            logger.info(f"[DEEP-FP] Layer 3 completed: {len(layer3_techs)} verified technologies")

        except Exception as e:
            logger.error(f"[DEEP-FP] Layer 3 failed: {e}")
            result['layers'].append({
                'id': 3,
                'name': 'Deep Verification',
                'duration': 0,
                'technologies': [],
                'count': 0,
                'status': 'failed',
                'error': str(e)
            })

        # ===================================
        # Summary
        # ===================================
        total_duration = time.time() - result['timestamp']
        total_techs = sum(layer['count'] for layer in result['layers'] if layer['status'] == 'completed')

        result['summary'] = {
            'total_duration': round(total_duration, 2),
            'total_technologies': total_techs,
            'layers_completed': sum(1 for layer in result['layers'] if layer['status'] == 'completed'),
            'layers_failed': sum(1 for layer in result['layers'] if layer['status'] == 'failed')
        }

        logger.info(f"[DEEP-FP] Scan completed: {total_techs} technologies in {total_duration:.2f}s")

        return jsonify(result)

    except Exception as e:
        logger.exception(f"[DEEP-FP] Scan failed: {e}")
        return jsonify({'error': str(e)}), 500
```
---

## File 86: collect_project_code.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\collect_project_code.py`

```python
import os
import json
from pathlib import Path
from datetime import datetime

class ProjectCodeCollector:
    def __init__(self, project_root, output_dir="code_collection", max_chars_per_file=50000):
        """
        프로젝트 코드를 수집하고 분할하여 저장하는 클래스
        
        Args:
            project_root: 프로젝트 루트 디렉터리 경로
            output_dir: 출력 디렉터리 이름
            max_chars_per_file: 파일당 최대 문자 수 (기본 5만자 - 더 잘게 나누기)
        """
        self.project_root = Path(project_root)
        self.output_dir = Path(output_dir)
        self.max_chars_per_file = max_chars_per_file
        
        # 확장자 → 언어 매핑
        self.extension_to_lang = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'jsx',
            '.tsx': 'tsx',
            '.html': 'html',
            '.htm': 'html',
            '.css': 'css',
            '.scss': 'scss',
            '.sass': 'sass',
            '.less': 'less',
            '.json': 'json',
            '.jsonc': 'json',
            '.yml': 'yaml',
            '.yaml': 'yaml',
            '.sql': 'sql',
            '.sh': 'bash',
            '.bash': 'bash',
            '.md': 'markdown',
            '.mdx': 'markdown',
            '.txt': '',
            '.xml': 'xml',
            '.java': 'java',
            '.cpp': 'cpp',
            '.c': 'c',
            '.go': 'go',
            '.rs': 'rust',
            '.rb': 'ruby',
            '.php': 'php',
            '.swift': 'swift',
            '.kt': 'kotlin',
            '.cs': 'csharp',
        }
        
        # 수집할 파일 확장자 - 핵심 코드만!
        self.include_extensions = {
            '.py', '.js', '.html', '.css',  # 웹 개발 핵심
            '.json', '.yml', '.yaml',        # 설정 파일
        }

        
        # 제외할 디렉터리
        self.exclude_dirs = {
            '__pycache__', 'node_modules', '.git',
            'venv', 'env', '.venv', 'dist', 'build',
            '.next', '__MACOSX', '.cache', '.pytest_cache'
        }
        
        # 제외할 파일
        self.exclude_files = {
            '.pyc', '.db', '.zip', '.exe', '.bin'
        }

    def should_include_file(self, file_path):
        """파일을 포함할지 결정"""
        # 확장자 확인
        if file_path.suffix not in self.include_extensions:
            return False
        
        # 제외 파일 확인
        if any(file_path.name.endswith(ext) for ext in self.exclude_files):
            return False
        
        # 경로에 제외 디렉터리 포함 여부 확인
        if any(excluded in file_path.parts for excluded in self.exclude_dirs):
            return False
        
        return True

    def collect_files(self):
        """프로젝트의 모든 파일 수집"""
        files_data = []
        for file_path in self.project_root.rglob('*'):
            if file_path.is_file() and self.should_include_file(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    relative_path = file_path.relative_to(self.project_root)
                    files_data.append({
                        'path': str(relative_path),
                        'content': content,
                        'size': len(content),
                        'extension': file_path.suffix
                    })
                    print(f"✓ 수집: {relative_path} ({len(content):,} chars)")
                except Exception as e:
                    print(f"✗ 오류: {file_path} - {str(e)}")
        
        return files_data

    def create_output_content(self, files_data, start_idx, end_idx, part_num):
        """출력 파일 내용 생성 - 코드 블록 포맷 적용"""
        content_parts = []
        
        # 헤더
        content_parts.append("=" * 80)
        content_parts.append(f"프로젝트 코드 수집 - Part {part_num}")
        content_parts.append(f"수집 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        content_parts.append(f"파일 범위: {start_idx + 1} ~ {end_idx}")
        content_parts.append("=" * 80)
        content_parts.append("")
        
        # 파일 목록
        content_parts.append("📁 이 파트에 포함된 파일:")
        for i in range(start_idx, end_idx):
            file_info = files_data[i]
            content_parts.append(f" {i+1}. {file_info['path']} ({file_info['size']:,} chars)")
        content_parts.append("")
        content_parts.append("=" * 80)
        content_parts.append("")
        
        # 각 파일의 내용 - 코드 블록으로 감싸기
        for i in range(start_idx, end_idx):
            file_info = files_data[i]
            ext = file_info['extension']
            lang = self.extension_to_lang.get(ext, '')
            
            content_parts.append("")
            content_parts.append("=" * 80)
            content_parts.append(f"파일 경로: {file_info['path']}")
            content_parts.append(f"파일 크기: {file_info['size']:,} characters")
            content_parts.append(f"확장자: {ext} ({lang if lang else '일반 텍스트'})")
            content_parts.append("=" * 80)
            content_parts.append("")
            
            # 코드 블록 시작 - 언어 태그 포함
            if lang:
                content_parts.append(f"```{lang}")
            else:
                content_parts.append("```")
            
            # 코드 내용 (끝의 개행 제거)
            content_parts.append(file_info['content'].rstrip("\n"))
            
            # 코드 블록 끝
            content_parts.append("```")
            content_parts.append("")
            content_parts.append("-" * 80)
            content_parts.append("")
        
        return "\n".join(content_parts)

    def split_and_save(self, files_data):
        """파일 데이터를 분할하여 저장"""
        self.output_dir.mkdir(exist_ok=True)
        
        current_size = 0
        current_files = []
        part_num = 1
        start_idx = 0
        
        for i, file_info in enumerate(files_data):
            # 현재 파일을 추가했을 때 크기 초과 여부 확인
            if current_size + file_info['size'] > self.max_chars_per_file and current_files:
                # 현재까지 모은 파일들을 저장
                self._save_part(files_data, start_idx, i, part_num)
                
                # 초기화
                part_num += 1
                start_idx = i
                current_files = []
                current_size = 0
            
            current_files.append(i)
            current_size += file_info['size']
        
        # 마지막 파트 저장
        if current_files:
            self._save_part(files_data, start_idx, len(files_data), part_num)
        
        return part_num

    def _save_part(self, files_data, start_idx, end_idx, part_num):
        """파트 저장"""
        content = self.create_output_content(files_data, start_idx, end_idx, part_num)
        output_file = self.output_dir / f"project_code_part_{part_num:02d}.txt"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        file_size = len(content)
        print(f"\n💾 저장됨: {output_file.name} ({file_size:,} chars, {end_idx - start_idx} files)")

    def auto_batch_for_upload(self, max_batch_size=10):
        """챗봇 10개 제한을 고려해서 자동 배치 생성"""
        part_files = sorted(self.output_dir.glob("project_code_part_*.txt"))
        
        if not part_files:
            print("⚠️ 배치할 파트 파일이 없습니다.")
            return
        
        print(f"\n📦 총 {len(part_files)}개 파트를 배치로 정리 중...")
        print("=" * 80)
        
        batch_num = 1
        batch_content = []
        part_count = 0
        
        for part_file in part_files:
            with open(part_file, 'r', encoding='utf-8') as f:
                batch_content.append(f.read())
            
            part_count += 1
            
            # max_batch_size개마다 저장
            if part_count >= max_batch_size:
                self._save_batch(batch_content, batch_num, part_count)
                batch_num += 1
                batch_content = []
                part_count = 0
        
        # 남은 파트 저장
        if batch_content:
            self._save_batch(batch_content, batch_num, part_count)
        
        print("=" * 80)
        print(f"✅ 총 {batch_num}개 배치 생성 완료!")
        print(f"💡 upload_batch_*.txt 파일들을 챗봇에 순서대로 업로드하세요!")

    def _save_batch(self, batch_content, batch_num, part_count):
        """배치 저장"""
        batch_text = "\n\n" + "=" * 80 + "\n\n".join(batch_content)
        output_file = self.output_dir / f"upload_batch_{batch_num:02d}.txt"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(batch_text)
        
        file_size = len(batch_text)
        print(f"✅ Batch {batch_num:02d}: {part_count}개 파트 → {output_file.name} ({file_size:,} chars)")

    def create_index_file(self, files_data, total_parts):
        """인덱스 파일 생성"""
        index_content = []
        
        index_content.append("=" * 80)
        index_content.append("프로젝트 코드 수집 인덱스")
        index_content.append(f"생성 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        index_content.append(f"프로젝트 경로: {self.project_root}")
        index_content.append("=" * 80)
        index_content.append("")
        
        # 통계
        index_content.append("📊 수집 통계:")
        index_content.append(f" - 총 파일 수: {len(files_data)}개")
        index_content.append(f" - 총 문자 수: {sum(f['size'] for f in files_data):,}자")
        index_content.append(f" - 분할된 파트 수: {total_parts}개")
        index_content.append(f" - 파트당 최대 크기: {self.max_chars_per_file:,}자")
        index_content.append("")
        
        # 확장자별 통계
        ext_stats = {}
        for file_info in files_data:
            ext = file_info['extension']
            if ext not in ext_stats:
                ext_stats[ext] = {'count': 0, 'size': 0}
            ext_stats[ext]['count'] += 1
            ext_stats[ext]['size'] += file_info['size']
        
        index_content.append("📈 확장자별 통계:")
        for ext, stats in sorted(ext_stats.items()):
            lang = self.extension_to_lang.get(ext, '일반')
            index_content.append(f" {ext:>6} ({lang:12}): {stats['count']:>3}개 파일, {stats['size']:>10,}자")
        index_content.append("")
        
        # 전체 파일 목록
        index_content.append("=" * 80)
        index_content.append("📂 전체 파일 목록:")
        index_content.append("=" * 80)
        for i, file_info in enumerate(files_data, 1):
            ext = file_info['extension']
            lang = self.extension_to_lang.get(ext, '?')
            index_content.append(
                f"{i:3d}. [{lang:>10}] {file_info['path']:<55} {file_info['size']:>8,}자"
            )
        
        # 저장
        index_file = self.output_dir / "INDEX.txt"
        with open(index_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(index_content))
        
        print(f"📋 인덱스 파일 생성: {index_file.name}")

    def run(self):
        """전체 프로세스 실행 - 스마트 분할 + 자동 배치까지!"""
        print("=" * 80)
        print("🚀 프로젝트 코드 수집 시작")
        print("=" * 80)
        print(f"📍 프로젝트 경로: {self.project_root.absolute()}")
        print(f"📁 출력 디렉터리: {self.output_dir}")
        print(f"⚙️  파일당 최대 크기: {self.max_chars_per_file:,}자")
        print("=" * 80)
        print()
        
        # 파일 수집
        print("📥 파일 수집 중...")
        files_data = self.collect_files()
        
        if not files_data:
            print("\n⚠️ 수집된 파일이 없습니다.")
            return
        
        print(f"\n✅ 총 {len(files_data)}개 파일 수집 완료")
        print(f"📊 총 {sum(f['size'] for f in files_data):,}자")
        
        # 파일 분할 및 저장
        print("\n💾 파일 분할 및 저장 중...")
        total_parts = self.split_and_save(files_data)
        
        # 인덱스 파일 생성
        self.create_index_file(files_data, total_parts)
        
        # 자동 배치 생성 (스마트 분할!)
        self.auto_batch_for_upload(max_batch_size=10)
        
        print("\n" + "=" * 80)
        print("✨ 코드 수집 완료!")
        print("=" * 80)
        print(f"📁 출력 디렉터리: {self.output_dir.absolute()}")
        print(f"📄 생성된 파일:")
        print(f"   - {total_parts}개 파트 파일 (project_code_part_*.txt)")
        print(f"   - N개 배치 파일 (upload_batch_*.txt) ← 이것들을 챗봇에 올리세요!")
        print(f"   - 1개 인덱스 파일 (INDEX.txt)")
        print("\n💡 각 파일은 코드 블록(```언어)으로 감싸져 있어 챗봇이 쉽게 인식합니다!")
        print("=" * 80)


if __name__ == "__main__":
    # 현재 스크립트가 있는 위치를 프로젝트 루트로 자동 설정
    PROJECT_ROOT = Path(__file__).parent
    
    # 수집기 생성 (파일당 5만자로 제한 - 더 잘게 나눔)
    collector = ProjectCodeCollector(
        project_root=PROJECT_ROOT,
        output_dir="code_collection",
        max_chars_per_file=50000  # 5만자 = 약 25-50KB 텍스트 (개선됨)
    )
    
    # 실행 (수집 → 분할 → 배치 모두 자동!)
    collector.run()
```
---

## File 87: patch_backend.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\patch_backend.py`

```python
import os

target_file = 'app/core/recon/web.py' # 파일 경로가 다르면 수정하세요
if not os.path.exists(target_file):
    print(f"Error: {target_file} not found.")
    exit(1)

with open(target_file, 'r', encoding='utf-8') as f:
    content = f.read()

# 데이터를 정제하고 병합하는 신규 로직 정의
new_logic = """
def refine_tech_data(raw_results):
    merged = {}
    for item in raw_results:
        # 1. 이름과 버전 정제 (v 제거 및 분리)
        name = str(item.get('name', '')).lower().strip()
        ver = str(item.get('version', '')).replace('v', '').strip()
        source = item.get('source', 'Unknown')
        
        if ':' in name:
            name, ver = name.split(':', 1)
        elif '/' in name:
            name, ver = name.split('/', 1)
            
        if not ver or ver.lower() == 'unknown':
            ver = "Unknown"

        # 2. 기술명 기준으로 데이터 통합
        if name not in merged:
            merged[name] = {
                "name": name,
                "version": ver,
                "sources": [source],
                "evidences": {source: item.get('raw_data', f"Detected via {source}")}
            }
        else:
            if merged[name]["version"] == "Unknown" and ver != "Unknown":
                merged[name]["version"] = ver
            if source not in merged[name]["sources"]:
                merged[name]["sources"].append(source)
                merged[name]["evidences"][source] = item.get('raw_data', f"Confirmed via {source}")
    
    return list(merged.values())
"""

# 기존 collect_web_info 함수 등의 반환 직전에 refine_tech_data 적용 로직 추가
# (이 부분은 기존 코드 구조에 따라 수동 조정이 필요할 수 있으나, 일단 로직 파일만 생성)
with open('app/core/recon/refine_logic.py', 'w', encoding='utf-8') as f:
    f.write(new_logic)

print("✅ 정제 로직 파일(refine_logic.py)이 생성되었습니다.")
```
---

## File 88: update_cpes.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\recog\update_cpes.py`

```python
#!/usr/bin/env python

import logging
import re
import sys

import yaml
from lxml import etree

BASE_LOG_FORMAT = '%(levelname)s: %(message)s'

# CPE w/o 2.3 component: cpe:/a:nginx:nginx:0.1.0"
REGEX_CPE = re.compile('^cpe:/([aho]):([^:]+):([^:]+)')
# CPE w/  2.3 component: cpe:2.3:a:f5:nginx:0.1.0:*:*:*:*:*:*:*
REGEX_CPE_23 = re.compile('^cpe:2.3:([aho]):([^:]+):([^:]+)')

XML_PATH_DEPRECATED_BY = "./{http://scap.nist.gov/schema/cpe-extension/2.3}cpe23-item/{http://scap.nist.gov/schema/cpe-extension/2.3}deprecation/{http://scap.nist.gov/schema/cpe-extension/2.3}deprecated-by"

# Percent-encoded character decode dict
PERCENT_DECODE = {
    '%21': '!',
    '%22': '\"',
    '%23': '#',
    '%24': '$',
    '%25': '%',
    '%26': '&',
    '%27': '\'',
    '%28': '(',
    '%29': ')',
    '%2a': '*',
    '%2b': '+',
    '%2c': ',',
    '%2f': '/',
    '%3a': ':',
    '%3b': ';',
    '%3c': '<',
    '%3d': '=',
    '%3e': '>',
    '%3f': '?',
    '%40': '@',
    '%5b': '[',
    '%5c': '\\',
    '%5d': ']',
    '%5e': '^',
    '%60': '`',
    '%7b': '{',
    '%7c': '|',
    '%7d': '}',
    '%7e': '~'
}

# Percent-encode character dict created from the decode dict
PERCENT_ENCODE = dict([(v, k) for k, v in PERCENT_DECODE.items()])

# Percent decode and encode regex patterns created by joining translation dictionary keys with regex OR
PERCENT_DECODE_PATTERN = re.compile('|'.join(PERCENT_DECODE))
PERCENT_ENCODE_PATTERN = re.compile('|'.join(list(map(re.escape, PERCENT_DECODE.values()))))

# Regex pattern used to check for interpolation markers
INTERPOLATION_PATTERN = re.compile(r'.*\{[^\s]+\}.*')


def repl_dict(pattern, d, s):
    """Performs regex replacement in string s by matching the pattern created from the translation
    dictionary d
    Args:
        pattern (re.Pattern): regex to match the key values in the translation dictionary d
        d (dict): translation dictionary where the key is the value to match and the value the replacement
        s (str): input string to process for replacements

    Returns:
        str, input string processed for replacements
    """
    # use lambda as repl function to lookup replacement value based on match
    return pattern.sub(lambda m: d[m.group()], s)


def parse_r7_remapping(file):
    with open(file) as remap_file:
        return yaml.safe_load(remap_file)["mappings"]


def update_vp_map(target_map, cpe_type, vendor, product):
    """Add an entry to the dict tracking valid combinations
    """

    if cpe_type not in target_map:
        target_map[cpe_type] = {}

    if vendor not in target_map[cpe_type]:
        target_map[cpe_type][vendor] = set()

    target_map[cpe_type][vendor].add(product)


def update_deprecated_map(target_map, dep_string, entry):
    """Add an entry to the dict tracking deprecations

    target_map example:

    {
      "a:100plus:101eip":
        {
          "deprecated_date": "2021-06-10T15:28:05.490Z",
          "deprecated_by": "a:hundredplus:101eip"
        }
    }

    Args:
        target_map (dict): dict containing deprecations
        dep_string (str): key to add in the format of 'type:vendor:product'
        entry (lxml.etree._Element): XML element to pull additional data from

    Returns:
        None, target_map modified in place
    """

    deprecated_date = entry.get("deprecation_date", "")

    # Find the CPE that deprecated this entry
    raw_dep_by = entry.find(XML_PATH_DEPRECATED_BY).get('name')

    # Extract the type, vendor, product
    dep_by_match = REGEX_CPE_23.match(raw_dep_by)
    if not dep_by_match:
        logging.error("CPE %s is deprecated but we can't build the deprecation mapping entry for some reason.", dep_string)
        return

    dep_type, dep_vendor, dep_product = dep_by_match.group(1, 2, 3)
    deprecated_by = "{}:{}:{}".format(dep_type, dep_vendor, dep_product)

    if dep_string not in target_map:
        target_map[dep_string] = {}

    if not target_map[dep_string].get('deprecated_date'):
        target_map[dep_string]['deprecated_date'] = deprecated_date

    if not target_map[dep_string].get('deprecated_by'):
        target_map[dep_string]['deprecated_by'] = deprecated_by


def parse_cpe_vp_map(file):
    deprecated_map = {}
    vp_map = {} # cpe_type -> vendor -> products

    parser = etree.XMLParser(remove_comments=False)
    doc = etree.parse(file, parser)
    namespaces = {
        'ns':     'http://cpe.mitre.org/dictionary/2.0',
        'meta':   'http://scap.nist.gov/schema/cpe-dictionary-metadata/0.2'
    }
    for entry in doc.xpath("//ns:cpe-list/ns:cpe-item", namespaces=namespaces):
        cpe_name = entry.get("name")
        if not cpe_name:
            continue

        cpe_match = REGEX_CPE.match(cpe_name)
        if cpe_match:
            cpe_type, vendor, product = cpe_match.group(1, 2, 3)
            # If the entry is deprecated then don't add it to our list of valid
            # CPEs, but instead add it to a list for reference later.
            if entry.get("deprecated"):
                # This will be the key under which we store the deprecation data
                deprecated_string = "{}:{}:{}".format(cpe_type, vendor, product)

                update_deprecated_map(deprecated_map, deprecated_string, entry)
                continue

            update_vp_map(vp_map, cpe_type, vendor, product)

        else:
            logging.error("Unexpected CPE %s", cpe_name)

    return vp_map, deprecated_map


def lookup_cpe(vendor, product, cpe_type, cpe_table, remap, deprecated_map):
    """Identify the correct vendor and product values for a CPE

    This function attempts to determine the correct CPE using vendor and product
    values supplied by the caller as well as a remapping dictionary for mapping
    these values to more correct values used by NIST.

    For example, the remapping might tell us that a value of 'alpine' for the
    vendor string should be 'alpinelinux' instead, or for product 'solaris'
    should be 'sunos'.

    This function should only emit values seen in the official NIST CPE list
    which is provided to it in cpe_table.

    Lookup priority:
    1. Original vendor / product
    2. Original vendor / remap product
    3. Remap vendor / original product
    4. Remap vendor / remap product

    Args:
        vendor (str):  vendor name
        product (str): product name
        cpe_type (str): CPE type - o, a, h, etc.
        cpe_table (dict): dict containing the official NIST CPE data
        remap (dict): dict containing the remapping values
        deprecated_cves (set): set of all deprecated CPEs in the format
            'type:vendor:product'
    Returns:
        success, vendor, product
    """

    if (
        vendor in cpe_table[cpe_type]
        and product in cpe_table[cpe_type][vendor]
    ):
        # Hot path, success with original values
        logging.debug(f"lookup_cpe: Hot path, success with original values; vendor = {vendor}, product = {product}")
        return True, vendor, product

    # Everything else depends on a remap of some sort.
    # get the remappings for this one vendor string.
    vendor_remap = None

    remap_type = remap.get(cpe_type, None)
    if remap_type:
        vendor_remap = remap_type.get(vendor, None)

    if vendor_remap:
        # If we have product remappings, work that angle next
        possible_product = None
        if (
            vendor_remap.get('products', None)
            and product in vendor_remap['products']
        ):
            possible_product = vendor_remap['products'][product]

        if (vendor in cpe_table[cpe_type]
            and possible_product
            and possible_product in cpe_table[cpe_type][vendor]):
            # Found original vendor, remap product
            logging.debug(f"lookup_cpe: Found original vendor, remap product; vendor = {vendor}, possible_product = {possible_product}")
            return True, vendor, possible_product

        # Start working the process to find a match with a remapped vendor name
        if vendor_remap.get('vendor', None):
            new_vendor = vendor_remap['vendor']

            if new_vendor in cpe_table[cpe_type]:

                if product in cpe_table[cpe_type][new_vendor]:
                    # Found remap vendor, original product
                    logging.debug(f"lookup_cpe: Found remap vendor, original product; new_vendor = {new_vendor}, product = {product}")
                    return True, new_vendor, product

                if possible_product and possible_product in cpe_table[cpe_type][new_vendor]:
                    # Found remap vendor, remap product
                    logging.debug(f"lookup_cpe: Found remap vendor, remap product; new_vendor = {new_vendor}, possible_product = {possible_product}")
                    return True, new_vendor, possible_product

    deprecated_string = "{}:{}:{}".format(cpe_type, vendor, product)
    if deprecated_map.get(deprecated_string, False):
        dep_by = deprecated_map[deprecated_string].get("deprecated_by", "")
        dep_date = deprecated_map[deprecated_string].get("deprecated_date", "")
        logging.error("Product %s from vendor %s invalid for CPE %s and no mapping.  This combination is DEPRECATED by %s at %s",
                    product, vendor, cpe_type, dep_by, dep_date)
    else:
        logging.error("Product %s from vendor %s invalid for CPE %s and no mapping.",
                    product, vendor, cpe_type)

    return False, None, None


def update_cpes(xml_file, cpe_vp_map, r7_vp_map, deprecated_cves):
    parser = etree.XMLParser(remove_comments=False, remove_blank_text=True)
    doc = etree.parse(xml_file, parser)

    for fingerprint in doc.xpath('//fingerprint'):

        # collect all the params, grouping by os and service params that could be used to compute a CPE
        params = {}
        for param in fingerprint.xpath('./param'):
            name = param.attrib['name']
            # remove any existing CPE params
            if re.match(r'^.*\.cpe\d{0,2}$', name):
                param.getparent().remove(param)
                continue

            match = re.search(r'^(?P<fp_type>hw|os|service(?:\.component)?)\.', name)
            if match:
                fp_type = match.group('fp_type')
                if not fp_type in params:
                    params[fp_type] = {}
                if name in params[fp_type]:
                    raise ValueError('Duplicated fingerprint named {} in fingerprint {} in file {}'.format(name, fingerprint.attrib['pattern'], xml_file))
                params[fp_type][name] = param

        # for each of the applicable os/service param groups, build a CPE
        for fp_type in params:
            if fp_type == 'os':
                cpe_type = 'o'
            elif fp_type.startswith('service'):
                cpe_type = 'a'
            elif fp_type == 'hw':
                cpe_type = 'h'
            else:
                raise ValueError('Unhandled param type {}'.format(fp_type))

            # extract the vendor/product/version values from each os/service group,
            # using the static value ('Apache', for example) when pos is 0, and
            # otherwise use a value that contains interpolation markers such that
            # products/projects that use recog content can insert the value
            # extracted from the banner/other data via regex capturing groups
            fp_data = {
                'vendor': None,
                'product': None,
                'version': '-',
            }
            for fp_datum in fp_data:
                fp_datum_param_name = "{}.{}".format(fp_type, fp_datum)
                if fp_datum_param_name in params[fp_type]:
                    fp_datum_e = params[fp_type][fp_datum_param_name]
                    if fp_datum_e.attrib['pos'] == '0':
                        fp_data[fp_datum] = fp_datum_e.attrib['value']
                    else:
                        fp_data[fp_datum] = "{{{}}}".format(fp_datum_e.attrib['name'])

            vendor = fp_data['vendor']
            product = fp_data['product']
            version = fp_data['version']

            # build a reasonable looking CPE value from the vendor/product/version,
            # lowercasing, replacing whitespace with _, and more
            if vendor and product:
                if not cpe_type in cpe_vp_map:
                    logging.error("Didn't find CPE type '%s' for '%s' '%s'", cpe_type, vendor, product)
                    continue

                if 'unknown' in [vendor, product]:
                    continue

                if INTERPOLATION_PATTERN.match(vendor) or INTERPOLATION_PATTERN.match(product):
                    continue

                vendor = vendor.lower().replace(' ', '_').replace(',', '')
                product = product.lower().replace(' ', '_').replace(',', '')

                tmp_product = product
                product = repl_dict(PERCENT_ENCODE_PATTERN, PERCENT_ENCODE, product)
                if tmp_product != product:
                    logging.debug(f"update_cpes: percent-encoded product {tmp_product} => {product}")

                success, vendor, product = lookup_cpe(vendor, product, cpe_type, cpe_vp_map, r7_vp_map, deprecated_cves)
                if not success:
                    continue

                # Sanity check the value to ensure that no invalid values will
                # slip in due to logic or mapping bugs.
                # If it's not in the official NIST list then log it and kick it out
                if product not in cpe_vp_map[cpe_type][vendor]:
                    logging.error("Invalid CPE type %s created for vendor %s and product %s. This may be due to an invalid mapping.", cpe_type, vendor, product)
                    continue

                # Create CPE string in URI Binding format value where variables are percent-encoded.
                # Note, this is only a partially complete encoding.
                cpe_value = 'cpe:/{}:{}:{}'.format(cpe_type, vendor, product)

                if version:
                    cpe_value += ":{}".format(version)

                cpe_param = etree.Element('param')
                cpe_param.attrib['pos'] = '0'
                cpe_param.attrib['name'] = '{}.cpe23'.format(fp_type)
                cpe_param.attrib['value'] = cpe_value

                for param_name in params[fp_type]:
                    param = params[fp_type][param_name]
                    parent = param.getparent()
                    index = parent.index(param) + 1
                    parent.insert(index, cpe_param)

    root = doc.getroot()

    with open(xml_file, 'wb') as xml_out:
        xml_out.write(etree.tostring(root, pretty_print=True, xml_declaration=True, encoding=doc.docinfo.encoding))


def main():
    if len(sys.argv) != 4:
        logging.critical("Expecting exactly 3 arguments; recog XML file, CPE 2.3 XML dictionary, JSON remapping, got %s", (len(sys.argv) - 1))
        sys.exit(1)

    cpe_vp_map, deprecated_map = parse_cpe_vp_map(sys.argv[2])
    if not cpe_vp_map:
        logging.critical("No CPE vendor => product mappings read from CPE 2.3 XML dictionary %s", sys.argv[2])
        sys.exit(1)

    r7_vp_map = parse_r7_remapping(sys.argv[3])
    if not r7_vp_map:
        logging.warning("No Rapid7 vendor/product => CPE mapping read from %s", sys.argv[3])

    # update format string for the logging handler to include the recog XML filename
    logging.basicConfig(force=True, format=f"{sys.argv[1]}: {BASE_LOG_FORMAT}")

    update_cpes(sys.argv[1], cpe_vp_map, r7_vp_map, deprecated_map)


if __name__ == '__main__':
    logging.basicConfig(format=BASE_LOG_FORMAT)
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
```
---

## File 89: run.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\run.py`

```python
import eventlet
eventlet.monkey_patch() # 이 코드가 맨 위에 와야 합니다!

from app import create_app, socketio

app, _ = create_app()

if __name__ == "__main__":
    # 포트 5000에서 실행
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
```
---

## File 90: test_scanner.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\test_scanner.py`

```python
# test_scanner.py (최종 수정본)
import sys
import os
import json
import logging

# 현재 작업 디렉토리 추가
current_dir = os.getcwd()
sys.path.insert(0, current_dir)

logging.basicConfig(level=logging.INFO, format='%(message)s') # 로그 포맷 간소화

print(f"[*] Current Directory: {current_dir}")

# 모듈 Import 시도 (가능한 모든 경로 순회)
module_imported = False
try:
    # Case 1: app/core/recon/web.py (가장 유력)
    from app.core.recon.web import detect_with_http_headers, detect_javascript_libraries
    print("[*] Successfully imported from: app.core.recon.web")
    module_imported = True
except ImportError:
    try:
        # Case 2: app/core/scanner/web.py
        from app.core.scanner.web import detect_with_http_headers, detect_javascript_libraries
        print("[*] Successfully imported from: app.core.scanner.web")
        module_imported = True
    except ImportError:
        try:
            # Case 3: core/recon/web.py (app 패키지 내부에서 실행 시)
            from core.recon.web import detect_with_http_headers, detect_javascript_libraries
            print("[*] Successfully imported from: core.recon.web")
            module_imported = True
        except ImportError:
             pass

if not module_imported:
    print("\n[!] Import Error: Could not find 'web.py' module.")
    print("Please verify the file exists at one of these locations:")
    print(f" - {os.path.join(current_dir, 'app/core/recon/web.py')}")
    print(f" - {os.path.join(current_dir, 'app/core/scanner/web.py')}")
    sys.exit(1)

# 테스트 실행 함수
def test_target(url):
    print(f"\n{'='*50}")
    print(f" TARGET: {url}")
    print(f"{'='*50}\n")

    print("[1] JS Library Analysis (BeautifulSoup)...")
    try:
        js_libs = detect_javascript_libraries(url)
        print(json.dumps(js_libs, indent=2))
    except Exception as e:
        print(f"Error: {e}")

    print("\n[2] HTTP & Behavioral Analysis (MMH3/Error Pages)...")
    try:
        headers_tech = detect_with_http_headers(url)
        print(json.dumps(headers_tech, indent=2))
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    target = input("\nEnter Target URL (default: http://testphp.vulnweb.com): ").strip()
    if not target:
        target = "http://testphp.vulnweb.com"
    
    if not target.startswith("http"):
        target = "http://" + target
        
    test_target(target)
```
---

## File 91: test_scanner_unified.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\test_scanner_unified.py`

```python
# test_scanner_unified.py 수정본

import sys
import os
import json
import logging

# 1. 경로 설정 (현재 폴더 및 상위 폴더 추가)
current_dir = os.getcwd()
sys.path.insert(0, current_dir)

logging.basicConfig(level=logging.INFO, format='%(message)s')

# 2. TechUnifier Import 시도
try:
    # unifier.py가 app/core/recon/unifier.py에 있다고 가정
    try:
        from app.core.recon.unifier import TechUnifier
    except ImportError:
        # 경로가 안 맞으면 상대 경로 시도
        from core.recon.unifier import TechUnifier
        
    print("[*] Successfully imported TechUnifier")
except ImportError as e:
    print(f"[!] TechUnifier Import Error: {e}")
    sys.exit(1)

# 3. Web Scanner Import 시도 (아까 성공했던 경로 우선)
web_module = None
try:
    # Case 1: app.core.recon.web (아까 성공한 경로!)
    import app.core.recon.web as web_module
    print("[*] Successfully imported web module from app.core.recon.web")
except ImportError:
    try:
        # Case 2: app.core.recon.scanner.web
        import app.core.recon.scanner.web as web_module
        print("[*] Successfully imported web module from app.core.recon.scanner.web")
    except ImportError as e:
        print(f"[!] Web Module Import Error: {e}")
        sys.exit(1)

# 4. 함수 별칭 지정
# web.py에 scan_target_unified 함수를 추가했는지 여부에 따라 처리
if hasattr(web_module, 'scan_target_unified'):
    scan_target_unified = web_module.scan_target_unified
    USE_INTERNAL_UNIFIER = True
else:
    # 함수를 아직 추가 안 했으면 여기서 직접 Unifier를 쓰도록 설정
    detect_with_http_headers = web_module.detect_with_http_headers
    detect_javascript_libraries = web_module.detect_javascript_libraries
    USE_INTERNAL_UNIFIER = False
    print("[!] scan_target_unified function not found in web.py. Using manual integration.")


def test_unified_scan(url):
    print(f"\n{'='*60}")
    print(f" UNIFIED SCAN TARGET: {url}")
    print(f"{'='*60}\n")
    
    if USE_INTERNAL_UNIFIER:
        # web.py 안에 있는 통합 함수 사용
        results = scan_target_unified(url)
    else:
        # 여기서 직접 통합 로직 실행
        unifier = TechUnifier()
        
        print("[*] Running Header/Behavioral Analysis...")
        # detect_with_http_headers 실행
        h_techs = detect_with_http_headers(url)
        unifier.merge_list(h_techs)
        
        print("[*] Running JS Analysis...")
        # detect_javascript_libraries 실행
        js_techs = detect_javascript_libraries(url)
        # JS 결과 포맷 변환
        for lib in js_techs:
            unifier.add_tech(
                name=lib.get('library'),
                version=lib.get('version'),
                category='javascript_library',
                source=lib.get('source', 'script'),
                confidence=80
            )
            
        results = unifier.get_results(min_confidence=30)
    
    print(f"\n[+] Final Unified Results ({len(results)} found):")
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    target = input("Enter Target URL (default: http://testphp.vulnweb.com): ").strip()
    if not target: target = "http://testphp.vulnweb.com"
    if not target.startswith("http"): target = "http://" + target
    test_unified_scan(target)
```
---

## File 92: test_zap_win.py
**Absolute Path:** `d:\3차 프로젝트\6트\12.26 app\test_zap_win.py`

```python
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.core.scanner.zap_scanner import ZapScanner
import json

print("=" * 70)
print("ZAP Scan (Windows)")
print("=" * 70)

scanner = ZapScanner(
    api_key='change-me-9203935709',
    proxy_host='127.0.0.1',
    proxy_port=8080,
    timeout=600
)

print("스캔 시작...\n")
result = scanner.full_scan(
    target_url='http://localhost:3000',
    run_spider=True,
    run_active=False,
    risk_levels=['High', 'Medium', 'Low', 'Informational']
)

if 'error' not in result:
    summary = result['summary']
    print("\n✓ 스캔 완료!")
    print(f"  - URL: {len(result['spider_result'].get('urls_found', []))}개")
    print(f"  - Alert: {summary.get('total_alerts', 0)}개")
    print(f"  - 🔴 High: {summary.get('high', 0)}개")
    print(f"  - 🟠 Medium: {summary.get('medium', 0)}개")
    print(f"  - 🟡 Low: {summary.get('low', 0)}개")
    
    alerts = result.get('alerts', [])
    for risk in ['High', 'Medium']:
        risk_alerts = [a for a in alerts if a['risk'] == risk]
        if risk_alerts:
            print(f"\n{risk} Alerts:")
            for idx, alert in enumerate(risk_alerts[:10], 1):
                print(f"  [{idx}] {alert['alert']}")
    
    with open('zap_result.json', 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\n💾 결과: zap_result.json")
else:
    print(f"✗ 실패: {result['error']}")
```
---

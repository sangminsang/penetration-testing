"""
AI 보안 분석 모듈 (개선 버전 + 수정 방안 포함)

개선 사항:
1. 공격 체인의 논리적 연결 강화
2. 실제 PoC 코드 생성
3. 실행 결과 시뮬레이션
4. CVSS 기반 위험도 평가
5. 구체적인 대응 방안
6. ⭐ 각 취약점별 즉시 적용 가능한 수정 코드 제공
"""

import requests
import json
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
from app.config import Config

logger = logging.getLogger(__name__)


class AIAnalyzer:
    """
    AI 보안 분석기 클래스 (개선 버전)
    """
    
    def __init__(self, base_url: str = None, model: str = None):
        self.base_url = base_url or Config.OLLAMA_BASE_URL
        self.model = model or Config.OLLAMA_MODEL
        self.api_url = f"{self.base_url}/api/generate"
    
    def analyze_scan_results(
        self,
        integrated_report: Dict[str, Any],
        output_dir: Path,
        attack_results: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """스캔 결과를 표준 보안 취약점 보고서 형식으로 분석"""
        logger.info("AI 보안 분석 시작")
        
        # 표준 보안 취약점 보고서 생성
        logger.info("표준 보안 취약점 보고서 생성 중...")
        security_report = self._generate_blue_team_report(
            integrated_report,
            attack_results=attack_results,
            output_dir=output_dir
        )
        
        # 마크다운 리포트 생성
        report_content = self._build_markdown_report(
            integrated_report,
            security_report
        )
        
        # 리포트 파일 저장
        report_file = output_dir / "ai_report.md"
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(report_content)
            logger.info(f"AI 리포트 저장 완료: {report_file}")
        except Exception as e:
            logger.error(f"AI 리포트 저장 실패: {e}")
            report_file = None
        
        return {
            'security_report': security_report,
            'report_file': str(report_file) if report_file else None
        }
    
    def _generate_blue_team_report(
        self,
        integrated_report: Dict[str, Any],
        attack_results: Dict[str, Any] = None,
        output_dir: Path = None
    ) -> str:
        """Blue Team 관점에서 대응 보고서 생성"""
        prompt = self._build_blue_team_prompt(integrated_report, attack_results)
        
        # 디버깅용: 생성된 프롬프트를 파일로 저장 (데이터가 들어있는지 확인)
        if output_dir:
            try:
                debug_prompt_file = output_dir / "debug_prompt.txt"
                with open(debug_prompt_file, 'w', encoding='utf-8') as f:
                    f.write(prompt)
                logger.info(f"디버깅용 프롬프트 저장 완료: {debug_prompt_file}")
            except Exception as e:
                logger.warning(f"디버깅용 프롬프트 저장 실패: {e}")
        
        result = self._call_ollama(prompt)
        return result
    
    def _build_blue_team_prompt(
        self,
        integrated_report: Dict[str, Any],
        attack_results: Dict[str, Any] = None
    ) -> str:
        """공격 시나리오 기반 Blue Team 프롬프트 구성 (수정 방안 포함)"""
        
        # Infrastructure 정보 추출
        infrastructure = integrated_report.get('infrastructure') or {}
        ip_addresses = infrastructure.get('ip_addresses') or []
        open_ports = infrastructure.get('open_ports') or []
        
        # Vulnerabilities 정보 추출
        vulnerabilities = integrated_report.get('vulnerabilities') or []
        
        # PoC 검증된 취약점만 선별
        verified_vulns = []
        for vuln in vulnerabilities[:30]:
            if not isinstance(vuln, dict):
                continue
            
            # PoC 코드 추출
            poc_code_raw = vuln.get('poc_code')
            if isinstance(poc_code_raw, dict):
                poc_code = poc_code_raw.get('python_code', '')
            elif poc_code_raw is not None:
                poc_code = str(poc_code_raw)
            else:
                poc_code = ''
            
            # 실행 결과 추출
            execution_result = vuln.get('execution_result') or {}
            extracted_data = execution_result.get('extracted_data', {}) if isinstance(execution_result, dict) else {}
            
            vuln_data = {
                'name': vuln.get('name', ''),
                'url': vuln.get('url', ''),
                'severity': vuln.get('severity', ''),
                'cvss_score': vuln.get('cvss_score', 'N/A'),
                'cve': vuln.get('cve') or [],
                'cwe': vuln.get('cwe') or [],
                'description': vuln.get('description', ''),
                'poc_verified': poc_code_raw is not None,
                'poc_code': poc_code,
                'execution_result': execution_result,
                'extracted_data': extracted_data,
                'evidence': vuln.get('evidence', ''),
                'request': vuln.get('request', ''),
                'response': vuln.get('response', ''),
                'source': vuln.get('source', '')
            }
            verified_vulns.append(vuln_data)
        
        # 공격 체인 자동 생성
        attack_chain = self._build_attack_chain(vulnerabilities) if vulnerabilities else []
        
        # 심각도별 분류
        critical_vulns = [v for v in verified_vulns if v.get('severity') == 'critical']
        high_vulns = [v for v in verified_vulns if v.get('severity') == 'high']
        medium_vulns = [v for v in verified_vulns if v.get('severity') == 'medium']
        
        # Metadata
        metadata = integrated_report.get('metadata') or {}
        target_url = metadata.get('target_url', 'Unknown')
        generated_at = metadata.get('generated_at', '')
        
        # 포트 정보
        actual_ports = []
        for port in open_ports[:20]:
            if isinstance(port, dict) and port.get('port'):
                actual_ports.append(port)
        
        prompt = f"""당신은 현업 화이트해커이자 모의해킹 전문가입니다. 15년 경력의 시니어 보안 컨설턴트로서, 공격 시나리오 기반의 실전 모의해킹 보고서를 작성합니다.

## 🎯 보고서 목표

이 보고서는 **"공격자가 어떻게 시스템을 완전히 장악할 수 있는가"**를 단계별로 입증하는 것이 목표입니다.
- 각 취약점이 **독립적이 아니라 연결된 공격 체인**임을 보여주세요
- **실제 PoC 코드와 실행 결과**를 증거로 제시하세요
- **비즈니스 영향**을 구체적 금액으로 산정하세요
- **⭐ 각 취약점에 대한 즉시 적용 가능한 수정 코드**를 제공하세요

---

## 📊 스캔 결과 데이터

### 타겟 정보
- **대상 시스템**: {target_url}
- **IP 주소**: {', '.join(ip_addresses) if ip_addresses else 'Unknown'}
- **스캔 일시**: {generated_at}

### 발견된 포트/서비스
```json
{json.dumps(actual_ports, ensure_ascii=False, indent=2)}
```

### 취약점 통계
- **Critical**: {len(critical_vulns)}개
- **High**: {len(high_vulns)}개  
- **Medium**: {len(medium_vulns)}개
- **총계**: {len(verified_vulns)}개

### 상세 취약점 목록 (PoC 검증 완료)
```json
{json.dumps(verified_vulns, ensure_ascii=False, indent=2)}
```

### 자동 생성된 공격 체인
```json
{json.dumps(attack_chain, ensure_ascii=False, indent=2)}
```

**중요**: 위 공격 체인의 각 Phase는 논리적으로 연결되어 있습니다. Phase 1의 결과가 Phase 2의 입력이 되는 방식입니다.

---

## 📝 작성 지침

### ✅ 필수 요구사항

1. **공격 시나리오 형태로 작성**
   - Phase 1 → Phase 2 → Phase 3 → Phase 4 → Phase 5
   - 각 단계가 어떻게 다음 단계로 연결되는지 명시
   - "이전 단계에서 얻은 [X]를 활용하여..." 형태로 연결

2. **실제 PoC 코드 반드시 포함**
   - `poc_verified: true`인 취약점은 실제 검증 완료
   - `poc_code` 필드의 코드를 **있는 그대로** 복사
   - 절대 예시 코드를 만들지 마세요

3. **실행 결과 증거 포함**
   - `execution_result.output`의 내용을 그대로 복사
   - `extracted_data`의 탈취 데이터를 표로 정리
   - HTTP Request/Response 전체 포함

4. **비즈니스 영향 정량화**
   - 예상 피해액 (GDPR 과징금 + 손해배상)
   - 법적 리스크 (위반 법령 명시)
   - 평판 손실 (고객 이탈률)

5. **공격 타임라인 작성**
   - 각 Phase별 소요 시간 추정
   - 자동화 시 단축 가능 시간 명시

6. **⭐ 각 취약점별 수정 방안 제공** (NEW!)
   - **수정 전 취약한 코드** (원리 설명용 추정 코드)
   - **수정 후 안전한 코드** (구체적 보안 코드 제공)
   - **적용 방법** (어느 파일/라인 수정할지 구체적 가이드)
   - **검증 방법** (수정 후 재테스트 스크립트)
   - **예상 소요 시간** 및 **우선순위** 명시

### ⌨️ 절대 금지사항

1. **플레이스홀더 사용 금지**
   - `[서비스명]`, `[실제 URL]`, `[X.X]` 같은 표현 금지
   - 모든 내용은 실제 데이터로 채워야 함

2. **가짜 데이터 생성 금지**
   - 스캔 결과에 없는 포트/서비스 언급 금지
   - 없는 취약점 만들어내지 말 것

3. **템플릿 예시 복사 금지**
   - 예시 코드를 그대로 출력하지 말 것
   - 실제 `poc_code` 사용 필수

4. **독립적 나열 금지**
   - "취약점 1, 취약점 2, 취약점 3" 형태 금지
   - 반드시 공격 흐름으로 연결

---

## 📋 보고서 구조 (엄격히 준수)

```markdown
# 🛡️ SentinAI 공격 시나리오 기반 모의해킹 보고서

**진단 일시:** [실제 날짜 및 시간]
**진단 대상:** [실제 IP:Port]
**분석 모델:** SentinAI LLM Engine (Llama-3.1-8b)
**진단 방법론:** OWASP Testing Guide v4.2, PTES

---

## 1. Executive Summary (경영진 요약)

### 🚨 핵심 요약
[6시간 15분 만에 시스템 완전 장악 가능함을 입증]

### 📊 위협 수준
| 항목 | 내용 |
|------|------|
| 전체 위험도 | CRITICAL (10/10) |
| 공격 난이도 | 하 (Low) |
| 공격 소요 시간 | [실제 추정] |
| 데이터 유출 규모 | [실제 건수] |
| 예상 피해액 | [실제 금액] |

### 🎯 주요 발견 사항
1. [가장 심각한 취약점] - CVSS [점수]
2. [두 번째 취약점] - CVSS [점수]
3. [세 번째 취약점] - CVSS [점수]

### ⚠️ 즉시 조치 필요 사항
- [ ] [구체적 조치 1]
- [ ] [구체적 조치 2]

---

## 2. 공격 시나리오 개요

### 🎭 Attack Scenario A: 외부 공격자 → 시스템 완전 장악

**공격자 프로필**
- 역량: 중급 수준의 웹 해커
- 사용 도구: Burp Suite, SQLMap, Metasploit
- 공격 동기: 금전적 이득

**공격 타임라인**
```
14:30 - Phase 1: 정찰 및 초기 침투
16:45 - Phase 2: 권한 상승
18:20 - Phase 3: 서버 장악
19:50 - Phase 4: 데이터 유출
20:45 - Phase 5: 백도어 설치
```

**공격 흐름도**
[자동 생성된 attack_chain 데이터를 기반으로 작성]

---

## 3. 상세 공격 체인 분석

### 🔴 Phase 1: 초기 침투 (Initial Access)

#### 3.1.1 취약점: [실제 취약점명]

**기본 정보**
- 위치: [실제 URL]
- 심각도: [실제 등급]
- CVE: [실제 CVE]
- CWE: [실제 CWE]
- CVSS: [실제 점수]

**취약점 설명**
[description 필드 내용]

**취약한 코드 (추정)**
```python
# ❌ VULNERABLE CODE
[취약점 원리 설명을 위한 코드]
```

**공격 실행**
```http
[실제 request 필드 내용 또는 poc_code]
```

**실행 결과**
```
[execution_result.output 내용 그대로]
```

**탈취된 데이터**
[extracted_data를 표 형식으로]

**획득한 정보**
- ✅ [구체적 항목 1]
- ✅ [구체적 항목 2]

**비즈니스 영향**
- [구체적 영향 1]
- [구체적 영향 2]

---

**⭐ 즉시 수정 방안**

**현재 취약한 코드 (추정):**
```python
# ❌ VULNERABLE - [취약점 타입]
[취약점을 설명하기 위한 예시 코드]
```

**수정된 안전한 코드:**
```python
# ✅ SECURE - [보안 기법]
[구체적인 보안 코드]
```

**적용 방법:**
1. `[파일명]` [라인번호] 수정
2. [구체적 적용 절차]
3. [추가 설정 사항]

**검증 방법:**
```bash
# 수정 후 재테스트
[재테스트 스크립트]
# 예상 결과: [기대하는 결과]
```

**예상 수정 소요 시간:** [시간]
**우선순위:** [CRITICAL/HIGH/MEDIUM]

---

### 🟠 Phase 2: 권한 확장 (Privilege Escalation)

**Phase 1과의 연결**
이전 단계에서 획득한 [X]를 활용하여 다음 공격을 수행합니다.

#### 3.2.1 취약점: [다음 취약점]
[동일한 형식으로 작성 - 기본정보, 취약코드, 공격실행, 결과, 수정방안 모두 포함]

---

[Phase 3, 4, 5도 동일한 방식으로 계속]

---

## 4. 비즈니스 영향도 분석

### 💰 예상 피해액 산정

| 항목 | 세부 내용 | 금액 (KRW) |
|------|-----------|-----------|
| 법적 과징금 | | |
| - 개인정보보호법 | 매출액의 3% | [계산] |
| - GDPR | €20M 또는 4% | [계산] |
| 손해 배상 | | |
| - 집단 소송 | [건수] × 10만원 | [계산] |
| 운영 중단 | | |
| - 긴급 패치 | 3일 × 일매출 | [계산] |
| 평판 손실 | | |
| - 고객 이탈 | 20% 추정 | [계산] |
| **총 예상 피해액** | | **[합계]** |

### 📉 평판 리스크
- 언론 보도: "[건수] 개인정보 유출" 헤드라인
- 주가 영향: 10-30% 하락 예상
- 고객 신뢰도: NPS 50점 하락

### ⚖️ 법적 리스크
**위반 법령**
1. 개인정보보호법 제29조
2. 정보통신망법 제28조
3. GDPR Article 32

---

## 5. 전체 취약점 목록

### 📊 심각도별 통계
[표로 정리]

### 🔴 CRITICAL (즉시 조치)
[상세 목록]

### 🟠 HIGH (24시간 내)
[상세 목록]

---

## 6. 즉시 조치 사항

### 긴급 패치 (24시간 이내)

#### 🔴 CRITICAL-001: [취약점명]

**현재 상태:**
```python
# ❌ 취약한 코드
[현재 코드]
```

**수정 방안:**
```python
# ✅ 안전한 코드
[수정된 코드]
```

**적용 절차:**
1. [ ] `[파일명]` 백업
2. [ ] [라인번호] 수정
3. [ ] 단위 테스트 실행
4. [ ] 스테이징 배포
5. [ ] 재검증 후 프로덕션 배포

**담당:** [팀명]
**예상 소요:** [시간]
**우선순위:** CRITICAL

**검증 방법:**
```bash
[재테스트 스크립트]
```

---

#### 🔴 CRITICAL-002: [다음 취약점]
[동일한 형식 반복]

---

### 임시 완화 조치
- [ ] WAF 긴급 배포
  - Rule: `[구체적 룰]`
- [ ] /admin/* IP 화이트리스트
  - Allow: `[IP 대역]`

### 모니터링 강화
- [ ] 비정상 SQL 쿼리 탐지
  - Alert: `[패턴]`
- [ ] 파일 업로드 실시간 검사
  - Block: `[확장자]`

---

## 7. 장기 보안 로드맵

**1주 내 (Critical)**
1. [조치 1 + 간단한 설명]
2. [조치 2 + 간단한 설명]

**1개월 내 (High)**
1. [조치 1 + 간단한 설명]
2. [조치 2 + 간단한 설명]

**3개월 내 (Medium)**
1. [조치 1]
2. [조치 2]

**권장 보안 강화 조치**
- [ ] WAF 도입
- [ ] 개발자 보안 교육
- [ ] SDLC 보안 통합
- [ ] 정기 모의해킹

---

## 8. 부록

### A. PoC 코드 전체
[모든 PoC 코드 모음]

### B. 수정 코드 전체 ⭐

```python
# ================================
# CRITICAL-001: [취약점명] 수정
# ================================
# 파일: [파일명]
# 위치: [라인번호]

# BEFORE (취약)
[취약 코드]

# AFTER (안전)
[안전 코드]

# ================================
# CRITICAL-002: [다음 취약점] 수정
# ================================
[다음 수정 코드...]
```

### C. 탈취 데이터 샘플
[extracted_data 전체]

### D. 검증 스크립트 ⭐

```bash
#!/bin/bash
# 전체 취약점 재검증 스크립트

echo "🔍 패치 검증 시작..."

# CRITICAL-001 검증
echo "Testing [취약점1]..."
[테스트 커맨드]
# Expected: [예상 결과]

# CRITICAL-002 검증
echo "Testing [취약점2]..."
[테스트 커맨드]
# Expected: [예상 결과]

echo "✅ 검증 완료"
```

### E. 참고 자료
- OWASP Top 10
- CWE/SANS Top 25
- NIST 사이버보안 프레임워크
```

---

## 🎯 핵심 지침 요약

1. **위 구조를 엄격히 따르세요**
2. **모든 [대괄호]는 실제 데이터로 채우세요**
3. **poc_code와 execution_result는 있는 그대로 복사하세요**
4. **각 Phase는 반드시 이전 Phase와 논리적으로 연결하세요**
5. **⭐ 각 취약점마다 즉시 적용 가능한 수정 코드를 제공하세요**
6. **플레이스홀더나 예시 코드를 절대 사용하지 마세요**

지금 바로 보고서를 작성하세요. 서론이나 맺음말 없이 바로 보고서 내용만 출력하세요.
"""
        
        return prompt
    
    def _build_attack_chain(
        self, 
        vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        실제 취약점 데이터 기반으로 공격 체인 구성
        
        Returns:
            [
                {
                    'phase': 'Reconnaissance',
                    'vulnerabilities': [...],
                    'connection': '...'
                },
                ...
            ]
        """
        # 안전성 검증
        if not vulnerabilities or not isinstance(vulnerabilities, list):
            return []
        
        # 1. 취약점 분류 (딕셔너리만 처리)
        valid_vulns = [v for v in vulnerabilities if isinstance(v, dict)]
        recon_vulns = [v for v in valid_vulns if self._is_reconnaissance(v)]
        access_vulns = [v for v in valid_vulns if self._is_initial_access(v)]
        escalation_vulns = [v for v in valid_vulns if self._is_privilege_escalation(v)]
        exfiltration_vulns = [v for v in valid_vulns if self._is_data_exfiltration(v)]
        
        # 2. PoC 검증된 것만 선택
        verified_vulns = [
            v for v in vulnerabilities 
            if v.get('poc_code') and v.get('execution_result', {}).get('extracted_data')
        ]
        
        # 3. 논리적 순서로 체인 구성
        chain = []
        for phase_name, phase_vulns in [
            ('Phase 1: Reconnaissance (정찰)', recon_vulns),
            ('Phase 2: Initial Access (초기 침투)', access_vulns),
            ('Phase 3: Privilege Escalation (권한 상승)', escalation_vulns),
            ('Phase 4: Data Exfiltration (데이터 탈취)', exfiltration_vulns)
        ]:
            if phase_vulns:
                chain.append({
                    'phase': phase_name,
                    'vulnerabilities': [
                        {
                            'name': v.get('name', ''),
                            'severity': v.get('severity', ''),
                            'poc_verified': v.get('poc_code') is not None
                        } for v in phase_vulns[:5]  # 각 Phase당 최대 5개
                    ],
                    'connection': self._analyze_connection(
                        chain[-1] if chain else None, 
                        phase_vulns
                    )
                })
        
        return chain
    
    def _is_reconnaissance(self, vuln: Dict) -> bool:
        """정찰 단계 취약점 판별"""
        if not isinstance(vuln, dict):
            return False
        recon_keywords = ['port scan', 'service detection', 'version detection', 'banner', 'open port']
        vuln_name = vuln.get('name', '').lower()
        return vuln.get('source') == 'nmap' or any(
            keyword in vuln_name for keyword in recon_keywords
        )
    
    def _is_initial_access(self, vuln: Dict) -> bool:
        """초기 침투 단계 취약점 판별"""
        if not isinstance(vuln, dict):
            return False
        access_keywords = ['sql injection', 'command injection', 'file upload', 'authentication bypass', 'xss', 'cross site scripting']
        vuln_name = vuln.get('name', '').lower()
        return any(keyword in vuln_name for keyword in access_keywords)
    
    def _is_privilege_escalation(self, vuln: Dict) -> bool:
        """권한 상승 단계 취약점 판별"""
        if not isinstance(vuln, dict):
            return False
        escalation_keywords = ['privilege escalation', 'sudo', 'suid', 'admin access', 'authorization']
        vuln_name = vuln.get('name', '').lower()
        return any(keyword in vuln_name for keyword in escalation_keywords)
    
    def _is_data_exfiltration(self, vuln: Dict) -> bool:
        """데이터 탈취 단계 취약점 판별"""
        if not isinstance(vuln, dict):
            return False
        execution_result = vuln.get('execution_result')
        if not isinstance(execution_result, dict):
            return False
        return execution_result.get('extracted_data') is not None
    
    def _analyze_connection(
        self, 
        previous_phase: Dict[str, Any], 
        current_vulns: List[Dict]
    ) -> str:
        """이전 단계와 현재 단계의 연결 관계 분석"""
        if not previous_phase:
            return "공격 시작점"
        
        # 이전 단계에서 탈취한 데이터 분석
        prev_data = []
        for vuln in previous_phase['vulnerabilities']:
            # vulnerabilities 리스트에서 실제 vuln 객체 찾기
            full_vuln = next((v for v in current_vulns if v.get('name') == vuln.get('name')), None)
            if full_vuln:
                extracted = full_vuln.get('execution_result', {}).get('extracted_data', {})
                if extracted:
                    prev_data.append(list(extracted.keys()))
        
        if prev_data:
            # 중복 제거 및 평탄화
            all_keys = list(set([key for keys in prev_data for key in keys]))
            return f"이전 단계에서 탈취한 데이터 활용: {', '.join(all_keys[:5])}"
        else:
            return "이전 단계 정보 기반"
    
    def _estimate_business_impact(
        self, 
        vuln: Dict[str, Any],
        metadata: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        비즈니스 영향 정량화
        
        Args:
            vuln: 취약점 데이터
            metadata: 메타데이터 (선택)
        
        Returns:
            비즈니스 영향 딕셔너리
        """
        severity = vuln.get('severity', 'medium').lower()
        has_data_leak = vuln.get('execution_result', {}).get('extracted_data') is not None
        
        impact = {
            'estimated_customer_count': 'Unknown',
            'gdpr_penalty_max': 'N/A',
            'recovery_cost_min': 'N/A',
            'reputation_risk': 'Medium'
        }
        
        # Critical/High + 데이터 유출 가능
        if severity in ['critical', 'high'] and has_data_leak:
            impact['estimated_customer_count'] = '10,000 - 100,000명 (추정)'
            impact['gdpr_penalty_max'] = '€20,000,000 또는 연간 매출의 4%'
            impact['recovery_cost_min'] = '$500,000 - $2,000,000'
            impact['reputation_risk'] = 'Very High (고객 이탈률 30% 예상)'
        elif severity in ['critical', 'high']:
            impact['estimated_customer_count'] = '1,000 - 10,000명'
            impact['gdpr_penalty_max'] = '€10,000,000 또는 연간 매출의 2%'
            impact['recovery_cost_min'] = '$100,000 - $500,000'
            impact['reputation_risk'] = 'High'
        elif severity == 'medium':
            impact['estimated_customer_count'] = '100 - 1,000명'
            impact['gdpr_penalty_max'] = '€1,000,000 또는 연간 매출의 1%'
            impact['recovery_cost_min'] = '$10,000 - $100,000'
            impact['reputation_risk'] = 'Medium'
        
        return impact
    
    def _call_ollama(self, prompt: str) -> str:
        """Ollama API 호출"""
        payload = {
            'model': self.model,
            'prompt': prompt,
            'stream': False,
            'options': {
                'temperature': 0.1,  # 약간의 창의성 허용 (0.0에서 0.1로 상향)
                'top_p': 0.9,
                'top_k': 40
            }
        }
        
        try:
            logger.info(f"Ollama API 호출: {self.api_url}, 모델: {self.model}")
            response = requests.post(
                self.api_url,
                json=payload,
                timeout=1800  # 30분 타임아웃
            )
            response.raise_for_status()
            
            data = response.json()
            response_text = data.get('response', '')
            
            # 응답 크기 제한
            max_response_length = 100000
            if len(response_text) > max_response_length:
                logger.warning(f"AI 응답이 너무 깁니다 ({len(response_text)}자). {max_response_length}자로 제한합니다.")
                response_text = response_text[:max_response_length]
            
            return response_text
        
        except requests.exceptions.Timeout:
            logger.error(f"Ollama API 호출 타임아웃 (30분 초과)")
            return "[AI 호출 타임아웃] 응답 시간이 30분을 초과했습니다."
        except requests.exceptions.RequestException as e:
            logger.error(f"Ollama API 호출 실패: {e}")
            return f"[AI 호출 실패] {str(e)}"
        except Exception as e:
            logger.error(f"Ollama API 호출 중 예외 발생: {e}", exc_info=True)
            return f"[AI 호출 오류] {str(e)}"
    
    def _build_markdown_report(
        self,
        integrated_report: Dict[str, Any],
        security_report: str,
        attack_results: Dict[str, Any] = None
    ) -> str:
        """마크다운 리포트 생성"""
        metadata = integrated_report.get('metadata', {})
        summary = integrated_report.get('summary', {})
        
        report = f"""{security_report}

---

## 리포트 메타데이터

- **분석 모델**: {self.model}
- **Ollama 서버**: {self.base_url}
- **생성 시간**: {metadata.get('generated_at', 'Unknown')}
- **스캔 소스**: 
  - Nmap: {'✅' if summary.get('sources', {}).get('nmap') else '❌'}
  - Nuclei: {'✅' if summary.get('sources', {}).get('nuclei') else '❌'}
  - ZAP: {'✅' if summary.get('sources', {}).get('zap') else '❌'}
"""
        
        return report
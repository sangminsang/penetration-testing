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

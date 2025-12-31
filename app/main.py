# main.py
from .nvd_client import NvdClient


def main():
    client = NvdClient()

    # 여기서 서비스/버전 문자열 넣어서 테스트
    # 예: service = "nginx 1.24", "apache httpd 2.4.59" 등[web:137]
    service_version = input("검색할 서비스/버전 키워드 입력 (예: 'nginx 1.24'): ").strip()

    if not service_version:
        print("키워드를 입력해주세요.")
        return

    print(f"\n[NVD 검색] 키워드: {service_version}")
    cve_list = client.search_and_summarize(service_version, max_pages=1)

    if not cve_list:
        print("검색 결과가 없습니다.")
        return

    for idx, item in enumerate(cve_list, start=1):
        print(f"\n[{idx}] CVE ID: {item['cve_id']}")
        print(f"    CVSS: {item['cvss']}")
        print(f"    DESC: {item['description'][:200]}")  # 너무 길면 앞 200자만


if __name__ == "__main__":
    main()

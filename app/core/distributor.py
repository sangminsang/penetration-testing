import subprocess
import os
import math
import logging

logger = logging.getLogger(__name__)

def spawn_workers(target_list, worker_count=6): # 20에서 8로 하향 조정
    total_targets = len(target_list)
    if total_targets == 0:
        return
        
    result_dir = os.path.abspath("./scan_results")
    if not os.path.exists(result_dir):
        os.makedirs(result_dir)
        
    chunk_size = math.ceil(total_targets / worker_count)
    print(f"[*] 총 {total_targets}개 타겟을 {worker_count}개 워커로 분산합니다.")

    for i in range(worker_count):
        start_idx = i * chunk_size
        end_idx = start_idx + chunk_size
        batch = target_list[start_idx:end_idx]

        if not batch:
            break

        worker_name = f"scanner-worker-{i+1}"
        target_str = ",".join(batch)

        docker_cmd = [
            "docker", "run", "-d",
            "--name", worker_name,
            "-v", f"{result_dir}:/app/results",
            "-e", f"TARGET_URLS={target_str}",
            "my-scanner-image:latest"
        ]

        try:
            subprocess.run(["docker", "rm", "-f", worker_name], capture_output=True)
            subprocess.run(docker_cmd)
            print(f"[+] {worker_name} 가동 시작 (할당: {len(batch)}개 타겟)")
        except Exception as e:
            print(f"[!] {worker_name} 실행 실패: {e}")

    print("[✅] 6워커 최적화 배치가 완료되었습니다.")

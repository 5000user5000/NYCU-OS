# sudo python3 ./test.py

import subprocess
import multiprocessing

def run_kfetch(option):
    """執行 kfetch 程式並傳入選項"""
    try:
        result = subprocess.run(
            ['sudo', './kfetch', option],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        print(f"選項 {option} 執行結果:\n{result.stdout}")
    except Exception as e:
        print(f"執行 {option} 時發生錯誤: {e}")

def test_thread_safety():
    """模擬多進程並發執行 kfetch"""
    options = ['-a', '-c', '-m', '-n', '-p', '-r', '-u']  # 可選參數
    processes = []

    # 為每個選項創建多個進程
    for option in options:
        for _ in range(2):  # 每個選項執行 3 次
            p = multiprocessing.Process(target=run_kfetch, args=(option,))
            processes.append(p)

    # 啟動所有進程
    for p in processes:
        p.start()

    # 等待所有進程完成
    for p in processes:
        p.join()

if __name__ == "__main__":
    test_thread_safety()

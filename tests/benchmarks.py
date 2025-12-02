import subprocess
import time
import csv

TARGET_IP = "10.0.0.2"
TEST_COUNT = 10
OUTPUT_FILE = "benchmark_results.csv"

def run_ping_test(label):
    print(f"\n[*] Running {label} ping test...")

    cmd = ["ping", "-c", str(TEST_COUNT), TARGET_IP]
    start = time.time()

    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    end = time.time()

    output = proc.stdout

    packet_loss = "unknown"
    avg_latency = "blocked"

    for line in output.split("\n"):
        if "packet loss" in line:
            packet_loss = line.split(",")[2].strip()
        if "rtt min/avg/max" in line:
            avg_latency = line.split("=")[1].split("/")[1].strip()

    duration = round(end - start, 2)

    print(f"    Target: {TARGET_IP}")
    print(f"    Avg Latency: {avg_latency}")
    print(f"    Packet Loss: {packet_loss}")
    print(f"    Test Duration: {duration} sec")

    return [label, avg_latency, packet_loss, duration]


def main():
    results = []

    print("\n===== SDN FIREWALL BENCHMARK TOOL =====")

    results.append(run_ping_test("STATIC_FIREWALL"))
    time.sleep(3)
    results.append(run_ping_test("DYNAMIC_FIREWALL_AFTER_BLOCK"))
    time.sleep(3)
    results.append(run_ping_test("DYNAMIC_FIREWALL_AFTER_TIMEOUT"))

    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Test Case", "Avg Latency (ms)", "Packet Loss", "Duration (s)"])
        writer.writerows(results)

    print(f"\n[✓] Benchmark results saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()

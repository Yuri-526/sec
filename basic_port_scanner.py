import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import json

def grab_banner(ip, port, timeout=2):
    try:
        with socket.socket() as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            try:
                banner = s.recv(1024).decode(errors='ignore').strip()
                return banner
            except Exception:
                return ""
    except Exception:
        return ""

def scan_port(ip, port, timeout=1, grab=False):
    result = {"port": port, "status": "closed", "banner": ""}
    try:
        with socket.socket() as s:
            s.settimeout(timeout)
            conn = s.connect_ex((ip, port))
            if conn == 0:
                result["status"] = "open"
                if grab:
                    result["banner"] = grab_banner(ip, port, timeout)
    except Exception:
        pass
    return result

def run_scan(ip, ports, threads=100, timeout=1, grab=False, randomize=False):
    results = []
    if randomize:
        ports = list(ports)
        random.shuffle(ports)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, ip, port, timeout, grab): port for port in ports}
        for future in as_completed(futures):
            results.append(future.result())
    return results

def save_results(results, path, json_out=False):
    with open(path, "w") as f:
        if json_out:
            json.dump(results, f, indent=2)
        else:
            for r in results:
                line = f"Port {r['port']:5}: {r['status']}"
                if r['banner']:
                    line += f" | Banner: {r['banner']}"
                f.write(line + "\n")
    print(f"[→] Results saved to {path}")

def main():
    parser = argparse.ArgumentParser(description="Fast & Stealthy Network Port Scanner")
    parser.add_argument("ip", help="Target IP or hostname")
    parser.add_argument("-p", "--ports", help="Ports to scan (e.g., 22,80,443 or 1-1024)", required=True)
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads")
    parser.add_argument("--timeout", type=float, default=1, help="Socket timeout seconds")
    parser.add_argument("--grab", action="store_true", help="Grab banners from open ports")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--json", action="store_true", help="Save output as JSON")
    parser.add_argument("--randomize", action="store_true", help="Randomize port scan order (stealth)")
    args = parser.parse_args()

    # Parse ports
    ports = set()
    for part in args.ports.split(","):
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end)+1))
        else:
            ports.add(int(part))

    print(f"[•] Starting scan on {args.ip}...")
    results = run_scan(args.ip, ports, args.threads, args.timeout, args.grab, args.randomize)

    for r in sorted(results, key=lambda x: x["port"]):
        line = f"Port {r['port']:5}: {r['status']}"
        if r['banner']:
            line += f" | Banner: {r['banner']}"
        print(line)

    if args.output:
        save_results(results, args.output, args.json)

if __name__ == "__main__":
    main()


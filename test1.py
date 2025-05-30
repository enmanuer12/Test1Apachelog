#!/usr/bin/env python3
import re
import sys

def main():
    if len(sys.argv) != 2:
        print(f"The argument is needed to run the program. Usage: {sys.argv[0]} <path-to-log-file>")
        sys.exit(1)

    log_path = sys.argv[1]
    url_of_interest = input("Enter URL path to analyze: ").strip()
    # normalize to no trailing slash
    url_norm = url_of_interest.rstrip('/')

    # regex for Apache “combined” format
    log_re = re.compile(
        r'^(?P<ip>\S+) '             # client IP
        r'\S+ \S+ '                  # ident / authuser (ignored)
        r'\[(?P<time>[^\]]+)\] '     # timestamp
        r'"(?P<method>\S+) '         # HTTP method
        r'(?P<path>\S+) '            # request path
        r'(?P<proto>[^"]+)" '        # protocol
        r'(?P<status>\d{3}) '        # status code
        r'(?P<size>\S+)'             # size (bytes or '-')
    )

    total_requests_to_url        = 0
    errors_to_url                = 0
    total_non200                 = 0
    put_requests_dev_report_path = 0
    ips                          = set()

    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = log_re.match(line)
            if not m:
                continue

            ip     = m.group("ip")
            path   = m.group("path").rstrip('/')   # strip any trailing slash
            status = int(m.group("status"))

            ips.add(ip)
            if status != 200:
                total_non200 += 1

            # match if the log’s path starts with your normalized URL
            if path.startswith(url_norm):
                total_requests_to_url += 1
                if status != 200:
                    errors_to_url += 1

            # specifically count PUT requests to /dev/report/
            if path.startswith('/dev/report/') and m.group("method") == 'PUT':
                put_requests_dev_report_path += 1

    print(f"\nURL prefix searched:                      {url_norm}")
    print(f"Total requests to path:                     {total_requests_to_url}")
    print(f"Of those, non-200:                          {errors_to_url}")
    print()
    print(f"Overall non-200 count:                      {total_non200}")
    print(f"Total PUT requests under /dev/report/ path: {put_requests_dev_report_path}")

    print("\nBreakdown of IP Address: ")
    print("---------------------------------------------")
    for ip in sorted(ips):
        print(f"  {ip}")
    print("---------------------------------------------")
    print(f"\nTotal unique client IPs:   {len(ips)}")

if __name__ == "__main__":
    main()

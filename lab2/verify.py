"""Exercise raw HTTP paths; save real responses without URL normalization."""
import argparse
import datetime
import http.client
import json
import platform
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CASES = [
    ('index', '/', 200, 'Hello, World!'),
    ('static', '/static/hello.txt', 200, 'PUBLIC_STATIC_OK'),
    ('traversal', '/static/../private/demo.txt', None, None),
    ('encoded_traversal', '/static/%2e%2e/private/demo.txt', None, None),
    ('missing', '/static/missing.txt', 404, '404: Not Found'),
]
VARIANTS = [('vulnerable', '3.9.1', 'true', 8080),
            ('updated', '3.9.2', 'true', 8081),
            ('configuration', '3.9.1', 'false', 8082),
            ('combined', '3.9.2', 'false', 8083)]

def request(port, path):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    try:
        conn.request('GET', path)
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read().decode('utf-8')
    finally:
        conn.close()

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--vulnerable-packages')
    p.add_argument('--fixed-packages')
    p.add_argument('--external', action='store_true', help='Check already running Docker services')
    args = p.parse_args()
    if not args.external and not (args.vulnerable_packages and args.fixed_packages):
        p.error('Provide both package directories or use --external')
    out = ROOT / 'evidence'
    out.mkdir(exist_ok=True)
    results = {'executed_at': datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=3))).isoformat(),
               'platform': platform.platform(), 'python': platform.python_version(),
               'execution': 'external services' if args.external else 'native Windows processes',
               'variants': [], 'passed': 0, 'total': 0}
    for name, version, follow, port in VARIANTS:
        process = None
        log_file = None
        if not args.external:
            packages = args.vulnerable_packages if version == '3.9.1' else args.fixed_packages
            log_file = (out / (name + '-server.log')).open('w', encoding='utf-8')
            command = [sys.executable, '-X', 'utf8', str(ROOT / 'app.py'), '--packages',
                       str(Path(packages).resolve()), '--port', str(port), '--follow-symlinks', follow]
            process = subprocess.Popen(command, stdout=log_file, stderr=subprocess.STDOUT,
                                       cwd=ROOT, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        try:
            for attempt in range(60):
                try:
                    if request(port, '/')[0] == 200:
                        break
                except (OSError, http.client.HTTPException):
                    pass
                if process is not None and process.poll() is not None:
                    raise RuntimeError('Server stopped: ' + name)
                time.sleep(0.1)
            else:
                raise RuntimeError('Server did not become ready: ' + name)
            variant = {'name': name, 'aiohttp': version, 'follow_symlinks': follow == 'true',
                       'port': port, 'cases': []}
            log = [f'CVE-2024-23334 | {name}', f'aiohttp={version}; follow_symlinks={follow}; port={port}',
                   f'Execution: {results["execution"]}; Python {results["python"]}', '']
            for label, path, expected, body_marker in CASES:
                if expected is None:
                    expected = 200 if name == 'vulnerable' else 404
                    body_marker = 'LAB_ONLY_SECRET_CVE_2024_23334' if name == 'vulnerable' else '404: Not Found'
                status, headers, body = request(port, path)
                ok = status == expected and body_marker in body and headers.get('Server', '').endswith('aiohttp/' + version)
                item = {'case': label, 'path': path, 'status': status, 'headers': headers,
                        'body': body, 'expected_status': expected, 'pass': ok}
                variant['cases'].append(item)
                results['total'] += 1
                results['passed'] += int(ok)
                log += [f'GET {path} HTTP/1.1', f'Host: 127.0.0.1:{port}',
                        f'HTTP status: {status}', f'Server: {headers.get("Server", "")}',
                        body.rstrip(), f'CHECK: {"PASS" if ok else "FAIL"}', '']
            results['variants'].append(variant)
            (out / (name + '.txt')).write_text('\n'.join(log), encoding='utf-8')
            print(f'{name}: {sum(c["pass"] for c in variant["cases"])}/5 checks passed')
        finally:
            if process:
                process.terminate()
                process.wait(timeout=10)
            if log_file:
                log_file.close()
    (out / 'results.json').write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'TOTAL: {results["passed"]}/{results["total"]}')
    return 0 if results['passed'] == results['total'] else 1

if __name__ == '__main__':
    raise SystemExit(main())

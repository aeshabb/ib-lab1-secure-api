"""Local CVE-2024-23334 lab, adapted from Vulhub's aiohttpServer.py."""
import argparse
import json
import os
import sys
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--packages', help='Isolated directory installed with pip --target')
parser.add_argument('--port', type=int, default=int(os.getenv('PORT', '8080')))
parser.add_argument('--host', default=os.getenv('HOST', '127.0.0.1'))
parser.add_argument('--follow-symlinks', choices=['true', 'false'],
                    default=os.getenv('FOLLOW_SYMLINKS', 'false'))
args = parser.parse_args()
if args.packages:
    sys.path.insert(0, str(Path(args.packages).resolve()))
import aiohttp
from aiohttp import web

async def index(request):
    return web.Response(text='Hello, World!')

app = web.Application()
app.router.add_routes([web.static('/static', Path(__file__).parent / 'static',
                                 follow_symlinks=args.follow_symlinks == 'true')])
app.router.add_get('/', index)
if __name__ == '__main__':
    print(json.dumps({'python': sys.version.split()[0], 'aiohttp': aiohttp.__version__,
                      'follow_symlinks': args.follow_symlinks, 'port': args.port}), flush=True)
    web.run_app(app, host=args.host, port=args.port)

import requests
import os

GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN')
if not GITHUB_TOKEN:
    raise ValueError('GITHUB_TOKEN environment variable is not set.')

OWNER = "ccsexyz"
REPO = "shadowsocks-go"
API_URL = f"https://api.github.com/repos/{OWNER}/{REPO}/releases"
HEADERS = {"Authorization": f"token {GITHUB_TOKEN}"}

# 获取所有 releases
response = requests.get(API_URL, headers=HEADERS)
releases = response.json()

# 删除所有 pre-releases
for release in releases:
    if release.get("prerelease"):
        delete_url = release["url"]
        requests.delete(delete_url, headers=HEADERS)
        print(f"Deleted pre-release: {release['name']}")
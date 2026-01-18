#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "httpx",
#     "feedparser",
# ]
# ///
"""
Daily website checker - only opens sites that have new content since last check.
Uses RSS feeds when available, falls back to content hashing.

Data stored in ~/.local/share/daily-web/
"""

import asyncio
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, asdict
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse, urljoin

import feedparser
import httpx

# Paths
DATA_DIR = Path.home() / ".local" / "share" / "daily-web"
SITES_FILE = DATA_DIR / "sites.json"
STATE_FILE = DATA_DIR / "state.json"
CONFIG_FILE = DATA_DIR / "config.json"

# Chrome's native bookmarks file (platform-specific)
def _get_chrome_bookmarks_path() -> Path:
    """Get the path to Chrome's bookmarks file for the current platform."""
    import platform
    system = platform.system()

    if system == "Darwin":  # macOS
        return Path.home() / "Library" / "Application Support" / "Google" / "Chrome" / "Default" / "Bookmarks"
    elif system == "Windows":
        # Use LOCALAPPDATA environment variable
        local_app_data = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return local_app_data / "Google" / "Chrome" / "User Data" / "Default" / "Bookmarks"
    else:  # Linux and others
        return Path.home() / ".config" / "google-chrome" / "Default" / "Bookmarks"

CHROME_BOOKMARKS_FILE = _get_chrome_bookmarks_path()

# Defaults (can be overridden in config.json)
DEFAULT_CONFIG = {
    "timeout": 5.0,
    "max_concurrent": 30,
    "max_content_size": 500_000,
    "feed_paths": [
        "/feed",
        "/rss",
        "/rss.xml",
        "/feed.xml",
        "/atom.xml",
        "/feeds/posts/default",
        "/index.xml",
        "/?feed=rss2",
    ],
    "manual_feeds": {},
}


def load_config() -> dict:
    """Load config from file, with defaults."""
    config = DEFAULT_CONFIG.copy()
    if CONFIG_FILE.exists():
        try:
            user_config = json.loads(CONFIG_FILE.read_text())
            # Merge user config over defaults
            for key in ["timeout", "max_concurrent", "max_content_size"]:
                if key in user_config:
                    config[key] = user_config[key]
            # Extend feed paths (don't replace)
            if "feed_paths" in user_config:
                config["feed_paths"] = list(dict.fromkeys(
                    config["feed_paths"] + user_config["feed_paths"]
                ))
            # Merge manual feeds
            if "manual_feeds" in user_config:
                config["manual_feeds"].update(user_config["manual_feeds"])
        except Exception as e:
            print(f"Warning: Error loading config: {e}")
    return config


def save_default_config() -> None:
    """Create a sample config file."""
    ensure_data_dir()
    sample_config = {
        "_comment": "All settings are optional. Delete any you don't need to change.",
        "timeout": 5.0,
        "max_concurrent": 30,
        "feed_paths": [
            "/custom/feed/path.xml",
        ],
        "manual_feeds": {
            "example.com": "https://example.com/rss.xml",
        },
    }
    CONFIG_FILE.write_text(json.dumps(sample_config, indent=2))
    print(f"Created config file: {CONFIG_FILE}")
    print("Edit it to customize settings. The defaults work for most sites.")


# Load config at module level
CONFIG = load_config()


def ensure_data_dir() -> None:
    """Create data directory if it doesn't exist."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class SiteState:
    url: str
    last_checked: str | None = None
    last_modified: str | None = None
    etag: str | None = None
    content_hash: str | None = None
    last_changed: str | None = None
    # RSS fields
    feed_url: str | None = None
    feed_checked: bool = False
    last_feed_item_id: str | None = None


@dataclass
class CheckResult:
    url: str
    index: int
    state: SiteState
    changed: bool
    slow: bool = False
    error: str | None = None
    method: str = "unknown"


class FeedLinkParser(HTMLParser):
    """Parse HTML to find RSS/Atom feed links."""

    def __init__(self):
        super().__init__()
        self.feed_urls: list[str] = []  # High confidence (link tags)
        self.possible_feed_urls: list[str] = []  # Lower confidence (a tags)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = dict(attrs)
        href = attrs_dict.get("href", "") or ""

        if tag.lower() == "link":
            rel = attrs_dict.get("rel", "") or ""
            type_ = attrs_dict.get("type", "") or ""

            if "alternate" in rel and href:
                if "rss" in type_ or "atom" in type_ or "feed" in type_:
                    self.feed_urls.append(href)

        # Also check <a> tags for links that look like feeds
        elif tag.lower() == "a" and href:
            href_lower = href.lower()
            # Check if URL contains feed-related keywords
            if any(kw in href_lower for kw in ["/rss", "/feed", "/atom", ".rss", ".xml"]):
                # Exclude obvious non-feeds
                if not any(skip in href_lower for skip in [".pdf", ".doc", "javascript:", "mailto:"]):
                    self.possible_feed_urls.append(href)


class BookmarkParser(HTMLParser):
    """Parse Chrome bookmarks HTML export to extract URLs from a specific folder."""

    def __init__(self, target_folder: str):
        super().__init__()
        self.target_folder = target_folder
        self.in_target_folder = False
        self.folder_depth = 0
        self.urls: list[str] = []
        self.current_tag = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.current_tag = tag.lower()
        attrs_dict = dict(attrs)

        if self.in_target_folder:
            if tag.lower() == "dl":
                self.folder_depth += 1
            elif tag.lower() == "a" and "href" in attrs_dict:
                href = attrs_dict["href"]
                if href and href.startswith(("http://", "https://")):
                    self.urls.append(href)

    def handle_endtag(self, tag: str) -> None:
        if self.in_target_folder and tag.lower() == "dl":
            self.folder_depth -= 1
            if self.folder_depth < 0:
                self.in_target_folder = False

    def handle_data(self, data: str) -> None:
        if self.current_tag == "h3" and data.strip() == self.target_folder:
            self.in_target_folder = True
            self.folder_depth = -1


def parse_bookmarks_html(bookmarks_file: Path, folder_name: str) -> list[str]:
    """Extract URLs from a specific folder in Chrome bookmarks HTML export."""
    content = bookmarks_file.read_text(encoding="utf-8")
    parser = BookmarkParser(folder_name)
    parser.feed(content)
    return parser.urls


def parse_chrome_bookmarks(bookmarks_file: Path, folder_name: str) -> list[str]:
    """Extract URLs from a specific folder in Chrome's native JSON bookmarks file."""
    data = json.loads(bookmarks_file.read_text(encoding="utf-8"))

    def find_folder(node: dict, name: str) -> dict | None:
        """Recursively find a folder by name."""
        if node.get("type") == "folder" and node.get("name") == name:
            return node
        for child in node.get("children", []):
            result = find_folder(child, name)
            if result:
                return result
        return None

    def extract_urls(node: dict) -> list[str]:
        """Extract all URLs from a folder (including subfolders)."""
        urls = []
        for child in node.get("children", []):
            if child.get("type") == "url":
                url = child.get("url", "")
                if url.startswith(("http://", "https://")):
                    urls.append(url)
            elif child.get("type") == "folder":
                urls.extend(extract_urls(child))
        return urls

    # Search in all root folders
    for root in data.get("roots", {}).values():
        if isinstance(root, dict):
            folder = find_folder(root, folder_name)
            if folder:
                return extract_urls(folder)

    return []


def parse_bookmarks(bookmarks_file: Path, folder_name: str) -> list[str]:
    """Auto-detect format and parse bookmarks file."""
    content = bookmarks_file.read_text(encoding="utf-8")

    # Check if it's JSON (Chrome native) or HTML (export)
    if content.strip().startswith("{"):
        return parse_chrome_bookmarks(bookmarks_file, folder_name)
    else:
        return parse_bookmarks_html(bookmarks_file, folder_name)


def load_sites() -> list[str]:
    """Load saved site URLs."""
    if not SITES_FILE.exists():
        return []
    return json.loads(SITES_FILE.read_text())


def save_sites(urls: list[str]) -> None:
    """Save site URLs."""
    ensure_data_dir()
    SITES_FILE.write_text(json.dumps(urls, indent=2))


def load_state() -> dict[str, SiteState]:
    """Load saved state from JSON file."""
    if not STATE_FILE.exists():
        return {}

    data = json.loads(STATE_FILE.read_text())
    result = {}
    for url, s in data.items():
        state_dict = {
            "url": s.get("url", url),
            "last_checked": s.get("last_checked"),
            "last_modified": s.get("last_modified"),
            "etag": s.get("etag"),
            "content_hash": s.get("content_hash"),
            "last_changed": s.get("last_changed"),
            "feed_url": s.get("feed_url"),
            "feed_checked": s.get("feed_checked", False),
            "last_feed_item_id": s.get("last_feed_item_id"),
        }
        result[url] = SiteState(**state_dict)
    return result


def save_state(state: dict[str, SiteState]) -> None:
    """Save state to JSON file."""
    ensure_data_dir()
    data = {url: asdict(s) for url, s in state.items()}
    STATE_FILE.write_text(json.dumps(data, indent=2))


def clean_content_for_hashing(content: str) -> str:
    """Clean HTML content to reduce false positives from dynamic elements."""
    content = re.sub(r'<script[^>]*>.*?</script>', '', content, flags=re.DOTALL | re.IGNORECASE)
    content = re.sub(r'<style[^>]*>.*?</style>', '', content, flags=re.DOTALL | re.IGNORECASE)
    content = re.sub(r'\b\d{1,2}:\d{2}(:\d{2})?\s*(AM|PM|am|pm)?\b', '', content)
    content = re.sub(r'nonce="[^"]*"', '', content)
    content = re.sub(r'csrf[^"]*"[^"]*"', '', content, flags=re.IGNORECASE)
    content = re.sub(r'<[^>]+>', ' ', content)
    content = ' '.join(content.split())
    return content


def compute_content_hash(content: str) -> str:
    """Compute SHA256 hash of content."""
    return hashlib.sha256(content.encode('utf-8')).hexdigest()[:16]


def discover_feeds_from_html(html: str, base_url: str) -> list[str]:
    """Look for RSS/Atom feed links in HTML. Returns candidates in priority order."""
    parser = FeedLinkParser()
    try:
        parser.feed(html)
    except Exception:
        return []

    candidates = []
    # High confidence first (from <link> tags)
    for url in parser.feed_urls:
        resolved = urljoin(base_url, url)
        if resolved not in candidates:
            candidates.append(resolved)
    # Then possible feeds (from <a> tags)
    for url in parser.possible_feed_urls:
        resolved = urljoin(base_url, url)
        if resolved not in candidates:
            candidates.append(resolved)
    return candidates


async def try_feed_url(client: httpx.AsyncClient, url: str) -> bool:
    """Check if a URL is a valid RSS/Atom feed."""
    try:
        response = await client.get(url, follow_redirects=True)
        if response.status_code != 200:
            return False
        content_type = response.headers.get("content-type", "").lower()
        if "xml" in content_type or "rss" in content_type or "atom" in content_type:
            return True
        feed = feedparser.parse(response.text)
        return bool(feed.entries)
    except Exception:
        return False


async def discover_feed(client: httpx.AsyncClient, url: str, html: str) -> str | None:
    """Try to discover an RSS feed for a site."""
    parsed = urlparse(url)
    domain = parsed.netloc.lower().removeprefix("www.")

    # First, check manual overrides from config
    for override_domain, feed_url in CONFIG["manual_feeds"].items():
        if override_domain in domain:
            if await try_feed_url(client, feed_url):
                return feed_url

    # Check for feed links in HTML (both <link> tags and <a> tags with feed-like URLs)
    candidates = discover_feeds_from_html(html, url)
    for feed_url in candidates:
        if await try_feed_url(client, feed_url):
            return feed_url

    # Try common feed paths
    base = f"{parsed.scheme}://{parsed.netloc}"

    for path in CONFIG["feed_paths"]:
        feed_url = base + path
        if await try_feed_url(client, feed_url):
            return feed_url

    return None


def get_feed_item_id(entry) -> str:
    """Get a unique identifier for a feed entry."""
    if hasattr(entry, 'id') and entry.id:
        return entry.id
    if hasattr(entry, 'link') and entry.link:
        return entry.link
    if hasattr(entry, 'title') and entry.title:
        return hashlib.md5(entry.title.encode()).hexdigest()[:16]
    return ""


async def check_feed(
    client: httpx.AsyncClient,
    feed_url: str,
    last_item_id: str | None,
) -> tuple[bool, str | None]:
    """Check if feed has new content."""
    try:
        response = await client.get(feed_url, follow_redirects=True)
        if response.status_code != 200:
            return True, last_item_id

        feed = feedparser.parse(response.text)
        if not feed.entries:
            return False, last_item_id

        latest_id = get_feed_item_id(feed.entries[0])

        if last_item_id is None:
            return True, latest_id

        if latest_id != last_item_id:
            return True, latest_id

        return False, latest_id

    except Exception:
        return True, last_item_id


async def check_site(
    url: str,
    index: int,
    previous: SiteState | None,
    client: httpx.AsyncClient,
    verbose: bool = False,
) -> CheckResult:
    """Check if a site has new content using RSS if available, else content hash."""
    now = datetime.now().isoformat()
    domain = urlparse(url).netloc
    start_time = asyncio.get_event_loop().time()

    new_state = SiteState(
        url=url,
        last_checked=now,
        last_modified=previous.last_modified if previous else None,
        etag=previous.etag if previous else None,
        content_hash=previous.content_hash if previous else None,
        last_changed=previous.last_changed if previous else None,
        feed_url=previous.feed_url if previous else None,
        feed_checked=previous.feed_checked if previous else False,
        last_feed_item_id=previous.last_feed_item_id if previous else None,
    )

    try:
        # If we already know this site has a feed, check it directly
        if new_state.feed_url:
            has_new, latest_id = await check_feed(client, new_state.feed_url, new_state.last_feed_item_id)
            elapsed = asyncio.get_event_loop().time() - start_time
            slow = elapsed > 5.0

            new_state.last_feed_item_id = latest_id
            if has_new:
                new_state.last_changed = now
                if verbose:
                    print(f"  {domain}: CHANGED (RSS)")
                return CheckResult(url, index, new_state, changed=True, slow=slow, method="rss")
            else:
                if verbose:
                    print(f"  {domain}: unchanged (RSS)")
                return CheckResult(url, index, new_state, changed=False, slow=slow, method="rss")

        # Fetch the page
        headers = {}
        if previous and previous.etag:
            headers["If-None-Match"] = previous.etag
        if previous and previous.last_modified:
            headers["If-Modified-Since"] = previous.last_modified

        response = await client.get(url, headers=headers, follow_redirects=True)
        elapsed = asyncio.get_event_loop().time() - start_time
        slow = elapsed > 5.0

        if response.status_code == 304:
            if verbose:
                print(f"  {domain}: unchanged (304)")
            return CheckResult(url, index, new_state, changed=False, slow=slow, method="etag")

        if response.status_code != 200:
            if verbose:
                print(f"  {domain}: status {response.status_code} (assuming changed)")
            return CheckResult(
                url, index, new_state, changed=True, slow=slow,
                error=f"status {response.status_code}", method="error"
            )

        html = response.text

        # Try to discover a feed if we haven't checked yet
        if not new_state.feed_checked:
            new_state.feed_checked = True
            feed_url = await discover_feed(client, url, html)
            if feed_url:
                new_state.feed_url = feed_url
                if verbose:
                    print(f"  {domain}: discovered RSS feed")
                has_new, latest_id = await check_feed(client, feed_url, None)
                new_state.last_feed_item_id = latest_id
                new_state.last_changed = now
                if verbose:
                    print(f"  {domain}: CHANGED (RSS, first check)")
                return CheckResult(url, index, new_state, changed=True, slow=slow, method="rss")

        # Check Last-Modified header
        if "Last-Modified" in response.headers:
            new_last_modified = response.headers["Last-Modified"]
            if previous and previous.last_modified != new_last_modified:
                new_state.last_modified = new_last_modified
                new_state.last_changed = now
                if verbose:
                    print(f"  {domain}: CHANGED (Last-Modified)")
                return CheckResult(url, index, new_state, changed=True, slow=slow, method="last-modified")
            new_state.last_modified = new_last_modified

        # Check ETag header
        if "ETag" in response.headers:
            new_etag = response.headers["ETag"]
            if previous and previous.etag and previous.etag != new_etag:
                new_state.etag = new_etag
                new_state.last_changed = now
                if verbose:
                    print(f"  {domain}: CHANGED (ETag)")
                return CheckResult(url, index, new_state, changed=True, slow=slow, method="etag")
            new_state.etag = new_etag

        # Fall back to content hashing
        content = html[:CONFIG["max_content_size"]]
        cleaned = clean_content_for_hashing(content)
        new_hash = compute_content_hash(cleaned)

        if previous and previous.content_hash and previous.content_hash != new_hash:
            new_state.content_hash = new_hash
            new_state.last_changed = now
            if verbose:
                print(f"  {domain}: CHANGED (content)")
            return CheckResult(url, index, new_state, changed=True, slow=slow, method="content")

        new_state.content_hash = new_hash
        if not new_state.last_changed:
            new_state.last_changed = now
            if verbose:
                print(f"  {domain}: CHANGED (first check)")
            return CheckResult(url, index, new_state, changed=True, slow=slow, method="content")

        if verbose:
            print(f"  {domain}: unchanged (content)")
        return CheckResult(url, index, new_state, changed=False, slow=slow, method="content")

    except httpx.TimeoutException:
        if verbose:
            print(f"  {domain}: TIMEOUT (assuming changed)")
        return CheckResult(url, index, new_state, changed=True, slow=True, error="timeout", method="error")

    except Exception as e:
        error_msg = str(e)
        if "nodename nor servname" in error_msg:
            error_msg = "host not found"
        if verbose:
            print(f"  {domain}: ERROR - {error_msg} (assuming changed)")
        return CheckResult(url, index, new_state, changed=True, slow=True, error=error_msg, method="error")


async def check_all_sites(
    urls: list[str],
    state: dict[str, SiteState],
    verbose: bool = False,
) -> list[CheckResult]:
    """Check all sites concurrently with a semaphore to limit parallelism."""
    semaphore = asyncio.Semaphore(CONFIG["max_concurrent"])

    async def check_with_semaphore(url: str, index: int) -> CheckResult:
        async with semaphore:
            previous = state.get(url)
            async with httpx.AsyncClient(timeout=CONFIG["timeout"]) as client:
                return await check_site(url, index, previous, client, verbose)

    tasks = [check_with_semaphore(url, i) for i, url in enumerate(urls)]
    results = await asyncio.gather(*tasks)
    return list(results)


def open_in_chrome(urls: list[str]) -> None:
    """Open URLs in a new Chrome window."""
    import platform

    if not urls:
        print("No sites to open.")
        return

    system = platform.system()

    if system == "Darwin":  # macOS
        cmd = ["open", "-na", "Google Chrome", "--args", "--new-window"] + urls
    elif system == "Windows":
        # Find Chrome executable
        chrome_paths = [
            os.path.join(os.environ.get("PROGRAMFILES", ""), "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(os.environ.get("PROGRAMFILES(X86)", ""), "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome", "Application", "chrome.exe"),
        ]
        chrome_exe = next((p for p in chrome_paths if os.path.exists(p)), "chrome")
        cmd = [chrome_exe, "--new-window"] + urls
    else:  # Linux
        # Try common Chrome executable names
        for chrome_cmd in ["google-chrome", "google-chrome-stable", "chromium-browser", "chromium"]:
            if subprocess.run(["which", chrome_cmd], capture_output=True).returncode == 0:
                cmd = [chrome_cmd, "--new-window"] + urls
                break
        else:
            # Fall back to xdg-open (opens in default browser)
            print("Chrome not found, using default browser")
            for url in urls:
                subprocess.run(["xdg-open", url])
            print(f"Opened {len(urls)} sites.")
            return

    subprocess.run(cmd)
    print(f"Opened {len(urls)} sites in Chrome.")


def do_import(bookmarks_file: Path, folder_name: str) -> None:
    """Import sites from Chrome bookmarks (native JSON or HTML export)."""
    if not bookmarks_file.exists():
        print(f"Bookmarks file not found: {bookmarks_file}")
        sys.exit(1)

    print(f"Reading from: {bookmarks_file}")
    urls = parse_bookmarks(bookmarks_file, folder_name)
    if not urls:
        print(f"No URLs found in folder '{folder_name}'")
        sys.exit(1)

    save_sites(urls)
    print(f"Imported {len(urls)} sites from '{folder_name}' folder")
    print(f"Saved to {SITES_FILE}")


def show_help() -> None:
    print(f"""Usage: daily-web [options]

Check your daily websites for new content and open changed ones in Chrome.

Options:
  -n, --dry-run     Show which sites would open without opening them
  -a, --all         Open all sites regardless of changes
  -v, --verbose     Show detailed progress
  -h, --help        Show this help
  --reset           Clear saved state (re-check all sites)
  --show-feeds      Show which sites have discovered RSS feeds
  --show-sites      List all tracked sites

Setup:
  --import [file] [folder]
                    Import sites from Chrome bookmarks
                    Default: Chrome's native bookmarks, folder "Daily"
                    Also accepts HTML exports
  --init-config     Create a sample config file

Data directory: {DATA_DIR}
Config file:    {CONFIG_FILE}
""")


def main():
    args = sys.argv[1:]

    if "-h" in args or "--help" in args:
        show_help()
        return

    # Handle import command
    if "--import" in args:
        idx = args.index("--import")
        # Check for optional file path (next arg that doesn't start with -)
        next_arg = args[idx + 1] if idx + 1 < len(args) else None
        if next_arg and not next_arg.startswith("-"):
            bookmarks_file = Path(next_arg).expanduser()
            folder_arg_idx = idx + 2
        else:
            # Default to Chrome's native bookmarks
            bookmarks_file = CHROME_BOOKMARKS_FILE
            folder_arg_idx = idx + 1
        # Check for optional folder name
        folder_arg = args[folder_arg_idx] if folder_arg_idx < len(args) else None
        folder_name = folder_arg if folder_arg and not folder_arg.startswith("-") else "Daily"
        do_import(bookmarks_file, folder_name)
        return

    if "--init-config" in args:
        if CONFIG_FILE.exists():
            print(f"Config file already exists: {CONFIG_FILE}")
            print("Edit it directly or delete it to create a new one.")
        else:
            save_default_config()
        return

    dry_run = "-n" in args or "--dry-run" in args
    force_all = "-a" in args or "--all" in args
    verbose = "-v" in args or "--verbose" in args

    if "--reset" in args:
        if STATE_FILE.exists():
            STATE_FILE.unlink()
            print("State reset.")
        else:
            print("No state to reset.")
        return

    if "--show-feeds" in args:
        state = load_state()
        feeds = [(url, s.feed_url) for url, s in state.items() if s.feed_url]
        if feeds:
            print(f"Sites with RSS feeds ({len(feeds)}):")
            for url, feed_url in sorted(feeds):
                domain = urlparse(url).netloc
                print(f"  {domain}: {feed_url}")
        else:
            print("No RSS feeds discovered yet. Run a check first.")
        return

    if "--show-sites" in args:
        urls = load_sites()
        if urls:
            print(f"Tracked sites ({len(urls)}):")
            for url in urls:
                domain = urlparse(url).netloc
                print(f"  {domain}")
        else:
            print("No sites configured. Use --import to add sites from bookmarks.")
        return

    # Load sites
    urls = load_sites()
    if not urls:
        print("No sites configured.")
        print(f"Use: daily-web --import <bookmarks.html> [folder_name]")
        print(f"Example: daily-web --import ~/Downloads/bookmarks.html Daily")
        sys.exit(1)

    print(f"Checking {len(urls)} sites...")

    if force_all:
        if dry_run:
            print("\nWould open all sites:")
            for url in urls:
                print(f"  {urlparse(url).netloc}")
        else:
            open_in_chrome(urls)
        return

    # Load previous state
    state = load_state()

    # Check all sites concurrently
    print(f"(max {CONFIG["max_concurrent"]} parallel, {CONFIG["timeout"]}s timeout)")
    results = asyncio.run(check_all_sites(urls, state, verbose))

    # Update state from results
    for result in results:
        state[result.url] = result.state

    # Save updated state
    save_state(state)

    # Separate changed and unchanged, preserving original order
    changed_results = sorted([r for r in results if r.changed], key=lambda r: r.index)
    unchanged_results = sorted([r for r in results if not r.changed], key=lambda r: r.index)
    slow_results = [r for r in results if r.slow]

    # Count by method
    rss_count = sum(1 for r in results if r.method == "rss")

    # Report results
    print(f"\n{len(changed_results)} changed, {len(unchanged_results)} unchanged ({rss_count} via RSS)")

    if slow_results:
        print(f"\nSlow/unresponsive ({len(slow_results)}):")
        for r in slow_results:
            domain = urlparse(r.url).netloc
            error_info = f" ({r.error})" if r.error else ""
            print(f"  {domain}{error_info}")

    changed_urls = [r.url for r in changed_results]

    if changed_urls:
        if dry_run:
            print("\nWould open:")
            for r in changed_results:
                domain = urlparse(r.url).netloc
                method_info = f" [{r.method}]" if verbose else ""
                print(f"  {domain}{method_info}")
        else:
            open_in_chrome(changed_urls)

    if verbose and unchanged_results:
        print("\nUnchanged:")
        for r in unchanged_results:
            domain = urlparse(r.url).netloc
            print(f"  {domain} [{r.method}]")


if __name__ == "__main__":
    main()

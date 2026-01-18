# daily-web

A Python tool that checks your bookmarked websites for new content and opens only the changed sites in Chrome. Saves time on your daily web browsing routine by skipping sites that haven't updated.

## Features

- **RSS/Atom feed discovery** - Automatically finds and uses RSS feeds for accurate change detection
- **Content hashing fallback** - Falls back to content hashing when no feed is available
- **Parallel checking** - Uses asyncio for fast concurrent requests
- **Cross-platform** - Supports macOS, Windows, and Linux
- **Chrome integration** - Imports from Chrome bookmarks and opens changed sites in a new Chrome window
- **Preserves order** - Opens tabs in your original bookmark order

## Installation

Requires Python 3.11+ and [uv](https://github.com/astral-sh/uv).

```bash
# Clone the repository
git clone https://github.com/garyo/daily-web.git
cd daily-web

# Optional: symlink to your PATH
ln -s "$(pwd)/daily_web.py" ~/bin/daily-web
```

## Usage

### Import your bookmarks

Import a folder from Chrome's bookmarks:

```bash
# Import from Chrome's default bookmarks location (auto-detected)
daily-web --import --folder "Daily"

# Or import from an exported HTML file
daily-web --import --file bookmarks.html --folder "Daily"
```

### Check for updates

```bash
# Check all sites and open changed ones in Chrome
daily-web

# Dry run - just show what would be opened
daily-web --dry-run

# Show verbose output
daily-web --verbose
```

### Other options

```bash
# List all tracked sites
daily-web --list

# Clear saved state (will treat all sites as changed on next run)
daily-web --clear-state
```

## How it works

1. **Feed detection**: For each site, attempts to discover RSS/Atom feeds by parsing `<link>` tags and scanning for feed-like URLs
2. **Change detection**:
   - If a feed is found, checks the most recent entry's publication date
   - Otherwise, fetches the page and computes a content hash (filtering out scripts, styles, and dynamic elements)
3. **State tracking**: Saves feed URLs, content hashes, and timestamps to `~/.local/share/daily-web/state.json`
4. **Browser opening**: Opens all changed sites in a new Chrome window, preserving your bookmark order

## Configuration

Data is stored in `~/.local/share/daily-web/`:

- `sites.json` - List of tracked URLs
- `state.json` - Per-site state (feed URLs, hashes, last check times)
- `config.json` - Optional configuration overrides

### Manual feed overrides

If a site has a feed that isn't auto-discovered, add it to `config.json`:

```json
{
  "feed_overrides": {
    "https://example.com/": "https://example.com/feed.xml"
  }
}
```

## License

MIT

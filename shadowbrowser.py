import os

if "GST_PLUGIN_SCANNER" in os.environ:
    del os.environ["GST_PLUGIN_SCANNER"]

import json
import ssl
import gi
import time
import re
import socket
import threading
from urllib.parse import urlparse, urlunparse
import logging
import datetime
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend

gi.require_version('Gtk', '4.0')
gi.require_version('WebKit', '6.0')
gi.require_version('Gdk', '4.0')
gi.require_version('GdkPixbuf', '2.0')
gi.require_version('GLib', '2.0')

from gi.repository import Gtk, WebKit, Gdk, GdkPixbuf, GLib

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

DOWNLOAD_EXTENSIONS = [
    ".3gp", ".7z", ".aac", ".apk", ".appimage", ".avi", ".bat", ".bin", ".bmp",
    ".bz2", ".c", ".cmd", ".cpp", ".cs", ".deb", ".dmg", ".dll", ".doc", ".docx",
    ".eot", ".exe", ".flac", ".flv", ".gif", ".gz", ".h", ".ico", ".img", ".iso",
    ".jar", ".java", ".jpeg", ".jpg", ".js", ".lua", ".lz", ".lzma", ".m4a", ".mkv",
    ".mov", ".mp3", ".mp4", ".mpg", ".mpeg", ".msi", ".odp", ".ods", ".odt", ".ogg",
    ".otf", ".pdf", ".php", ".pkg", ".pl", ".png", ".pps", ".ppt", ".pptx", ".ps1",
    ".py", ".rar", ".rb", ".rpm", ".rtf", ".run", ".sh", ".so", ".svg", ".tar",
    ".tar.bz2", ".tar.gz", ".tbz2", ".tgz", ".tiff", ".ttf", ".txt", ".vhd", ".vmdk",
    ".wav", ".webm", ".webp", ".wma", ".woff", ".woff2", ".wmv", ".xls", ".xlsx", ".zip"
]

BOOKMARKS_FILE = "bookmarks.json"
HISTORY_FILE = "history.json"
SESSION_FILE = "session.json"
TABS_FILE = "tabs.json"
HISTORY_LIMIT = 100

class SSLUtils:
    def __init__(self):
        self.context = ssl.create_default_context()

    def fetch_certificate(self, url):
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 443
        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                with self.context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                    logger.info(f"Fetched certificate from {url}")
                    return cert
        except Exception as e:
            logger.error(f"Error fetching certificate from {url}: {e}")
            return None

    def get_ocsp_url(self, cert):
        try:
            aia = cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            ).value
            for access in aia:
                if access.access_method == x509.AuthorityInformationAccessOID.OCSP:
                    return access.access_location.value
        except Exception:
            return None

    def is_certificate_expired(self, cert: x509.Certificate) -> bool:
        """
        Check if the certificate is expired.

        Args:
            cert (x509.Certificate): The X.509 certificate object.

        Returns:
            bool: True if the certificate is expired, False otherwise.
        """
        try:
            return cert.not_valid_after < datetime.datetime.utcnow()
        except Exception as e:
            logger.error(f"Error checking certificate expiration: {e}")
            return True

class DownloadManager:
    def __init__(self, parent_window):
        self.parent_window = parent_window
        self.box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.downloads = {}
        self.ensure_download_directory()

    def add_webview(self, webview):
        """Connect download signals to the download manager."""

    def on_download_requested(self, context, download):
        """Handle download request event."""
        try:
            uri = download.get_request().get_uri()
            if not uri:
                logger.warning("Download URI is empty; skipping.")
                return False
            downloads_dir = GLib.get_user_special_dir(
                GLib.UserDirectory.DIRECTORY_DOWNLOAD
            ) or os.path.expanduser("~/Downloads")
            os.makedirs(downloads_dir, exist_ok=True)
            filename = os.path.basename(uri)
            counter = 1
            base_name, ext = os.path.splitext(filename)
            while os.path.exists(os.path.join(downloads_dir, filename)):
                filename = f"{base_name}_{counter}{ext}"
                counter += 1
            filepath = os.path.join(downloads_dir, filename)
            hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            label = Gtk.Label(label=f"Downloading {filename}")
            progress = Gtk.ProgressBar()
            self.downloads[download] = {
                "hbox": hbox,
                "label": label,
                "progress": progress,
                "filepath": filepath,
                "status": "Downloading",
                "cancelled": False
            }
            hbox.append(label)
            hbox.append(progress)
            self.box.append(hbox)
            download.connect("progress-changed", self.on_progress_changed)
            download.connect("finished", self.on_download_finished)
            download.connect("failed", self.on_download_failed)
            download.connect("cancelled", self.on_download_cancelled)
            return True
        except Exception as e:
            logger.error(f"Error starting download: {str(e)}")
            self.show_error_message(f"Download failed: {str(e)}")
            return False

    def add_progress_bar(self, progress_info):
        """Add progress bar for manual downloads."""
        hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        label = Gtk.Label(label=f"Downloading {progress_info['filename']}")
        progress = Gtk.ProgressBar()
        self.downloads[progress_info['filename']] = {
            "hbox": hbox,
            "label": label,
            "progress": progress,
            "filepath": os.path.join(
                GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_DOWNLOAD) or 
                os.path.expanduser("~/Downloads"),
                progress_info['filename']
            ),
            "status": "Downloading",
            "cancelled": False
        }
        hbox.append(label)
        hbox.append(progress)
        self.box.append(hbox)

    def update_progress(self, progress_info, progress):
        """Update progress for manual downloads."""
        info = self.downloads.get(progress_info['filename'])
        if info:
            info["progress"].set_fraction(progress)
            info["progress"].set_text(f"{progress * 100:.1f}%")
            info["label"].set_text(f"Downloading {progress_info['filename']}")

    def download_finished(self, progress_info):
        """Handle manual download finished."""
        info = self.downloads.get(progress_info['filename'])
        if info:
            info["status"] = "Finished"
            info["progress"].set_fraction(1.0)
            info["progress"].set_text("100%")
            info["label"].set_text(f"Download finished: {progress_info['filename']}")
            GLib.timeout_add_seconds(5, lambda: self.cleanup_download(progress_info['filename']))

    def download_failed(self, progress_info, error_message):
        """Handle manual download failure."""
        info = self.downloads.get(progress_info['filename'])
        if info:
            info["status"] = "Failed"
            info["label"].set_text(f"Download failed: {error_message}")
            info["progress"].set_text("Failed")
            GLib.timeout_add_seconds(5, lambda: self.cleanup_download(progress_info['filename']))

    def cleanup_download(self, download_key):
        """Clean up download UI elements."""
        info = self.downloads.pop(download_key, None)
        if info:
            if info["hbox"].get_parent():
                self.box.remove(info["hbox"])

    def ensure_download_directory(self):
        """Ensure the downloads directory exists."""
        downloads_dir = GLib.get_user_special_dir(
            GLib.UserDirectory.DIRECTORY_DOWNLOAD
        ) or os.path.expanduser("~/Downloads")
        try:
            os.makedirs(downloads_dir, exist_ok=True)
        except OSError as e:
            logger.error(f"Failed to create downloads directory: {str(e)}")
            raise

    def show(self):
        """Show the downloads area."""
        if not hasattr(self, "download_area"):
            self.download_area = Gtk.ScrolledWindow()
            self.download_area.set_policy(
                Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC
            )
            self.download_area.set_max_content_height(200)
            self.download_area.set_min_content_height(0)
            self.download_area.set_child(self.box)
            self.download_area.set_vexpand(False)
            self.download_area.set_margin_top(5)
            self.download_area.set_margin_bottom(5)
            parent_window = self.parent_window
            parent_child = parent_window.get_child()
            if parent_child is not None and hasattr(parent_child, "append"):
                if self.download_area.get_parent() is None:
                    parent_child.append(self.download_area)

    def clear_all(self):
        """Clear all completed downloads from the UI."""
        for download, info in list(self.downloads.items()):
            if info["status"] in ["Finished", "Failed", "Cancelled"]:
                self.cleanup_download(download)

class AdBlocker:
    def __init__(self):
        self.blocked_patterns = []
        self.enabled = True
        self.block_list_url = "https://easylist.to/easylist/easylist.txt"
        self.cache_file = "easylist_cache.txt"
        self.cache_max_age = 86400
        self.adult_patterns = [

        ]
        self.load_block_lists()

    def inject_to_webview(self, user_content_manager):
        self.inject_adblock_script_to_ucm(user_content_manager)

    def inject_adblock_script_to_ucm(self, user_content_manager):
        """
        Injects JavaScript into UserContentManager to block ads and handle void links.
        """
        adblock_script = r"""
        (function() {
            // List of CSS selectors for common ad/tracker elements
            const selectorsToHide = [
                '.ad', '.ads', '.advert', '.advertisement', '.banner', '.promo', '.sponsored',
                '[id*="ad-"]', '[id*="ads-"]', '[id*="advert-"]', '[id*="banner"]',
                '[class*="-ad"]', '[class*="-ads"]', '[class*="-advert"]', '[class*="-banner"]',
                '[class*="adbox"]', '[class*="adframe"]', '[class*="adwrapper"]', '[class*="bannerwrapper"]',
                'iframe[src*="ad"], iframe[src*="ads"]',
                'div[id^="google_ads_"]',
                'div[class^="adsbygoogle"]',
                'ins.adsbygoogle'
            ];
            function hideElements() {
                selectorsToHide.forEach(selector => {
                    try {
                        document.querySelectorAll(selector).forEach(el => {
                            if (el.style.display !== 'none' || el.style.visibility !== 'hidden') {
                                el.style.setProperty('display', 'none', 'important');
                                el.style.setProperty('visibility', 'hidden', 'important');
                            }
                        });
                    } catch (e) {
                        console.error('AdBlock: Error querying selector', selector, e);
                    }
                });
            }
            // URL blocking patterns
            function isUrlBlocked(url) {
                if (!url) return false;
                const patterns = [
                    /doubleclick\.net/,
                    /googlesyndication\.com/,
                    /\/ads\//,
                    /adframe\./,
                    /bannerads\./
                ];
                return patterns.some(p => p.test(url));
            }
            // Intercept XMLHttpRequest
            const OriginalXHR = window.XMLHttpRequest;
            window.XMLHttpRequest = function() {
                const xhr = new OriginalXHR();
                const originalOpen = xhr.open;
                xhr.open = function(method, url) {
                    if (isUrlBlocked(url)) {
                        arguments[1] = 'about:blank#blocked';
                    }
                    return originalOpen.apply(this, arguments);
                };
                return xhr;
            };
            // Intercept fetch
            if (window.fetch) {
                const originalFetch = window.fetch;
                window.fetch = function(input, init) {
                    const url = typeof input === 'string' ? input : (input && input.url);
                    if (isUrlBlocked(url)) {
                        return Promise.reject(new Error('AdBlock: Fetch blocked'));
                    }
                    return originalFetch.apply(this, arguments);
                };
            }
            // Override window.open to prevent popups to ad URLs
            const originalOpen = window.open;
            window.open = function(url, name, features) {
                if (isUrlBlocked(url)) return null;
                return originalOpen.apply(this, arguments);
            };
            // Hide existing ad elements
            hideElements();
            // Observe DOM for dynamically added ads
            const observer = new MutationObserver(() => {
                hideElements();
            });
            if (document.body instanceof Node) {
                observer.observe(document.body, { childList: true, subtree: true });
            }
        })();
        """
        custom_script = r"""
        // Inject a script to handle void(0) links
        (function() {
            window.addEventListener('click', function(event) {
                // Look for void(0) links with onclick handlers
                let target = event.target;
                while (target && target.tagName !== 'A') {
                    target = target.parentElement;
                }
                if (target && target.tagName === 'A') {
                    const href = target.getAttribute('href');
                    if (href && href.trim().toLowerCase() === 'javascript:void(0)') {
                        // Prevent default behavior
                        event.preventDefault();
                        event.stopPropagation();

                        // Get the onclick handler
                        const onclick = target.getAttribute('onclick');
                        if (onclick) {
                            // Look for dbneg function call
                            const match = onclick.match(/dbneg\(['"]([^'"]+)['"]\)/);
                            if (match) {
                                const id = match[1];
                                console.log('Found dbneg ID:', id);

                                // Construct the URL using the dbneg function
                                const url = window.dbneg(id);
                                console.log('Constructed URL:', url);

                                // Send the URL to Python
                                if (url && url !== 'about:blank' && url !== window.location.href) {
                                    if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.voidLinkClicked) {
                                        window.webkit.messageHandlers.voidLinkClicked.postMessage(url);
                                    }
                                }
                            }
                        }
                    }
                }
            }, true);
        })();
        """
        user_content_manager.add_script(
            WebKit.UserScript.new(
                adblock_script,
                WebKit.UserContentInjectedFrames.ALL_FRAMES,
                WebKit.UserScriptInjectionTime.START,
            )
        )
        user_content_manager.add_script(
            WebKit.UserScript.new(
                custom_script,
                WebKit.UserContentInjectedFrames.ALL_FRAMES,
                WebKit.UserScriptInjectionTime.END,
            )
        )
        print("AdBlock scripts and link handler injected.")

    def enable(self):
        self.enabled = True
        logger.info("Ad Blocker Enabled")

    def disable(self):
        self.enabled = False
        logger.info("Ad Blocker Disabled")

    def load_block_lists(self):
        """Loads and caches ad blocking patterns from EasyList."""
        if (
            os.path.exists(self.cache_file)
            and (time.time() - os.path.getmtime(self.cache_file)) < self.cache_max_age
        ):
            with open(self.cache_file, "r", encoding="utf-8") as f:
                lines = [
                    line.strip() for line in f if line and not line.startswith("!")
                ]
            logger.info("Loaded block list from cache.")
        else:
            lines = self.fetch_block_list(self.block_list_url)
            with open(self.cache_file, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            logger.info("Fetched and cached new block list.")
        self.blocked_patterns = self._parse_block_patterns(lines)
        logger.info(f"Loaded {len(self.blocked_patterns)} ad blocking patterns.")

    def fetch_block_list(self, url):
        """Fetches the block list content from a URL."""
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return [
                line.strip()
                for line in response.text.splitlines()
                if line and not line.startswith("!")
            ]
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching block list from {url}: {e}")
            return []

    def _parse_block_patterns(self, lines):
        """Parses block list rules into regex patterns."""
        compiled_patterns = []
        for line in lines:
            if any(s in line for s in ("##", "#@#", "@@")):
                continue
            try:
                pattern = line
                if pattern.startswith("||"):
                    pattern = r"^https?://([a-z0-9-]+\.)?" + re.escape(pattern[2:])
                elif pattern.startswith("|"):
                    pattern = r"^" + re.escape(pattern[1:])
                elif pattern.endswith("|"):
                    pattern = re.escape(pattern[:-1]) + r"$"
                pattern = re.escape(pattern)
                pattern = pattern.replace(r"\*", ".*")
                pattern = pattern.replace(r"\^", r"[^a-zA-Z0-9_\-%\.]")
                pattern = pattern.replace(r"\|", "")
                regex = re.compile(pattern, re.IGNORECASE)
                compiled_patterns.append(regex)
            except re.error as e:
                logger.warning(f"Skipped invalid pattern: {line} (error: {e})")
        return compiled_patterns

    def is_blocked(self, url):
        """Checks if the given URL matches any blocked pattern."""
        if not self.enabled or not url:
            return False
        try:
            parsed = urlparse(url)
            full_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            for pattern in self.adult_patterns:
                if pattern in full_url.lower():
                    logger.warning(f"Blocked adult content URL: {url}")
                    return True
            for pattern in self.blocked_patterns:
                if pattern.search(full_url):
                    logger.debug(
                        f"Blocked URL: {url} matched pattern {pattern.pattern}"
                    )
                    return True
        except Exception as e:
            logger.error(f"Error checking URL '{url}': {e}")
        return False

    def connect_webview_signals(self, webview):
        webview.connect("load-changed", self.on_load_changed)
        webview.connect("notify::title", self.on_title_changed)
        webview.connect("decide-policy", self.on_decide_policy)

    def is_mime_type_displayable(self, mime_type):
        displayable_types = [
            "text/html",
            "text/plain",
            "image/png",
            "image/jpeg",
            "image/gif",
            "application/xhtml+xml",
        ]
        return mime_type in displayable_types if mime_type else False

    def validate_and_clean_url(self, url):
        cleaned_url = url.strip()
        if not re.match(r"^(http|https)://", cleaned_url):
            cleaned_url = "https://" + cleaned_url
        parsed_url = urlparse(cleaned_url)
        if not parsed_url.netloc:
            raise ValueError(f"Invalid URL: {cleaned_url}")
        return urlunparse(parsed_url)

    def enable_csp(self, webview):
        settings = webview.get_settings()
        csp_policy = "default-src 'self'; script-src 'self' https://trusted.com;"
        settings.set_property("content-security-policy", csp_policy)
        logger.info(f"Content Security Policy enabled: {csp_policy}")

    def report_csp_violation(self, report):
        logger.warning(f"CSP Violation Report: {report}")

    def on_csp_violation(self, report):
        """Handles CSP violation and passes it to report_csp_violation."""
        self.report_csp_violation(report)

    def is_third_party_request(self, url, current_origin):
        try:
            page_origin = urlparse(self.get_current_webview().get_uri()).netloc
            return current_origin != page_origin
        except Exception as e:
            logger.warning(f"origin comparison error: {e}")
            return False

    def enable_mixed_content_blocking(self, webview):
        settings = webview.get_settings()
        settings.set_property("allow-running-insecure-content", False)
        webview.set_settings(settings)
        logger.info("Mixed content blocking enabled.")

    def secure_cookies(self):
        """Disable all cookies by setting accept policy to NEVER."""
        try:
            webview = self.get_current_webview()
            if webview:
                cookie_manager = webview.get_context().get_cookie_manager()
                cookie_manager.set_accept_policy(WebKit.CookieAcceptPolicy.NEVER)
                logger.info("All cookies acceptance disabled.")
        except Exception as e:
            logger.error(f"Error securing cookies: {e}")

    def set_samesite_cookie(self, cookie_manager, cookie):
        cookie.set_same_site(WebKit.CookieSameSitePolicy.STRICT)
        cookie_manager.set_cookie(cookie)
        logger.info(f"Cookie {cookie.get_name()} set with SameSite Strict policy.")

class Tab:
    def __init__(self, url, webview):
        self.url = url
        self.webview = webview
        self.label_widget = None

class ShadowBrowser(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="com.shadowyfigure.shadowbrowser")
        self.webview = WebKit.WebView()
        self.setup_webview_settings(self.webview)
        self.webview.connect("create", self.on_webview_create)
        self.bookmarks = self.load_json(BOOKMARKS_FILE)
        self.history = self.load_json(HISTORY_FILE)
        self.tabs = []
        self.blocked_urls = []
        self.window = None
        self.notebook = Gtk.Notebook()
        self.url_entry = Gtk.Entry()
        self.home_url = "https://duckduckgo.com/"
        self.theme = "dark"
        self.download_manager = DownloadManager(self)
        self.content_manager = WebKit.UserContentManager()
        self.context = ssl.create_default_context()
        self.adblocker = AdBlocker()
        self.adblocker.disable()
        self.debug_mode = True
        self.error_handlers = {}
        self.register_error_handlers()
        self.download_spinner = Gtk.Spinner()
        self.download_spinner.set_visible(False)
        try:
            self.adblocker.inject_to_webview(self.content_manager)
            self.content_manager.register_script_message_handler("voidLinkClicked")
            self.content_manager.connect("script-message-received::voidLinkClicked", self.on_void_link_clicked)
            test_script = WebKit.UserScript.new(
                "console.log('Test script injected into shared content manager');",
                WebKit.UserContentInjectedFrames.ALL_FRAMES,
                WebKit.UserScriptInjectionTime.START,
            )
            self.content_manager.add_script(test_script)
        except Exception as e:
            print(f"AdBlock injection error in shared content manager: {e}")
        self.inject_mouse_event_script()

    def uuid_to_token(self, uuid_str: str) -> str:
        """
        Convert a UUID string to a short base64url token.
        """
        import base64
        import uuid
        try:
            u = uuid.UUID(uuid_str)
            b = u.bytes
            token = base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')
            return token
        except Exception as e:
            logger.error(f"Error converting UUID to token: {e}")
            return uuid_str

    def transform_embed_selector_links(self, html_content: str) -> str:
        """
        Transform UUIDs in <a> tags with class 'embed-selector asg-hover even' and onclick handlers
        by replacing UUIDs with short tokens in the onclick attribute.
        """
        import re

        def replace_uuid(match):
            original = match.group(0)
            uuid_str = match.group(1)
            token = self.uuid_to_token(uuid_str)
            replaced = original.replace(uuid_str, token)
            return replaced
        pattern = r"onclick=\"window\.open\(dbneg\('([0-9a-fA-F\-]+)'\)"
        transformed_html = re.sub(pattern, replace_uuid, html_content)
        return transformed_html

    def dbneg(self, id_string: str) -> str:
        """
        Python equivalent of the JavaScript dbneg function.
        Constructs a URL with the given IDs as a query parameter.
        """
        base_url = "https://example.com/dbneg?ids="
        import urllib.parse
        encoded_ids = urllib.parse.quote(id_string)
        return base_url + encoded_ids

    def get_current_webview(self):
        """Return the webview of the currently active tab."""
        current_page = self.notebook.get_current_page()
        if current_page == -1:
            return None
        child = self.notebook.get_nth_page(current_page)
        if child is None:
            return None
        if isinstance(child, Gtk.ScrolledWindow):
            inner_child = child.get_child()
            if isinstance(inner_child, Gtk.Viewport):
                webview = inner_child.get_child()
                return webview
            return inner_child
        if isinstance(child, WebKit.WebView):
            return child
        return None

    def create_secure_webview(self):
        webview = WebKit.WebView(user_content_manager=self.content_manager)
        settings = webview.get_settings()
        settings.set_property("enable-javascript", True)
        settings.set_property("enable-media-stream", True)
        settings.set_property("enable-webgl", True)
        self.setup_webview_settings(webview)
        self.download_manager.add_webview(webview)
        return webview

    def on_void_link_clicked(self, user_content_manager, js_message):
        try:
            url = js_message.to_string()
            logger.info(f"Final URL received: {url}")
            if url and url != 'about:blank':
                logger.info(f"Opening URL in new tab: {url}")
                self.open_url_in_new_tab(url)
        except Exception as e:
            logger.error(f"Error handling voidLinkClicked message: {e}")

    def setup_webview_settings(self, webview):
        """Configure WebView settings for security and compatibility."""
        settings = webview.get_settings()
        settings.set_enable_javascript(True)
        settings.set_enable_developer_extras(True)
        settings.set_enable_media_stream(True)
        settings.set_enable_media_capabilities(True)
        settings.set_enable_mediasource(True)
        settings.set_enable_smooth_scrolling(True)
        settings.set_enable_webgl(True)
        settings.set_enable_webaudio(True)
        settings.set_allow_file_access_from_file_urls(False)
        settings.set_allow_universal_access_from_file_urls(False)
        settings.set_allow_modal_dialogs(True)
        settings.set_javascript_can_access_clipboard(True)
        settings.set_javascript_can_open_windows_automatically(True)
        settings.set_media_playback_requires_user_gesture(False)

    def inject_mouse_event_script(self):
        """Injects JavaScript to capture mouse events in webviews."""
        script = WebKit.UserScript.new(
            """
            (function() {
                document.addEventListener('click', function(e) {
                    let target = e.target;
                    while (target && target.tagName !== 'A') {
                        target = target.parentElement;
                    }
                    if (target && target.tagName === 'A') {
                        const href = target.getAttribute('href');
                        if (href && href.trim().toLowerCase() === 'javascript:void(0)') {
                            e.preventDefault();
                            e.stopPropagation();
                            const dataUrl = target.getAttribute('data-url');
                            if (dataUrl) {
                                // Instead of opening new tab here, send message to Python side
                                const clickEvent = new CustomEvent('voidLinkClicked', { detail: { href: dataUrl } });
                                target.dispatchEvent(clickEvent);
                            } else {
                                console.warn('No data-url specified for this link. No action taken.');
                            }
                        }
                    }
                }, true);
            })();
            """,
            WebKit.UserContentInjectedFrames.ALL_FRAMES,
            WebKit.UserScriptInjectionTime.START,
        )
        self.content_manager.add_script(script)

    def create_toolbar(self):
        if hasattr(self, "toolbar") and self.toolbar is not None:
            return self.toolbar
        self.toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        self.toolbar.set_spacing(6)
        self.toolbar.set_margin_start(6)
        self.toolbar.set_margin_end(6)
        self.toolbar.set_margin_top(6)
        self.toolbar.set_margin_bottom(6)
        back_button = Gtk.Button.new_from_icon_name("go-previous")
        back_button.connect("clicked", self.on_back_clicked)
        self.toolbar.append(back_button)
        forward_button = Gtk.Button.new_from_icon_name("go-next")
        forward_button.connect("clicked", self.on_forward_clicked)
        self.toolbar.append(forward_button)
        refresh_button = Gtk.Button.new_from_icon_name("view-refresh")
        refresh_button.connect("clicked", self.on_refresh_clicked)
        self.toolbar.append(refresh_button)
        home_button = Gtk.Button.new_from_icon_name("go-home")
        home_button.connect("clicked", lambda b: self.load_url(self.home_url))
        self.toolbar.append(home_button)
        self.url_entry = Gtk.Entry()
        self.url_entry.set_placeholder_text("Enter URL")
        self.url_entry.connect("activate", self.on_go_clicked)
        self.toolbar.append(self.url_entry)
        go_button = Gtk.Button.new_from_icon_name("go-jump")
        go_button.connect("clicked", self.on_go_clicked)
        self.toolbar.append(go_button)
        add_bookmark_button = Gtk.Button.new_from_icon_name("bookmark-new")
        add_bookmark_button.set_tooltip_text("Add current page to bookmarks")
        add_bookmark_button.connect("clicked", self.on_add_bookmark_clicked)
        self.toolbar.append(add_bookmark_button)
        new_tab_button = Gtk.Button.new_from_icon_name("tab-new")
        new_tab_button.connect("clicked", self.on_new_tab_clicked)
        self.toolbar.append(new_tab_button)
        self.toolbar.append(self.download_spinner)
        self.download_spinner.set_halign(Gtk.Align.END)
        self.download_spinner.set_valign(Gtk.Align.CENTER)
        self.download_spinner.set_margin_start(10)
        self.download_spinner.set_margin_end(10)
        self.download_spinner.set_visible(False)
        return self.toolbar

    def _show_bookmarks_menu(self, button=None):
        """Show the bookmarks menu."""
        if hasattr(self, "toolbar") and self.toolbar is not None:
            for child in self.toolbar.get_children():
                if isinstance(child, Gtk.MenuButton) and child.get_label() == "Bookmarks":
                    popover = child.get_popover()
                    if popover:
                        popover.popup()
                        return

    def do_startup(self):
        Gtk.Application.do_startup(self)

    def do_activate(self):
        try:
            self.window = Gtk.ApplicationWindow(application=self)
            self.window.set_default_size(1024, 768)
            self.window.set_title("Shadow Browser")
            self.window.set_icon_name("web-browser")
            vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            self.window.set_child(vbox)
            menubar = self.create_menubar()
            if menubar.get_parent() is None:
                vbox.append(menubar)
            toolbar = self.create_toolbar()
            if toolbar.get_parent() is None:
                vbox.append(toolbar)
            if self.notebook.get_parent() is None:
                vbox.append(self.notebook)
            self.download_area = self.download_manager.box
            self.download_area.set_vexpand(False)
            if self.download_area.get_parent() is None:
                vbox.append(self.download_area)
            if not self.tabs:
                self.add_new_tab(self.home_url)
            self.apply_theme()
            self.window.present()

        except Exception as e:
            logger.error(f"Error during activation: {e}")

    def do_shutdown(self):
        try:
            self.save_session()
            self.save_tabs()
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
        Gtk.Application.do_shutdown(self)

    def register_error_handlers(self):
        self.error_handlers["gtk_warning"] = self.handle_gtk_warning
        self.error_handlers["network_error"] = self.handle_network_error
        self.error_handlers["webview_error"] = self.handle_webview_error
        self.error_handlers["memory_error"] = self.handle_memory_error

    def handle_gtk_warning(self, message):
        logger.warning(f"GTK Warning: {message}")
        return True

    def handle_network_error(self, url, error):
        logger.warning(f"Network error loading {url}: {error}")
        return True

    def handle_webview_error(self, webview, error):
        logger.warning(f"WebView error: {error}")
        return True

    def handle_memory_error(self, error):
        logger.warning(f"Memory error: {error}")
        return True

    def toggle_debug_mode(self, action, parameter):
        self.debug_mode = not self.debug_mode
        logger.info(f"Debug mode: {'enabled' if self.debug_mode else 'disabled'}")

    def create_menubar(self):
        menubar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        bookmark_menu_button = Gtk.MenuButton(label="Bookmarks")
        bookmark_popover = Gtk.Popover()
        self.bookmark_menu = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.update_bookmarks_menu(self.bookmark_menu)
        bookmark_popover.set_child(self.bookmark_menu)
        bookmark_menu_button.set_popover(bookmark_popover)
        bookmark_popover.connect("closed", lambda popover: popover.set_visible(False))
        menubar.append(bookmark_menu_button)
        about_button = Gtk.Button(label="About")
        about_button.connect("clicked", self.on_about)
        menubar.append(about_button)
        return menubar

    def on_search_activate(self, search_entry):
        query = search_entry.get_text().strip()
        if not query:
            return
        if self.is_valid_url(query):
            self.load_url(query)
        else:
            search_url = f"https://duckduckgo.com/?q={requests.utils.quote(query)}"
            self.load_url(search_url)

    def is_valid_url(self, url):
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False

    def load_url(self, url):
        """Load a URL in the current active webview."""
        try:
            if not url.startswith(("http://", "https://")):
                if url.startswith("www."):
                    url = "https://" + url
                else:
                    url = f"https://duckduckgo.com/?q={requests.utils.quote(url)}"
            logger.info(f"Loading URL: {url}")
            webview = self.get_current_webview()
            if webview:
                webview.load_uri(url)
                self.url_entry.set_text(url)
                self.update_history(url)
        except Exception as e:
            logger.error(f"Error loading URL: {e}")
            self.show_error_message(f"Error loading URL: {e}")

    def on_add_bookmark_clicked(self, button):
        """Handle Add Bookmark button click."""
        current_webview = self.get_current_webview()
        if current_webview:
            url = current_webview.get_uri()
            if url:
                self.add_bookmark(url)

    def add_bookmark(self, url):
        """Add URL to bookmarks."""
        if not url or not url.startswith(("http://", "https://")):
            logger.warning(f"Attempted to add invalid bookmark URL: {url}")
            return
        if url not in self.bookmarks:
            self.bookmarks.append(url)
            self.save_json(BOOKMARKS_FILE, self.bookmarks)
            self.update_bookmarks_menu(self.bookmark_menu)
            logger.info(f"Added bookmark: {url}")
            return True
        return False

    def update_bookmarks_menu(self, menu_box):
        """Update the bookmarks menu with current bookmarks."""
        while menu_box.get_first_child():
            menu_box.remove(menu_box.get_first_child())
        for bookmark in self.bookmarks:
            if isinstance(bookmark, str) and bookmark.startswith(
                ("http://", "https://")
            ):
                row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
                bookmark_button = Gtk.Button(label=bookmark)
                bookmark_button.connect(
                    "clicked", lambda btn, url=bookmark: self.load_url(url)
                )
                row.append(bookmark_button)
                delete_button = Gtk.Button(label="❌")
                delete_button.connect(
                    "clicked", lambda btn, url=bookmark: self.delete_bookmark(url)
                )
                row.append(delete_button)
                menu_box.append(row)

    def delete_bookmark(self, bookmark):
        """Remove a bookmark."""
        if bookmark in self.bookmarks:
            self.bookmarks.remove(bookmark)
            self.save_json(BOOKMARKS_FILE, self.bookmarks)
            self.update_bookmarks_menu(self.bookmark_menu)
            logger.info(f"Deleted bookmark: {bookmark}")
        else:
            logger.warning(f"Attempted to delete non-existent bookmark: {bookmark}")

    def update_history(self, url):
        """Add URL to browser history."""
        if url and url.startswith(("http://", "https://")):
            logger.info(f"Adding URL to history: {url}")
            self.history.append({"url": url, "timestamp": time.time()})
            self.history = self.history[-HISTORY_LIMIT:]
            self.save_json(HISTORY_FILE, self.history)

    def load_json(self, filename):
        """Load JSON data from file."""
        try:
            if os.path.exists(filename):
                with open(filename, "r") as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Error loading JSON from {filename}: {e}")
        return []

    def save_json(self, filename, data):
        """Save JSON data to file."""
        try:
            with open(filename, "w") as f:
                json.dump(data, f)
        except Exception as e:
            logger.error(f"Error saving JSON to {filename}: {e}")

    def show_error_message(self, message):
        """Display an error message dialog."""
        dialog = Gtk.MessageDialog(
            transient_for=self.window,
            modal=True,
            message_type=Gtk.MessageType.ERROR,
            buttons=Gtk.ButtonsType.OK,
            text=message,
        )
        dialog.connect("response", lambda d, r: d.destroy())
        dialog.present()

    def on_about(self, button):
        """Show the about dialog."""
        about = Gtk.AboutDialog(transient_for=self.window)
        about.set_program_name("Shadow Browser")
        about.set_version("1.0")
        about.set_copyright(" 2025 ShadowyFigure")
        about.set_comments("A privacy-focused web browser")
        about.set_website("https://github.com/shadowyfigure/shadow-browser")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        image_path = os.path.join(script_dir, "background.png")
        try:
            if os.path.exists(image_path):
                pixbuf = GdkPixbuf.Pixbuf.new_from_file(image_path)
                texture = Gdk.Texture.new_for_pixbuf(pixbuf)
                about.set_logo(texture)
            else:
                logger.warning(f"Logo file not found: {image_path}")
                about.set_logo_icon_name("web-browser")
        except Exception as e:
            logger.error(f"Failed to load image: {e}")
        about.present()

    def on_back_clicked(self, button):
        """Handle back button click."""
        webview = self.get_current_webview()
        if webview and webview.can_go_back():
            webview.go_back()

    def on_new_tab_clicked(self, button):
        """Handle New Tab button click."""
        self.add_new_tab(self.home_url)

    def add_new_tab(self, url):
        """Add a new tab with a webview loading the specified URL."""
        webview = self.create_secure_webview()
        webview.load_uri(url)
        scrolled_window = Gtk.ScrolledWindow()
        scrolled_window.set_vexpand(True)
        scrolled_window.set_child(webview)
        label = Gtk.Label(label=self.extract_tab_title(url))
        close_button = Gtk.Button.new_from_icon_name("window-close")
        close_button.set_size_request(24, 24)
        close_button.set_tooltip_text("Close tab")
        close_button.connect("clicked", self.on_tab_close_clicked, webview)
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        box.append(label)
        box.append(close_button)
        index = self.notebook.append_page(scrolled_window, box)
        self.notebook.set_current_page(index)
        tab = Tab(url, webview)
        tab.label_widget = label
        self.tabs.append(tab)
        webview.connect("load-changed", self.on_load_changed)
        webview.connect("notify::title", self.on_title_changed)
        webview.connect("decide-policy", self.on_decide_policy)

    def on_tab_close_clicked(self, button, tab_index):
        """Close the tab at the given index."""
        logger.info(f"Close button clicked for tab index: {tab_index}")
        if 0 <= tab_index < len(self.tabs):
            tab = self.tabs[tab_index]
            webview = tab.webview
            notebook_page_num = None
            for page_index in range(self.notebook.get_n_pages()):
                page = self.notebook.get_nth_page(page_index)
                logger.info(f"Checking notebook page {page_index} for webview")
                if isinstance(page, Gtk.ScrolledWindow):
                    child = page.get_child()
                    if child == webview or (isinstance(child, Gtk.Viewport) and child.get_child() == webview):
                        notebook_page_num = page_index
                        logger.info(f"Found notebook page {notebook_page_num} for webview")
                        break
            if notebook_page_num is not None:
                logger.info(f"Removing notebook page {notebook_page_num}")
                self.notebook.remove_page(notebook_page_num)
            else:
                logger.warning("Notebook page for webview not found")
            self.tabs.pop(tab_index)
            logger.info(f"Removed tab at index {tab_index}")
            try:
                webview.unparent()
                logger.info("Webview unparented successfully")
            except Exception as e:
                logger.error(f"Error unparenting webview on tab close: {e}")

    def on_load_changed(self, webview, load_event):
        """Handle load state changes."""
        from gi.repository import WebKit
        if load_event == WebKit.LoadEvent.COMMITTED:
            logger.info(f"Page load committed: {webview.get_uri()}")
            current_webview = self.get_current_webview()
            if webview == current_webview:
                self.url_entry.set_text(webview.get_uri() or "")
            GLib.idle_add(self.download_spinner.start)
            GLib.idle_add(lambda: self.download_spinner.set_visible(True))
        elif load_event == WebKit.LoadEvent.FINISHED:
            logger.info(f"Page load finished: {webview.get_uri()}")
            GLib.idle_add(self.download_spinner.stop)
            GLib.idle_add(lambda: self.download_spinner.set_visible(False))

    def on_title_changed(self, webview, param):
        """Update tab label when page title changes."""
        max_length = 10
        title = webview.get_title() or "Untitled"
        if len(title) > max_length:
            title = title[:max_length - 3] + "..."
        for i, tab in enumerate(self.tabs):
            if tab.webview == webview and tab.label_widget is not None:
                tab.label_widget.set_text(title)
                break

    def on_webview_create(self, webview, navigation_action, window_features=None):
        """Handle creation of new webviews."""
        try:
            logger.info("on_webview_create called")
            user_content_manager = webview.get_user_content_manager()
            new_webview = WebKit.WebView(user_content_manager=user_content_manager)
            settings = webview.get_settings()
            new_webview.set_settings(settings)
            self.setup_webview_settings(new_webview)
            if not hasattr(new_webview, "_create_signal_connected"):
                new_webview.connect("create", self.on_webview_create)
                new_webview._create_signal_connected = True
            if not hasattr(new_webview, "_decide_policy_connected"):
                new_webview.connect("decide-policy", self.on_decide_policy)
                new_webview._decide_policy_connected = True
            if window_features:
                try:
                    if hasattr(window_features, "get") and callable(window_features.get):
                        if window_features.get("modal"):
                            new_webview.set_modal(True)
                        width = window_features.get("width")
                        height = window_features.get("height")
                        if width and height:
                            new_webview.set_size_request(width, height)
                    else:
                        logger.warning("window_features does not have a get method")
                except Exception as wf_exc:
                    logger.error(f"Exception accessing window_features: {wf_exc}")
            is_popup = False
            try:
                if window_features and hasattr(window_features, "get") and callable(window_features.get):
                    is_popup = window_features.get("popup", False)
            except Exception as e:
                logger.error(f"Error checking popup flag in window_features: {e}")
            if is_popup:
                logger.info("Opening in popup window.")
                self.open_popup_window(new_webview, window_features)
            else:
                logger.info("Opening in new tab.")
                self.add_webview_to_tab(new_webview)
            return new_webview
        except Exception as e:
            logger.error(f"Error in on_webview_create: {e}")
            return None

    def on_decide_policy(self, webview, decision, decision_type):
        """Handle navigation and new window actions, manage downloads, and apply adblocker policies."""
        try:
            from gi.repository import WebKit
            if decision_type == WebKit.PolicyDecisionType.NAVIGATION_ACTION:
                navigation_action = decision.get_navigation_action()
                request = navigation_action.get_request()
                url = request.get_uri()
                if not url:
                    logger.warning("Navigation request has no URL")
                    decision.ignore()
                    return True
                if url.lower() == "javascript:void(0)":
                    logger.info("Ignoring navigation to javascript:void(0)")
                    decision.ignore()
                    return True
                if self.adblocker.is_blocked(url):
                    logger.warning(f"Blocked navigation to: {url}")
                    decision.ignore()
                    return True
                if url.lower().endswith(tuple(DOWNLOAD_EXTENSIONS)):
                    logger.info(f"Starting download for: {url}")
                    self.start_manual_download(url)
                    decision.ignore()
                    return True
                decision.use()
                return False
            elif decision_type == WebKit.PolicyDecisionType.NEW_WINDOW_ACTION:
                try:
                    logger.info("Handling new window action")
                    navigation_action = decision.get_navigation_action()
                    if navigation_action is None:
                        logger.warning("Navigation action is None in NEW_WINDOW_ACTION")
                        decision.ignore()
                        return True
                    request = navigation_action.get_request()
                    if request is None:
                        logger.warning("Request is None in NEW_WINDOW_ACTION")
                        decision.ignore()
                        return True
                    url = request.get_uri()
                    if url is None:
                        logger.warning("URL is None in NEW_WINDOW_ACTION")
                        decision.ignore()
                        return True
                    if url.lower() == "javascript:void(0)":
                        logger.info("Ignoring void(0) new window action")
                        decision.ignore()
                        return True
                    if any(url.lower().endswith(ext) for ext in DOWNLOAD_EXTENSIONS):
                        logger.info(f"Starting download for URL: {url}")
                        self.start_manual_download(url)
                        decision.ignore()
                        return True
                    logger.info(f"Opening new window action URL in new tab: {url}")
                    new_webview = WebKit.WebView()
                    self.setup_webview_settings(new_webview)
                    self.download_manager.add_webview(new_webview)
                    if not hasattr(new_webview, "_create_signal_connected"):
                        new_webview.connect("create", self.on_webview_create)
                        new_webview._create_signal_connected = True
                    if not hasattr(new_webview, "_decide_policy_connected"):
                        new_webview.connect("decide-policy", self.on_decide_policy)
                        new_webview._decide_policy_connected = True
                    self.add_webview_to_tab(new_webview)
                    new_webview.load_uri(url)
                    decision.ignore()
                    return True
                except Exception as e:
                    logger.error(f"Error handling new window action: {e}")
                    decision.ignore()
                    return True
            else:
                decision.use()
                return False
        except Exception as ex:
            logger.error(f"Error in decide_policy: {str(ex)}")
            decision.ignore()
            return True

    def add_download_spinner(self, toolbar):
        """Add download spinner to toolbar."""
        if toolbar:
            toolbar.append(self.download_spinner)
            self.download_spinner.set_halign(Gtk.Align.END)
            self.download_spinner.set_valign(Gtk.Align.END)
            self.download_spinner.set_margin_start(10)
            self.download_spinner.set_margin_end(10)
            self.download_spinner.set_visible(True)

    def start_manual_download(self, url):
        """Manually download a file from the given URL."""
        import requests
        from urllib.parse import urlparse

        def download_thread():
            try:
                parsed_url = urlparse(url)
                if not parsed_url.scheme or not parsed_url.netloc:
                    GLib.idle_add(
                        lambda: self.show_error_message("Invalid URL format"),
                        priority=GLib.PRIORITY_DEFAULT
                    )
                    return
                with requests.get(url, stream=True, timeout=30) as response:
                    response.raise_for_status()
                    filename = None
                    content_disposition = response.headers.get('content-disposition')
                    if content_disposition:
                        filename_match = re.search(r'filename="?([^"\\s]+)"?', content_disposition)
                        if filename_match:
                            filename = filename_match.group(1)
                    if not filename:
                        filename = os.path.basename(parsed_url.path)
                    if not filename:
                        filename = "download"
                    downloads_dir = GLib.get_user_special_dir(
                        GLib.UserDirectory.DIRECTORY_DOWNLOAD
                    ) or os.path.expanduser("~/Downloads")
                    os.makedirs(downloads_dir, exist_ok=True)
                    counter = 1
                    base_name, ext = os.path.splitext(filename)
                    while os.path.exists(os.path.join(downloads_dir, filename)):
                        filename = f"{base_name}_{counter}{ext}"
                        counter += 1
                    filepath = os.path.join(downloads_dir, filename)
                    total_size = int(response.headers.get('content-length', 0))
                    block_size = 8192
                    downloaded = 0
                    progress_info = {
                        'filename': filename,
                        'total_size': total_size,
                        'downloaded': downloaded,
                        'cancelled': False
                    }
                    self.download_manager.add_progress_bar(progress_info)
                    
                    try:
                        with open(filepath, 'wb') as f:
                            for chunk in response.iter_content(block_size):
                                if progress_info['cancelled']:
                                    break
                                if chunk:
                                    f.write(chunk)
                                    downloaded += len(chunk)
                                    progress = downloaded / total_size if total_size > 0 else 0
                                    GLib.idle_add(
                                        self.download_manager.update_progress,
                                        progress_info,
                                        progress
                                    )
                        if not progress_info['cancelled']:
                            GLib.idle_add(
                                self.download_manager.download_finished,
                                progress_info
                            )
                    except Exception as write_error:
                        logger.error(f"Error writing to file: {write_error}")
                        GLib.idle_add(
                            self.download_manager.download_failed,
                            progress_info,
                            str(write_error)
                        )
                    finally:
                        GLib.idle_add(
                            self.download_manager.cleanup_download,
                            progress_info['filename']
                        )
            except requests.exceptions.RequestException as req_error:
                logger.error(f"Download request failed: {req_error}")
                GLib.idle_add(
                    self.download_manager.download_failed,
                    None,
                    str(req_error)
                )
            except Exception as ex:
                logger.error(f"Unexpected download error: {ex}")
                GLib.idle_add(
                    self.download_manager.download_failed,
                    None,
                    str(ex)
                )
        threading.Thread(target=download_thread, daemon=True, name=f"download_{url}").start()

    def on_forward_clicked(self, button):
        """Navigate forward in the current tab."""
        webview = self.get_current_webview()
        if webview and webview.can_go_forward():
            webview.go_forward()

    def on_go_clicked(self, button):
        """Load URL from URL entry."""
        url = self.url_entry.get_text().strip()
        if url:
            self.load_url(url)

    def on_refresh_clicked(self, button):
        """Reload the current webview."""
        webview = self.get_current_webview()
        if webview:
            webview.reload()

    def extract_tab_title(self, url):
        """Extract a display title from a URL, limited to 30 characters."""
        max_length = 30
        try:
            parsed = urlparse(url)
            title = parsed.netloc or "New Tab"
            if len(title) > max_length:
                title = title[:max_length - 3] + "..."
            return title
        except Exception:
            return "New Tab"

    def save_session(self):
        """Save current browser session."""
        session_data = [
            {
                "url": tab.url,
                "title": tab.label_widget.get_text() if tab.label_widget else "",
            }
            for tab in self.tabs
        ]
        self.save_json(SESSION_FILE, session_data)

    def save_tabs(self):
        """Save current tabs info."""
        tabs_data = [tab.url for tab in self.tabs if tab.url]
        self.save_json(TABS_FILE, tabs_data)

    def restore_session(self):
        """Restore previous session."""
        if os.path.exists(SESSION_FILE):
            session_data = self.load_json(SESSION_FILE)
            if session_data and isinstance(session_data, list):
                for tab_data in session_data:
                    if isinstance(tab_data, dict) and "url" in tab_data:
                        self.add_new_tab(tab_data["url"])

    def apply_theme(self):
        """Apply the current theme setting."""
        settings = Gtk.Settings.get_default()
        settings.set_property("gtk-application-prefer-dark-theme", self.theme == "dark")

    def on_window_destroy(self, window):
        """Handle window closure."""
        self.save_session()
        self.quit()
        about = Gtk.AboutDialog()
        about.set_transient_for(self.window)
        about.set_modal(True)
        about.set_program_name("The Shadow Browser")
        about.set_version("1.0")
        about.set_comments("A privacy-focused web browser.")
        about.set_website("https://")
        about.set_website_label("Visit Github")
        about.set_authors(["Shadowy Figure <you@example.com>"])
        about.set_license_type(Gtk.License.MIT_X11)
        script_dir = os.path.dirname(os.path.abspath(__file__))
        image_path = os.path.join(script_dir, "background.png")
        try:
            pixbuf = GdkPixbuf.Pixbuf.new_from_file(image_path)
            texture = Gdk.Texture.new_for_pixbuf(pixbuf)
            about.set_logo(texture)
        except Exception as e:
            logger.error(f"Failed to load image: {e}")

        about.present()

    def simulate_left_click_on_void_link(self, data_url):
        js_code = (
            "(function() {"
            "let links = document.querySelectorAll('a[href=\"javascript:void(0)\"]');"
            f"let targetDataUrl = {json.dumps(data_url)};"
            "for (let link of links) {"
            "if (link.getAttribute('data-url') === targetDataUrl) {"
            "['mousedown', 'mouseup', 'click'].forEach(eventType => {"
            "let event = new MouseEvent(eventType, { view: window, bubbles: true, cancelable: true, button: 0 });"
            "link.dispatchEvent(event);"
            "});"
            "console.log('Simulated click on data-url: ' + targetDataUrl);"
            "return true;"
            "}"
            "}"
            "console.warn('No link found with data-url: ' + targetDataUrl);"
            "return false;"
            "})();"
        )
        webview = self.get_current_webview()
        if webview:
            webview.evaluate_javascript(js_code, self.js_callback)
        else:
            print("No webview available.")

    def js_callback(self, webview, result):
        try:
            if result is None:
                logger.error("JavaScript evaluation error: result is None")
                return
            value = webview.evaluate_javascript_finish(result)
            logger.debug(f"JavaScript evaluation result: {value}")
        except Exception as e:
            logger.error(f"JavaScript evaluation error: {e}")

    def test_js_execution(self):
        webview = self.get_current_webview()
        if webview:
            js_code = "console.log('Test JS execution in webview'); 'JS executed';"
            webview.evaluate_javascript(js_code, self.js_callback)
        else:
            logger.warning("No active webview to test JS execution.")

    def open_url_in_new_tab(self, url):
        new_webview = self.create_secure_webview()
        new_webview.load_uri(url)
        scrolled_window = Gtk.ScrolledWindow()
        scrolled_window.set_vexpand(True)
        scrolled_window.set_child(new_webview)
        label = Gtk.Label(label="Loading...")
        close_button = Gtk.Button.new_from_icon_name("window-close")
        close_button.set_size_request(24, 24)
        close_button.set_tooltip_text("Close tab")
        
        def on_close_clicked(button):
            try:
                tab_index = self.tabs.index(tab)
                self.on_tab_close_clicked(button, tab_index)
            except ValueError:
                logger.warning("Tab not found for close button")
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        box.append(label)
        box.append(close_button)
        index = self.notebook.append_page(scrolled_window, box)
        tab = Tab(url, new_webview)
        self.tabs.append(tab)
        close_button.connect("clicked", on_close_clicked)
        self.notebook.set_current_page(index)
        new_webview.connect("load-changed", self.on_load_changed)
        new_webview.connect("notify::title", self.on_title_changed)
        new_webview.connect("decide-policy", self.on_decide_policy)
        new_webview.connect("create", self.on_webview_create)

    def add_webview_to_tab(self, webview):
        scrolled_window = Gtk.ScrolledWindow()
        scrolled_window.set_vexpand(True)
        scrolled_window.set_child(webview)
        label = Gtk.Label(label=self.extract_tab_title(webview.get_uri()))
        close_button = Gtk.Button.new_from_icon_name("window-close")
        close_button.set_size_request(24, 24)
        def on_close_clicked(button):
            try:
                tab_index = self.tabs.index(tab)
                self.on_tab_close_clicked(button, tab_index)
            except ValueError:
                logger.warning("Tab not found for close button")
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        box.append(label)
        box.append(close_button)
        index = self.notebook.append_page(scrolled_window, box)
        tab = Tab(webview.get_uri(), webview)
        tab.label_widget = label
        self.tabs.append(tab)
        close_button.connect("clicked", on_close_clicked)
        self.notebook.set_current_page(index)
        webview.connect("load-changed", self.on_load_changed)
        webview.connect("notify::title", self.on_title_changed)
        webview.connect("decide-policy", self.on_decide_policy)

    def open_popup_window(self, webview, window_features):
        window = Gtk.Window(title="Popup")
        window.set_transient_for(self.window)
        window.set_destroy_with_parent(True)
        window.set_modal(False)
        if window_features:
            default_width = int(window_features.get_width() or 800)
            default_height = int(window_features.get_height() or 600)
            window.set_default_size(default_width, default_height)
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        vbox.append(webview)
        close_button = Gtk.Button.new_from_icon_name("window-close")
        close_button.set_size_request(24, 24)
        close_button.set_tooltip_text("Close popup")
        close_button.connect("clicked", lambda btn: window.destroy())
        vbox.append(close_button)
        window.set_child(vbox)
        window.show()

    def load_html_with_bootstrap(self, html):
        """
        Load HTML content into the current webview with Bootstrap CSS linked in the head.
        If Bootstrap CSS link is not present, it will be injected.
        """
        webview = self.get_current_webview()
        if not webview:
            logger.error("No active webview to load HTML.")
            return

if __name__ == "__main__":
    app = ShadowBrowser()
    app.run(None)

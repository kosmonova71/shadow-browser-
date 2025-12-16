import base64
import datetime
import hashlib
import json
import os
import threading
import time
import urllib.parse
import ssl
import re
import uuid
import subprocess
import sys
import requests
import gc
import random
import psutil
import socket
import shutil
import gi
from urllib.parse import urlparse, urlunparse, unquote, quote, parse_qs
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from requests.adapters import HTTPAdapter
from stem.control import Controller
from urllib3.util.retry import Retry

try:
    gi.require_version("Gtk", "4.0")
    gi.require_version("WebKit", "6.0")
    gi.require_version("Adw", "1")
    gi.require_version("Gdk", "4.0")
    gi.require_version('Gst', '1.0')
    gi.require_version('GstVideo', '1.0')
    gi.require_version("Soup", "3.0")
    from gi.repository import Gtk, GLib, WebKit, Gdk, Gst, Soup, GdkPixbuf, Gio, GObject, Pango
except (ValueError, ImportError):
    exit(1)

def safe_widget_append(container, widget):
    if not container or not widget:
        return False
    try:
        current_parent = widget.get_parent()
        if current_parent is not None and current_parent != container:
            widget.unparent()
        container.append(widget)
        return True
    except (AttributeError, TypeError):
        return False

DOWNLOAD_EXTENSIONS = [
    ".3gp", ".7z", ".aac", ".apk", ".appimage", ".avi", ".bat", ".bin", ".bmp",
    ".bz2", ".c", ".cmd", ".cpp", ".cs", ".deb", ".dmg", ".dll", ".doc", ".docx",
    ".eot", ".exe", ".flac", ".flv", ".gif", ".gz", ".h", ".ico", ".img", ".iso",
    ".jar", ".java", ".jpeg", ".jpg", ".js", ".lua", ".lz", ".lzma", ".m4a", ".mkv",
    ".mov", ".mp3", ".mp4", ".mpg", ".mpeg", ".msi", ".odp", ".ods", ".odt", ".ogg",
    ".otf", ".pdf", ".pkg", ".pl", ".png", ".pps", ".ppt", ".pptx", ".ps1",
    ".py", ".rar", ".rb", ".rpm", ".rtf", ".run", ".sh", ".so", ".svg", ".tar",
    ".tar.bz2", ".tar.gz", ".tbz2", ".tgz", ".tiff", ".ttf", ".txt", ".vhd", ".vmdk",
    ".wav", ".webm", ".webp", ".wma", ".woff", ".woff2", ".wmv", ".xls", ".xlsx", ".zip"
]

BOOKMARKS_FILE = "bookmarks.json"
HISTORY_FILE = "history.json"
SESSION_FILE = "session.json"
TABS_FILE = "tabs.json"
SETTINGS_FILE = os.path.expanduser("~/.config/shadowbrowser/settings.json")
HISTORY_LIMIT = 100
GST_AVAILABLE = True

try:
    from js_obfuscation_improved import extract_url_from_javascript as js_extract_url
    from js_obfuscation_improved import extract_onclick_url
    extract_onclick_url = extract_onclick_url
except ImportError:
    js_extract_url = None
    extract_onclick_url = None

class SSLUtils:
    def __init__(self):
        self.context = ssl.create_default_context()

    def fetch_certificate(self, url):
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 443
        with socket.create_connection((host, port), timeout=5) as sock:
            with self.context.wrap_socket(sock, server_hostname=host) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                return cert

    def get_ocsp_url(self, cert):
        aia = cert.extensions.get_extension_for_oid(
            x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value
        for access in aia:
            if access.access_method == x509.AuthorityInformationAccessOID.OCSP:
                return access.access_location.value

    def is_certificate_expired(self, cert: x509.Certificate) -> bool:
        return cert.not_valid_after < datetime.datetime.now(datetime.timezone.utc)

class DownloadManager:
    def __init__(self, parent_window):
        self.parent_window = parent_window
        self.box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.downloads = {}
        self.lock = threading.Lock()
        self.ensure_download_directory()
        self.on_download_start_callback = None
        self.on_download_finish_callback = None

    def add_webview(self, webview):
        webview.connect("download-started", self.on_download_started)

    def on_download_started(self, context, download):
        if self.on_download_start_callback:
            self.on_download_start_callback()
        uri = download.get_request().get_uri()
        if not uri:
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
        with self.lock:
            self.downloads[download] = {
                "hbox": hbox,
                "label": label,
                "progress": progress,
                "filepath": filepath,
                "status": "Downloading",
                "cancelled": False,
            }
        safe_widget_append(hbox, label)
        safe_widget_append(hbox, progress)
        safe_widget_append(self.box, hbox)
        download.connect("notify::estimated-progress", self.on_progress_changed)
        download.connect("notify::status", self.on_download_status_changed)
        return True

    def on_progress_changed(self, download, param):
        with self.lock:
            info = self.downloads.get(download)
            if info:
                progress = download.get_estimated_progress()
                info["progress"].set_fraction(progress)
                info["progress"].set_text(f"{progress * 100:.1f}%")
                info["label"].set_text(f"Downloading {os.path.basename(info['filepath'])}")

    def on_download_status_changed(self, download, param):
        with self.lock:
            info = self.downloads.get(download)
            if info:
                status = download.get_status()
                if status == WebKit.DownloadStatus.FINISHED:
                    info["status"] = "Finished"
                    info["progress"].set_fraction(1.0)
                    info["progress"].set_text("100%")
                    info["label"].set_text(f"Download finished: {os.path.basename(info['filepath'])}")
                    GLib.timeout_add_seconds(5, lambda: self.cleanup_download(download))
                elif status == WebKit.DownloadStatus.FAILED:
                    info["status"] = "Failed"
                    info["label"].set_text(f"Download failed: {os.path.basename(info['filepath'])}")
                    info["progress"].set_text("Failed")
                    GLib.timeout_add_seconds(5, lambda: self.cleanup_download(download))
                elif status == WebKit.DownloadStatus.CANCELLED:
                    info["status"] = "Cancelled"
                    info["label"].set_text(f"Download cancelled: {os.path.basename(info['filepath'])}")
                    info["progress"].set_text("Cancelled")
                    GLib.timeout_add_seconds(5, lambda: self.cleanup_download(download))

    def add_progress_bar(self, progress_info):
        with self.lock:
            if self.on_download_start_callback:
                self.on_download_start_callback()
            hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            label = Gtk.Label(label=f"Downloading {progress_info['filename']}")
            progress = Gtk.ProgressBar()
            self.downloads[progress_info["filename"]] = {
                "hbox": hbox,
                "label": label,
                "progress": progress,
                "filepath": os.path.join(
                    GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_DOWNLOAD)
                    or os.path.expanduser("~/Downloads"),
                    progress_info["filename"],
                ),
                "status": "Downloading",
                "cancelled": False,
            }
            safe_widget_append(hbox, label)
            safe_widget_append(hbox, progress)
            safe_widget_append(self.box, hbox)

    def update_progress(self, progress_info, progress):
        with self.lock:
            info = self.downloads.get(progress_info["filename"])
            if info:
                info["progress"].set_fraction(progress)
                info["progress"].set_text(f"{progress * 100:.1f}%")
                info["label"].set_text(f"Downloading {progress_info['filename']}")

    def download_finished(self, progress_info):
        with self.lock:
            if self.on_download_finish_callback:
                self.on_download_finish_callback()
            info = self.downloads.get(progress_info["filename"])
            if info:
                info["status"] = "Finished"
                info["progress"].set_fraction(1.0)
                info["progress"].set_text("100%")
                info["label"].set_text(f"Download finished: {progress_info['filename']}")
                GLib.timeout_add_seconds(
                    5, lambda: self.cleanup_download(progress_info["filename"])
                )

    def download_failed(self, progress_info, error_message):
        with self.lock:
            if self.on_download_finish_callback:
                self.on_download_finish_callback()
            if progress_info is None:
                return
            info = self.downloads.get(progress_info["filename"])
            if info:
                info["status"] = "Failed"
                info["label"].set_text(f"Download failed: {error_message}")
                info["progress"].set_text("Failed")
                GLib.timeout_add_seconds(
                    5, lambda: self.cleanup_download(progress_info["filename"])
                )

    def cleanup_download(self, download_key):
        with self.lock:
            info = self.downloads.pop(download_key, None)
            if info:
                try:
                    parent = info["hbox"].get_parent()
                    if parent and hasattr(parent, "remove"):
                        if info["hbox"].get_parent() == parent:
                            parent.remove(info["hbox"])
                except Exception:
                    pass

    def ensure_download_directory(self):
        downloads_dir = GLib.get_user_special_dir(
            GLib.UserDirectory.DIRECTORY_DOWNLOAD
        ) or os.path.expanduser("~/Downloads")
        try:
            os.makedirs(downloads_dir, exist_ok=True)
        except OSError:
            raise

    def show(self):
        if hasattr(self, "download_area") and self.download_area:
            if self.download_area.get_parent() is not None:
                return
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
        if parent_window is None:
            return
        parent_child = parent_window.get_child()
        if parent_child is not None and hasattr(parent_child, "append"):
            if hasattr(self.download_area, 'get_parent') and self.download_area.get_parent() is not None:
                parent = self.download_area.get_parent()
                if parent and hasattr(parent, "remove"):
                    try:
                        if self.download_area.get_parent() == parent:
                            parent.remove(self.download_area)
                    except Exception:
                        pass
            try:
                parent_child.append(self.download_area)
            except Exception:
                pass

    def clear_all(self):
        for download, info in list(self.downloads.items()):
            if info["status"] in ["Finished", "Failed", "Cancelled"]:
                self.cleanup_download(download)

class AdBlocker:
    def __init__(self, popup_whitelist=None):
        self.blocked_patterns = []
        self.enabled = True
        self.block_list_url = {
            "easylist": "https://easylist.to/easylist/easylist.txt",
            "easyprivacy": "https://easylist.to/easylist/easyprivacy.txt",
            "fanboy_annoyance": "https://secure.fanboy.co.nz/fanboy-annoyance.txt",
            "fanboy_social": "https://secure.fanboy.co.nz/fanboy-social.txt",
            "peter_lowe": "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"
        }
        self.cache_file = "easylist_cache.txt"
        self.cache_max_age = 86400
        self.adult_patterns = []
        self.popup_whitelist = popup_whitelist or []
        self.load_block_lists()

    def inject_to_webview(self, user_content_manager):
        self.inject_adblock_script_to_ucm(user_content_manager)

    def inject_adblock_script_to_ucm(self, user_content_manager):
        adblock_script = r"""
        (function() {
            const selectorsToHide = [
                '.ad', '.ads', '.advert', '.advertisement', '.banner', '.promo', '.sponsored',
                '[id*="ad-"]', '[id*="ads-"]', '[id*="advert-"]', '[id*="banner"]',
                '[class*="-ad"]', '[class*="-ads"]', '[class*="-advert"]', '[class*="-banner"]',
                '[class*="adbox"]', '[class*="adframe"]', '[class*="adwrapper"]', '[class*="bannerwrapper"]',
                '[class*="__wrap"]','[class*="__content"]','[class*="__btn-block"]',
                '[src*="cdn.creative-sb1.com"]','[src*="cdn.storageimagedisplay.com"]',
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
            function isUrlBlocked(url) {
                if (!url) return false;
                const patterns = [
                    /doubleclick\.net/,
                    /googlesyndication\.com/,
                    /\/ads\//,
                    /adframe\./,
                    /bannerads\./
                ];
                // Whitelist Java video player domains
                const whitelist = %s;
                for (let i = 0; i < whitelist.length; i++) {
                    if (url.includes(whitelist[i])) {
                        return false;
                    }
                }
                return patterns.some(p => p.test(url));
            }
            const OriginalXHR = window.XMLHttpRequest;
            window.XMLHttpRequest = function() {
                const xhr = new OriginalXHR();
                const originalOpen = xhr.open;
                xhr.open = function(method, url) {
                    if (isUrlBlocked(url)) {
                        // Don't modify arguments - return early instead
                        return;
                    }
                    return originalOpen.apply(this, arguments);
                };
                return xhr;
            };
            if (window.fetch) {
                const originalFetch = window.fetch;
                window.fetch = function(input, init) {
                    const url = typeof input === 'string' ? input : (input && input.url);
                    if (isUrlBlocked(url)) {
                        return Promise.reject(new Error('AdBlock: Request blocked'));
                    }
                    return originalFetch.apply(this, arguments);
                };
            }
            const originalOpen = window.open;
            window.open = function(url, name, features) {
                if (isUrlBlocked(url)) return null;
                return originalOpen.apply(this, arguments);
            };
            hideElements();
            const observer = new MutationObserver(() => {
                hideElements();
            });
            if (document.body instanceof Node) {
                observer.observe(document.body, { childList: true, subtree: true });
            }
        })();
        """ % json.dumps(["java.com", "oracle.com", "javaplugin.com", "javaplayer.com"])
        custom_script = r"""
        (function() {
            window.addEventListener('click', function(event) {
                let target = event.target;
                while (target && target.tagName !== 'A') {
                    target = target.parentElement;
                }
                if (target && target.tagName === 'A') {
                    const href = target.getAttribute('href');
                    if (href && href.trim().toLowerCase() === 'javascript:void(0)') {
                        // Remove preventDefault and stopPropagation to allow click event
                        // event.preventDefault();
                        // event.stopPropagation();
                        const onclick = target.getAttribute('onclick');
                        if (onclick) {
                            const match = onclick.match(/dbneg\(['"]([^'"]+)['"]\)/);
                            if (match) {
                                const id = match[1];
                                const url = window.dbneg(id);
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

    def enable(self):
        self.enabled = True

    def disable(self):
        self.enabled = False

    def load_block_lists(self):
        if (
            os.path.exists(self.cache_file)
            and (time.time() - os.path.getmtime(self.cache_file)) < self.cache_max_age
        ):
            with open(self.cache_file, "r", encoding="utf-8") as f:
                lines = [
                    line.strip() for line in f if line and not line.startswith("!")
                ]
        else:
            lines = []
            for name, url in self.block_list_url.items():
                block_lines = self.fetch_block_list(url)
                lines.extend(block_lines)
            with open(self.cache_file, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
        self.blocked_patterns = self._parse_block_patterns(lines)

    def fetch_block_list(self, url):
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return [
                line.strip()
                for line in response.text.splitlines()
                if line and not line.startswith("!")
            ]
        except requests.exceptions.RequestException:
            return []

    def _parse_block_patterns(self, lines):
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
            except re.error:
                pass
        return compiled_patterns

    def is_blocked(self, url: str) -> bool:
        if not self.enabled or not url:
            return False
        parsed = urlparse(url)
        target = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".lower()
        for token in self.adult_patterns:
            if token in target:
                return True
        for pat in self.blocked_patterns:
            if pat.search(target):
                return True
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

    def validate_and_clean_url(self, url: str) -> str:
        url = url.strip()
        if not re.match(r"^https?://", url):
            url = "https://" + url
        parsed = urlparse(url)
        if not parsed.netloc:
            raise ValueError(f"Invalid URL: {url}")
        return urlunparse(parsed)

    def enable_csp(self, webview, policy=None):
        policy = policy or """
            default-src https: http: data: blob:;
            script-src 'unsafe-inline' 'unsafe-eval' https: http:;
            style-src 'unsafe-inline' https: http:;
            img-src data: https: http: blob:;
            media-src blob: https: http: data:;
        """
        policy = re.sub(
            r"\b(manifest-src|sandbox|trusted-types)[^;]*;?",
            "",
            policy,
            flags=re.IGNORECASE,
        ).strip()
        script = f"""
        (function () {{
            const meta = document.createElement('meta');
            meta.httpEquiv = 'Content-Security-Policy';
            meta.content = `{policy}`;
            (document.head || document.documentElement).appendChild(meta);
        }})();
        """
        ucm = webview.get_user_content_manager()
        ucm.add_script(
            WebKit.UserScript.new(
                script,
                WebKit.UserContentInjectedFrames.ALL_FRAMES,
                WebKit.UserScriptInjectionTime.START,
                None,
                None,
            )
        )

    def report_csp_violation(self, report):
        report_url = "http://127.0.0.1:9000/"
        data = json.dumps({"csp-report": report}).encode("utf-8")
        req = urllib.request.Request(
            report_url,
            data=data,
            headers={"Content-Type": "application/csp-report"}
        )
        with urllib.request.urlopen(req) as _:
            pass

    def on_csp_violation(self, report):
        self.report_csp_violation(report)

    def is_third_party_request(self, url, current_origin):
        page_origin = urlparse(self.get_current_webview().get_uri()).netloc
        return current_origin != page_origin

    def enable_mixed_content_blocking(self, webview):
        settings = webview.get_settings()
        settings.set_property("allow-running-insecure-content", False)
        webview.set_settings(settings)

    def secure_cookies(self):
        webview = self.get_current_webview()
        if webview:
            cookie_manager = webview.get_context().get_cookie_manager()
            cookie_manager.set_accept_policy(WebKit.CookieAcceptPolicy.NEVER)

    def inject_security_headers(self, webview, load_event):
        if load_event != WebKit.LoadEvent.STARTED:
            return False
        uri = webview.get_uri()
        if not uri:
            return False
        if not uri.startswith(("http:", "https:", "blob:")):
            return False
        if any(b in uri.lower() for b in self.blocked_urls):
            return True
        settings = webview.get_settings()
        try:
            ua = settings.get_property("user-agent")
            if not ua:
                ua = (
                    "Mozilla/5.0 (X11; Linux x86_64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Safari/537.36"
                )
            if "SecurityBrowser" not in ua:
                settings.set_property(
                    "user-agent", f"{ua} SecurityBrowser/1.0"
                )
        except Exception:
            pass
        core = {
            "enable-javascript": True,
            "auto-load-images": True,
            "enable-page-cache": True,
            "enable-smooth-scrolling": True,
            "enable-fullscreen": True,
            "enable-media": True,
            "enable-media-stream": True,
            "enable-webaudio": True,
            "enable-webgl": True,
            "enable-html5-local-storage": True,
            "enable-html5-database": False,
            "enable-java": False,
            "enable-plugins": False,
            "enable-developer-extras": False,
            "enable-site-specific-quirks": True,
            "enable-universal-access-from-file-uris": False,
            "allow-file-access-from-file-urls": False,
            "allow-universal-access-from-file-urls": False,
        }
        for k, v in core.items():
            try:
                settings.set_property(k, v)
            except (TypeError, ValueError):
                pass
        if hasattr(settings, "set_auto_play_policy"):
            settings.set_auto_play_policy(WebKit.AutoPlayPolicy.ALLOW)
        if hasattr(settings, "set_media_playback_requires_user_gesture"):
            settings.set_media_playback_requires_user_gesture(False)
        if hasattr(settings, "set_media_playback_allows_inline"):
            settings.set_media_playback_allows_inline(True)
        if hasattr(settings, "set_webrtc_ip_handling_policy"):
            settings.set_webrtc_ip_handling_policy(
                WebKit.WebRTCIPHandlingPolicy.DEFAULT_PUBLIC_AND_PRIVATE_INTERFACES
            )
        webview.set_settings(settings)
        GLib.idle_add(self._inject_videojs_support, webview)
        return False

    def is_social_tracker(self, url: str) -> bool:
        """Check if a URL is a known social media tracker."""
        url_lower = url.lower()
        return any(tracker in url_lower for tracker in self.blocklist)

class SocialTrackerBlocker:
    def __init__(self):
        self.blocklist = [
            "facebook.com",
            "facebook.net",
            "fbcdn.net",
            "instagram.com",
            "t.co",
            "twitter.com",
            "x.com",
            "linkedin.com",
            "doubleclick.net",
            "google-analytics.com",
            "googletagmanager.com",
            "snapchat.com",
            "pixel.wp.com",
        ]

    def handle_blob_uri(self, request, user_data=None):
        request.finish_error(WebKit.NetworkError.CANCELLED, "Blob URI media playback not supported")

    def handle_data_uri(self, request, user_data=None):
        request.finish_error(WebKit.NetworkError.CANCELLED, "Data URI handling not implemented")

    def handle_media_request(self, request, user_data=None):
        uri = request.get_uri()
        if any(substring in uri for substring in self.blocklist):
            request.finish_error(WebKit.NetworkError.CANCELLED, "Media request blocked")
            return
        request.finish()

class TorManager:
    def __init__(self, tor_port=None, control_port=9051):
        self.tor_port = tor_port or self.detect_tor_port()
        self.control_port = control_port
        self.controller = None
        self.is_running_flag = False
        self.tor_data_dir = os.path.join(os.path.expanduser('~'), '.tor', 'shadow-browser')
        self.torrc_path = os.path.join(self.tor_data_dir, 'torrc')
        self.password = None
        self.use_bridges = False
        self.proxy_settings = None
        self.use_system_tor = True
        self.network_session = None

    @staticmethod
    def detect_tor_port():
        for port in (9050, 9150, 9051, 9151):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex(('127.0.0.1', port)) == 0:
                        return port
            except (socket.error, OSError):
                continue
        return None

    def _is_tor_already_running(self):
        detected_port = self.detect_tor_port()
        if detected_port:
            self.tor_port = detected_port
            self.use_system_tor = True
            self.is_running_flag = True
            return True
        for port in (9050, 9150, 9051, 9151):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex(('127.0.0.1', port)) == 0:
                        self.tor_port = port
                        self.use_system_tor = True
                        self.is_running_flag = True
                        return True
            except (socket.error, OSError):
                continue
        for proc in psutil.process_iter(['name', 'cmdline', 'pid']):
            try:
                if proc.info['name'] and 'tor' in proc.info['name'].lower():
                    cmdline = proc.info['cmdline'] or []
                    if any(self.tor_data_dir in arg for arg in cmdline):
                        return True
                    if any('9050' in arg or '9051' in arg for arg in cmdline):
                        return True
                    try:
                        for conn in proc.net_connections(kind='inet'):
                            if conn.laddr.port in [9050, 9051]:
                                return True
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        continue
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return False

    def stop(self):
        try:
            if self.controller:
                self.controller.close()
                self.controller = None
            if hasattr(self, 'process') and self.process:
                try:
                    self.process.terminate()
                    self.process.wait(timeout=5)
                except (subprocess.TimeoutExpired, ProcessLookupError):
                    try:
                        self.process.kill()
                    except (ProcessLookupError, subprocess.SubprocessError):
                        self.process = None
            self.is_running_flag = False
            self.tor_port = None
            return True
        except Exception:
            return False

    def is_running(self):
        if self.is_running_flag:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    if s.connect_ex(('127.0.0.1', self.tor_port or 9050)) == 0:
                        return True
                self.is_running_flag = False
            except Exception:
                self.is_running_flag = False
        if self._is_tor_already_running():
            self.is_running_flag = True
            return True
        return False

    def start(self):
        if self.is_running():
            return True
        if not shutil.which("tor"):
            return False
        if hasattr(self, 'process') and self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except (subprocess.TimeoutExpired, ProcessLookupError):
                try:
                    self.process.kill()
                except (ProcessLookupError, subprocess.SubprocessError):
                        self.process = None
        if self._is_tor_already_running():
            self.use_system_tor = True
            self.is_running_flag = True
            return True
        if self._is_tor_already_running():
            for control_port in [9051, 9151, 9152, 9153]:
                controller = Controller.from_port(port=control_port)
                controller.authenticate(password="shadow-browser")
                self.controller = controller
                socks_ports = controller.get_conf('SocksPort', multiple=True)
                if socks_ports:
                    try:
                        self.tor_port = int(socks_ports[0].split(':')[0])
                    except (ValueError, IndexError):
                        self.tor_port = 9050
                control_ports = controller.get_conf('ControlPort', multiple=True)
                if control_ports:
                    try:
                        self.control_port = int(control_ports[0])
                    except (ValueError, IndexError):
                        self.control_port = control_port
                    controller.get_info('version')
                    self.is_running_flag = True
                    return True
            if not self.is_running_flag:
                return self._start_new_tor_instance()
        return False

    def _get_network_session(self, webview):
        if self.network_session is None and webview:
            try:
                if hasattr(webview, 'get_context'):
                    webview.get_context()
                    self.network_session = WebKit.NetworkSession.get_default()
                else:
                    self.network_session = WebKit.NetworkSession.get_default()
            except AttributeError:
                self.network_session = WebKit.NetworkSession.get_default()
        return self.network_session or WebKit.NetworkSession.get_default()

    def setup_proxy(self, webview):
        if not self.is_running() and not self.start():
            return False
        if not self.tor_port:
            self.tor_port = self.detect_tor_port()
            if not self.tor_port:
                return False
        session = self._get_network_session(webview)
        if session is None:
            return False
        proxy_uri = f"socks5://127.0.0.1:{self.tor_port}"
        schemes = ["http", "https", "ftp", "ws", "wss"]
        try:
            proxy_settings = WebKit.NetworkProxySettings()
            for scheme in schemes:
                try:
                    proxy_settings.add_proxy_for_scheme(scheme, proxy_uri)
                except (TypeError, GLib.Error, AttributeError):
                    os.environ['http_proxy'] = proxy_uri
            os.environ['https_proxy'] = proxy_uri
            os.environ['all_proxy'] = proxy_uri
            session.set_proxy_settings(
                WebKit.NetworkProxyMode.CUSTOM,
                proxy_settings
            )
            env_proxy_uri = f"socks5://127.0.0.1:{self.tor_port}"
            os.environ['http_proxy'] = env_proxy_uri
            os.environ['https_proxy'] = env_proxy_uri
            os.environ['ftp_proxy'] = env_proxy_uri
            os.environ['all_proxy'] = f"socks5://127.0.0.1:{self.tor_port}"
            return True
        except (TypeError, GLib.Error, AttributeError):
            try:
                os.environ['http_proxy'] = proxy_uri
                os.environ['https_proxy'] = proxy_uri
                os.environ['ftp_proxy'] = proxy_uri
                os.environ['all_proxy'] = proxy_uri
                return True
            except Exception:
                return False

    def _start_new_tor_instance(self):
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "--quiet", "tor"],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                return False
            try:
                self.controller = Controller.from_port(port=9051)
                try:
                    self.controller.authenticate()
                except Exception:
                    self.controller.authenticate(password="shadow-browser")
                self.is_running_flag = True
                try:
                    socks_ports = self.controller.get_conf("SocksPort", multiple=True)
                    if socks_ports:
                        self.tor_port = int(socks_ports[0].split(":")[0])
                    else:
                        self.tor_port = 9050
                except Exception:
                    self.tor_port = 9050
                return True
            except Exception:
                return False
        except FileNotFoundError:
            if self._check_system_tor_running():
                self.tor_port = 9050
                self.control_port = 9051
                return True
            return False

    def _print_bootstrap_lines(self, line=None):
        if not hasattr(self, 'bootstrap_status'):
            self.bootstrap_status = {
                'progress': 0,
                'tag': None,
                'summary': 'Starting Tor...',
                'warning': None,
                'last_update': 0
            }
        current_time = time.time()
        if line:
            line = line.strip()
            if not line:
                return
            if 'Bootstrapped' in line and '%' in line:
                try:
                    progress = int(line.split('%')[0].split()[-1])
                    self.bootstrap_status['progress'] = min(100, max(0, progress))
                    if '[' in line and ']' in line:
                        tag_start = line.find('[') + 1
                        tag_end = line.find(']')
                        if tag_start < tag_end:
                            self.bootstrap_status['tag'] = line[tag_start:tag_end].lower()
                    if ':' in line:
                        summary = line.split(':', 1)[1].strip()
                        self.bootstrap_status['summary'] = summary
                except (ValueError, IndexError):
                    self.bootstrap_status['summary'] = line
            elif any(w in line.lower() for w in ['warn', 'error', 'failed']):
                self.bootstrap_status['warning'] = line
        if current_time - self.bootstrap_status['last_update'] < 1.0 and line is not None:
            return
        self.bootstrap_status['last_update'] = current_time

        def update_ui():
            if not hasattr(self, 'status_bar'):
                return
            status_text = f"Tor: {self.bootstrap_status['summary']}"
            if self.bootstrap_status['progress'] > 0:
                status_text = f"[{self.bootstrap_status['progress']}%] {status_text}"
            self.status_bar.push(0, status_text)
            self.status_bar.push(0, status_text)
            if self.bootstrap_status.get('warning'):
                self.show_error_message(
                    self.bootstrap_status['warning'],
                    title="Tor Warning"
                )
                self.bootstrap_status['warning'] = None
        if Gtk.main_level() > 0:
            GLib.idle_add(update_ui)
        else:
            update_ui()

class Tab:
    def __init__(self, url, webview, scrolled_window=None, favicon=None):
        self.url = url or "about:blank"
        self.webview = webview
        self.scrolled_window = scrolled_window
        self.favicon = favicon
        self.label_box = None
        self.favicon_widget = None
        self.title_label = None
        self.close_button = None
        self.header_box = None
        self.last_activity = time.time()
        self.pinned = False
        self.muted = False

    def update_favicon(self, favicon):
        if not favicon:
            return
        self.favicon = favicon
        if not self.favicon_widget:
            self.favicon_widget = Gtk.Image()
            self.favicon_widget.set_size_request(16, 16)
            if self.label_box:
                self.label_box.prepend(self.favicon_widget)
                self.favicon_widget.set_visible(True)
        if hasattr(favicon, 'get_type') and 'Gdk' in str(favicon.get_type()):
            self.favicon_widget.set_from_paintable(favicon)
        else:
            if isinstance(favicon, GdkPixbuf.Pixbuf):
                self.favicon_widget.set_from_pixbuf(favicon)
            elif isinstance(favicon, str):
                if os.path.exists(favicon) or favicon.startswith(('http://', 'https://', 'file://')):
                    self.favicon_widget.set_from_file(favicon)
            else:
                if hasattr(favicon, 'get_paintable'):
                    self.favicon_widget.set_from_paintable(favicon.get_paintable())
                else:
                    self.favicon_widget.set_from_paintable(favicon)
        self.favicon_widget.set_visible(True)

    def update_activity(self):
        self.last_activity = time.time()

    def __repr__(self):
        return f"<Tab url='{self.url}' pinned={self.pinned} muted={self.muted}>"

class ShadowBrowser(Gtk.Application):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.favicon_lock = threading.Lock()
        self.favicon_cache = {}
        self.settings_dialog = None
        self.cookies_check = None
        self.webview = WebKit.WebView()
        self.content_manager = WebKit.UserContentManager()
        self.adblocker = AdBlocker()
        self.social_tracker_blocker = SocialTrackerBlocker()
        self.setup_webview_settings(self.webview)
        try:
            if hasattr(self.webview, 'connect'):
                self.webview.connect('context-menu', self.on_webview_context_menu)
                try:
                    key_controller = Gtk.EventControllerKey()
                    key_controller.connect('key-pressed', self.on_webview_key_press)
                    self.webview.add_controller(key_controller)
                except Exception:
                    pass
        except Exception:
            pass
        self.webview.connect("create", self.on_webview_create)
        bookmarks_data = self.load_json(BOOKMARKS_FILE, default=[])
        self.bookmarks = bookmarks_data if isinstance(bookmarks_data, list) else []
        self.history = self.load_json(HISTORY_FILE, default=[])
        self.tabs = []
        self.tabs_lock = threading.Lock()
        self.webview_to_tab = {}
        self.tab_to_index = {}
        self.blocked_urls = []
        self.window = None
        self.notebook = Gtk.Notebook()
        self.notebook.set_size_request(-1, 200)
        self.url_entry = Gtk.Entry()
        self.tor_enabled = self.load_json(SETTINGS_FILE, {}).get('tor_enabled', False)
        self.initialize_tor()
        if self.tor_enabled and self.tor_manager and self.tor_manager.is_running():
            tor_port = getattr(self.tor_manager, 'tor_port', 9050)
            tor_proxy = f"socks5h://127.0.0.1:{tor_port}"
            os.environ['http_proxy'] = tor_proxy
            os.environ['https_proxy'] = tor_proxy
            os.environ['all_proxy'] = tor_proxy
            self.tor_status = "running"
        self.download_manager = DownloadManager(None)
        self.active_downloads = 0
        self.context = ssl.create_default_context()
        self.error_handlers = {}
        self.register_error_handlers()
        self.download_spinner = Gtk.Spinner()
        self.download_spinner.set_visible(False)
        self.bookmark_menu = None
        self.home_url = "https://duckduckgo.com/"
        self.setup_security_policies()
        self.download_manager.on_download_start_callback = self.on_download_start
        self.download_manager.on_download_finish_callback = self.on_download_finish
        self.wake_lock_active = False
        try:
            self.adblocker.inject_to_webview(self.content_manager)
            self.inject_nonce_respecting_script()
            self.inject_remove_malicious_links()
            self.inject_adware_cleaner()
            self.disable_biometrics_in_webview(self.content_manager)
            self.content_manager.register_script_message_handler("voidLinkClicked")
            self.content_manager.connect(
                "script-message-received::voidLinkClicked", self.on_void_link_clicked
            )
            test_script = WebKit.UserScript.new(
                "console.log('Test script injected into shared content manager');",
                WebKit.UserContentInjectedFrames.ALL_FRAMES,
                WebKit.UserScriptInjectionTime.START,
            )
            self.content_manager.add_script(test_script)
        except Exception:
            pass

    def initialize_tor(self, retry_count=0, max_retries=2):
        if not self.tor_enabled:
            self.tor_manager = None
            self.tor_status = "disabled"
            return False
        try:
            if not self.tor_manager:
                self.tor_manager = TorManager()
            if self.tor_manager.is_running():
                self.tor_status = "running"
                return True
            if retry_count >= max_retries:
                self.tor_status = "failed"
                return False
            if self.tor_manager.start():
                self.tor_status = "running"
                tor_port = getattr(self.tor_manager, 'tor_port', 9050)
                proxies = {
                    'http': f'socks5h://127.0.0.1:{tor_port}',
                    'https': f'socks5h://127.0.0.1:{tor_port}'
                }
                session = requests.Session()
                session.proxies = proxies
                try:
                    response = session.get('https://check.torproject.org/api/ip', timeout=30)
                    response.raise_for_status()
                    result = response.json()
                    if result.get('IsTor', False):
                        self.tor_status = "running"
                        return True
                    else:
                        self.tor_status = "misconfigured"
                        return False
                except requests.exceptions.RequestException as e:
                    if hasattr(e, 'response') and e.response is not None:
                        return self.initialize_tor(retry_count + 1, max_retries)
                    return self.initialize_tor(retry_count + 1, max_retries)
            else:
                if retry_count < max_retries:
                    if self.tor_manager:
                        self.tor_manager.stop()
                        self.tor_manager = None
                    return self.initialize_tor(retry_count + 1, max_retries)
                return False
        except Exception:
            self.tor_status = "error"
            if retry_count < max_retries:
                if hasattr(self, 'tor_manager') and self.tor_manager:
                    self.tor_manager.stop()
                    self.tor_manager = None
                return self.initialize_tor(retry_count + 1, max_retries)
            return False

    def create_secure_webview(self):
        webview = None
        try:
            content_manager = WebKit.UserContentManager()
            webview = WebKit.WebView(user_content_manager=content_manager)
            webview.set_hexpand(True)
            webview.set_vexpand(True)
            webview._content_manager = content_manager
            webview.connect('load-changed', self._on_webview_load_changed)
            self.setup_webview_settings(webview)
            context = webview.get_context()
            if hasattr(context, 'get_soup_session'):
                soup_session = context.get_soup_session()
                if hasattr(soup_session, 'trust_env'):
                    soup_session.trust_env = True
        except Exception:
            return None
        if self.tor_enabled and self.tor_manager:
            if not self.tor_manager.is_running():
                self.initialize_tor()
            if self.tor_manager.is_running():
                web_context = webview.get_context()
                self.tor_manager.setup_proxy(web_context)
        self._register_webview_message_handlers(webview)
        self.adblocker.inject_to_webview(content_manager)
        self.adblocker.enable_csp(webview)
        try:
            self._setup_webview_handlers(webview)
        except Exception:
            pass
        webview.connect("create", self.on_webview_create)
        return webview

    def cleanup_webview(self, webview):
        if not webview:
            return
        try:
            for handler_id in getattr(webview, '_signal_handlers', []):
                try:
                    webview.handler_disconnect(handler_id)
                except Exception:
                    pass
            if hasattr(webview, '_content_manager'):
                try:
                    content_manager = webview._content_manager
                    if hasattr(content_manager, 'remove_all_scripts'):
                        content_manager.remove_all_scripts()
                    if hasattr(webview, '_handler_ids'):
                        for content_mgr, handler_id in webview._handler_ids:
                            if handler_id > 0 and content_mgr:
                                try:
                                    content_mgr.disconnect(handler_id)
                                except Exception:
                                    pass
                        del webview._handler_ids
                    del webview._content_manager
                except Exception:
                    pass
            try:
                webview.load_uri('about:blank')
                if hasattr(webview, 'stop_loading'):
                    webview.stop_loading()
                if hasattr(webview, 'load_html_string'):
                    webview.load_html_string('', 'about:blank')
            except Exception:
                pass
            parent = webview.get_parent()
            if parent:
                parent.remove(webview)
        except Exception:
            pass
        finally:
            gc.collect()

    def _register_webview_message_handlers(self, webview):
        content_manager = webview._content_manager
        content_manager.register_script_message_handler("voidLinkClicked")
        handler_id = content_manager.connect(
            "script-message-received::voidLinkClicked",
            self.on_void_link_clicked
        )
        content_manager.register_script_message_handler("windowOpenHandler")
        handler_id2 = content_manager.connect(
            "script-message-received::windowOpenHandler",
            self.on_window_open_handler
        )
        if not hasattr(webview, '_handler_ids'):
            webview._handler_ids = []
        webview._handler_ids.append((content_manager, handler_id))
        webview._handler_ids.append((content_manager, handler_id2))

    def inject_wau_tracker_removal_script(self):
        try:
            wau_removal_script = WebKit.UserScript.new(
                """
                (function() {
                    var wauScript = document.getElementById('_wau3wa');
                    if (wauScript) {
                        var parentDiv = wauScript.parentElement;
                        if (parentDiv && parentDiv.style && parentDiv.style.display === 'none') {
                            parentDiv.remove();
                        } else {
                            wauScript.remove();
                        }
                    }
                    var scripts = document.getElementsByTagName('script');
                    for (var i = scripts.length - 1; i >= 0; i--) {
                        var src = scripts[i].getAttribute('src');
                        if (src && src.indexOf('waust.at') !== -1) {
                            scripts[i].remove();
                        }
                    }
                })();
                """,
                WebKit.UserContentInjectedFrames.ALL_FRAMES,
                WebKit.UserScriptInjectionTime.START,
            )
            self.content_manager.add_script(wau_removal_script)
        except Exception:
            pass

    def on_download_start(self):
        try:
            if not self.download_spinner:
                return
            self.active_downloads += 1
            if self.active_downloads == 1:
                GLib.idle_add(self.download_spinner.start)
                GLib.idle_add(lambda: self.download_spinner.set_visible(True))
        except Exception:
            pass

    def on_download_finish(self):
        try:
            if not self.download_spinner:
                return
            if self.active_downloads > 0:
                self.active_downloads -= 1
            if self.active_downloads == 0:
                GLib.idle_add(self.download_spinner.stop)
                GLib.idle_add(lambda: self.download_spinner.set_visible(False))
        except Exception:
            pass

    def setup_security_policies(self):
        self.blocked_urls.extend(
            [
                "accounts.google.com/gsi/client",
                "facebook.com/connect",
                "twitter.com/widgets",
                "youtube.com/player_api",
                "doubleclick.net",
                "googletagmanager.com",
            ]
        )

    def inject_security_headers(self, webview, load_event):
        if load_event != WebKit.LoadEvent.STARTED:
            return False
        uri = webview.get_uri()
        if not uri:
            return False
        if not (uri.startswith(('http:', 'https:', 'blob:'))):
            return False
        if any(blocked_url in uri.lower() for blocked_url in self.blocked_urls):
            return True
        settings = webview.get_settings()
        try:
            default_ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            user_agent = settings.get_property('user-agent') or default_ua
            if 'SecurityBrowser' not in user_agent:
                settings.set_property("user-agent", f"{user_agent} SecurityBrowser/1.0")
        except Exception:
            pass
        core_settings = {
            "enable-javascript": True,
            "enable-page-cache": True,
            "enable-smooth-scrolling": True,
            "enable-fullscreen": True,
            "auto-load-images": True,
            "enable-media": True,
            "enable-media-stream": True,
            "enable-webaudio": True,
            "enable-webgl": True,
            "enable-java": False,
            "enable-plugins": False,
            "enable-html5-database": False,
            "enable-html5-local-storage": True,
            "enable-site-specific-quirks": True,
            "enable-universal-access-from-file-uris": False,
            "allow-file-access-from-file-urls": False,
            "allow-universal-access-from-file-urls": False,
            "enable-developer-extras": False,
            "enable-write-console-messages-to-stdout": False,
        }
        for k, v in core_settings.items():
            settings.set_property(k, v)
        if hasattr(settings, "set_hardware_acceleration_policy"):
            if hasattr(WebKit, "HardwareAccelerationPolicy"):
                settings.set_hardware_acceleration_policy(
                    WebKit.HardwareAccelerationPolicy.ALWAYS
                )
        accel_settings = [
            "enable-accelerated-compositing",
            "enable-accelerated-video",
            "enable-accelerated-video-decode",
            "enable-accelerated-webgl",
            "enable-webrtc-hw-decoding",
            "enable-webrtc-hw-encoding"
        ]
        for accel_flag in accel_settings:
            try:
                settings.set_property(accel_flag, True)
            except (TypeError, ValueError):
                pass
        if hasattr(settings, "set_auto_play_policy"):
            settings.set_auto_play_policy(WebKit.AutoPlayPolicy.ALLOW)
        if hasattr(settings, "set_webrtc_ip_handling_policy"):
            settings.set_webrtc_ip_handling_policy(
                WebKit.WebRTCIPHandlingPolicy.DEFAULT_PUBLIC_AND_PRIVATE_INTERFACES
            )
        if hasattr(settings, "set_media_playback_requires_user_gesture"):
            settings.set_media_playback_requires_user_gesture(False)
        if hasattr(settings, "set_media_playback_allows_inline"):
            settings.set_media_playback_allows_inline(True)
        if hasattr(settings, "set_enable_media"):
            settings.set_enable_media(True)
        if hasattr(settings, "set_enable_mediasource"):
            settings.set_enable_mediasource(True)
        if hasattr(settings, "set_enable_media_capabilities"):
            settings.set_enable_media_capabilities(True)
        if hasattr(settings, "set_enable_encrypted_media"):
            settings.set_enable_encrypted_media(True)
        if hasattr(settings, "set_media_content_types_requiring_hardware_support"):
            settings.set_media_content_types_requiring_hardware_support("video/.*")
        webview.set_settings(settings)
        return False

    def _inject_videojs_support(self, webview):
        videojs_init_script = """
        function initVideoJS() {
            const videos = document.querySelectorAll('video.video-js:not(.vjs-has-started)');
            videos.forEach(video => {
                try {
                    if (!video.classList.contains('vjs-has-started')) {
                        const player = videojs(video, {
                            controls: true,
                            autoplay: 'muted',
                            preload: 'auto'
                        });
                        video.classList.add('vjs-has-started');
                    }
                } catch (e) {
                    console.error('Video.js initialization error:', e);
                }
            });
        }
        function unmuteOnGesture() {
            function handler() {
                try {
                    document.querySelectorAll('video').forEach(v => {
                        try { v.muted = false; if (v.volume === 0) v.volume = 0.5; } catch(e) {}
                    });
                    if (window.videojs && typeof videojs.getAllPlayers === 'function') {
                        try {
                            const players = videojs.getAllPlayers();
                            Object.keys(players).forEach(k => {
                                try { players[k].muted(false); players[k].volume(0.5); } catch(e) {}
                            });
                        } catch(e) {}
                    }
                } catch(e) {}
                window.removeEventListener('click', handler);
                window.removeEventListener('touchstart', handler);
            }
            window.addEventListener('click', handler, {once: true});
            window.addEventListener('touchstart', handler, {once: true});
        }
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', function() { initVideoJS(); unmuteOnGesture(); });
        } else {
            initVideoJS(); unmuteOnGesture();
        }
        const observer = new MutationObserver((mutations) => {
            initVideoJS();
        });
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
        """
        webview.evaluate_javascript(videojs_init_script, -1, None, None, None)

    def block_social_trackers(self, webview, decision, decision_type):
        if decision_type == WebKit.PolicyDecisionType.NAVIGATION_ACTION:
            nav_action = decision.get_navigation_action()
            uri = nav_action.get_request().get_uri()
            if any(
                tracker in uri.lower()
                for tracker in self.social_tracker_blocker.blocklist
            ):
                decision.ignore()
                return True
        return False

    def uuid_to_token(self, uuid_str: str) -> str:
        try:
            u = uuid.UUID(uuid_str)
            b = u.bytes
            token = base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")
            return token
        except Exception:
            return uuid_str

    def transform_embed_selector_links(self, html_content: str) -> str:
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
        base_url = "https://example.com/dbneg?ids="
        import urllib.parse
        encoded_ids = urllib.parse.quote(id_string)
        return base_url + encoded_ids

    def inject_window_open_handler(self, content_manager):
        js_code = '''
        (function() {
            console.log('[ShadowBrowser] Injecting window.open override');
            const originalOpen = window.open;
            window.open = function(url, name, features) {
                console.log('[ShadowBrowser] window.open called with:', url, name, features);
                if (typeof isUrlBlocked === 'function' && isUrlBlocked(url)) {
                    console.log('[ShadowBrowser] window.open blocked by adblocker:', url);
                    return null;
                }
                var urlToSend = (typeof url === 'string' && url) ? url : '';
                if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.windowOpenHandler) {
                    window.webkit.messageHandlers.windowOpenHandler.postMessage(urlToSend);
                    return null;
                }
                return originalOpen.apply(this, arguments);
            };
        })();
        '''
        content_manager.add_script(
            self._create_user_script(js_code)
        )

    def _register_webview_message_handlers(self, webview):
        content_manager = webview._content_manager
        content_manager.register_script_message_handler("voidLinkClicked")
        handler_id = content_manager.connect(
            "script-message-received::voidLinkClicked",
            self.on_void_link_clicked
        )
        content_manager.register_script_message_handler("windowOpenHandler")
        handler_id2 = content_manager.connect(
            "script-message-received::windowOpenHandler",
            self.on_window_open_handler
        )
        if not hasattr(webview, '_handler_ids'):
            webview._handler_ids = []
        webview._handler_ids.append((content_manager, handler_id))
        webview._handler_ids.append((content_manager, handler_id2))

    def on_window_open_handler(self, user_content_manager, js_message):
        data = js_message.get_js_value() if hasattr(js_message, 'get_js_value') else js_message
        url = None
        if isinstance(data, dict):
            url = data.get('url')
        elif isinstance(data, str):
            url = data
        if url is None:
            pass
        elif not isinstance(url, str):
            url = str(url)
            url = url.strip() if isinstance(url, str) else ''
            if url:
                self.open_url_in_new_tab(url)
            else:
                pass

    def get_current_webview(self):
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

    def replace_uuid(self, match):
        original = match.group(0)
        uuid_str = match.group(1)
        token = self.uuid_to_token(uuid_str)
        replaced = original.replace(uuid_str, token)
        return replaced

    def _handle_syntax_error(self, webview, source_id, message):
        recovery_script = """
        (function() {
            console.log('[WebKitGTK Recovery] Attempting to fix syntax errors...');
            if (typeof window.fixSyntaxErrors === 'undefined') {
                window.fixSyntaxErrors = function() {
                    try {
                        var scripts = document.querySelectorAll('script');
                        scripts.forEach(function(script) {
                            if (script.src && script.src.includes('xnxx.header.static.js')) {
                                console.log('[WebKitGTK Recovery] Detected problematic script, attempting recovery...');
                            }
                        });
                    } catch(e) {
                        console.log('[WebKitGTK Recovery] Fix attempt failed:', e);
                    }
                };
                if (document.readyState === 'loading') {
                    document.addEventListener('DOMContentLoaded', window.fixSyntaxErrors);
                } else {
                    setTimeout(window.fixSyntaxErrors, 100);
                }
            }
        })();
        """ 
        webview.evaluate_javascript(recovery_script, -1, None, None, None)

    def _handle_reference_error(self, webview, message, source_id):
        match = re.search(r'ReferenceError:\s*(\w+)\s+is not defined', message)
        if match:
            var_name = match.group(1)
            polyfill_script = f"""
            (function() {{
                console.log('[WebKitGTK Recovery] Providing missing variable: {var_name}');
                if (typeof {var_name} === 'undefined') {{
                    {self._get_polyfill_for_variable(var_name)}
                }}
            }})();
            """
            webview.evaluate_javascript(polyfill_script, -1, None, None, None)

    def _handle_storage_warning(self, webview, message):
        storage_polyfill = """
        (function() {
            console.log('[WebKitGTK Recovery] Applying storage polyfills...');
            if (typeof document.originalCookie === 'undefined') {
                document.originalCookie = document.cookie || '';
                Object.defineProperty(document, 'cookie', {
                    get: function() {
                        return document.originalCookie;
                    },
                    set: function(value) {
                        try {
                            document.originalCookie = value;
                            if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.setCookie) {
                                window.webkit.messageHandlers.setCookie.postMessage(value);
                            }
                        } catch(e) {
                            console.log('[Cookie Polyfill] Warning:', e);
                        }
                    }
                });
            }
            if (typeof window.localStorage === 'undefined') {
                window.localStorage = {
                    _data: {},
                    setItem: function(key, value) {
                        try {
                            this._data[key] = String(value);
                            if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.localStorage) {
                                window.webkit.messageHandlers.localStorage.postMessage({action: 'setItem', key: key, value: value});
                            }
                        } catch(e) { console.log('[localStorage] Warning:', e); }
                    },
                    getItem: function(key) {
                        try {
                            return this._data.hasOwnProperty(key) ? this._data[key] : null;
                        } catch(e) { return null; }
                    },
                    removeItem: function(key) {
                        try {
                            delete this._data[key];
                            if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.localStorage) {
                                window.webkit.messageHandlers.localStorage.postMessage({action: 'removeItem', key: key});
                            }
                        } catch(e) { console.log('[localStorage] Warning:', e); }
                    },
                    clear: function() {
                        try {
                            this._data = {};
                            if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.localStorage) {
                                window.webkit.messageHandlers.localStorage.postMessage({action: 'clear'});
                            }
                        } catch(e) { console.log('[localStorage] Warning:', e); }
                    },
                    get length() {
                        return Object.keys(this._data).length;
                    },
                    key: function(index) {
                        try {
                            return Object.keys(this._data)[index] || null;
                        } catch(e) { return null; }
                    }
                };
            }
            if (typeof window.sessionStorage === 'undefined') {
                window.sessionStorage = {
                    _data: {},
                    setItem: function(key, value) {
                        try { this._data[key] = String(value); } catch(e) { console.log('[sessionStorage] Warning:', e); }
                    },
                    getItem: function(key) {
                        try { return this._data.hasOwnProperty(key) ? this._data[key] : null; } catch(e) { return null; }
                    },
                    removeItem: function(key) {
                        try { delete this._data[key]; } catch(e) { console.log('[sessionStorage] Warning:', e); }
                    },
                    clear: function() {
                        try { this._data = {}; } catch(e) { console.log('[sessionStorage] Warning:', e); }
                    },
                    get length() {
                        return Object.keys(this._data).length;
                    },
                    key: function(index) {
                        try { return Object.keys(this._data)[index] || null; } catch(e) { return null; }
                    }
                };
            }
        })();
        """
        webview.evaluate_javascript(storage_polyfill, -1, None, None, None)

    def _get_polyfill_for_variable(self, var_name):
        polyfills = {
            'agego_aver': 'window.agego_aver = "true";',
            'dbneg': '''window.dbneg = function(id) {
                console.log('[Polyfill] dbneg called with id:', id);
                try {
                    var elements = document.querySelectorAll('[data-id="' + id + '"], [onclick*="' + id + '"]');
                    if (elements.length > 0) {
                        var onclick = elements[0].getAttribute('onclick') || '';
                        var match = onclick.match(/['"]([^'"]+)['"]/);
                        return match ? match[1] : 'about:blank';
                    }
                } catch(e) { console.log('[dbneg] Error:', e); }
                return 'about:blank';
            };''',
            'pl_': 'window.pl_ = {};',
            'ex_': 'window.ex_ = {};',
            'videoPlayer': '''window.videoPlayer = {
                play: function() { console.log('[Polyfill] videoPlayer.play() called'); },
                pause: function() { console.log('[Polyfill] videoPlayer.pause() called'); },
                load: function() { console.log('[Polyfill] videoPlayer.load() called'); }
            };''',
        }
        return polyfills.get(var_name, f'window.{var_name} = {{}};')

    def on_webview_console_message(self, webview, console_message):
        try:
            if hasattr(console_message, 'get_text'):
                message = console_message.get_text()
            else:
                message = str(console_message)
            if hasattr(console_message, 'get_source_id'):
                source_id = console_message.get_source_id()
            else:
                source_id = "unknown"
            if hasattr(console_message, 'get_line'):
                line = console_message.get_line()
            else:
                line = 0
            if hasattr(console_message, 'get_level'):
                level = console_message.get_level()
            else:
                level = 1
            if any(msg in message for msg in [
                'Unknown logging channel:',
                'The resource was preloaded using link preload',
                'was preloaded using link preload',
                'DevTools listening on',
                'Document was loaded from',
                'Consider using',
                'Third-party cookie'
            ]):
                return True
            if any(error in message for error in [
                'SyntaxError:',
                'ReferenceError:',
                'TypeError:',
                'Unexpected EOF',
                'Unexpected token',
                'Unexpected identifier',
                'Unexpected end of input'
            ]):
                print(f"[WebKitGTK JS Error] {level}: {message} at {source_id}:{line}")
                if 'Unexpected EOF' in message or 'Unexpected end of input' in message:
                    self._handle_syntax_error(webview, source_id, message)
                if 'ReferenceError:' in message:
                    self._handle_reference_error(webview, message, source_id)
                return False
            if any(warning in message for warning in [
                'cookie',
                'localStorage',
                'sessionStorage',
                'document.cookie'
            ]):
                self._handle_storage_warning(webview, message)
                return True
        except Exception:
            return False

    def _create_user_script(self, js_code, injection_time=WebKit.UserScriptInjectionTime.START,
                           frames=WebKit.UserContentInjectedFrames.ALL_FRAMES):
        return WebKit.UserScript.new(
            js_code,
            frames,
            injection_time,
        )

    def on_webview_create(self, webview, navigation_action):
        try:
            return None
        except Exception:
            return None

    def _setup_webview_handlers(self, webview):
        if hasattr(webview, 'connect'):
            webview.connect('context-menu', self.on_webview_context_menu)
            key_controller = Gtk.EventControllerKey()
            key_controller.connect('key-pressed', self.on_webview_key_press)
            webview.add_controller(key_controller)
        webview.connect('notify::favicon', self._on_favicon_changed)
        if not hasattr(self, '_original_load_changed'):
            self._original_load_changed = webview.connect('load-changed', self._on_webview_load_changed)
        webview.connect("create", self.on_webview_create)
        webview.connect('resource-load-started', self.on_resource_load_started)

    def _configure_common_webview_settings(self, settings, webview):
        settings.set_enable_javascript(True)
        if hasattr(settings, 'set_enable_html5_local_storage'):
            settings.set_enable_html5_local_storage(True)
        if hasattr(settings, 'set_enable_html5_database'):
            settings.set_enable_html5_database(True)
        if hasattr(settings, 'set_auto_load_images'):
            settings.set_auto_load_images(True)
        if hasattr(settings, 'set_enable_smooth_scrolling'):
            settings.set_enable_smooth_scrolling(True)
        if hasattr(settings, 'set_enable_fullscreen'):
            settings.set_enable_fullscreen(True)
        if hasattr(settings, 'set_enable_developer_extras'):
            settings.set_enable_developer_extras(False)
        if hasattr(settings, 'set_enable_private_browsing'):
            settings.set_enable_private_browsing(False)
        if hasattr(settings, 'set_enable_write_console_messages_to_stdout'):
            settings.set_enable_write_console_messages_to_stdout(False)

    def inject_video_ad_skipper(self, webview):
        js_code = """
        (function() {
            console.log('Video Ad Skipper script injected');
            function clickSkip() {
                const skipBtn = document.querySelector('.ytp-ad-skip-button');
                if (skipBtn) {
                    skipBtn.click();
                    console.log('Ad skipped');
                }
            }
            const observer = new MutationObserver(() => {
                clickSkip();
            });
            observer.observe(document.body, { childList: true, subtree: true });
            setInterval(clickSkip, 1000);
        })();
        """
        script = WebKit.UserScript.new(
            js_code,
            WebKit.UserContentInjectedFrames.ALL_FRAMES,
            WebKit.UserScriptInjectionTime.END,
        )
        webview.get_user_content_manager().add_script(script)

    def _process_clicked_url(self, url, metadata):
        if not url:
            return
        try:
            if url.startswith('/'):
                current_uri = self.webview.get_uri()
                if current_uri:
                    from urllib.parse import urljoin
                    abs_url = urljoin(current_uri, url)
                    url = abs_url
            if url.startswith('javascript:'):
                return
            self.open_url_in_new_tab(url)
        except Exception:
            pass

    def on_javascript_finished(self, webview, result, user_data):
        js_result = webview.evaluate_javascript_finish(result)
        if js_result:
            value = js_result.get_js_value()
            if value and value.is_string():
                pass
            else:
                pass

    def _extract_url_from_message(self, message_data):
        if message_data is None:
            return None, {}
        if hasattr(message_data, 'is_string') and message_data.is_string():
            return message_data.to_string(), {'url': message_data.to_string()}
        if isinstance(message_data, str):
            try:
                parsed = json.loads(message_data)
                if isinstance(parsed, dict):
                    return self._extract_url_from_dict(parsed)
                return str(parsed), {'url': str(parsed)}
            except (json.JSONDecodeError, TypeError):
                return message_data, {'url': message_data}
        if isinstance(message_data, dict):
            return self._extract_url_from_dict(message_data)
        return None, {}

    def _extract_url_from_dict(self, data):
        if not isinstance(data, dict):
            return None, {}
        url = data.get('url', '')
        if not url and 'message' in data:
            url = data.get('message', '')
        return url, data.copy()

    def on_void_link_clicked(self, user_content_manager, js_message):
        if hasattr(js_message, 'get_js_value'):
            message_data = js_message.get_js_value()
            if hasattr(message_data, 'to_dict') and callable(getattr(message_data, 'to_dict')):
                message_data = message_data.to_dict()
        else:
            message_data = js_message
        url, metadata = self._extract_url_from_message(message_data)
        if url and url != "about:blank":
            GLib.idle_add(self._process_clicked_url, url, metadata)

    def setup_webview_settings(self, webview):
        try:
            settings = webview.get_settings()
            self.webview = webview
            self.last_video_url = None
            settings.set_enable_write_console_messages_to_stdout(False)

            def on_console_message(webview, console_message):
                message = console_message.get_text()
                if any(msg in message for msg in [
                    'Unknown logging channel:',
                    'The resource was preloaded using link preload',
                    'was preloaded using link preload'
                ]):
                    return True
                return False
            os.environ['WEBKIT_DISABLE_COMPOSITING_MODE'] = '1'
            core_settings = {
                "enable-javascript": True,
                "enable-javascript-markup": True,
                "enable-html5-local-storage": True,
                "enable-page-cache": True,
                "media-playback-allows-inline": True,
                "media-playback-requires-user-gesture": False,
                "auto-load-images": True,
                "enable-caret-browsing": False,
                "enable-webaudio": True,
                "enable-webgl": True,
                "enable-mediasource": True,
                "enable-encrypted-media": True,
                "enable-media-stream": True,
                "enable-webrtc": True,
                "enable-developer-extras": True,
                "enable-site-specific-quirks": True,
                "enable-write-console-messages-to-stdout": False,
            }
            for key, value in core_settings.items():
                try:
                    if hasattr(settings, f"set_{key.replace('-', '_')}"):
                        getattr(settings, f"set_{key.replace('-', '_')}")(value)
                    else:
                        settings.set_property(key, value)
                except Exception:
                    pass
            try:
                if hasattr(settings, 'set_hardware_acceleration_policy'):
                    policy = getattr(WebKit, 'HardwareAccelerationPolicy', None)
                    if policy:
                        settings.set_hardware_acceleration_policy(policy.ALWAYS)
            except Exception:
                pass
            try:
                context = webview.get_context()
                if hasattr(context, 'get_website_data_manager'):
                    manager = context.get_website_data_manager()
                    if hasattr(manager, 'set_cache_model'):
                        manager.set_cache_model(WebKit.CacheModel.DOCUMENT_BROWSER)
            except Exception:
                pass
            self._init_gstreamer()
            try:
                if hasattr(settings, 'set_enable_webrtc_hardware_acceleration'):
                    settings.set_enable_webrtc_hardware_acceleration(True)
            except Exception:
                pass
            try:
                settings.set_enable_mediasource(True)
                settings.set_enable_media_capabilities(True)
                settings.set_enable_media_stream(True)
            except Exception:
                pass
            try:
                context = webview.get_context()
                if context:
                    if hasattr(context, "set_process_model"):
                        context.set_process_model(WebKit.ProcessModel.MULTIPLE_SECONDARY_PROCESSES)
                    if hasattr(context, "set_media_playback_requires_user_gesture"):
                        context.set_media_playback_requires_user_gesture(False)
                    if hasattr(settings, "set_auto_play_policy"):
                        settings.set_auto_play_policy(WebKit.AutoPlayPolicy.ALLOW)
                    if hasattr(context, "set_webrtc_ice_transport_policy"):
                        context.set_webrtc_ice_transport_policy(WebKit.WebRTCIceTransportPolicy.ALL)
                    if hasattr(context, "set_cache_model"):
                        context.set_cache_model(WebKit.CacheModel.DOCUMENT_BROWSER)
            except Exception:
                pass
        except Exception:
            pass
        return webview

    def on_resource_load_started(self, webview, resource, request):
        headers = request.get_http_headers()
        if not headers:
            try:
                headers = Soup.MessageHeaders.new(Soup.MessageHeadersType.REQUEST)
            except (AttributeError, TypeError):
                headers = Soup.MessageHeaders(Soup.MemoryUse.COPY)
        headers.replace('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8')
        headers.replace('Accept-Language', 'en-US,en;q=0.5')
        headers.replace('Accept-Encoding', 'gzip, deflate, br')
        headers.replace('DNT', '1')
        headers.replace('Connection', 'keep-alive')
        headers.replace('Upgrade-Insecure-Requests', '1')
        headers.replace('Sec-Fetch-Dest', 'document')
        headers.replace('Sec-Fetch-Mode', 'navigate')
        headers.replace('Sec-Fetch-Site', 'none')
        headers.replace('Sec-Fetch-User', '?1')
        return None

    def register_error_handlers(self):
        self.error_handlers = {}
        if hasattr(self, 'webview') and hasattr(self.webview, 'connect'):
            self.webview.connect('load-failed', self.on_load_failed)
        self.error_handlers["gtk_warning"] = self.handle_gtk_warning
        self.error_handlers["network_error"] = self.handle_network_error
        self.error_handlers["webview_error"] = self.handle_webview_error
        self.error_handlers["memory_error"] = self.handle_memory_error

    def on_load_failed(self, webview, load_event, failing_uri, error):
        error_message = self.error_handlers.get(error.code, f"Unknown error: {error.message}")
        error_html = f"""
        <html>
        <head><title>Error loading page</title></head>
        <body style="font-family: sans-serif; padding: 20px;">
            <h2>Error loading page</h2>
            <p>Could not load the page: <strong>{failing_uri}</strong></p>
            <p><em>{error_message}</em></p>
            <p><a href="{failing_uri}">Try again</a> or <a href="about:blank">go to home page</a></p>
        </body>
        </html>
        """
        webview.load_alternate_html(error_html, failing_uri, None)
        return True

    def inject_csp_headers(self, webview, load_event, user_data=None):
        if load_event == WebKit.LoadEvent.STARTED:
            try:
                uri = webview.get_uri()
                if not uri or uri.startswith(('data:', 'about:')):
                    return
                csp_meta_script = """
                (function() {
                    try {
                        var existingMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
                        if (existingMeta) {
                            existingMeta.parentNode.removeChild(existingMeta);
                        }
                        var meta = document.createElement('meta');
                        meta.httpEquiv = 'Content-Security-Policy';
                        meta.content = '%%s';
                        if (document.head) {
                            document.head.insertBefore(meta, document.head.firstChild);
                        } else {
                            var head = document.createElement('head');
                            head.appendChild(meta);
                            document.documentElement.insertBefore(head, document.documentElement.firstChild);
                        }
                        document.cookie = 'csp_meta=' + encodeURIComponent(meta.content) + '; path=/; max-age=60';
                        console.log('[CSP] Content Security Policy applied');
                    } catch (e) {
                        console.error('Error applying CSP:', e);
                    }
                })();
                """
                csp_policy = """
                    default-src https: http: data: blob:;
                    script-src 'unsafe-inline' 'unsafe-eval' https: http: data: blob: *;
                    style-src 'unsafe-inline' https: http: data: *;
                    img-src data: https: http: blob: *;
                    font-src data: https: http: *;
                    connect-src https: http: wss: ws: * theanimecommunity.com *.theanimecommunity.com justanime.vercel.app *.justanime.vercel.app animixplay.st *.animixplay.st;
                    media-src https: http: blob: data: *;
                    object-src 'none';
                    frame-ancestors 'none';
                    base-uri 'self';
                    form-action https: http: *;
                    frame-src https: http: *;
                    worker-src blob: https: http: *;
                    child-src blob: https: http: *;
                """.replace('\n', ' ').strip()
                csp_meta_script = csp_meta_script % csp_policy.replace('"', '\\"')
                manager = webview.get_user_content_manager()

                def inject_csp_delayed():
                    try:
                        script = WebKit.UserScript.new(
                            csp_meta_script,
                            WebKit.UserContentInjectedFrames.TOP_FRAME,
                            WebKit.UserScriptInjectionTime.START,
                            None,
                            None
                        )
                        manager.add_script(script)
                    except Exception:
                        pass
                GLib.timeout_add(3000, inject_csp_delayed)
                self.content_manager = manager
            except Exception:
                pass
            webview.connect("load-changed", self.inject_security_headers)
            webview.connect("load-changed", self.inject_csp_headers)
            webview.connect("decide-policy", self.block_social_trackers)
        try:
            if hasattr(self, 'content_manager') and self.content_manager:
                self.content_manager.register_script_message_handler("consoleMessage")
                self.content_manager.connect(
                    "script-message-received::consoleMessage", self.on_webview_console_message
                )
        except Exception:
            pass
        js_console_override = """
        (function() {
            function sendMessage(level, args) {
                try {
                    window.webkit.messageHandlers.consoleMessage.postMessage({
                        level: level,
                        message: Array.from(args).map(String).join(' ')
                    });
                } catch (e) {
                }
            }
            const levels = ['log', 'warn', 'error', 'info', 'debug'];
            levels.forEach(function(level) {
                const original = console[level];
                console[level] = function() {
                    try {
                        sendMessage(level, arguments);
                    } catch (e) {
                    }
                    try {
                        if (typeof original === 'function') {
                            return original.apply(console, arguments);
                        }
                    } catch (e) {
                    }
                };
            });
        })();
        """
        script = WebKit.UserScript.new(
            js_console_override,
            WebKit.UserContentInjectedFrames.ALL_FRAMES,
            WebKit.UserScriptInjectionTime.START,
        )
        if hasattr(self, 'content_manager') and self.content_manager:
            self.content_manager.add_script(script)
        return webview

    def inject_mouse_event_script(self):
        script = WebKit.UserScript.new(
            """
            (function() {
                console.log('[DEBUG] Mouse event handler script loaded');
                function logDebug(message, obj) {
                    console.log('[DEBUG] ' + message, obj || '');
                }
                function handleClick(e) {
                    console.log('[DEBUG] Click event detected on:', e.target);
                    if (e.button !== 0) {
                        logDebug('Not a left-click, ignoring');
                        return;
                    }
                    let target = e.target;
                    logDebug('Click target:', target);
                    let link = target.closest('a, [onclick], [data-href], [data-link], [data-url], [role="button"]');
                    if (!link && target.matches && !target.matches('a')) {
                        const clickable = target.closest('[onclick], [data-href], [data-link], [data-url], [role="button"]');
                        if (clickable) {
                            link = clickable;
                        }
                    }
                    if (link) {
                        logDebug('Found clickable element:', link);
                        const href = link.getAttribute('href') || '';
                        const hasOnClick = link.hasAttribute('onclick') || link.onclick;
                        const isVoidLink = href.trim().toLowerCase() === 'javascript:void(0)' ||
                                         href.trim() === '#' ||
                                         hasOnClick ||
                                         window.getComputedStyle(link).cursor === 'pointer';
                        logDebug(`Link details - href: ${href}, hasOnClick: ${hasOnClick}, isVoidLink: ${isVoidLink}`);
                        if (isVoidLink) {
                            if (link.getAttribute('data-handled') === 'true') {
                                logDebug('Link already handled, preventing default');
                                e.preventDefault();
                                e.stopPropagation();
                                return false;
                            }
                            let dataUrl = link.getAttribute('data-url') ||
                                       link.getAttribute('data-href') ||
                                       link.getAttribute('data-link') ||
                                       link.href;
                            if (!dataUrl || dataUrl === 'javascript:void(0)' || dataUrl === '#') {
                                const onclick = link.getAttribute('onclick');
                                if (onclick) {
                                    logDebug('Parsing onclick attribute:', onclick);
                                    let windowOpenMatch = onclick.match(/window\\.open\\s*\\(\\s*['"]([^'"]+)['"](?:,[^)]*)?\\)/);
                                    if (windowOpenMatch) {
                                        dataUrl = windowOpenMatch[1];
                                        logDebug('Extracted URL from window.open():', dataUrl);
                                    } else {
                                        const funcMatch = onclick.match(/window\\.open\\s*\\(\\s*(\\w+)\\s*\\(\\s*['"]([^'"]+)['"](?:,[^)]*)?\\)\\s*(?:,[^)]*)?\\)/);
                                        if (funcMatch) {
                                            const funcName = funcMatch[1];
                                            const funcArg = funcMatch[2];
                                            logDebug(`Found function call: ${funcName}('${funcArg}')`);
                                            try {
                                                if (typeof window[funcName] === 'function') {
                                                    const result = window[funcName](funcArg);
                                                    if (result && typeof result === 'string' &&
                                                        (result.startsWith('http') || result.startsWith('/') || result.startsWith('www'))) {
                                                        dataUrl = result;
                                                        logDebug(`Executed ${funcName}('${funcArg}') = ${dataUrl}`);
                                                    }
                                                }
                                            } catch (err) {
                                                logDebug(`Error executing ${funcName}:`, err);
                                            }
                                        }
                                    }
                                }
                            }
                            if (!dataUrl || dataUrl === 'javascript:void(0)' || dataUrl === '#') {
                                const possibleElements = link.querySelectorAll('[href], [data-href], [data-link], [data-src], [data-url]');
                                for (const el of possibleElements) {
                                    const val = el.href || el.getAttribute('href') ||
                                              el.getAttribute('data-href') || el.getAttribute('data-link') ||
                                              el.getAttribute('data-src') || el.getAttribute('data-url');
                                    if (val && (val.startsWith('http') || val.startsWith('/'))) {
                                        dataUrl = val;
                                        break;
                                    }
                                }
                            }
                            logDebug('Extracted URL:', dataUrl);
                            if (dataUrl && dataUrl !== 'javascript:void(0)' && dataUrl !== '#') {
                                link.setAttribute('data-handled', 'true');
                                const message = {
                                    url: dataUrl,
                                    href: link.href || '',
                                    text: (link.innerText || link.textContent || '').trim(),
                                    hasOnClick: hasOnClick,
                                    onclick: link.getAttribute('onclick') || '',
                                    tagName: link.tagName,
                                    className: link.className || '',
                                    id: link.id || ''
                                };
                               logDebug('Sending message to Python:', message);
                                try {
                                    if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.voidLinkClicked) {
                                        window.webkit.messageHandlers.voidLinkClicked.postMessage(message);
                                        logDebug('Message sent successfully');
                                        e.preventDefault();
                                        e.stopPropagation();
                                        return false;
                                    } else {
                                        logDebug('Error: Message handler not found');
                                    }
                                } catch (err) {
                                    logDebug('Error sending message:', err);
                                }
                            } else {
                                logDebug('No URL found for clickable element');
                            }
                        }
                    } else {
                        logDebug('No clickable element found for:', target);
                    }
                }
                document.addEventListener('click', handleClick, {capture: true, passive: false});
                document.addEventListener('mousedown', function(e) {
                    if (e.button === 0) {
                        handleClick(e);
                    }
                }, {capture: true, passive: false});
                const observer = new MutationObserver(function(mutations) {
                    logDebug('DOM mutation detected, reinjecting event listeners');
                    document.removeEventListener('click', handleClick, {capture: true, passive: false});
                    document.addEventListener('click', handleClick, {capture: true, passive: false});
                });
                observer.observe(document.body, {
                    childList: true,
                    subtree: true
                });
                logDebug('Mouse event handler injected successfully');
            })();
            """,
            WebKit.UserContentInjectedFrames.ALL_FRAMES,
            WebKit.UserScriptInjectionTime.START,
            [],
            []
        )
        end_script = WebKit.UserScript.new(
            """
            (function() {
                console.log('[DEBUG] End-of-document mouse event handler loaded');
            })();
            """,
            WebKit.UserContentInjectedFrames.ALL_FRAMES,
            WebKit.UserScriptInjectionTime.END,
            [],
            []
        )
        self.content_manager.add_script(script)
        self.content_manager.add_script(end_script)

    def _create_icon_button(self, icon_name, callback, tooltip_text=None):
        image = Gtk.Image.new_from_icon_name(icon_name)
        button = Gtk.Button()
        button.set_child(image)
        button.set_has_frame(False)
        button.set_margin_start(2)
        button.set_margin_end(2)
        if tooltip_text:
            button.set_tooltip_text(tooltip_text)
        button.connect("clicked", callback)
        return button

    def on_zoom_in_clicked(self, button):
        self.zoom_in()

    def on_zoom_out_clicked(self, button):
        self.zoom_out()

    def on_zoom_reset_clicked(self, button):
        self.zoom_reset()

    def on_tor_status_clicked(self, button):
        self.toggle_tor(not self.tor_enabled)
        self.update_tor_status_indicator()

    def create_toolbar(self):
        if getattr(self, "toolbar", None) and self.toolbar.get_parent():
            return self.toolbar
        self.toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        self.toolbar.set_margin_start(4)
        self.toolbar.set_margin_end(4)
        self.toolbar.set_margin_top(2)
        self.toolbar.set_margin_bottom(2)
        self.toolbar.add_css_class("toolbar")
        try:
            self.toolbar.set_hexpand(True)
        except Exception:
            pass
        nav_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        nav_box.add_css_class("linked")
        nav_box.append(self._create_icon_button("go-previous-symbolic",
                                             self.on_back_clicked,
                                             "Back"))
        nav_box.append(self._create_icon_button("go-next-symbolic",
                                             self.on_forward_clicked,
                                             "Forward"))
        nav_box.append(self._create_icon_button("view-refresh-symbolic",
                                             self.on_refresh_clicked,
                                             "Reload"))
        nav_box.append(self._create_icon_button("go-home-symbolic",
                                             lambda b: self.load_url(self.home_url),
                                             "Home"))
        self.toolbar.append(nav_box)
        url_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        url_box.add_css_class("linked")
        self.url_entry = Gtk.Entry(placeholder_text="Enter URL or search terms")
        self.url_entry.set_hexpand(True)
        self.url_entry.connect("activate", self.on_go_clicked)
        url_box.append(self.url_entry)
        go_button = Gtk.Button(label="Go")
        go_button.connect("clicked", self.on_go_clicked)
        url_box.append(go_button)
        self.toolbar.append(url_box)
        action_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        action_box.add_css_class("linked")
        action_box.append(self._create_icon_button("bookmark-new-symbolic",
                                                self.on_add_bookmark_clicked,
                                                "Add Bookmark"))
        action_box.append(self._create_icon_button("tab-new-symbolic",
                                                self.on_new_tab_clicked,
                                                "New Tab"))
        action_box.append(self._create_icon_button("camera-photo-symbolic",
                                                self.on_screenshot_clicked,
                                                "Take Screenshot"))
        zoom_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        zoom_box.add_css_class("linked")
        zoom_box.append(self._create_icon_button("zoom-out-symbolic",
                                              self.on_zoom_out_clicked,
                                              "Zoom Out"))
        zoom_box.append(self._create_icon_button("zoom-fit-best-symbolic",
                                              self.on_zoom_reset_clicked,
                                              "Reset Zoom"))
        zoom_box.append(self._create_icon_button("zoom-in-symbolic",
                                              self.on_zoom_in_clicked,
                                              "Zoom In"))
        self.toolbar.append(action_box)
        self.toolbar.append(zoom_box)
        try:
            dev_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
            dev_box.add_css_class("linked")
            inspect_button = Gtk.Button(label="Inspect")
            inspect_button.set_tooltip_text("Open Web Inspector")
            inspect_button.connect("clicked", self.on_inspect_clicked)
            dev_box.append(inspect_button)
            self.toolbar.append(dev_box)
        except Exception:
            pass
        if hasattr(self, 'download_spinner') and self.download_spinner:
            self.download_spinner.set_halign(Gtk.Align.END)
            self.download_spinner.set_valign(Gtk.Align.CENTER)
            self.download_spinner.set_margin_start(6)
            self.download_spinner.set_margin_end(6)
            self.download_spinner.set_visible(False)
            self.toolbar.append(self.download_spinner)
        return self.toolbar

    def on_inspect_clicked(self, button=None):
        webview = self.get_current_webview() or getattr(self, 'webview', None)
        if not webview:
            return
        settings = getattr(webview, 'get_settings', lambda: None)()
        dev_enabled = False
        if settings:
            try:
                dev_enabled = bool(
                    getattr(settings, 'get_enable_developer_extras', lambda: None)()
                )
            except Exception:
                try:
                    dev_enabled = bool(settings.get_property('enable-developer-extras'))
                except Exception:
                    pass
            if not dev_enabled:
                try:
                    if hasattr(settings, 'set_enable_developer_extras'):
                        settings.set_enable_developer_extras(True)
                    else:
                        settings.set_property('enable-developer-extras', True)
                except Exception:
                    pass
        inspector = getattr(webview, 'get_inspector', lambda: None)()
        if inspector and hasattr(inspector, 'show'):
            inspector.show()
        elif hasattr(webview, 'run_javascript'):
            js = "console.log('[Inspector] Requested via toolbar'); debugger;"
            try:
                webview.run_javascript(js, None, None, None)
            except Exception:
                pass

    def safe_show_popover(self, popover):
        if not popover:
            return
        try:
            if not popover.get_child():
                return
            if popover.get_visible():
                return
            child = popover.get_child()
            if (
                child
                and child.get_parent() is not None
                and child.get_parent() != popover
            ):
                try:
                    if hasattr(child, 'get_parent') and child.get_parent() is not None:
                        parent = child.get_parent()
                        if parent and hasattr(parent, "remove") and child.get_parent() == parent:
                            parent.remove(child)
                except Exception:
                    pass
            parent = popover.get_parent()
            if parent is None:
                pass
            popover.popup()
        except Exception:
            pass

    def _show_bookmarks_menu(self, button=None):
        if hasattr(self, "toolbar") and self.toolbar is not None:
            child = self.toolbar.get_first_child()
            while child:
                if (
                    isinstance(child, Gtk.MenuButton)
                    and child.get_label() == "Bookmarks"
                ):
                    popover = child.get_popover()
                    if popover:
                        self.safe_show_popover(popover)
                        break
                child = child.get_next_sibling()

    def update_bookmarks_menu(self, menu_container):
        if not menu_container:
            return
        try:
            while True:
                child = menu_container.get_first_child()
                if not child:
                    break
                menu_container.remove(child)
        except Exception:
            pass
        if menu_container == self.bookmark_menu:
            scrolled = Gtk.ScrolledWindow()
            scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
            scrolled.set_property("height-request", 700)
            scrolled.set_property("width-request", 300)
            bookmarks_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            bookmarks_box.set_margin_top(6)
            bookmarks_box.set_margin_bottom(6)
            bookmarks_box.set_margin_start(6)
            bookmarks_box.set_margin_end(6)
            scrolled.set_child(bookmarks_box)
            menu_container.append(scrolled)
            menu_container = bookmarks_box
        if not hasattr(self, 'bookmarks') or not self.bookmarks:
            empty_label = Gtk.Label(label="No bookmarks yet")
            empty_label.set_margin_top(12)
            empty_label.set_margin_bottom(12)
            menu_container.append(empty_label)
        else:
            for bookmark in self.bookmarks:
                if isinstance(bookmark, str):
                    bookmark = {"url": bookmark, "title": None, "favicon": None}
                url = bookmark.get("url")
                if not url:
                    continue
                title = bookmark.get("title") or url
                display_text = (title[:30] + "...") if len(title) > 30 else title
                menu_item = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
                menu_item.set_hexpand(True)
                menu_item.set_halign(Gtk.Align.FILL)
                menu_item.set_margin_start(6)
                menu_item.set_margin_end(6)
                bookmark_btn = Gtk.Button()
                bookmark_btn.set_hexpand(True)
                bookmark_btn.set_halign(Gtk.Align.FILL)
                bookmark_btn.set_has_frame(False)
                bookmark_btn.set_can_focus(False)
                content_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
                content_box.set_hexpand(True)
                favicon = bookmark.get("favicon")
                favicon_img = Gtk.Image.new_from_icon_name("bookmark-new-symbolic")
                if favicon:
                    try:
                        if isinstance(favicon, str) and favicon.startswith("data:image/"):
                            encoded = favicon.split(",", 1)[1]
                        else:
                            encoded = favicon
                        if isinstance(encoded, str):
                            padding = len(encoded) % 4
                            if padding:
                                encoded += "=" * (4 - padding)
                            try:
                                image_data = base64.b64decode(encoded)
                                bytes_data = GLib.Bytes.new(image_data)
                                stream = Gio.MemoryInputStream.new_from_bytes(bytes_data)
                                try:
                                    pixbuf = GdkPixbuf.Pixbuf.new_from_stream(stream, None)
                                    if pixbuf:
                                        if pixbuf.get_width() != 16 or pixbuf.get_height() != 16:
                                            pixbuf = pixbuf.scale_simple(16, 16, GdkPixbuf.InterpType.BILINEAR)
                                        width = pixbuf.get_width()
                                        height = pixbuf.get_height()
                                        has_alpha = pixbuf.get_has_alpha()
                                        rowstride = pixbuf.get_rowstride()
                                        pixels = pixbuf.get_pixels()
                                        fmt = Gdk.MemoryFormat.R8G8B8A8_PREMULTIPLIED if has_alpha else Gdk.MemoryFormat.R8G8B8X8
                                        texture = Gdk.MemoryTexture.new(
                                            width,
                                            height,
                                            fmt,
                                            GLib.Bytes.new(pixels),
                                            rowstride
                                        )
                                        favicon_img = Gtk.Picture.new_for_paintable(texture)
                                        favicon_img.set_size_request(16, 16)
                                except Exception:
                                    pass
                                finally:
                                    stream.close()
                            except Exception:
                                pass
                    except Exception:
                        pass
                favicon_img.set_margin_end(6)
                content_box.append(favicon_img)
                label = Gtk.Label(label=display_text)
                label.set_halign(Gtk.Align.START)
                label.set_ellipsize(3)
                content_box.append(label)
                bookmark_btn.set_child(content_box)
                bookmark_btn.set_tooltip_text(url)
                bookmark_btn.connect("clicked", lambda _, u=url: self.load_url(u))
                delete_btn = Gtk.Button()
                delete_btn.set_icon_name("edit-delete-symbolic")
                delete_btn.add_css_class("flat")
                delete_btn.set_tooltip_text("Delete bookmark")
                delete_btn.connect("clicked", self._on_delete_bookmark_clicked, url)
                menu_item.append(bookmark_btn)
                menu_item.append(delete_btn)
                menu_container.append(menu_item)
        if hasattr(self, 'bookmarks') and self.bookmarks:
            separator = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
            separator.set_margin_top(6)
            separator.set_margin_bottom(6)
            menu_container.append(separator)
            btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            btn_box.set_halign(Gtk.Align.CENTER)
            clear_btn = Gtk.Button(label="Clear All Bookmarks")
            clear_btn.set_halign(Gtk.Align.CENTER)
            clear_btn.connect("clicked", self._clear_all_bookmarks)
            btn_box.append(clear_btn)
            menu_container.append(btn_box)

    def do_startup(self):
        Gtk.Application.do_startup(self)

    def do_activate(self):
        if not self.wake_lock_active:
            self.wake_lock = self.inhibit(None, Gtk.ApplicationInhibitFlags.SUSPEND, "Prevent system suspend while browser is running")
            self.wake_lock_active = True
        if hasattr(self, "window") and self.window:
            try:
                self.window.present()
                return
            except Exception:
                self.window = None
        self.window = Gtk.ApplicationWindow(application=self)
        self.window.set_title("Shadow Browser")
        self.window.set_default_size(1200, 800)
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        menubar = self.create_menubar()
        safe_widget_append(vbox, menubar)
        toolbar = self.create_toolbar()
        safe_widget_append(vbox, toolbar)
        safe_widget_append(vbox, self.notebook)
        self.download_manager.parent_window = self.window
        self.download_manager.show()
        safe_widget_append(vbox, self.download_manager.box)
        if not self.window.get_child():
            self.window.set_child(vbox)
        if not hasattr(self, '_window_signals_connected'):
            self.window.connect("close-request", self.on_window_destroy)
            self._window_signals_connected = True
        if len(self.tabs) == 0:
            self.add_new_tab(self.home_url)
        self.window.present()

    def do_shutdown(self):
        try:
            if self.wake_lock_active and hasattr(self, 'wake_lock'):
                self.uninhibit(self.wake_lock)
                self.wake_lock_active = False
            self.save_session()
            self.save_tabs()
            if hasattr(self, '_popup_windows'):
                try:
                    for popup in self._popup_windows:
                        try:
                            popup.destroy()
                        except Exception:
                            pass
                    self._popup_windows = []
                except Exception:
                    pass
            if hasattr(self, 'tor_manager') and self.tor_manager:
                try:
                    self.tor_manager.stop()
                    self.tor_manager = None
                except Exception:
                    pass
            if hasattr(self, 'download_manager') and self.download_manager:
                try:
                    if hasattr(self.download_manager, 'box') and self.download_manager.box:
                        self.download_manager.clear_all()
                        try:
                            if hasattr(self.download_manager.box, 'get_parent') and self.download_manager.box.get_parent() is not None:
                                parent = self.download_manager.box.get_parent()
                                if parent and hasattr(parent, "remove") and self.download_manager.box.get_parent() == parent:
                                    parent.remove(self.download_manager.box)
                        except Exception:
                            pass
                        self.download_manager.box = None
                    if hasattr(self.download_manager, 'download_area') and self.download_manager.download_area:
                        try:
                            if hasattr(self.download_manager.download_area, 'get_parent') and self.download_manager.download_area.get_parent() is not None:
                                parent = self.download_manager.download_area.get_parent()
                                if parent and hasattr(parent, "remove") and self.download_manager.download_area.get_parent() == parent:
                                    parent.remove(self.download_manager.download_area)
                        except Exception:
                            pass
                        self.download_manager.download_area = None
                    if hasattr(self.download_manager, 'download_spinner') and self.download_manager.download_spinner:
                        try:
                            self.download_manager.download_spinner.stop()
                            self.download_manager.download_spinner.set_visible(False)
                        except Exception:
                            pass
                        self.download_manager.download_spinner = None
                    self.download_manager = None
                except Exception:
                    pass
        except Exception:
            pass
        Gtk.Application.do_shutdown(self)

    def handle_gtk_warning(self, message):
        return True

    def handle_network_error(self, url, error):
        return True

    def handle_webview_error(self, webview, error):
        return True

    def handle_memory_error(self, error):
        return True

    def set_logging_level(self):
        pass

    def _close_bookmark_popover(self):
        if hasattr(self, 'bookmark_popover') and self.bookmark_popover:
            if self.bookmark_popover.get_visible():
                self.bookmark_popover.popdown()

    def _on_key_pressed(self, controller, keyval, keycode, state):
        ctrl = (state & Gdk.ModifierType.CONTROL_MASK)
        shift = (state & Gdk.ModifierType.SHIFT_MASK)
        if ctrl and shift and keyval == Gdk.KEY_b:
            self.test_bookmarks_menu()
            return True
        if ctrl and keyval == Gdk.KEY_t:
            self.add_new_tab(self.home_url)
            return True
        elif ctrl and keyval == Gdk.KEY_w:
            current_page = self.notebook.get_current_page()
            if current_page >= 0 and current_page < len(self.tabs):
                self.on_tab_close_clicked(None, current_page)
            return True
        elif ctrl and keyval == Gdk.KEY_Tab:
            self.switch_to_next_tab()
            return True
        elif ctrl and shift and keyval == Gdk.KEY_Tab:
            self.switch_to_previous_tab()
            return True
        elif ctrl and keyval >= Gdk.KEY_1 and keyval <= Gdk.KEY_9:
            tab_index = keyval - Gdk.KEY_1
            if tab_index < len(self.tabs):
                self.notebook.set_current_page(tab_index)
            return True
        elif ctrl and keyval == Gdk.KEY_f:
            self.show_tab_search_dialog()
            return True
        return False

    def switch_to_next_tab(self):
        current_page = self.notebook.get_current_page()
        next_page = (current_page + 1) % len(self.tabs) if len(self.tabs) > 0 else current_page
        self.notebook.set_current_page(next_page)

    def switch_to_previous_tab(self):
        current_page = self.notebook.get_current_page()
        prev_page = (current_page - 1) % len(self.tabs) if len(self.tabs) > 0 else current_page
        self.notebook.set_current_page(prev_page)

    def show_tab_search_dialog(self):
        dialog = Gtk.Dialog(title="Search Tabs", parent=self.window)
        dialog.set_default_size(400, 300)
        search_entry = Gtk.Entry()
        search_entry.set_placeholder_text("Type to search tabs...")
        listbox = Gtk.ListBox()
        listbox.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.update_tab_search_list(listbox, "")

        def on_search_changed(entry):
            search_text = entry.get_text().lower()
            self.update_tab_search_list(listbox, search_text)
        search_entry.connect("changed", on_search_changed)

        def on_row_activated(listbox, row):
            tab_index = row.get_index()
            if 0 <= tab_index < len(self.tabs):
                self.notebook.set_current_page(tab_index)
                dialog.close()
        listbox.connect("row-activated", on_row_activated)
        content_area = dialog.get_content_area()
        content_area.append(search_entry)
        content_area.append(listbox)
        dialog.add_button("Close", Gtk.ResponseType.CLOSE)
        dialog.connect("response", lambda dialog, response: dialog.close())
        dialog.show_all()
        search_entry.grab_focus()

    def update_tab_search_list(self, listbox, search_text=""):
        child = listbox.get_first_child()
        while child:
            next_child = child.get_next_sibling()
            listbox.remove(child)
            child = next_child
        for i, tab in enumerate(self.tabs):
            tab_title = ""
            tab_url = ""
            if hasattr(tab, 'webview') and tab.webview:
                if tab.webview.get_title():
                    tab_title = tab.webview.get_title()
                if tab.webview.get_uri():
                    tab_url = tab.webview.get_uri()
            display_text = f"{tab_title} - {tab_url}" if tab_title else tab_url
            if search_text == "" or search_text in display_text.lower():
                row = Gtk.ListBoxRow()
                label = Gtk.Label(label=display_text)
                label.set_halign(Gtk.Align.START)
                label.set_ellipsize(Pango.EllipsizeMode.END)
                label.set_max_width_chars(50)
                row.set_child(label)
                listbox.append(row)

    def _on_delete_bookmark_clicked(self, button, url):
        for i, bookmark in enumerate(self.bookmarks):
            if isinstance(bookmark, dict) and bookmark.get('url') == url:
                del self.bookmarks[i]
                self.save_json(BOOKMARKS_FILE, self.bookmarks)
                self._close_bookmark_popover()
                self.update_bookmarks_menu(self.bookmark_menu)
                break

    def _clear_all_bookmarks(self, button=None):
        self.bookmarks.clear()
        self.save_json(BOOKMARKS_FILE, self.bookmarks)
        self._close_bookmark_popover()
        self.update_bookmarks_menu(self.bookmark_menu)

    def create_menubar(self):
        menubar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        try:
            if hasattr(self, 'bookmark_menu_button') and self.bookmark_menu_button:
                if hasattr(self.bookmark_menu_button, 'get_parent') and self.bookmark_menu_button.get_parent() is not None:
                    try:
                        parent = self.bookmark_menu_button.get_parent()
                        if parent and hasattr(parent, "remove") and self.bookmark_menu_button.get_parent() == parent:
                            parent.remove(self.bookmark_menu_button)
                    except Exception:
                        pass
            if not hasattr(self, 'bookmark_menu_button') or not self.bookmark_menu_button:
                self.bookmark_menu_button = Gtk.MenuButton(label="Bookmarks")
            self.bookmark_menu_button.set_tooltip_text("Show bookmarks")
            if not hasattr(self, 'bookmark_popover') or not self.bookmark_popover:
                self.bookmark_popover = Gtk.Popover()
            self.bookmark_popover.set_size_request(300, -1)
            if not hasattr(self, 'bookmark_menu') or self.bookmark_menu is None:
                self.bookmark_menu = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
            else:
                try:
                    child = self.bookmark_menu.get_first_child()
                    while child:
                        next_child = child.get_next_sibling()
                        try:
                            if hasattr(child, 'get_parent') and child.get_parent() is not None:
                                parent = child.get_parent()
                                if parent and hasattr(parent, "remove") and child.get_parent() == parent:
                                    parent.remove(child)
                        except Exception:
                            pass
                        child = next_child
                except Exception:
                    pass
            self.update_bookmarks_menu(self.bookmark_menu)
            self.bookmark_popover.set_child(self.bookmark_menu)
            self.bookmark_menu_button.set_popover(self.bookmark_popover)
            safe_widget_append(menubar, self.bookmark_menu_button)
        except Exception:
            pass
        try:
            if hasattr(self, 'window') and self.window:
                shortcut_controller = Gtk.EventControllerKey()
                shortcut_controller.connect("key-pressed", self._on_key_pressed)
                self.window.add_controller(shortcut_controller)
        except Exception:
            pass
        try:
            download_button = Gtk.Button(label="Downloads")
            download_button.set_tooltip_text("Open Downloads Folder")
            download_button.connect("clicked", self.on_downloads_clicked)
            safe_widget_append(menubar, download_button)
        except Exception:
            pass
        try:
            settings_button = Gtk.Button(label="Settings")
            settings_button.set_tooltip_text("Open settings dialog")
            settings_button.connect("clicked", lambda x: self.on_settings_clicked(x))
            safe_widget_append(menubar, settings_button)
        except Exception:
            pass
        try:
            self.tor_button = Gtk.Button()
            self.tor_button.add_css_class("tor-button")
            self.tor_button.set_tooltip_text("Toggle Tor connection")
            self.update_tor_button()
            self.tor_button.connect("clicked", self.on_tor_button_clicked)
            safe_widget_append(menubar, self.tor_button)
        except Exception:
            pass
        try:
            clear_data_button = Gtk.Button(label="Clear Data")
            clear_data_button.set_tooltip_text("Clear browsing data")
            clear_data_button.connect("clicked", lambda x: self.create_clear_data_dialog().present())
            safe_widget_append(menubar, clear_data_button)
        except Exception:
            pass
        try:
            about_button = Gtk.Button(label="About")
            about_button.connect("clicked", self.on_about)
            safe_widget_append(menubar, about_button)
        except Exception:
            pass
        return menubar

    def _on_settings_save(self, button):
        self.adblocker.enabled = self.adblock_toggle.get_active()
        self.incognito_mode = self.incognito_toggle.get_active()
        self.anti_fingerprinting_enabled = self.anti_fp_toggle.get_active()
        self.search_engine = self.search_engine_entry.get_text().strip()
        self.home_url = self.home_page_entry.get_text().strip()
        with self.tabs_lock:
            for tab in self.tabs:
                if hasattr(tab, 'webview'):
                    GLib.idle_add(tab.webview.reload)
        if hasattr(self, 'settings_dialog') and self.settings_dialog is not None:
            self.settings_dialog.emit("response", Gtk.ResponseType.APPLY)

    def _on_settings_dialog_response(self, dialog, response_id):
        if response_id == Gtk.ResponseType.ACCEPT or response_id == Gtk.ResponseType.OK:
            self._on_settings_save(None)
        if dialog:
            dialog.destroy()
        if hasattr(self, 'settings_dialog') and self.settings_dialog == dialog:
            self.settings_dialog = None

    def on_settings_clicked(self, button):
        if hasattr(self, "settings_dialog") and self.settings_dialog:
            self.settings_dialog.present()
            return
        self.settings_dialog = Gtk.Dialog(
            title="Settings",
            transient_for=self.window,
            modal=True,
            destroy_with_parent=False,
        )
        content_area = self.settings_dialog.get_child()
        grid = Gtk.Grid(column_spacing=10, row_spacing=10)
        content_area.append(grid)
        grid.set_margin_top(10)
        grid.set_margin_bottom(10)
        grid.set_margin_start(10)
        grid.set_margin_end(10)
        self.adblock_toggle = Gtk.CheckButton(label="Enable AdBlocker")
        self.adblock_toggle.set_active(getattr(self.adblocker, "enabled", True))
        grid.attach(self.adblock_toggle, 0, 0, 1, 1)
        self.incognito_toggle = Gtk.CheckButton(label="Enable Incognito Mode")
        self.incognito_toggle.set_active(getattr(self, "incognito_mode", False))
        grid.attach(self.incognito_toggle, 0, 1, 1, 1)
        self.anti_fp_toggle = Gtk.CheckButton(label="Enable Anti-Fingerprinting")
        self.anti_fp_toggle.set_active(getattr(self, "anti_fingerprinting_enabled", True))
        grid.attach(self.anti_fp_toggle, 0, 2, 1, 1)
        self.tor_toggle = Gtk.CheckButton(label="Enable Tor (Requires Tor to be installed)")
        self.tor_toggle.set_active(getattr(self, "tor_enabled", False))
        self.tor_toggle.connect("toggled", self.on_tor_toggled)
        grid.attach(self.tor_toggle, 0, 3, 2, 1)
        search_label = Gtk.Label(label="Default Search Engine URL:")
        search_label.set_halign(Gtk.Align.START)
        grid.attach(search_label, 0, 4, 1, 1)
        self.search_engine_entry = Gtk.Entry()
        self.search_engine_entry.set_text(getattr(self, "search_engine", "https://duckduckgo.com/?q={}"))
        grid.attach(self.search_engine_entry, 1, 4, 1, 1)
        home_label = Gtk.Label(label="Home Page URL:")
        home_label.set_halign(Gtk.Align.START)
        grid.attach(home_label, 0, 5, 1, 1)
        self.home_page_entry = Gtk.Entry()
        self.home_page_entry.set_text(getattr(self, "home_url", "https://duckduckgo.com/").replace("https://", "").replace("http://", ""))
        grid.attach(self.home_page_entry, 1, 5, 1, 1)
        button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        save_button = Gtk.Button(label="Save")
        cancel_button = Gtk.Button(label="Cancel")
        button_box.append(save_button)
        button_box.append(cancel_button)
        grid.attach(button_box, 0, 6, 2, 1)
        save_button.connect("clicked", self._on_settings_save)
        cancel_button.connect("clicked", lambda btn: self.settings_dialog.emit("response", Gtk.ResponseType.CANCEL))
        self.settings_dialog.connect("response", self._on_settings_dialog_response)
        self.settings_dialog.present()

    def on_settings_dialog_response(self, dialog, response_id):
        if response_id == Gtk.ResponseType.ACCEPT or response_id == Gtk.ResponseType.OK:
            self.on_settings_save(None)
        if dialog:
            dialog.destroy()
        if hasattr(self, 'settings_dialog') and self.settings_dialog == dialog:
            self.settings_dialog = None

    def on_settings_save(self, button):
        self.adblocker.enabled = self.adblock_toggle.get_active()
        self.incognito_mode = self.incognito_toggle.get_active()
        self.anti_fingerprinting_enabled = self.anti_fp_toggle.get_active()
        self.search_engine = self.search_engine_entry.get_text().strip()
        self.home_url = self.home_page_entry.get_text().strip()
        with self.tabs_lock:
            for tab in self.tabs:
                if hasattr(tab, 'webview') and tab.webview:
                    GLib.idle_add(tab.webview.reload)

    def toggle_tor(self, enabled):
        try:
            if not hasattr(self, 'tor_manager') or not self.tor_manager:
                self.tor_manager = TorManager()
            if enabled:
                if not self.tor_manager.is_running() and not self.tor_manager.start():
                    self.tor_status = "failed"
                    return False
                self.tor_enabled = True
                self.tor_status = "enabled"
                return True
            else:
                if hasattr(self, 'tor_manager') and self.tor_manager:
                    if not self.tor_manager.stop():
                        return False
                for tab in self.tabs:
                    if hasattr(tab, 'webview') and tab.webview:
                        session = self.tor_manager._get_network_session(tab.webview)
                        if session:
                            try:
                                session.set_proxy_settings(
                                    WebKit.NetworkProxyMode.NO_PROXY,
                                    None
                                )
                            except Exception:
                                pass
                for var in ['http_proxy', 'https_proxy', 'ftp_proxy', 'all_proxy']:
                    os.environ.pop(var, None)
                self.tor_enabled = False
                self.tor_status = "disabled"
                return True
        except Exception:
            self.tor_status = "error"
            return False

    def on_tor_toggled(self, toggle_button):
        enabled = toggle_button.get_active()
        if self.toggle_tor(enabled):
            with self.tabs_lock:
                for tab in self.tabs:
                    if hasattr(tab, 'webview'):
                        self.update_webview_tor_proxy(tab.webview)
                        GLib.idle_add(tab.webview.reload)
            if enabled:
                GLib.timeout_add(1000, self.update_tor_status_indicator)
        else:
            toggle_button.set_active(not enabled)
            self.show_error_message("Failed to toggle Tor. Please check the logs for more details.")
            self.update_tor_status_indicator()

    def update_webview_tor_proxy(self, webview):
        if not webview:
            return
        web_context = webview.get_context()
        if self.tor_enabled and self.tor_manager and self.tor_manager.is_running():
            if not self.tor_manager.setup_proxy(web_context):
                pass
        else:
            self.clear_webview_proxy(web_context)

    def clear_webview_proxy(self, web_context):
        if hasattr(web_context, 'set_proxy_settings'):
            web_context.set_proxy_settings(WebKit.NetworkProxySettings.new())
        elif hasattr(web_context, 'set_network_proxy_settings'):
            web_context.set_network_proxy_settings(WebKit.NetworkProxyMode.NO_PROXY, None)

    def update_tor_status_indicator(self):
        if not hasattr(self, 'tor_status_icon'):
            return
        if self.tor_enabled and hasattr(self, 'tor_manager') and self.tor_manager and self.tor_manager.is_running():
            icon_name = "network-transmit-receive-symbolic"
            tooltip = "Tor is enabled (click to disable)"
            opacity = 1.0
        else:
            icon_name = "network-transmit-receive-symbolic"
            tooltip = "Tor is disabled (click to enable)"
            opacity = 0.5
        self.tor_status_icon.set_from_icon_name(icon_name)
        new_icon = Gtk.Image.new_from_icon_name(icon_name, Gtk.IconSize.BUTTON)
        if hasattr(self.tor_status_button, 'get_child'):
            self.tor_status_button.remove(self.tor_status_button.get_child())
            self.tor_status_button.append(new_icon)
            self.tor_status_icon = new_icon
        self.tor_status_icon.set_tooltip_text(tooltip)
        if hasattr(self.tor_status_icon.props, 'opacity'):
            self.tor_status_icon.props.opacity = opacity

        def widget_show_all(widget):
            if hasattr(widget, 'set_visible'):
                widget.set_visible(True)
            elif hasattr(widget, 'show_all'):
                widget.show_all()
            else:
                widget.show()
        widget_show_all(self.tor_status_button)

    def update_tor_button(self):
        if not hasattr(self, 'tor_button') or not self.tor_button:
            return
        is_tor_running = (self.tor_enabled and
                        hasattr(self, 'tor_manager') and
                        self.tor_manager and
                        self.tor_manager.is_running())
        if is_tor_running:
            self.tor_button.set_label("🔗 Tor ON")
            self.tor_button.set_tooltip_text("Tor is enabled - Click to disable")
            css_provider = Gtk.CssProvider()
            css_provider.load_from_data(b"""
                .tor-button {
                    background: #ADD8E6;
                    color: black;
                    border: 1px solid #45a049;
                }
            """)
            display = self.tor_button.get_display() or Gdk.Display.get_default()
            if display:
                Gtk.StyleContext.add_provider_for_display(display, css_provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        else:
            self.tor_button.set_label("⚪ Tor OFF")
            self.tor_button.set_tooltip_text("Tor is disabled - Click to enable")
            css_provider = Gtk.CssProvider()
            css_provider.load_from_data(b"""
                .tor-button {
                    background: #ADD8E6;
                    color: white;
                    border: 1px solid #616161;
                }
            """)
            display = self.tor_button.get_display() or Gdk.Display.get_default()
            if display:
                Gtk.StyleContext.add_provider_for_display(display, css_provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

    def on_tor_button_clicked(self, button):
        current_state = (self.tor_enabled and
                        hasattr(self, 'tor_manager') and
                        self.tor_manager and
                        self.tor_manager.is_running())
        new_state = not current_state
        if self.toggle_tor(new_state):
            with self.tabs_lock:
                for tab in self.tabs:
                    if hasattr(tab, 'webview'):
                        self.update_webview_tor_proxy(tab.webview)
                        GLib.idle_add(tab.webview.reload)
            self.update_tor_button()
            if new_state:
                self.show_info_message("Tor enabled - All traffic now routed through Tor")
            else:
                self.show_info_message("Tor disabled - Using direct connection")
        else:
            self.show_error_message("Failed to toggle Tor connection")
            self.update_tor_button()

    def show_info_message(self, message):
        try:
            transient_for = self.window if hasattr(self, 'window') and self.window else None
            dialog = Gtk.MessageDialog(
                transient_for=transient_for,
                modal=True,
                message_type=Gtk.MessageType.INFO,
                buttons=Gtk.ButtonsType.OK,
         )
            dialog.connect("response", lambda d, r: d.destroy())
            dialog.present()
        except Exception:
            pass

    def on_anti_fingerprinting_toggled(self, toggle_button):
        self.anti_fingerprinting_enabled = toggle_button.get_active()
        with self.tabs_lock:
            for tab in self.tabs:
                GLib.idle_add(tab.webview.reload)

    def create_clear_data_dialog(self):
        dialog = Gtk.Dialog(
            title="Clear Browsing Data",
            transient_for=self.window,
            modal=True,
            destroy_with_parent=True
        )
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        main_box.set_margin_top(12)
        main_box.set_margin_bottom(12)
        main_box.set_margin_start(12)
        main_box.set_margin_end(12)
        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        content_box.append(Gtk.Label(label="Select the types of data to clear:"))
        self.cookies_check = Gtk.CheckButton(label="Cookies and other site data")
        self.cookies_check.set_active(True)
        content_box.append(self.cookies_check)
        self.cache_check = Gtk.CheckButton(label="Cached images and files")
        self.cache_check.set_active(True)
        content_box.append(self.cache_check)
        self.passwords_check = Gtk.CheckButton(label="Saved passwords")
        content_box.append(self.passwords_check)
        self.history_check = Gtk.CheckButton(label="Browsing history")
        content_box.append(self.history_check)
        main_box.append(content_box)
        button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        button_box.set_halign(Gtk.Align.END)
        cancel_button = Gtk.Button(label="_Cancel", use_underline=True)
        cancel_button.connect("clicked", lambda btn: dialog.close())
        button_box.append(cancel_button)
        clear_button = Gtk.Button(label="_Clear Data", use_underline=True)
        clear_button.connect("clicked", lambda btn: self.on_clear_data_confirm(dialog))
        button_box.append(clear_button)
        main_box.append(button_box)
        dialog.set_child(main_box)
        return dialog

    def clear_cookies(self):
        webview = self.get_current_webview()
        if not webview:
            return False
        if hasattr(webview, 'get_website_data_manager'):
            data_manager = webview.get_website_data_manager()
            cookie_manager = data_manager.get_cookie_manager()
        else:
            context = webview.get_context()
            if hasattr(context, 'get_cookie_manager'):
                cookie_manager = context.get_cookie_manager()
            else:
                return False
        if not cookie_manager:
            return False

        def on_cookies_deleted(manager, result, user_data=None):
            success = manager.delete_all_cookies_finish(result)
            if success:
                pass
            else:
                pass
            cookie_manager.delete_all_cookies(None, on_cookies_deleted, None)
            return True

    def clear_cache(self):
        try:
            webview = self.get_current_webview()
            if not webview:
                return False
            context = webview.get_context()
            if not context:
                return False
            try:
                if hasattr(context, 'clear_cache'):
                    context.clear_cache()
                if hasattr(context, 'clear_website_data'):
                    data_types = 0
                    for attr in dir(WebKit.WebsiteDataTypes):
                        if not attr.startswith('_'):
                            data_types |= getattr(WebKit.WebsiteDataTypes, attr)
                    if data_types > 0:
                        context.clear_website_data(
                            data_types,
                            0,
                            None, None, None
                        )
                current_uri = webview.get_uri()
                if current_uri:
                    webview.load_uri(current_uri)
                return True
            except Exception:
                current_uri = webview.get_uri()
                if current_uri:
                    webview.load_uri(current_uri)
                return True
        except Exception:
            return False

    def clear_history(self):
        self.history = []
        self.save_json(HISTORY_FILE, self.history)

    def on_clear_data_confirm(self, dialog):
        if hasattr(self, 'cookies_check') and self.cookies_check.get_active():
            self.clear_cookies()
        if hasattr(self, 'cache_check') and self.cache_check.get_active():
            self.clear_cache()
        if hasattr(self, 'history_check') and self.history_check.get_active():
            self.clear_history()
        if hasattr(self, 'local_storage_check') and self.local_storage_check.get_active():
            self.clear_all_data()
        if dialog and dialog.is_visible():
            dialog.destroy()

    def on_clear_data_response(self, dialog, response_id):
        if response_id == Gtk.ResponseType.OK:
            self.on_clear_data_confirm(dialog)
        dialog.destroy()

    def clear_all_data(self):
        data_types = 0
        if hasattr(self, 'cookies_check') and self.cookies_check.get_active():
            data_types |= WebKit.WebsiteDataTypes.COOKIES
            data_types |= WebKit.WebsiteDataTypes.WEBSQL_DATABASES
            data_types |= WebKit.WebsiteDataTypes.INDEXEDDB_DATABASE
        if hasattr(self, 'cache_check') and self.cache_check.get_active():
            data_types |= WebKit.WebsiteDataTypes.DISK_CACHE
            data_types |= WebKit.WebsiteDataTypes.MEMORY_CACHE
        if hasattr(self, 'history_check') and self.history_check.get_active():
            self.history = []
            self.save_json(HISTORY_FILE, self.history)
        if hasattr(self, 'local_storage_check') and self.local_storage_check.get_active():
            data_types |= WebKit.WebsiteDataTypes.LOCAL_STORAGE
            data_types |= WebKit.WebsiteDataTypes.SESSION_STORAGE
            data_types |= WebKit.WebsiteDataTypes.WEBSQL_DATABASES
            data_types |= WebKit.WebsiteDataTypes.INDEXEDDB_DATABASE
        if data_types == 0:
            data_types = WebKit.WebsiteDataTypes.ALL

    def on_data_cleared(self, manager, result, user_data=None):
        manager.clear_finish(result)
        self.show_info_message("✅ Browsing data cleared successfully")
        notification = Gtk.InfoBar()
        notification.set_message_type(Gtk.MessageType.INFO)
        notification.add_button("_OK", Gtk.ResponseType.OK)
        content = notification.get_content_area()
        content.append(Gtk.Label(label="Browsing data has been cleared"))
        if hasattr(self, 'window') and self.window:
            overlay = Gtk.Overlay()
            overlay.set_child(self.window.get_child())
            overlay.add_overlay(notification)
            self.window.set_child(overlay)
            GLib.timeout_add_seconds(3, self._remove_notification, notification)

    def _remove_notification(self, notification):
        if hasattr(self, 'window') and self.window:
            overlay = notification.get_parent()
            if overlay and isinstance(overlay, Gtk.Overlay):
                child = overlay.get_child()
                overlay.unparent()
                self.window.set_child(child)
        return False

    def on_downloads_clicked(self, button):
        downloads_dir = GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_DOWNLOAD)
        if not downloads_dir:
            downloads_dir = os.path.expanduser("~/Downloads")
        import subprocess
        subprocess.Popen(["xdg-open", downloads_dir])

    def is_valid_url(self, url):
        result = urlparse(url)
        return all([result.scheme, result.netloc])

    def update_history(self, url):
        if not url or not isinstance(url, str):
            return
        if url.startswith(("http://", "https://")):
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    history_entry = {
                        "url": url,
                        "title": self.extract_tab_title(url),
                        "timestamp": time.time()
                    }
                    self.history.append(history_entry)
                    if len(self.history) > HISTORY_LIMIT:
                        self.history = self.history[-HISTORY_LIMIT:]
                    self.save_json(HISTORY_FILE, self.history)
            except (ValueError, AttributeError):
                pass

    def on_add_bookmark_clicked(self, button):
        current_webview = self.get_current_webview()
        if current_webview:
            url = current_webview.get_uri()
            if url:
                favicon = None
                with self.favicon_lock:
                    if url in self.favicon_cache:
                        favicon = self.favicon_cache[url]
                if favicon is not None:
                    self.add_bookmark(url, favicon=favicon)
                else:
                    self.add_bookmark(url)

    def add_bookmark(self, url, title=None, favicon=None):
        if not url or not url.startswith(("http://", "https://")):
            return False

        def pixbuf_to_base64(pixbuf):
            if not pixbuf or not hasattr(pixbuf, 'save_to_bufferv'):
                return None
            try:
                success, buffer = pixbuf.save_to_bufferv('png', [], [])
                if success and buffer:
                    import base64
                    return base64.b64encode(buffer).decode('utf-8')
            except Exception:
                return None

        def process_favicon(icon):
            if icon is None:
                return None
            if isinstance(icon, str):
                return icon
            if hasattr(icon, 'save_to_bufferv'):
                return pixbuf_to_base64(icon)
            if isinstance(icon, bytes):
                try:
                    return base64.b64encode(icon).decode('utf-8')
                except Exception:
                    return None
            return None
        favicon_data = process_favicon(favicon)
        for i, bookmark in enumerate(self.bookmarks):
            if isinstance(bookmark, dict) and bookmark.get('url') == url:
                if title is not None:
                    self.bookmarks[i]['title'] = title
                if favicon_data is not None:
                    self.bookmarks[i]['favicon'] = favicon_data
                self.save_json(BOOKMARKS_FILE, self.bookmarks)
                GLib.idle_add(self.update_bookmarks_menu, self.bookmark_menu)
                return True
            elif isinstance(bookmark, str) and bookmark == url:
                self.bookmarks[i] = {
                    'url': url,
                    'title': title or url,
                    'favicon': favicon_data
                }
                self.save_json(BOOKMARKS_FILE, self.bookmarks)
                GLib.idle_add(self.update_bookmarks_menu, self.bookmark_menu)
                return True
        if title is None:
            webview = self.get_current_webview()
            title = webview.get_title() if webview else url
        if isinstance(self.bookmarks, dict):
            self.bookmarks = [{'url': k, 'title': v.get('title', k), 'favicon': v.get('favicon')}
                           for k, v in self.bookmarks.items()]
        if not isinstance(self.bookmarks, list):
            self.bookmarks = []
        self.bookmarks.append({
            'url': url,
            'title': title,
            'favicon': favicon_data
        })
        self.save_json(BOOKMARKS_FILE, self.bookmarks)
        GLib.idle_add(self.update_bookmarks_menu, self.bookmark_menu)
        if favicon is None:

            def update_favicon():
                favicon_pixbuf = self.get_favicon(url)
                if favicon_pixbuf:
                    for i, bookmark in enumerate(self.bookmarks):
                        if isinstance(bookmark, dict) and bookmark.get('url') == url:
                            with self.favicon_lock:
                                favicon_data = self.favicon_cache.get(url)
                                if favicon_data:
                                    if isinstance(favicon_data, bytes):
                                        favicon_data = base64.b64encode(favicon_data).decode('utf-8')
                                    self.bookmarks[i]['favicon'] = favicon_data
                                    self.save_json(BOOKMARKS_FILE, self.bookmarks)
                                    GLib.idle_add(self.update_bookmarks_menu, self.bookmark_menu)
                                    break
            threading.Thread(target=update_favicon, daemon=True).start()
        return True

    def load_json(self, filename, default=None):
        if default is None:
            default = {}
        if not filename:
            return default
        try:
            dirname = os.path.dirname(filename)
            if dirname:
                os.makedirs(dirname, exist_ok=True)
            if not os.path.exists(filename):
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(default, f, indent=2)
                return default
            with open(filename, 'r', encoding='utf-8') as f:
                try:
                    return json.load(f)
                except json.JSONDecodeError:
                    try:
                        backup_file = f"{filename}.corrupted.{int(time.time())}"
                        shutil.copy2(filename, backup_file)
                    except Exception:
                        pass
                    return default
        except (FileNotFoundError, PermissionError, OSError):
            return default
        except (OSError, IOError):
            return default

    def save_json(self, filename, data):
        with open(filename, "w") as f:
            json.dump(data, f)

    def show_error_message(self, message):
        """Display an error message dialog."""
        try:
            dialog = Gtk.MessageDialog(
                transient_for=self.window,
                message_type=Gtk.MessageType.ERROR,
                buttons=Gtk.ButtonsType.OK,
                text=message
            )
            dialog.connect("response", lambda d, r: d.destroy())
            dialog.present()
        except Exception:
            pass

    def _init_gstreamer(self):
        global GST_AVAILABLE
        if not GST_AVAILABLE:
            return False
        os.environ.setdefault("GST_DEBUG", "1")
        os.environ.setdefault("LIBVA_MESSAGING_LEVEL", "1")
        if os.path.exists("/dev/dri"):
            os.environ.setdefault("GST_VAAPI_ALL_DRIVERS", "1")
            os.environ.setdefault("LIBVA_DRIVER_NAME", "iHD")
            os.environ.setdefault("GST_VAAPI_ENABLED", "1")
            os.environ.setdefault("WEBKIT_DISABLE_DMABUF_RENDERER", "0")
        os.environ.setdefault("GST_GL_PLATFORM", "egl")
        os.environ.setdefault("GST_GL_API", "gles2")
        os.environ.setdefault("WEBKIT_FORCE_SANDBOX", "1")
        if "--disable-gpu" in sys.argv:
            os.environ["GST_VAAPI_DISABLE"] = "1"
            os.environ["LIBVA_DRIVER_NAME"] = ""
        ok, err = Gst.init_check(None)
        if not ok:
            return False
        return True

    def _load_texture_from_file(self, filepath):
        try:
            return Gdk.Texture.new_from_filename(filepath)
        except Exception:
            pass
            return None

    def on_about(self, button):
        about = Gtk.AboutDialog(transient_for=self.window)
        about.set_program_name("Shadow Browser")
        about.set_version("2.1")
        about.set_copyright(" 2025 ShadowyFigure")
        about.set_comments("A privacy-focused web browser")
        about.set_website("https://github.com/shadowyfigure/shadow-browser-")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        image_path = os.path.join(script_dir, "background.png")
        if os.path.exists(image_path):
            texture = self._load_texture_from_file(image_path)
            if texture:
                about.set_logo(texture)
            else:
                about.set_logo_icon_name("web-browser")
        else:
            about.set_logo_icon_name("web-browser")
        about.present()

    def on_back_clicked(self, button):
        webview = self.get_current_webview()
        if webview and webview.can_go_back():
            webview.go_back()

    def on_screenshot_clicked(self, button):
        self.show_info_message("Screenshot functionality is currently disabled.")

    def _create_tab_with_close_button(self, url, webview, scrolled_window):
        """Unified method to create a tab with working close button"""
        label_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        title_label = Gtk.Label(label=self.extract_tab_title(url))
        title_label.add_css_class("tab-label")
        label_box.append(title_label)
        close_button = Gtk.Button.new_from_icon_name("window-close")
        close_button.set_size_request(24, 24)
        close_button.set_tooltip_text("Close tab")
        close_button.add_css_class("flat")
        tab = Tab(url, webview, scrolled_window)
        tab.label_widget = title_label
        tab.label_box = label_box
        tab.close_button = close_button
        label_box.append(close_button)
        index = self.notebook.append_page(scrolled_window, label_box)
        self.notebook.set_current_page(index)
        self.tabs.append(tab)
        self.webview_to_tab[webview] = tab
        self.tab_to_index[tab] = index

        def on_close_clicked(button):
            self.on_tab_close_clicked_by_button(button)
        gesture = Gtk.GestureClick.new()
        gesture.set_button(0)

        def on_gesture_pressed(g, n, x, y):
            picked = g.get_widget().pick(x, y, Gtk.PickFlags.DEFAULT)
            current = picked
            while current:
                if current == close_button:
                    on_close_clicked(close_button)
                    g.set_state(Gtk.EventSequenceState.CLAIMED)
                    return
                current = current.get_parent()
        gesture.connect("pressed", on_gesture_pressed)
        label_box.add_controller(gesture)

        def on_tab_right_click(gesture, n_press, x, y):
            if n_press == 1:
                self.show_tab_context_menu(tab, x, y)
        right_click_gesture = Gtk.GestureClick.new()
        right_click_gesture.set_button(3)
        right_click_gesture.connect("pressed", on_tab_right_click)
        label_box.add_controller(right_click_gesture)
        webview.connect("notify::favicon", self._on_favicon_changed)
        webview.connect("load-changed", self.on_load_changed)
        webview.connect("notify::title", self.on_title_changed)
        webview.connect("decide-policy", self.on_decide_policy)
        return tab

    def on_new_tab_clicked(self, button):
        self.add_new_tab(self.home_url)

    def add_new_tab(self, url):
        webview = self.create_secure_webview()
        if webview is None:
            return
        webview.load_uri(url)
        scrolled_window = Gtk.ScrolledWindow()
        scrolled_window.set_vexpand(True)
        scrolled_window.set_child(webview)
        self._create_tab_with_close_button(url, webview, scrolled_window)

    def _page_contains_webview(self, page, webview):
        if not page or not webview:
            return False
        scrolled_window = page.get_child()
        if not scrolled_window:
            return False
        child = scrolled_window.get_child()
        if child is None:
            return False
        if child == webview:
            return True
        if hasattr(child, 'get_first_child'):
            viewport_child = child.get_first_child()
            if viewport_child == webview:
                return True
        return False

    def on_tab_close_clicked_by_button(self, button):
        for i, tab in enumerate(self.tabs):
            if hasattr(tab, 'close_button') and tab.close_button == button:
                self.on_tab_close_clicked(button, i)
                break

    def on_tab_close_clicked(self, button, tab_index):
        if not (0 <= tab_index < len(self.tabs)):
            return
        tab = self.tabs.pop(tab_index)
        webview = getattr(tab, "webview", None)
        if not webview:
            return
        self.webview_to_tab.pop(webview, None)
        self.tab_to_index.pop(tab, None)
        for i, remaining_tab in enumerate(self.tabs[tab_index:], start=tab_index):
            self.tab_to_index[remaining_tab] = i
        page_index = next(
            (i for i in range(self.notebook.get_n_pages())
            if self._page_contains_webview(self.notebook.get_nth_page(i), webview)),
            None
        )
        if page_index is not None:
            self.notebook.remove_page(page_index)
        if len(self.tabs) == 0:
            self.add_new_tab(self.home_url)
        if hasattr(tab, "webview") and tab.webview:
            try:
                if hasattr(tab.webview, 'disconnect_by_func'):
                    tab.webview.disconnect_by_func(self.on_load_changed)
                    tab.webview.disconnect_by_func(self.on_title_changed)
                    tab.webview.disconnect_by_func(self.on_decide_policy)
                    tab.webview.disconnect_by_func(self._on_favicon_changed)
                tab.webview.load_uri("about:blank")
                if hasattr(tab.webview, 'destroy'):
                    tab.webview.destroy()
            except Exception:
                pass
            tab.webview = None
        if hasattr(tab, "label_widget"):
            tab.label_widget = None
        if hasattr(tab, "favicon_widget"):
            tab.favicon_widget = None
        if hasattr(tab, "close_button"):
            tab.close_button = None
        if hasattr(tab, "label_box"):
            tab.label_box = None

    def on_load_changed(self, webview, load_event):
        if not hasattr(self, 'download_spinner') or not self.download_spinner:
            return
        current_webview = self.get_current_webview()
        current_url = webview.get_uri() or ""
        if any(ext in current_url.lower() for ext in ['.mp4', '.webm', '.m3u8', '.mpd', '.m3u', '.mp3', '.ogg', '.m4a', '.m4v']):
            return
        if load_event == WebKit.LoadEvent.COMMITTED:
            if webview == current_webview:
                if hasattr(self, 'url_entry') and self.url_entry:
                    self.url_entry.set_text(current_url)
                    current_tab = self.webview_to_tab.get(webview)
                    if current_tab:
                        current_tab.url = current_url
                        if current_tab.label_widget and not webview.get_title():
                            current_tab.label_widget.set_text(self.extract_tab_title(current_url))
                if not any(ext in current_url.lower() for ext in ['.mp4', '.webm', '.m3u8', '.mpd', '.m3u', '.mp3', '.ogg', '.m4a', '.m4v']):
                    GLib.idle_add(self.download_spinner.start)
                    GLib.idle_add(lambda: self.download_spinner.set_visible(True))
        elif load_event == WebKit.LoadEvent.FINISHED:
            if hasattr(self, 'url_entry') and self.url_entry and webview == current_webview:
                self.url_entry.set_text(current_url)
            current_tab = self.webview_to_tab.get(webview)
            if current_tab:
                current_tab.url = current_url
                if current_tab.label_widget and not webview.get_title():
                    current_tab.label_widget.set_text(self.extract_tab_title(current_url))
            uri = webview.get_uri()
            if uri and uri.startswith(("http://", "https://")):
                threading.Thread(
                    target=self.fetch_favicon,
                    args=(uri, lambda favicon: self.set_tab_favicon_from_fetch(webview, favicon)),
                    daemon=True
                ).start()
            if not any(ext in current_url.lower() for ext in ['.mp4', '.webm', '.m3u8', '.mpd', '.m3u', '.mp3', '.ogg', '.m4a', '.m4v']):
                GLib.idle_add(self.download_spinner.stop)
                GLib.idle_add(lambda: self.download_spinner.set_visible(False))
            if current_url and not current_url.startswith(('about:', 'data:')):
                self.update_history(current_url)

    def on_title_changed(self, webview, param):
        title = webview.get_title() or "Untitled"
        url = webview.get_uri()
        if not url:
            return
        max_length = getattr(self, "tab_title_max_length", 10)
        display_title = title[:max_length - 3] + "..." if len(title) > max_length else title
        tab = self.webview_to_tab.get(webview)
        if not tab:
            return
        if hasattr(tab.label_widget, "set_text"):
            tab.label_widget.set_text(display_title)
        if hasattr(tab, "_favicon_thread") and tab._favicon_thread.is_alive():
            return

        def update_favicon():
            try:
                favicon = self.get_favicon(url)
                if favicon:
                    GLib.idle_add(self._update_tab_favicon, tab, favicon)
                    self._update_bookmark_favicon(url, favicon)
            except Exception:
                pass
        tab._favicon_thread = threading.Thread(target=update_favicon, daemon=True)
        tab._favicon_thread.start()

    def _on_favicon_changed(self, webview, param):
        if not webview or not hasattr(webview, 'get_uri'):
            return
        url = webview.get_uri()
        if not url:
            return
        favicon = webview.get_favicon()
        if not favicon:
            return
        with self.favicon_lock:
            self.favicon_cache[url] = favicon
        current_tab = self.webview_to_tab.get(webview)
        if current_tab:
            GLib.idle_add(self._update_tab_favicon, current_tab, favicon)
        if hasattr(self, 'bookmarks'):
            self._update_bookmark_favicon(url, favicon)

    def set_tab_favicon_from_fetch(self, webview, favicon):
        current_tab = self.webview_to_tab.get(webview)
        if current_tab and favicon:
            GLib.idle_add(self._update_tab_favicon, current_tab, favicon)

    def set_tab_favicon(self, tab, paintable):
        if paintable:
            if not hasattr(tab, "favicon_widget") or not tab.favicon_widget:
                tab.favicon_widget = Gtk.Image()
                tab.favicon_widget.set_size_request(16, 16)
                tab.label_box.prepend(tab.favicon_widget)
            tab.favicon_widget.set_from_paintable(paintable)
            tab.favicon = paintable
            tab.favicon_widget.set_visible(True)
        else:
            self._set_fallback_favicon(tab)

    def _update_bookmark_favicon(self, url, favicon):
        if not url or not favicon or not hasattr(self, 'bookmarks'):
            return
        try:
            if hasattr(favicon, 'save_to_png_bytes'):
                bytes_data = favicon.save_to_png_bytes()
            elif hasattr(favicon, 'get_paintable'):
                paintable = favicon.get_paintable()
                if paintable and hasattr(paintable, 'save_to_png_bytes'):
                    bytes_data = paintable.save_to_png_bytes()
                else:
                    return
            elif isinstance(favicon, GLib.Bytes):
                bytes_data = favicon.get_data()
            else:
                bytes_data = favicon
            if not bytes_data:
                return
            if hasattr(bytes_data, 'get_data'):
                bytes_data = bytes(bytes_data.get_data())
            elif hasattr(bytes_data, 'tobytes'):
                bytes_data = bytes_data.tobytes()
            elif not isinstance(bytes_data, (bytes, bytearray)):
                try:
                    bytes_data = bytes(bytes_data)
                except (TypeError, ValueError):
                    return
            base64_data = base64.b64encode(bytes_data).decode('utf-8')
            if not base64_data:
                return
            updated = False
            for i, bookmark in enumerate(self.bookmarks):
                if isinstance(bookmark, dict) and bookmark.get('url') == url:
                    self.bookmarks[i]['favicon'] = base64_data
                    updated = True
                    break
            if updated:
                self.save_json(BOOKMARKS_FILE, self.bookmarks)
                if hasattr(self, 'bookmark_menu'):
                    GLib.idle_add(self.update_bookmarks_menu, self.bookmark_menu)
        except Exception:
            pass

    def _update_tab_favicon(self, tab, favicon):
        if not favicon or not hasattr(tab, "label_box"):
            return
        try:
            if not hasattr(tab, "favicon_widget") or not tab.favicon_widget:
                tab.favicon_widget = Gtk.Image()
                tab.favicon_widget.set_size_request(16, 16)
                tab.label_box.prepend(tab.favicon_widget)
                tab.favicon_widget.set_visible(True)
            tab.favicon_widget.set_visible(True)
            if isinstance(favicon, Gdk.Texture):
                tab.favicon_widget.set_from_paintable(favicon)
                tab.favicon = favicon
            elif isinstance(favicon, Gdk.Paintable):
                tab.favicon_widget.set_from_paintable(favicon)
                tab.favicon = favicon
            elif isinstance(favicon, (bytes, bytearray, GLib.Bytes)):
                try:
                    data = favicon.get_data() if hasattr(favicon, "get_data") else favicon
                    gbytes = GLib.Bytes.new(data)
                    texture = Gdk.Texture.new_from_bytes(gbytes)
                    tab.favicon_widget.set_from_paintable(texture)
                    tab.favicon = texture
                except Exception:
                    self._set_fallback_favicon(tab)
            elif isinstance(favicon, GdkPixbuf.Pixbuf):
                tab.favicon_widget.set_from_pixbuf(favicon)
                tab.favicon = favicon
            else:
                try:
                    if hasattr(favicon, 'get_paintable'):
                        paintable = favicon.get_paintable()
                        tab.favicon_widget.set_from_paintable(paintable)
                        tab.favicon = paintable
                    else:
                        tab.favicon_widget.set_from_paintable(favicon)
                        tab.favicon = favicon
                except Exception:
                    self._set_fallback_favicon(tab)
        except Exception:
            pass

    def on_webview_key_press(self, controller, keyval, keycode, state):
        ctrl = bool(state & Gdk.ModifierType.CONTROL_MASK)
        shift = bool(state & Gdk.ModifierType.SHIFT_MASK)
        webview = controller.get_widget()
        if keyval == Gdk.KEY_F12:
            insp = webview.get_inspector() if hasattr(webview, 'get_inspector') else None
            if insp and hasattr(insp, 'show'):
                insp.show()
                return True
        if ctrl and shift and keyval in (Gdk.KEY_i, Gdk.KEY_I):
            insp = webview.get_inspector() if hasattr(webview, 'get_inspector') else None
            if insp and hasattr(insp, 'show'):
                insp.show()
                return True

    def on_webview_context_menu(self, webview, context_menu, hit_test_result):
        settings = getattr(webview, "get_settings", lambda: None)()
        dev_enabled = False
        if settings:
            get_extras = getattr(settings, "get_enable_developer_extras", None)
            if callable(get_extras):
                dev_enabled = bool(get_extras())
            elif hasattr(settings, "get_property"):
                dev_enabled = bool(settings.get_property("enable-developer-extras"))
        if not dev_enabled:
            return False
        if hasattr(WebKit, "ContextMenuItem") and hasattr(WebKit, "ContextMenuAction"):
            item = WebKit.ContextMenuItem.new_from_stock_action(
                WebKit.ContextMenuAction.INSPECT_ELEMENT
            )
            if item and hasattr(context_menu, "append"):
                context_menu.append(item)
                return False

            def _activate_inspect(_item):
                inspector = getattr(webview, "get_inspector", lambda: None)()
                if inspector and hasattr(inspector, "show"):
                    inspector.show()
                    return
                if hasattr(webview, "run_javascript"):
                    js = (
                        "(function(){"
                        "if (window.webkit && window.webkit.messageHandlers) {"
                        "console.log('Inspector requested');"
                        "}"
                        "})();"
                    )
                    webview.run_javascript(js, None, None, None)
            if hasattr(WebKit, "ContextMenuItem"):
                item = WebKit.ContextMenuItem.new_from_stock_action_with_label(
                    WebKit.ContextMenuAction.NO_ACTION, "Inspect Element"
                )
                if hasattr(item, "connect"):
                    item.connect("activate", _activate_inspect)
                if hasattr(context_menu, "append"):
                    context_menu.append(item)
        return False
    BLOCKED_INTERNAL_URLS = [
        "about:blank",
        "about:srcdoc",
        "blob:",
        "data:",
        "about:debug",
    ]
    allow_about_blank = False

    def is_internal_url_blocked(self, url, is_main_frame):
        if not url:
            return False
        if url.startswith("about:blank") and not self.allow_about_blank:
            return True
        if url in self.BLOCKED_INTERNAL_URLS:
            return True
        if not is_main_frame and url.startswith(("about:", "data:", "blob:", "_blank", "_data:")):
            return True
        return False

    def _handle_navigation_action(self, webview, decision, navigation_action):
        if not navigation_action:
            decision.ignore()
            return True
        request = navigation_action.get_request()
        if not request:
            decision.ignore()
            return True
        requested_url = request.get_uri()
        if not requested_url:
            decision.ignore()
            return True
        lower_url = requested_url.lower()
        if lower_url.startswith("javascript:"):
            decision.ignore()
            return True
        is_main_frame = True
        try:
            frame = getattr(navigation_action, "get_frame", lambda: None)()
            if frame and hasattr(frame, "is_main_frame"):
                is_main_frame = frame.is_main_frame()
        except Exception:
            pass
        if self.is_internal_url_blocked(requested_url, is_main_frame):
            decision.ignore()
            return True
        if lower_url.startswith(("about:", "data:", "blob:", "_data:", "_blank", "_parent", "_self", "_top", "_window")):
            if not is_main_frame:
                decision.ignore()
                return True
            decision.use()
            return True
        parsed = urlparse(requested_url)
        if parsed.scheme and parsed.scheme not in ("http", "https"):
            decision.ignore()
            return True
        if not is_main_frame:
            top_url = webview.get_uri()
            if top_url:
                top_host = urlparse(top_url).hostname
                req_host = parsed.hostname
                if top_host and req_host and top_host != req_host:
                    decision.ignore()
                    return True
        if self.adblocker.is_blocked(requested_url):
            decision.ignore()
            return True
        if lower_url.endswith(tuple(DOWNLOAD_EXTENSIONS)):
            self.start_manual_download(requested_url)
            decision.ignore()
            return True
        cleanup_js = """
            document.querySelectorAll('a').forEach(a => {
                if (
                    (!a.textContent.trim() && !a.innerHTML.trim()) ||
                    getComputedStyle(a).opacity === '0' ||
                    getComputedStyle(a).visibility === 'hidden'
                ) {
                    a.remove();
                }
            });
        """
        try:
            webview.evaluate_javascript(cleanup_js, -1, None, None, None, None)
        except Exception:
            try:
                script = WebKit.UserScript.new(
                    cleanup_js,
                    WebKit.UserContentInjectedFrames.ALL_FRAMES,
                    WebKit.UserScriptInjectionTime.END,
                    None,
                    None
                )
                webview.get_user_content_manager().add_script(script)
            except Exception:
                pass
        decision.use()
        return True

    def _handle_new_window_action(self, webview, decision):
        navigation_action = decision.get_navigation_action()
        if navigation_action is None:
            decision.ignore()
            return True
        request = navigation_action.get_request()
        if request is None:
            decision.ignore()
            return True
        url = request.get_uri()
        if url is None:
            decision.ignore()
            return True
        if url.lower() in ["about:blank", "javascript:void(0)"]:
            decision.ignore()
            return True
        if url.lower().endswith(tuple(DOWNLOAD_EXTENSIONS)):
            self.start_manual_download(url)
            decision.ignore()
            return True
        new_webview = self.create_secure_webview()
        if new_webview is None:
            decision.ignore()
            return True
        self.add_webview_to_tab(new_webview)
        new_webview.load_uri(url)
        decision.ignore()
        return True

    def on_decide_policy(self, webview, decision, decision_type):
        if decision_type == WebKit.PolicyDecisionType.NAVIGATION_ACTION:
            navigation_action = decision.get_navigation_action()
            if not navigation_action:
                decision.ignore()
                return True
            request = navigation_action.get_request()
            if not request:
                decision.ignore()
                return True
            uri = request.get_uri()
            if uri and uri.strip().lower().startswith('javascript:'):
                js_uri = 'javascript:' + uri.split(':', 1)[1].lstrip()
                self.open_url_in_new_tab(js_uri)
                decision.ignore()
                return True
            if uri in ["about:blank#blocked", "about:blank"]:
                decision.use()
                return True
            return self._handle_navigation_action(webview, decision, navigation_action)
        elif decision_type == WebKit.PolicyDecisionType.NEW_WINDOW_ACTION:
            return self._handle_new_window_action(webview, decision)
        decision.use()
        return True

    def add_download_spinner(self, toolbar):
        if toolbar:
            toolbar.append(self.download_spinner)
            self.download_spinner.set_halign(Gtk.Align.END)
            self.download_spinner.set_valign(Gtk.Align.END)
            self.download_spinner.set_margin_start(10)
            self.download_spinner.set_margin_end(10)
            self.download_spinner.set_visible(True)

    def start_manual_download(self, url):
        import requests
        from urllib.parse import urlparse, unquote

        def sanitize_filename(filename):
            filename = re.sub(r'[?#].*$', '', filename)
            filename = re.sub(r'[?&][^/]+$', '', filename)
            filename = re.sub(r'[^\w\-_. ]', '_', filename).strip()
            return filename or 'download'

        def get_filename_from_url(parsed_url):
            path = unquote(parsed_url.path)
            filename = os.path.basename(path)
            if not filename and parsed_url.path.endswith('/'):
                filename = parsed_url.netloc.split('.')[-2] if '.' in parsed_url.netloc else 'file'
            if 'download' in parse_qs(parsed_url.query):
                dl_param = parse_qs(parsed_url.query)['download'][0]
                if dl_param:
                    filename = unquote(dl_param)
            return sanitize_filename(filename)

        def get_extension_from_content_type(content_type):
            content_type = (content_type or '').split(';')[0].lower()
            ext_map = {
                'video/mp4': '.mp4',
                'video/webm': '.webm',
                'video/quicktime': '.mov',
                'video/x-msvideo': '.avi',
                'video/x-matroska': '.mkv',
                'video/3gpp': '.3gp',
                'video/mpeg': '.mpeg',
                'video/ogg': '.ogv',
                'video/x-flv': '.flv',
                'application/x-mpegURL': '.m3u8',
                'application/dash+xml': '.mpd',
                'application/octet-stream': '.bin',
                'application/zip': '.zip',
                'application/x-rar-compressed': '.rar',
                'application/x-7z-compressed': '.7z',
                'application/x-tar': '.tar',
                'application/gzip': '.gz',
                'application/x-bzip2': '.bz2',
                'application/pdf': '.pdf',
                'application/msword': '.doc',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
                'application/vnd.ms-excel': '.xls',
                'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': '.xlsx',
                'application/vnd.ms-powerpoint': '.ppt',
                'application/vnd.openxmlformats-officedocument.presentationml.presentation': '.pptx',
                'text/plain': '.txt',
                'text/html': '.html',
                'text/css': '.css',
                'text/csv': '.csv',
                'application/json': '.json',
                'application/javascript': '.js',
                'image/jpeg': '.jpg',
                'image/png': '.png',
                'image/gif': '.gif',
                'image/webp': '.webp',
                'image/svg+xml': '.svg',
                'audio/mpeg': '.mp3',
                'audio/wav': '.wav',
                'audio/ogg': '.ogg',
                'audio/webm': '.weba',
            }
            return ext_map.get(content_type, '')

        def download_thread():
            progress_info = {}
            try:
                parsed_url = urlparse(url)
                if not parsed_url.scheme or not parsed_url.netloc:
                    raise ValueError("Invalid URL format")
                headers = {
                    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
                with requests.get(url, stream=True, timeout=30, headers=headers) as response:
                    response.raise_for_status()
                    content_disposition = response.headers.get("content-disposition", "")
                    filename = None
                    if content_disposition:
                        filename_match = re.search(r'filename[^;=]*=([^;\n]*)', content_disposition, flags=re.IGNORECASE)
                        if filename_match:
                            filename = filename_match.group(1).strip('\'" ')
                            filename = unquote(filename)
                            filename = sanitize_filename(filename)
                    if not filename:
                        filename = get_filename_from_url(parsed_url)
                    base_name, ext = os.path.splitext(filename)
                    if not ext:
                        content_type = response.headers.get('content-type', '')
                        ext = get_extension_from_content_type(content_type)
                        if ext:
                            filename = f"{base_name}{ext}"
                    downloads_dir = GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_DOWNLOAD) or os.path.expanduser("~/Downloads")
                    os.makedirs(downloads_dir, exist_ok=True)
                    base_name, ext = os.path.splitext(filename)
                    counter = 1
                    while os.path.exists(os.path.join(downloads_dir, filename)):
                        filename = f"{base_name}_{counter}{ext}"
                        counter += 1
                    filepath = os.path.join(downloads_dir, filename)
                    total_size = int(response.headers.get("content-length", 0))
                    progress_info = {
                        "filename": filename,
                        "total_size": total_size,
                        "cancelled": False,
                    }
                    self.download_manager.add_progress_bar(progress_info)
                    with open(filepath, "wb") as f:
                        downloaded = 0
                        for chunk in response.iter_content(chunk_size=8192):
                            if progress_info["cancelled"]:
                                break
                            if chunk:
                                f.write(chunk)
                                downloaded += len(chunk)
                                progress = downloaded / total_size if total_size > 0 else 0
                                GLib.idle_add(self.download_manager.update_progress, progress_info, progress)
                    if not progress_info["cancelled"]:
                        GLib.idle_add(self.download_manager.download_finished, progress_info)
            except requests.exceptions.RequestException as e:
                GLib.idle_add(self.download_manager.download_failed, progress_info, f"Download request failed: {e}")
            except Exception as e:
                GLib.idle_add(self.download_manager.download_failed, progress_info, f"Unexpected download error: {e}")
            finally:
                if progress_info:
                    GLib.idle_add(self.download_manager.cleanup_download, progress_info["filename"])
        thread = threading.Thread(
            target=download_thread, daemon=True, name=f"download_{url}"
        )
        thread.start()
        return thread.ident

    def on_forward_clicked(self, button):
        webview = self.get_current_webview()
        if webview and webview.can_go_forward():
            webview.go_forward()

    def on_go_clicked(self, button):
        url = self.url_entry.get_text().strip()
        self.load_url(url)

    def load_url(self, url):
        if not url or not isinstance(url, str):
            return
        url = url.strip()
        if not url:
            return
        if not re.match(r'^https?://', url):
            url = 'https://' + url
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return
            if len(url) > 2048:
                return
        except (ValueError, AttributeError):
            return
        webview = self.get_current_webview()
        if webview:
            webview.load_uri(url)
            self.update_history(url)
            if hasattr(self, 'url_entry') and self.url_entry:
                self.url_entry.set_text(url)

    def on_refresh_clicked(self, button):
        webview = self.get_current_webview()
        if webview:
            webview.reload()

    def extract_tab_title(self, url):
        max_length = 30
        try:
            parsed = urlparse(url)
            title = parsed.netloc or "New Tab"
            if len(title) > max_length:
                title = title[: max_length - 3] + "..."
            return title
        except Exception:
            return "New Tab"

    def save_session(self):
        session_data = [
            {
                "url": tab.url,
                "title": tab.title_label.get_text() if hasattr(tab, 'title_label') and tab.title_label else "",
            }
            for tab in self.tabs
        ]
        self.save_json(SESSION_FILE, session_data)

    def save_tabs(self):
        tabs_data = [tab.url for tab in self.tabs if tab.url]
        self.save_json(TABS_FILE, tabs_data)

    def restore_session(self):
        if os.path.exists(SESSION_FILE):
            session_data = self.load_json(SESSION_FILE)
            if session_data and isinstance(session_data, list):
                for tab_data in session_data:
                    if isinstance(tab_data, dict) and "url" in tab_data:
                        self.add_new_tab(tab_data["url"])

    def apply_theme(self):
        settings = Gtk.Settings.get_default()
        settings.set_property("gtk-application-prefer-dark-theme", self.theme == "dark")

    def safe_window_cleanup(self):
        if not hasattr(self, 'window') or not self.window:
            return
        if hasattr(self.window, 'disconnect_by_func'):
            self.window.disconnect_by_func(self.on_window_destroy)
        if hasattr(self.window, 'get_child'):
            child = self.window.get_child()
            if child and hasattr(child, 'destroy'):
                    if hasattr(child, 'remove'):
                        self.window.remove(child)
                    child.destroy()
        if hasattr(self.window, 'destroy'):
            self.window.destroy()
        self.window = None

    def cleanup_widgets(self):
        for tab in self.tabs[:]:
            if hasattr(tab, 'webview') and tab.webview:
                try:
                    tab.webview.stop_loading()
                except Exception:
                    pass
                try:
                    tab.webview.destroy()
                except Exception:
                    pass
        try:
            while Gtk.events_pending():
                Gtk.main_iteration()
        except Exception:
            pass
        self.webview_to_tab.clear()
        self.tab_to_index.clear()
        for tab in self.tabs[:]:
            if hasattr(tab, 'webview'):
                tab.webview = None
            if hasattr(tab, 'title_label'):
                tab.title_label = None
        self.tabs.clear()
        if hasattr(self, 'notebook') and self.notebook:
            try:
                for i in range(self.notebook.get_n_pages() - 1, -1, -1):
                    page = self.notebook.get_nth_page(i)
                    if page:
                        try:
                            self.notebook.remove_page(i)
                        except Exception:
                            pass
            except Exception:
                pass

    def show_tab_context_menu(self, tab, x, y):
        menu = Gtk.Menu()
        close_item = Gtk.MenuItem(label="Close Tab")
        close_item.connect("activate", lambda _: self.on_tab_close_clicked(None, self.tab_to_index.get(tab, 0)))
        menu.append(close_item)
        close_others_item = Gtk.MenuItem(label="Close Other Tabs")
        close_others_item.connect("activate", lambda _: self.close_other_tabs(tab))
        menu.append(close_others_item)
        close_right_item = Gtk.MenuItem(label="Close Tabs to Right")
        close_right_item.connect("activate", lambda _: self.close_tabs_to_right(tab))
        menu.append(close_right_item)
        duplicate_item = Gtk.MenuItem(label="Duplicate Tab")
        duplicate_item.connect("activate", lambda _: self.duplicate_tab(tab))
        menu.append(duplicate_item)
        reload_item = Gtk.MenuItem(label="Reload Tab")
        reload_item.connect("activate", lambda _: self.reload_tab(tab))
        menu.append(reload_item)
        menu.show_all()
        menu.popup_at_pointer(None)

    def close_other_tabs(self, current_tab):
        tabs_to_close = [tab for tab in self.tabs if tab != current_tab]
        for tab in reversed(tabs_to_close):
            tab_index = self.tab_to_index.get(tab)
            if tab_index is not None:
                self.on_tab_close_clicked(None, tab_index)

    def close_tabs_to_right(self, current_tab):
        current_index = self.tab_to_index.get(current_tab)
        if current_index is None:
            return
        tabs_to_close = self.tabs[current_index + 1:]
        for tab in reversed(tabs_to_close):
            tab_index = self.tab_to_index.get(tab)
            if tab_index is not None:
                self.on_tab_close_clicked(None, tab_index)

    def duplicate_tab(self, tab):
        if hasattr(tab, 'url') and tab.url:
            self.open_url_in_new_tab(tab.url)

    def reload_tab(self, tab):
        if hasattr(tab, 'webview') and tab.webview:
            tab.webview.reload()

    def disconnect_all_signals(self):
        pass

    def on_window_destroy(self, window):
        self.save_session()
        self.save_tabs()
        self.cleanup_widgets()
        self.disconnect_all_signals()
        if hasattr(self, '_popup_windows'):
            try:
                for popup in self._popup_windows:
                    try:
                        popup.destroy()
                    except Exception:
                        pass
                self._popup_windows = []
            except Exception:
                pass
        if hasattr(self, 'download_manager') and self.download_manager:
            try:
                self.download_manager.clear_all()
                self.download_manager = None
            except Exception:
                pass
        self.safe_window_cleanup()
        self.quit()

    def simulate_left_click_on_void_link(self, data_url):
        webview = self.get_current_webview()
        if not webview:
            return False
        js_code = (
            "(function() {"
            "const targetDataUrl = %s;"
            "const links = document.querySelectorAll('a');"
            "for (const link of links) {"
            "  if (link.getAttribute('data-url') === targetDataUrl) {"
            "    ['mousedown', 'mouseup', 'click'].forEach(type => {"
            "      const event = new MouseEvent(type, {"
            "        view: window,"
            "        bubbles: true,"
            "        cancelable: true,"
            "        button: 0,"
            "        buttons: 1,"
            "        detail: 1"
            "      });"
            "      link.dispatchEvent(event);"
            "    });"
            "    return true;"
            "  }"
            "}"
            "return false;"
            "})();"
        ) % json.dumps(data_url)
        try:
            webview.evaluate_javascript(
                js_code,
                None,
                None,
                self._on_js_click_result
            )
            return True
        except Exception:
            return False

    def _on_js_click_result(self, webview, result, user_data):
        webview.run_javascript_finish(result)

    def test_js_execution(self):
        webview = self.get_current_webview()
        if webview:
            js_code = "console.log('Test JS execution in webview'); 'JS executed';"
            webview.evaluate_javascript(js_code, self.js_callback)

    def _on_js_executed(self, webview, result, user_data):
        webview.run_javascript_finish(result)

    def _on_webview_load_changed(self, webview, load_event):
        if load_event == WebKit.LoadEvent.STARTED:
            self._update_loading_state(webview, True)
        elif load_event == WebKit.LoadEvent.COMMITTED:
            self._inject_early_page_fixes(webview)
        elif load_event == WebKit.LoadEvent.FINISHED:
            self._update_loading_state(webview, False)
            self._handle_page_completion(webview)

    def _inject_early_page_fixes(self, webview):
        try:
            early_fix_script = """
            (function() {
                console.log('[WebKitGTK] Injecting early page fixes...');
                if (typeof document.addEventListener !== 'undefined') {
                    document.addEventListener('DOMContentLoaded', function() {
                        console.log('[WebKitGTK] DOM loaded, applying fixes...');
                        if (document.body) {
                            document.body.offsetHeight;
                        }
                        setTimeout(function() {
                            if (typeof window.init === 'function') {
                                try { window.init(); } catch(e) { console.log('[WebKitGTK] init() failed:', e); }
                            }
                            if (typeof window.setup === 'function') {
                                try { window.setup(); } catch(e) { console.log('[WebKitGTK] setup() failed:', e); }
                            }
                            if (typeof window.load === 'function') {
                                try { window.load(); } catch(e) { console.log('[WebKitGTK] load() failed:', e); }
                            }
                        }, 100);
                    });
                }
            })();
            """
            webview.evaluate_javascript(early_fix_script, -1, None, None, None)
        except Exception:
            pass

    def _handle_page_completion(self, webview):
        completion_script = """
        (function() {
            console.log('[WebKitGTK] Page load completed, checking for issues...');
            var hasContent = document.body && document.body.innerHTML.trim().length > 0;
            var hasImages = document.querySelectorAll('img').length > 0;
            var hasScripts = document.querySelectorAll('script').length > 0;
            console.log('[WebKitGTK] Content check:', {
                hasContent: hasContent,
                hasImages: hasImages,
                hasScripts: hasScripts,
                bodyHTML: document.body ? document.body.innerHTML.substring(0, 200) : 'No body'
            });
            if (!hasContent || (hasScripts && document.readyState === 'complete')) {
                setTimeout(function() {
                    console.log('[WebKitGTK] Triggering soft refresh for incomplete page...');
                    if (document.body) {
                        var originalHTML = document.body.innerHTML;
                        document.body.style.display = 'none';
                        document.body.offsetHeight;
                        document.body.style.display = '';
                        var event = new Event('DOMContentLoaded');
                        document.dispatchEvent(event);
                        var loadEvent = new Event('load');
                        window.dispatchEvent(loadEvent);
                    }
                }, 500);
            }
            if (typeof window.webkit === 'undefined') {
                console.log('[WebKitGTK] Applying compatibility layer...');
            }
        })();
        """
        webview.evaluate_javascript(completion_script, -1, None, None, None)

    def _update_loading_state(self, webview, loading):
        if hasattr(self, 'statusbar') and self.statusbar:
            self.statusbar.set_visible(loading)
            if loading:
                self.statusbar.push(0, "Loading...")
        if hasattr(self, 'refresh_button') and self.refresh_button:
            self.refresh_button.set_sensitive(not loading)

    def _on_webview_loaded(self, webview, load_event, js_code=None):
        if load_event == WebKit.LoadEvent.FINISHED and js_code:
            webview.run_javascript("""
                if (document.readyState === 'complete' || document.readyState === 'interactive') {
                    return true;
                } else {
                    return new Promise(resolve => {
                        window.addEventListener('DOMContentLoaded', () => resolve(true));
                    });
                }
            """, None, self._execute_js_after_ready, js_code)

    def detect_environment(self):
        try:
            if os.path.exists('/.flatpak-info'):
                return 'flatpak'
            if 'SNAP' in os.environ:
                return 'snap'
            if os.path.exists('/proc/self/exe') and 'appimage' in os.readlink('/proc/self/exe'):
                return 'appimage'
            return 'native'
        except (OSError, FileNotFoundError, PermissionError):
            return 'unknown'

    def check_file_access(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                f.read(1)
            return True
        except (IOError, OSError, PermissionError):
            return False

    def _execute_js_after_ready(self, webview, result, js_code):
        webview.run_javascript_finish(result)
        webview.run_javascript(js_code, None, self._on_js_executed, None)

    def open_url_in_new_tab(self, url, execute_js=True):
        if not url or not isinstance(url, str):
            return
        if url.startswith('file://'):
            parsed = urlparse(url)
            file_path = unquote(parsed.path)
            abs_path = Path(file_path).resolve()
            if not abs_path.exists():
                return
            if not abs_path.is_file():
                return
            file_accessible = self.check_file_access(str(abs_path))
            if not file_accessible:
                with open(abs_path, 'rb') as f:
                    content = f.read()
                import mimetypes
                mime_type, _ = mimetypes.guess_type(str(abs_path))
                if mime_type is None:
                    mime_type = 'text/html' if abs_path.suffix.lower() in ['.html', '.htm'] else 'text/plain'
                encoded_content = base64.b64encode(content).decode('utf-8')
                url = f"data:{mime_type};base64,{encoded_content}"
            else:
                url = f"file://{quote(str(abs_path))}"
        elif os.path.exists(url):
            file_path = url
            abs_path = Path(file_path).resolve()
            if not abs_path.exists():
                return
            if not abs_path.is_file():
                return
            file_accessible = self.check_file_access(str(abs_path))
            if not file_accessible:
                import mimetypes
                mime_type, _ = mimetypes.guess_type(str(abs_path))
                if mime_type is None:
                    mime_type = 'text/html' if abs_path.suffix.lower() in ['.html', '.htm'] else 'text/plain'
            try:
                with open(abs_path, 'rb') as f:
                    content = f.read()
                import mimetypes
                mime_type, _ = mimetypes.guess_type(str(abs_path))
                if mime_type is None:
                    mime_type = 'text/html' if abs_path.suffix.lower() in ['.html', '.htm'] else 'text/plain'
                encoded_content = base64.b64encode(content).decode('utf-8')
                url = f"data:{mime_type};base64,{encoded_content}"
            except Exception:
                return
            else:
                url = f"file://{quote(str(abs_path))}"
        new_webview = self.create_secure_webview()
        if new_webview is None:
            return
        new_webview.set_vexpand(True)
        new_webview.set_hexpand(True)
        new_webview.connect('load-changed', self.on_load_changed)
        new_webview.connect('notify::title', self.on_title_changed)
        new_webview.connect('decide-policy', self.on_decide_policy)
        new_webview.connect('create', self.on_webview_create)
        scrolled_window = Gtk.ScrolledWindow()
        scrolled_window.set_vexpand(True)
        scrolled_window.set_child(new_webview)
        self._create_tab_with_close_button(url, new_webview, scrolled_window)
        if url.lower().startswith("javascript:"):
            if not execute_js:
                return
            js_code = url[11:].strip()
            if not js_code:
                return

            def on_js_webview_loaded(webview, load_event, js_code):
                if load_event == WebKit.LoadEvent.FINISHED:
                    webview.run_javascript("""
                        if (document.readyState === 'complete' || document.readyState === 'interactive') {
                            return true;
                        } else {
                            return new Promise(resolve => {
                                document.addEventListener('DOMContentLoaded', () => resolve(true));
                            });
                        }
                    """, None, self._execute_js_after_ready, js_code)
                    webview.disconnect_by_func(on_js_webview_loaded)
            new_webview.connect('load-changed', on_js_webview_loaded, js_code)
            new_webview.load_uri("about:blank")
        else:
            new_webview.load_uri(url)
        self.notebook.set_visible(True)

    def add_webview_to_tab(self, webview, is_terminal=False):
        if is_terminal and not hasattr(webview, 'is_terminal'):
            webview.is_terminal = True
        scrolled_window = Gtk.ScrolledWindow()
        scrolled_window.set_vexpand(True)
        scrolled_window.set_child(webview)
        label_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        title_text = "Terminal" if is_terminal else self.extract_tab_title(webview.get_uri() or "New Tab")
        title_label = Gtk.Label(label=title_text)
        label_box.append(title_label)
        close_button = Gtk.Button.new_from_icon_name("window-close")
        close_button.set_size_request(24, 24)
        close_button.add_css_class("flat")
        close_button.set_tooltip_text("Close tab")
        header_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        header_box.append(label_box)
        header_box.append(close_button)
        tab = Tab(webview.get_uri() or ("terminal" if is_terminal else ""), webview, scrolled_window)
        tab.title_label = title_label
        tab.close_button = close_button
        tab.header_box = header_box
        tab.is_terminal = is_terminal
        index = self.notebook.append_page(scrolled_window, header_box)
        self.tabs.append(tab)
        self.webview_to_tab[webview] = tab
        self.tab_to_index[tab] = index
        close_button.connect("clicked", self.on_tab_close_clicked_by_button)
        self.notebook.set_current_page(index)
        return tab

    def open_popup_window(self, webview, window_features):
        try:
            window = Gtk.Window(title="Popup")
            if hasattr(self, 'window') and self.window:
                window.set_transient_for(self.window)
            window.set_destroy_with_parent(True)
            window.set_modal(False)
            if window_features and hasattr(window_features, 'get_width') and hasattr(window_features, 'get_height'):
                try:
                    width = window_features.get_width()
                    height = window_features.get_height()
                    default_width = int(width) if width is not None else 800
                    default_height = int(height) if height is not None else 600
                    window.set_default_size(default_width, default_height)
                except (ValueError, TypeError):
                    window.set_default_size(800, 600)
            else:
                window.set_default_size(800, 600)
            vbox = Gtk.Box.new(Gtk.Orientation.VERTICAL, 0)
            vbox.set_ox(orientation=Gtk.Orientation.VERTICAL)
            if hasattr(webview, 'get_parent') and webview.get_parent() is not None:
                parent = webview.get_parent()
                if parent and hasattr(parent, "remove") and webview.get_parent() == parent:
                    parent.remove(webview)
                safe_widget_append(vbox, webview)
                close_button = Gtk.Button.new_from_icon_name("window-close")
                close_button.set_size_request(24, 24)
                close_button.set_tooltip_text("Close popup")
                window._webview = webview
                window._close_button = close_button
                close_button.connect("clicked", lambda btn: window.close())
                header_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
                header_box.append(close_button)
                vbox.append(header_box)
                window.set_child(vbox)

                def on_popup_destroy(widget):
                    if hasattr(window, '_webview'):
                        window._webview = None
                    if hasattr(window, '_close_button'):
                        window._close_button = None
                    if hasattr(window, '_vbox'):
                        window._vbox = None
                window.connect("destroy", on_popup_destroy)
                window._vbox = vbox
                window.present()
                return window
        except Exception:
            return None

    def load_html_with_bootstrap(self, html):
        webview = self.get_current_webview()
        if not webview:
            return

    def inject_css_adblock(self):
        css = """
            div[class*="ad"]:not(.player-container, #player, .controls) {
                display: none !important;
            }
        """
        style = WebKit.UserStyleSheet.new(
            css,
            WebKit.UserContentInjectedFrames.TOP_FRAME,
            WebKit.UserStyleSheetLevel.USER,
            [], []
        )
        self.content_manager.add_style_sheet(style)

    def inject_adware_cleaner(self):
        script_source = """
        (function() {
            const playerSelectors = [
                '[class*="player" i]',
                '[id*="player" i]',
                '[class*="video" i]',
                '[id*="video" i]',
                '[class*="media" i]',
                '[id*="media" i]',
                'video', 'audio', 'object', 'embed',
                '[class*="jwplayer" i]',
                '[class*="vjs-" i]',
                '[class*="video-js" i]',
                '[class*="mejs-" i]',
                '[class*="flowplayer" i]',
                '[class*="plyr" i]',
                '[class*="shaka-" i]',
                '[class*="dash-" i]',
                '[class*="hls-" i]',
                '[class*="youtube" i]',
                '[class*="vimeo" i]',
                '[class*="netflix" i]',
                '[class*="hulu" i]',
                '[class*="amazon" i]',
                '[class*="disney" i]',
                '[class*="crunchyroll" i]',
                '[class*="funimation" i]',
                '[class*="tubi" i]',
                '[class*="peacock" i]',
                '[class*="paramount" i]',
                '[class*="hbomax" i]',
                '[class*="max" i]',
                '[class*="roku" i]',
                '[class*="twitch" i]',
                '[class*="kick" i]',
                '[class*="tiktok" i]',
                '[class*="instagram" i]',
                '[class*="facebook" i]',
                '[class*="twitter" i]',
                '[class*="x" i]',
                '[class*="snapchat" i]',
                '[class*="linkedin" i]',
                '[class*="pinterest" i]',
                '[class*="reddit" i]',
                '[class*="tumblr" i]',
                '[class*="discord" i]',
                '[class*="mixer" i]',
                '[class*="beam" i]',
                '[class*="hitbox" i]',
                '[class*="smashcast" i]',
                '[class*="azubu" i]',
                '[class*="dailymotion" i]',
                '[class*="vevo" i]',
                '[class*="mtv" i]',
                '[class*="vh1" i]',
                '[class*="bet" i]',
                '[class*="cm" i]'
            ];
            const whitelistedClasses = [
                'java', 'javaplayer', 'javaplugin', 'jvplayer', 'jwplayer',
                'video', 'player', 'mediaplayer', 'html5-video-player',
                'vjs-', 'mejs-', 'flowplayer', 'plyr', 'mediaelement',
                'shaka-', 'dash-', 'hls-', 'video-js', 'youtube', 'vimeo',
                'netflix', 'hulu', 'amazon', 'disney', 'crunchyroll', 'funimation',
                'tubi', 'peacock', 'paramount', 'hbomax', 'max', 'roku', 'twitch',
                'kick', 'tiktok', 'instagram', 'facebook', 'twitter', 'x', 'snapchat',
                'linkedin', 'pinterest', 'reddit', 'tumblr', 'discord', 'dailymotion',
                'vevo', 'mtv', 'vh1', 'bet', 'cm', 'logo', 'brand', 'sponsor', 'promo',
                'commercial', 'advert', 'banner', 'popup', 'overlay', 'modal', 'lightbox',
                'interstitial', 'pre-roll', 'mid-roll', 'post-roll', 'skip', 'close',
                'dismiss', 'hide', 'remove', 'block', 'mute', 'pause', 'stop', 'cancel',
                'exit', 'quit', 'end', 'finish', 'complete', 'done', 'finished', 'completed',
                'ended', 'stopped', 'paused', 'muted', 'blocked', 'removed', 'hidden',
                'dismissed', 'closed', 'skipped', 'post-rolled', 'mid-rolled', 'pre-rolled',
                'interstitialed', 'lightboxed', 'modaled', 'overlaid', 'popped', 'bannered',
                'advertised', 'promoted', 'sponsored', 'branded', 'logod', 'cmd'
            ];
            const blockedSelectors = [
                'iframe[src*="doubleclick.net" i]',
                'iframe[src*="googlesyndication.com" i]',
                'iframe[src*="adsystem.amazon" i]',
                'iframe[src*="adsystem" i]',
                'div[class*="ad-container" i]:not([class*="player" i]):not([class*="video" i]):not([class*="media" i])',
                'div[class*="ad_wrapper" i]:not([class*="player" i]):not([class*="video" i]):not([class*="media" i])',
                'div[class*="ad-wrapper" i]:not([class*="player" i]):not([class*="video" i]):not([class*="media" i])',
                'div[class*="popup" i]:not([class*="player" i]):not([class*="video" i]):not([class*="media" i])',
                'div[class*="overlay" i]:not([class*="player" i]):not([class*="video" i]):not([class*="media" i])',
                'div[class*="modal" i]:not([class*="player" i]):not([class*="video" i]):not([class*="media" i])',
                'div[class*="lightbox" i]:not([class*="player" i]):not([class*="video" i]):not([class*="media" i])'
            ];
            function isInPlayer(element) {
                let parent = element;
                while (parent) {
                    if (playerSelectors.some(selector => parent.matches && parent.matches(selector))) {
                        return true;
                    }
                    parent = parent.parentElement;
                }
                return false;
            }
            function hasPlayerClass(element) {
                let parent = element;
                while (parent) {
                    const classList = parent.classList || [];
                    for (const className of classList) {
                        if (whitelistedClasses.some(whitelist => className.toLowerCase().includes(whitelist.toLowerCase()))) {
                            return true;
                        }
                    }
                    parent = parent.parentElement;
                }
                return false;
            }
            function removeAds() {
                blockedSelectors.forEach(selector => {
                    try {
                        document.querySelectorAll(selector).forEach(el => {
                            if (el.offsetParent !== null && !isInPlayer(el) && !hasPlayerClass(el)) {
                                if (!el.querySelector('video, audio, object, embed')) {
                                    el.remove();
                                }
                            }
                        });
                    } catch (e) {
                        console.warn('Error in ad blocker:', e);
                    }
                });
            }
            document.addEventListener('DOMContentLoaded', removeAds);
            const observer = new MutationObserver(removeAds);
            observer.observe(document.body, {
                childList: true,
                subtree: true,
                attributes: true,
                attributeFilter: ['class', 'id', 'src']
            });
        })();
        """
        script = WebKit.UserScript.new(
            script_source,
            WebKit.UserContentInjectedFrames.ALL_FRAMES,
            WebKit.UserScriptInjectionTime.END,
        )
        self.content_manager.add_script(script)

    def inject_remove_malicious_links(self):
        script_source = """
        function sanitizeLinks() {
            const links = document.querySelectorAll('a[href^="javascript:"]:not([href^="javascript:void(0)"])');
            links.forEach(link => {
                link.removeAttribute('onclick');
                link.removeAttribute('onmousedown');
                link.href = '#';
                link.title = 'Potentially harmful link blocked';
            });
        }
        document.addEventListener('DOMContentLoaded', sanitizeLinks);
        const observer = new MutationObserver(sanitizeLinks);
        observer.observe(document.body, { childList: true, subtree: true });
        """
        script = WebKit.UserScript.new(
                script_source,
                WebKit.UserContentInjectedFrames.ALL_FRAMES,
                WebKit.UserScriptInjectionTime.END,
            )
        self.content_manager.add_script(script)

    def inject_nonce_respecting_script(self):
        script_source = """
        (function() {
            const scripts = document.querySelectorAll('script[nonce]');
            if (scripts.length > 0) {
                const nonce = scripts[0].nonce || scripts[0].getAttribute('nonce');
                if (nonce) {
                    const meta = document.createElement('meta');
                    meta.httpEquiv = "Content-Security-Policy";
                    meta.content = `script-src 'nonce-${nonce}' 'strict-dynamic' 'unsafe-inline'`;
                    document.head.appendChild(meta);
                }
            }
        })();
        """
        script = WebKit.UserScript.new(
                script_source,
                WebKit.UserContentInjectedFrames.ALL_FRAMES,
                WebKit.UserScriptInjectionTime.START,
            )
        self.content_manager.add_script(script)

    def disable_biometrics_in_webview(self, webview):
        """
        (function() {
            if (navigator.credentials) {
                const originalGet = navigator.credentials.get;
                const originalCreate = navigator.credentials.create;
                    navigator.credentials.get = function(options) {
                        if (options && options.publicKey) {
                            console.warn("[WebAuthn Blocked] navigator.credentials.get intercepted");
                            return Promise.reject(new DOMException("Biometric login blocked by user", "NotAllowedError"));
                        }
                        return originalGet.apply(this, arguments);
                    };
                    navigator.credentials.create = function(options) {
                        if (options && options.publicKey) {
                            console.warn("[WebAuthn Blocked] navigator.credentials.create intercepted");
                            return Promise.reject(new DOMException("Biometric credential creation blocked", "NotAllowedError"));
                        }
                        return originalCreate.apply(this, arguments);
                    };
                }
            })();
            """

    def block_biometric_apis(self, webview: WebKit.WebView):
        if not webview or not hasattr(webview, 'get_user_content_manager'):
            return
        script = """
        (function() {
            if (navigator.credentials) {
                    const originalGet = navigator.credentials.get;
                    const originalCreate = navigator.credentials.create;
                    const originalWarn = console.warn;
                    const originalError = console.error;
                    let warningShown = false;
                    function showWarningOnce(message) {
                        if (!warningShown) {
                            originalWarn.call(console, "[Shadow Browser] " + message);
                            warningShown = true;
                        }
                    }
                    navigator.credentials.get = function(options) {
                        if (options && options.publicKey) {
                            showWarningOnce("WebAuthn authentication blocked for security");
                            return Promise.reject(
                                new DOMException(
                                    "Biometric authentication is disabled in this browser for security reasons.",
                                    "NotAllowedError"
                                )
                            );
                        }
                        return originalGet.apply(this, arguments);
                    };
                    navigator.credentials.create = function(options) {
                        if (options && options.publicKey) {
                            showWarningOnce("WebAuthn registration blocked for security");
                            return Promise.reject(
                                new DOMException(
                                    "Biometric registration is disabled in this browser for security reasons.",
                                    "NotAllowedError"
                                )
                            );
                        }
                        return originalCreate.apply(this, arguments);
                    };
                    Object.defineProperty(console, 'warn', {
                        value: originalWarn,
                        writable: false,
                        configurable: false
                    });
                    Object.defineProperty(console, 'error', {
                        value: originalError,
                        writable: false,
                        configurable: false
                    });
                }
                const originalSendBeacon = navigator.sendBeacon;
                navigator.sendBeacon = function() {
                    return false;
                };
                Object.defineProperty(navigator, 'sendBeacon', {
                    value: navigator.sendBeacon,
                    writable: false,
                    configurable: false
                });
            })();
            """
        user_script = WebKit.UserScript.new(
                    script,
                    WebKit.UserContentInjectedFrames.ALL_FRAMES,
                    WebKit.UserScriptInjectionTime.START,
                    [],
                    []
                )
        content_manager = webview.get_user_content_manager()
        content_manager.remove_all_scripts()
        content_manager.add_script(user_script)

    def inject_anti_fingerprinting_script(self, user_content_manager):
        dnt_script = """
        Object.defineProperty(navigator, 'doNotTrack', {
            get: function() { return '1'; }
        });
        """
        user_script = WebKit.UserScript.new(
            dnt_script,
            WebKit.UserContentInjectedFrames.TOP_FRAME,
            WebKit.UserScriptInjectionTime.START,
            [], []
        )
        webview = self.get_current_webview()
        if webview:
            content_manager = webview.get_user_content_manager()
            content_manager.add_script(user_script)

    def _create_http_session(self):
        session = requests.Session()
        try:
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1'
            })
            retry_strategy = Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[408, 429, 500, 502, 503, 504],
                allowed_methods=["GET", "POST", "HEAD", "OPTIONS"],
                raise_on_status=False
            )
            adapter = HTTPAdapter(
                max_retries=retry_strategy,
                pool_connections=10,
                pool_maxsize=10,
                pool_block=False
            )
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            if self.tor_enabled and hasattr(self, 'tor_manager'):
                try:
                    if not self.tor_manager.is_running():
                        self.tor_manager.start()
                    if self.tor_manager.is_running():
                        proxy_url = f'socks5h://127.0.0.1:{self.tor_manager.tor_port}'
                        session.proxies = {
                            'http': proxy_url,
                            'https': proxy_url
                        }
                        response = session.get(
                            'https://check.torproject.org/api/ip',
                            timeout=15
                        )
                        response.raise_for_status()
                        if not response.json().get('IsTor', False):
                            self.tor_enabled = False
                            session.proxies = {}
                    else:
                        self.tor_enabled = False
                except Exception:
                    self.tor_enabled = False
                    session.proxies = {}
            return session
        except Exception:
            session.close()
            raise

    def initialize(self):
        if self._gst_initialized:
            return True
        try:
            if not self.Gst.init_check(None):
                error = self.Gst.init_get_error()
                if error:
                    return False
                try:
                    self.Gst = Gst
                    self.GLib = GLib
                    self.GObject = GObject
                except (ImportError, ValueError):
                    return False
            required_plugins = [
                'playbin', 'h264parse', 'h265parse', 'videoconvert', 'audioconvert'
            ]
            missing_plugins = []
            registry = self.Gst.Registry.get()
            for plugin in required_plugins:
                try:
                    feature = registry.lookup_feature(plugin)
                    if not feature:
                        missing_plugins.append(plugin)
                except (TypeError, AttributeError):
                    try:
                        feature = registry.lookup_feature(plugin.encode('utf-8'))
                        if not feature:
                            missing_plugins.append(plugin)
                    except Exception:
                        missing_plugins.append(plugin)
            if missing_plugins:
                return False
            self._gst_initialized = True
            return True
        except Exception:
            return False

    def load_page(self):
        self.webview.load_uri(self.url)
        time.sleep(random.uniform(2, 5))

    def navigate_to(self, path):
        new_url = f"{self.url.rstrip('/')}/{path.lstrip('/')}"
        self.webview.load_uri(new_url)
        time.sleep(random.uniform(2, 5))

    def get_favicon_(self, url):
        if not url:
            return None
        with self.favicon_lock:
            if url in self.favicon_cache:
                return self.favicon_cache[url]
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return None
        favicon_url = f"{parsed.scheme}://{parsed.netloc.rstrip('/')}/favicon.ico"
        try:
            response = requests.get(favicon_url, timeout=5)
            if response.status_code == 200 and response.content:
                texture = self._texture_from_bytes(response.content)
                if texture:
                    with self.favicon_lock:
                        self.favicon_cache[url] = texture
                    return texture
        except Exception:
            return None

    def _get_favicon_cache_path(self, url):
        cache_dir = os.path.join(os.path.expanduser("~"), ".shadowbrowser", "favicons")
        os.makedirs(cache_dir, exist_ok=True)
        filename = hashlib.sha1(url.encode("utf-8")).hexdigest() + ".png"
        return os.path.join(cache_dir, filename)

    def _load_cached_favicon(self, url):
        cache_path = self._get_favicon_cache_path(url)
        if os.path.exists(cache_path):
            try:
                with open(cache_path, "rb") as f:
                    return self._texture_from_bytes(f.read())
            except (FileNotFoundError, PermissionError, OSError, ValueError):
                return None
        return None

    def _texture_from_bytes(self, data):
        if not data:
            return None
        if not isinstance(data, GLib.Bytes):
            data = GLib.Bytes.new(data)
        try:
            return Gdk.Texture.new_from_bytes(data)
        except Exception:
            pass
        try:
            raw = data.get_data()
            if not raw:
                return None
            length = len(raw)
            if length % 4 != 0:
                return None
            pixels = length // 4
            size = int(pixels ** 0.5)
            if size * size * 4 != length:
                return None
            stride = size * 4
            return Gdk.MemoryTexture.new(
                size,
                size,
                Gdk.MemoryFormat.R8G8B8A8_PREMULTIPLIED,
                data,
                stride
            )
        except Exception:
            return None

    def _save_favicon_to_cache(self, url, texture_or_data):
        cache_path = self._get_favicon_cache_path(url)
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        try:
            if isinstance(texture_or_data, (bytes, bytearray)):
                with open(cache_path, "wb") as f:
                    f.write(texture_or_data)
                return True
            elif hasattr(texture_or_data, "get_bytes"):
                gbytes = texture_or_data.get_bytes()
                if gbytes:
                    with open(cache_path, "wb") as f:
                        f.write(gbytes.get_data())
                    return True
        except Exception:
            return False

    def get_favicon(self, url, callback=None):
        if not url or not isinstance(url, str):
            if callback:
                GLib.idle_add(callback, None)
            return None
        cache_key = url.lower().strip()
        with self.favicon_lock:
            if cache_key in self.favicon_cache:
                cached = self.favicon_cache[cache_key]
                if cached is not None and callback:
                    GLib.idle_add(callback, cached)
                return cached
        disk_cached = self._load_cached_favicon(cache_key)
        if disk_cached:
            with self.favicon_lock:
                self.favicon_cache[cache_key] = disk_cached
            if callback:
                GLib.idle_add(callback, disk_cached)
            return disk_cached

        def load_favicon_async():
            texture = self._load_favicon_async(url)
            if texture:
                with self.favicon_lock:
                    self.favicon_cache[cache_key] = texture
                if callback:
                    GLib.idle_add(callback, texture)
                return texture
            return None
        threading.Thread(target=load_favicon_async, daemon=True).start()
        return None

    def _on_favicon_loaded(self, cache_key, texture):
        with self.favicon_lock:
            if texture:
                self.favicon_cache[cache_key] = texture
                self._save_favicon_to_cache(cache_key, texture)
        if hasattr(self, '_pending_favicon_callbacks'):
            callbacks = self._pending_favicon_callbacks.pop(cache_key, [])
            for callback in callbacks:
                GLib.idle_add(callback, texture)

    def _load_favicon_async(self, url, callback=None):
        if not url:
            if callback:
                GLib.idle_add(callback, None)
            return None
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            if callback:
                GLib.idle_add(callback, None)
            return None
        domain = parsed.netloc[4:] if parsed.netloc.startswith("www.") else parsed.netloc
        favicon_urls = [
            f"https://www.google.com/s2/favicons?domain={domain}&sz=32",
            f"{parsed.scheme}://{domain}/favicon.ico",
            f"https://{domain}/favicon.ico",
            f"{parsed.scheme}://{domain}/favicon.png",
        ]
        if parsed.scheme == "https":
            favicon_urls.extend([
                f"http://{domain}/favicon.ico",
                f"http://{domain}/favicon.png",
            ])
        session = self._create_http_session()
        session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/91.0.4472.124 Safari/537.36"
            ),
            "Accept": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
        })
        valid_content_types = {
            "image/svg+xml", "image/svg", "image/webp", "image/png",
            "image/x-icon", "image/vnd.microsoft.icon", "image/icon",
            "image/ico", "image/jpeg", "image/jpg", "image/gif",
            "application/ico", "application/x-ico", "application/octet-stream"
        }

        def try_next_favicon(index=0):
            if index >= len(favicon_urls):
                if callback:
                    GLib.idle_add(callback, None)
                return
            favicon_url = favicon_urls[index]

            def on_response(session, response):
                try:
                    if response.status_code != 200:
                        raise Exception(f"HTTP {response.status_code}")
                    content_type = response.headers.get("content-type", "").lower()
                    if not any(x in content_type for x in valid_content_types):
                        if not response.content.startswith((b"\x89PNG", b"GIF", b"\xff\xd8", b"<svg", b"<?xml", b"\x00\x00")):
                            raise Exception("Invalid content type")
                    data = response.content
                    if not data:
                        raise Exception("Empty response")
                    texture = self._texture_from_bytes(data)
                    if texture:
                        try:
                            cache_key = f"{parsed.scheme}://{parsed.netloc}"
                            cache_path = self._get_favicon_cache_path(cache_key)
                            with open(cache_path, "wb") as f:
                                f.write(data)
                        except Exception:
                            pass
                        if callback:
                            GLib.idle_add(callback, texture)
                        return
                except Exception:
                    pass
                try_next_favicon(index + 1)

            def make_request():
                try:
                    response = session.get(favicon_url, timeout=5, stream=False)
                    GLib.idle_add(lambda: on_response(session, response))
                except Exception:
                    pass
                    GLib.idle_add(lambda: try_next_favicon(index + 1))
            threading.Thread(target=make_request, daemon=True).start()
        try_next_favicon()

    def fetch_favicon(self, page_url, callback):
        if not page_url or not isinstance(page_url, str):
            GLib.idle_add(callback, None)
            return
        page_url = page_url.strip()
        if not page_url.startswith(("http://", "https://")):
            GLib.idle_add(callback, None)
            return
        try:
            parsed = urlparse(page_url)
            if not parsed.scheme or not parsed.netloc:
                GLib.idle_add(callback, None)
                return
            if len(page_url) > 2048:
                GLib.idle_add(callback, None)
                return
        except (ValueError, AttributeError):
            GLib.idle_add(callback, None)
            return
        parsed = urllib.parse.urlparse(page_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        html = self.download_data(page_url)
        candidates = []
        if html:
            text = html.decode("utf-8", errors="ignore")
            for rel in ["icon", "shortcut icon", "apple-touch-icon"]:
                for m in re.finditer(rf'<link[^>]+rel=["\']?(?:{rel})[^>]*href=["\']([^"\'>]+)', text, re.I):
                    candidates.append(urllib.parse.urljoin(page_url, m.group(1)))
        for p in ["/favicon.ico", "/favicon.png", "/apple-touch-icon.png"]:
            candidates.append(urllib.parse.urljoin(base + "/", p))
        for url in candidates:
            data = self.download_data(url)
            if not data:
                continue
            try:
                gbytes = GLib.Bytes.new(data)
                texture = Gdk.Texture.new_from_bytes(gbytes)
                GLib.idle_add(callback, texture)
                return
            except Exception:
                continue
        GLib.idle_add(callback, None)

    def download_data(self, url, timeout=15):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ShadowBrowser/1.0"})
            return urllib.request.urlopen(req, timeout=timeout).read()
        except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout, ValueError):
            return None

    def _set_fallback_favicon(self, tab):
        try:
            icon_theme = Gtk.IconTheme.get_for_display(self.get_display())
            paintable = icon_theme.lookup_icon(
                "web-browser-symbolic",
                None,
                16,
                self.get_scale_factor(),
                Gtk.TextDirection.NONE,
                Gtk.IconLookupFlags.FORCE_SYMBOLIC
            )
            if paintable:
                tab.favicon_widget.set_from_paintable(paintable)
                tab.favicon = paintable
        except Exception:
            pass

    def get_favicon_from_cache(self, url):
        if not url or not isinstance(url, str):
            return None
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return None
        cache_key = f"{parsed.scheme}://{parsed.netloc}"
        with self.favicon_lock:
            tex = self.favicon_cache.get(cache_key)
            if tex:
                return tex
        try:
            disk_tex = self._load_cached_favicon(cache_key)
            if disk_tex:
                with self.favicon_lock:
                    self.favicon_cache[cache_key] = disk_tex
                return disk_tex
        except Exception:
            pass
        session = self._create_http_session()
        favicon_urls = [
            f"https://www.google.com/s2/favicons?domain={parsed.netloc}&sz=32",
            f"{parsed.scheme}://{parsed.netloc}/favicon.ico",
            f"{parsed.scheme}://{parsed.netloc}/favicon.png",
            f"{parsed.scheme}://{parsed.netloc}/favicon.jpg",
        ]
        valid_sig_prefixes = (
            b"\x89PNG\r\n\x1a\n",
            b"\xff\xd8\xff",
            b"GIF8",
            b"<?xml",
            b"<svg",
            b"\x00\x00\x01\x00"
        )
        for fav_url in favicon_urls:
            try:
                r = session.get(fav_url, timeout=5)
            except Exception:
                continue
            if r.status_code != 200:
                continue
            raw_bytes = r.content
            if not raw_bytes:
                continue
            content_type = (r.headers.get("content-type") or "").lower()
            if content_type and not any(x in content_type for x in ("image/", "application/octet-stream", "image/vnd.microsoft.icon")):
                if not any(raw_bytes.startswith(sig) for sig in valid_sig_prefixes):
                    continue
            try:
                tex = self._texture_from_bytes(raw_bytes)
            except Exception:
                tex = None
            if tex:
                with self.favicon_lock:
                    self.favicon_cache[cache_key] = tex
                try:
                    cache_path = self._get_favicon_cache_path(cache_key)
                    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
                    with open(cache_path, "wb") as f:
                        gbytes = tex.get_bytes()
                        f.write(gbytes.get_data())
                except (PermissionError, OSError, ValueError):
                    pass
                return tex
        return None

    def _process_favicon_texture(self, favicon_data, url):
        try:
            cache_key = url
            with self.favicon_lock:
                cached = self.favicon_cache.get(cache_key)
            if isinstance(cached, Gdk.Texture):
                return cached
            if isinstance(cached, (bytes, bytearray)):
                tex = self._texture_from_bytes(cached)
                if tex:
                    with self.favicon_lock:
                        self.favicon_cache[cache_key] = tex
                    return tex
            if favicon_data:
                tex = self._texture_from_bytes(favicon_data)
                if tex:
                    with self.favicon_lock:
                        self.favicon_cache[cache_key] = tex
                    return tex
            return None
        except Exception:
            pass
            return None

    def zoom_in(self):
        current_webview = self.get_current_webview()
        if current_webview:
            current_zoom = current_webview.get_zoom_level()
            current_webview.set_zoom_level(round(min(current_zoom + 0.1, 5.0), 1))

    def zoom_out(self):
        current_webview = self.get_current_webview()
        if current_webview:
            current_zoom = current_webview.get_zoom_level()
            current_webview.set_zoom_level(round(max(current_zoom - 0.1, 0.25), 1))

    def zoom_reset(self):
        current_webview = self.get_current_webview()
        if current_webview:
            current_webview.set_zoom_level(1.0)

    def check_turnstile(self):
        script = """
        var turnstile = document.querySelector('.cf-turnstile');
        if (turnstile) {
            console.log('Turnstile detected');
            turnstile;
        } else {
            console.log('No Turnstile found');
            null;
        }
        """
        self.webview.run_javascript(script, None, self.turnstile_callback, None)

    def turnstile_callback(self, webview, result, user_data):
        js_result = webview.run_javascript_finish(result)
        if js_result:
            value = js_result.get_js_value()
            if not value.is_null():
                pass
            else:
                pass

def main():
    app = ShadowBrowser()
    return app.run(sys.argv)

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
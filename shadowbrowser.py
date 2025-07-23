import datetime
import json
import os
import re
import socket
import ssl
import threading
import time
import traceback
from urllib.parse import urlparse, urlunparse, quote, unquote, parse_qs

import gi
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend

gi.require_version('Gtk', '4.0')
gi.require_version('WebKit', '6.0')
gi.require_version('Gdk', '4.0')
gi.require_version('GdkPixbuf', '2.0')
gi.require_version('GLib', '2.0')

from gi.repository import Gtk, GLib, WebKit, GdkPixbuf, Gdk

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

try:
    from js_obfuscation_improved import extract_url_from_javascript as js_extract_url
    from js_obfuscation_improved import extract_onclick_url

except ImportError:
    try:
        from js_obfuscation import extract_url_from_javascript as js_extract_url
        extract_onclick_url = None
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
        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                with self.context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                    return cert
        except Exception:
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
        except Exception:
            return True

class DownloadManager:
    def __init__(self, parent_window):
        self.parent_window = parent_window
        self.box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.downloads = {}
        self.ensure_download_directory()
        self.on_download_start_callback = None
        self.on_download_finish_callback = None

    def safe_append(self, container, widget):
        """Append widget to container after unparenting if needed to avoid GTK warnings."""
        if widget.get_parent() is not None:
            try:
                widget.unparent()
            except Exception:
                pass
        container.append(widget)

    def add_webview(self, webview):
        """Connect download signals to the download manager."""
        try:
            webview.connect("download-requested", self.on_download_requested)
        except Exception:
            pass

    def on_download_requested(self, context, download):
        """Handle download request event."""
        try:
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
            self.downloads[download] = {
                "hbox": hbox,
                "label": label,
                "progress": progress,
                "filepath": filepath,
                "status": "Downloading",
                "cancelled": False,
            }
            self.safe_append(hbox, label)
            self.safe_append(hbox, progress)
            self.safe_append(self.box, hbox)
            download.connect("progress-changed", self.on_progress_changed)
            download.connect("finished", self.on_download_finished)
            download.connect("failed", self.on_download_failed)
            download.connect("cancelled", self.on_download_cancelled)
            return True
        except Exception as e:
            self.show_error_message(f"Download failed: {str(e)}")
            return False

    def add_progress_bar(self, progress_info):
        """Add progress bar for manual downloads."""
        if self.on_download_start_callback:
            self.on_download_start_callback()
        hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        label = Gtk.Label(label=f"Downloading {progress_info['filename']}")
        progress = Gtk.ProgressBar()
        cancel_button = Gtk.Button(label="Cancel")
        cancel_button.set_tooltip_text("Cancel download")
        self.downloads[progress_info['filename']] = {
            "hbox": hbox,
            "label": label,
            "progress": progress,
            "cancel_button": cancel_button,
            "filepath": os.path.join(
                GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_DOWNLOAD) or 
                os.path.expanduser("~/Downloads"),
                progress_info['filename']
            ),
            "status": "Downloading",
            "cancelled": False
        }
        cancel_button.connect("clicked", lambda btn, info=progress_info: self.cancel_download(info))
        self.safe_append(hbox, label)
        self.safe_append(hbox, progress)
        self.safe_append(hbox, cancel_button)
        self.safe_append(self.box, hbox)

    def cancel_download(self, progress_info):
        """Cancel a manual download."""
        info = self.downloads.get(progress_info['filename'])
        if info and not info["cancelled"]:
            info["cancelled"] = True
            info["label"].set_text(f"Download cancelled: {progress_info['filename']}")
            info["progress"].set_text("Cancelled")
            if self.on_download_finish_callback:
                self.on_download_finish_callback()

    def update_progress(self, progress_info, progress):
        """Update progress for manual downloads."""
        info = self.downloads.get(progress_info['filename'])
        if info:
            info["progress"].set_fraction(progress)
            info["progress"].set_text(f"{progress * 100:.1f}%")
            info["label"].set_text(f"Downloading {progress_info['filename']}")

    def download_finished(self, progress_info):
        """Handle manual download finished."""
        if self.on_download_finish_callback:
            self.on_download_finish_callback()
        info = self.downloads.get(progress_info['filename'])
        if info:
            info["status"] = "Finished"
            info["progress"].set_fraction(1.0)
            info["progress"].set_text("100%")
            info["label"].set_text(f"Download finished: {progress_info['filename']}")
            GLib.timeout_add_seconds(5, lambda: self.cleanup_download(progress_info['filename']))

    def download_failed(self, progress_info, error_message):
        """Handle manual download failure."""
        if self.on_download_finish_callback:
            self.on_download_finish_callback()
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
        except OSError:
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
                else:
                    parent = self.download_area.get_parent()
                    if parent and hasattr(parent, "remove"):
                        parent.remove(self.download_area)
                    parent_child.append(self.download_area)

class AdBlocker:
    def __init__(self):
        self.blocked_patterns = []
        self.enabled = True
        self.block_list_url = "https://easylist.to/easylist/easylist.txt"
        self.cache_file = "easylist_cache.txt"
        self.cache_max_age = 86400
        self.adult_patterns = []
        self.load_block_lists()

    def inject_to_webview(self, user_content_manager):
        self.inject_adblock_script_to_ucm(user_content_manager)

    def inject_adblock_script_to_ucm(self, user_content_manager):
        """
        Injects JavaScript into UserContentManager to block ads and handle void links.
        """
        adblock_script = r"""
        (function() {
            const selectorsToHide = [
                '.ad', '.ads', '.advert', '.advertisement', '.banner', '.promo', '.sponsored',
                '[id*="ad-"]', '[id*="ads-"]', '[id*="advert-"]', '[id*="banner"]', '[id*="container"]',
                '[class*="-ad"]', '[class*="-ads"]', '[class*="-advert"]', '[class*="-banner"]',
                '[class*="adbox"]', '[class*="adframe"]', '[class*="adwrapper"]', '[class*="bannerwrapper"]',
                '[class*="__wrap"]','[class*="__content"]','[class*="__btn-block"]',
                '[src*="cdn.creative-sb1.com"]','[src*="cdn.storageimagedisplay.com"]',
                'iframe[src*="ad"]', 
                'div[id^="google_ads_"]',
                'div[class^="adsbygoogle"]',
                'ins.adsbygoogle'
            ].filter(selector => !selector.includes('.player-container') && !selector.includes('#player'));
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
                return patterns.some(p => p.test(url));
            }
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
        """
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
                        event.preventDefault();
                        event.stopPropagation();
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
        """Loads and caches ad blocking patterns from EasyList."""
        if (
            os.path.exists(self.cache_file)
            and (time.time() - os.path.getmtime(self.cache_file)) < self.cache_max_age
        ):
            with open(self.cache_file, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line and not line.startswith("!")]
        else:
            lines = self.fetch_block_list(self.block_list_url)
            with open(self.cache_file, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
        self.blocked_patterns = self._parse_block_patterns(lines)

    def fetch_block_list(self, url):
        """Fetches the block list content from a URL."""
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return [line.strip() for line in response.text.splitlines() if line and not line.startswith("!")]
        except requests.exceptions.RequestException:
            return []

    def _parse_block_patterns(self, lines):
        """Parses block list rules into regex patterns."""
        import pickle
        cache_file = "block_patterns_cache.pkl"
        if os.path.exists(cache_file):
            try:
                with open(cache_file, "rb") as f:
                    return pickle.load(f)
            except Exception:
                pass
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
        try:
            with open(cache_file, "wb") as f:
                pickle.dump(compiled_patterns, f)
        except Exception:
            pass
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
                    return True
            for pattern in self.blocked_patterns:
                if pattern.search(full_url):
                    return True
        except Exception:
            pass
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

    def enable_csp(self, webview, csp_policy=None):
        """
        Enable Content Security Policy on the webview with optional CSP string.
        Sanitizes the CSP string to remove unsupported directives like 'manifest-src'.
        Merges with existing CSP if provided.
        """

        default_csp = "default-src 'self'; script-src 'self' https://trusted.com;"
        if csp_policy is None:
            csp_policy = default_csp
        else:
            csp_directives = set(d.strip() for d in csp_policy.split(';') if d.strip())
            default_directives = set(d.strip() for d in default_csp.split(';') if d.strip())
            merged_directives = default_directives.union(csp_directives)
            csp_policy = '; '.join(sorted(merged_directives))
        sanitized_csp = re.sub(r'\bmanifest-src[^;]*;?', '', csp_policy, flags=re.IGNORECASE).strip()
        if sanitized_csp.endswith(';'):
            sanitized_csp = sanitized_csp[:-1].strip()
        settings = webview.get_settings()
        try:
            settings.set_property("content-security-policy", sanitized_csp)
        except Exception:
            settings.set_property("content-security-policy", default_csp)

    def report_csp_violation(self, report):
        pass

    def on_csp_violation(self, report):
        """Handles CSP violation and passes it to report_csp_violation."""
        self.report_csp_violation(report)

    def is_third_party_request(self, url, current_origin):
        try:
            page_origin = urlparse(self.get_current_webview().get_uri()).netloc
            return current_origin != page_origin
        except Exception:
            return False

    def enable_mixed_content_blocking(self, webview):
        settings = webview.get_settings()
        settings.set_property("allow-running-insecure-content", False)
        webview.set_settings(settings)

    def secure_cookies(self):
        """Disable all cookies by setting accept policy to NEVER."""
        try:
            webview = self.get_current_webview()
            if webview:
                cookie_manager = webview.get_context().get_cookie_manager()
                cookie_manager.set_accept_policy(WebKit.CookieAcceptPolicy.NEVER)
        except Exception:
            pass

    def set_samesite_cookie(self, cookie_manager, cookie):
        cookie.set_same_site(WebKit.CookieSameSitePolicy.STRICT)
        cookie_manager.set_cookie(cookie)

class SocialTrackerBlocker:
    def __init__(self):
        self.blocklist = self.load_blocklist("social_trackers.txt")

    def load_blocklist(self, filename):
        try:
            with open(filename, "r") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return ["twitter.com", "facebook.com", "instagram.com"]
        except Exception:
            return ["twitter.com", "facebook.com", "instagram.com"]

    def block_trackers(self, webview, url):
        parsed_url = urlparse(url)
        if any(domain in parsed_url.netloc for domain in self.blocklist):
            return False
        return True

class Tab:
    def __init__(self, url, webview):
        self.url = url
        self.webview = webview
        self.label_widget = None

class ShadowBrowser(Gtk.Application):
    def __init__(self):
        try:
            super().__init__(application_id="com.shadowyfigure.shadowbrowser")
            self.debug_mode = True
            self.content_manager = WebKit.UserContentManager()
            self.webview = WebKit.WebView(user_content_manager=self.content_manager)
            self.tabs = []
            self.blocked_urls = []
            self.window = None
            self.notebook = Gtk.Notebook()
            self.url_entry = Gtk.Entry()
            self.home_url = "https://duckduckgo.com/"
            self.theme = "dark"
            self.adblocker = AdBlocker()
            self.social_tracker_blocker = SocialTrackerBlocker()
            self.setup_security_policies()
            self.setup_webview_settings(self.webview)
            self.webview.connect("create", self.on_webview_create)
            self.bookmarks = self.load_json(BOOKMARKS_FILE) or {}
            self.history = self.load_json(HISTORY_FILE) or []
            self.download_manager = DownloadManager(None)
            self.active_downloads = 0
            self.download_spinner = Gtk.Spinner()
            self.download_spinner.set_visible(False)
            self.download_manager.on_download_start_callback = self.on_download_start
            self.download_manager.on_download_finish_callback = self.on_download_finish
            self.context = ssl.create_default_context()
            self.context.set_ciphers('DEFAULT@SECLEVEL=1')
            self.error_handlers = {}
            self.register_error_handlers()
            self.bookmark_menu = None
            self.incognito_mode = False
            try:
                self.adblocker.inject_to_webview(self.content_manager)
                self.inject_nonce_respecting_script()
                self.inject_remove_malicious_links()
                self.content_manager.register_script_message_handler("voidLinkClicked")
                self.content_manager.connect(
                    "script-message-received::voidLinkClicked", 
                    self.on_void_link_clicked
                )
                test_script = WebKit.UserScript.new(
                    "console.log('Shadow Browser initialized');",
                    WebKit.UserContentInjectedFrames.ALL_FRAMES,
                    WebKit.UserScriptInjectionTime.START,
                )
                self.content_manager.add_script(test_script)
                self.inject_wau_tracker_removal_script()
                self.inject_mouse_event_script()
                
            except Exception:
                pass
            
        except Exception:
            raise

    def toggle_incognito_mode(self, action=None, parameter=None):
        self.incognito_mode = not self.incognito_mode
        if self.incognito_mode:
            self.history = []
            self.save_json(HISTORY_FILE, [])
            try:
                pass
            except Exception:
                pass
        else:
            try:
                pass
            except Exception:
                pass

    def inject_wau_tracker_removal_script(self):
        try:
            wau_removal_script = WebKit.UserScript.new(
                """
                (function() {
                    // Remove script with id "_wau3wa"
                    var wauScript = document.getElementById('_wau3wa');
                    if (wauScript) {
                        var parentDiv = wauScript.parentElement;
                        if (parentDiv && parentDiv.style && parentDiv.style.display === 'none') {
                            parentDiv.remove();
                        } else {
                            wauScript.remove();
                        }
                    }
                    // Remove any script loading from waust.at domain
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
        self.active_downloads += 1
        if self.active_downloads == 1:
            GLib.idle_add(self.download_spinner.start)
            GLib.idle_add(lambda: self.download_spinner.set_visible(True))

    def on_download_finish(self):
        if self.active_downloads > 0:
            self.active_downloads -= 1
        if self.active_downloads == 0:
            GLib.idle_add(self.download_spinner.stop)
            GLib.idle_add(lambda: self.download_spinner.set_visible(False))

    def setup_security_policies(self):
        """Setup comprehensive security policies for the browser."""
        self.blocked_urls.extend([
            "accounts.google.com/gsi/client",
            "facebook.com/connect",
            "twitter.com/widgets",
            "youtube.com/player_api",
            "doubleclick.net",
            "googletagmanager.com"
        ])

    def inject_security_headers(self, webview, load_event):
        """Inject security headers into web requests."""
        if load_event == WebKit.LoadEvent.STARTED:
            uri = webview.get_uri()
            if uri and uri.startswith("http"):
                if any(blocked_url in uri.lower() for blocked_url in self.blocked_urls):
                    return True
                user_agent = webview.get_settings().get_user_agent()
                webview.get_settings().set_user_agent(
                    f"{user_agent} SecurityBrowser/1.0"
                )
                webview.get_settings().set_enable_javascript(True)
                webview.get_settings().set_javascript_can_access_clipboard(False)
                webview.get_settings().set_javascript_can_open_windows_automatically(False)
                return True
        return False

    def block_social_trackers(self, webview, decision, decision_type):
        """Block social media trackers."""
        if decision_type == WebKit.PolicyDecisionType.NAVIGATION_ACTION:
            nav_action = decision.get_navigation_action()
            uri = nav_action.get_request().get_uri()
            if any(tracker in uri.lower() for tracker in self.social_tracker_blocker.blocklist):
                decision.ignore()
                return True
        return False

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
        except Exception:
            return uuid_str

    def transform_embed_selector_links(self, html_content: str) -> str:
        """
        Transform UUIDs in <a> tags with class 'embed-selector asg-hover even' and onclick handlers
        by replacing UUIDs with short tokens in the onclick attribute.
        """

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
        encoded_ids = quote(id_string)
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
        context = WebKit.WebContext.get_default()
        webview = WebKit.WebView(user_content_manager=self.content_manager, web_context=context)
        settings = webview.get_settings()
        settings.set_property("enable-javascript", True)
        settings.set_property("enable-media-stream", True)
        settings.set_media_playback_requires_user_gesture(False)
        settings.set_property("enable-webgl", True)
        self.setup_webview_settings(webview)
        self.download_manager.add_webview(webview)
        return webview

    def on_void_link_clicked(self, user_content_manager, js_message):
        try:
            url = js_message.to_string()
            if url and url != 'about:blank':
                self.open_url_in_new_tab(url)
        except Exception:
            pass

    def setup_webview_settings(self, webview):
        """Configure WebView settings for security and compatibility."""
        settings = webview.get_settings()
        settings.set_enable_javascript(True)
        settings.set_enable_developer_extras(self.debug_mode)
        settings.set_enable_media_stream(True)
        settings.set_enable_media_capabilities(True)
        settings.set_enable_mediasource(True)
        settings.set_enable_smooth_scrolling(True)
        settings.set_enable_webgl(True)
        settings.set_enable_webaudio(True)
        settings.set_allow_file_access_from_file_urls(False)
        settings.set_allow_universal_access_from_file_urls(False)
        settings.set_allow_modal_dialogs(False)
        settings.set_javascript_can_access_clipboard(False) 
        settings.set_javascript_can_open_windows_automatically(False)
        settings.set_media_playback_requires_user_gesture(False) 
        webview.connect("load-changed", self.inject_security_headers)
        webview.connect("decide-policy", self.block_social_trackers)
        return webview
    
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
        self.safe_append(self.toolbar, back_button)
        forward_button = Gtk.Button.new_from_icon_name("go-next")
        forward_button.connect("clicked", self.on_forward_clicked)
        self.safe_append(self.toolbar, forward_button)
        refresh_button = Gtk.Button.new_from_icon_name("view-refresh")
        refresh_button.connect("clicked", self.on_refresh_clicked)
        self.safe_append(self.toolbar, refresh_button)
        home_button = Gtk.Button.new_from_icon_name("go-home")
        home_button.connect("clicked", lambda b: self.load_url(self.home_url))
        self.safe_append(self.toolbar, home_button)
        self.url_entry = Gtk.Entry()
        self.url_entry.set_placeholder_text("Enter URL")
        self.url_entry.connect("activate", self.on_go_clicked)
        self.safe_append(self.toolbar, self.url_entry)
        go_button = Gtk.Button.new_from_icon_name("go-jump")
        go_button.connect("clicked", self.on_go_clicked)
        self.safe_append(self.toolbar, go_button)
        add_bookmark_button = Gtk.Button.new_from_icon_name("bookmark-new")
        add_bookmark_button.set_tooltip_text("Add current page to bookmarks")
        add_bookmark_button.connect("clicked", self.on_add_bookmark_clicked)
        self.safe_append(self.toolbar, add_bookmark_button)
        new_tab_button = Gtk.Button.new_from_icon_name("tab-new")
        new_tab_button.connect("clicked", self.on_new_tab_clicked)
        self.safe_append(self.toolbar, new_tab_button)
        if self.download_spinner.get_parent() is not None:
            parent = self.download_spinner.get_parent()
            if parent and hasattr(parent, "remove"):
                parent.remove(self.download_spinner)
        self.safe_append(self.toolbar, self.download_spinner)
        self.download_spinner.set_halign(Gtk.Align.END)
        self.download_spinner.set_valign(Gtk.Align.CENTER)
        self.download_spinner.set_margin_start(10)
        self.download_spinner.set_margin_end(10)
        self.download_spinner.set_visible(False)
        return self.toolbar

    def safe_show_popover(self, popover):
        """Safely show a Gtk.Popover, avoiding multiple popups or broken state."""
        if not popover:
            return
        try:
            if popover.get_visible():
                return
            child = popover.get_child()
            if child and child.get_parent() is not None and child.get_parent() != popover:
                try:
                    child.get_parent().remove(child)
                except Exception:
                    pass
            parent = popover.get_parent()
            if parent is None:
                pass
            popover.popup()
        except Exception:
            pass

    def _show_bookmarks_menu(self, button=None):
        """Show the bookmarks menu."""
        if hasattr(self, "toolbar") and self.toolbar is not None:
            for child in self.toolbar.get_children():
                if isinstance(child, Gtk.MenuButton) and child.get_label() == "Bookmarks":
                    popover = child.get_popover()
                    if popover:
                        self.safe_show_popover(popover)
                        return

    def do_startup(self):
        """Initialize the application."""
        try:
            Gtk.Application.do_startup(self)
        except Exception:
            raise

    def do_activate(self):
        """Create and show the main window."""
        try:
            if not self.window:
                self.window = Gtk.ApplicationWindow(application=self)
                self.window.set_title("Shadow Browser")
                self.window.set_default_size(1200, 800)
                vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
                try:
                    menubar = self.create_menubar()
                    if menubar:
                        self.safe_append(vbox, menubar)
                    toolbar = self.create_toolbar()
                    if toolbar:
                        self.safe_append(vbox, toolbar)
                    if hasattr(self, 'notebook') and self.notebook:
                        self.safe_append(vbox, self.notebook)
                    if hasattr(self, 'download_manager') and self.download_manager:
                        self.download_manager.parent_window = self.window
                        self.download_manager.show()
                        self.safe_append(vbox, self.download_manager.box)
                    self.window.set_child(vbox)
                    self.window.connect("close-request", self.on_window_destroy)
                    self.add_new_tab(self.home_url)
                    self.apply_theme()
                except Exception:
                    return
            self.window.present()
        except Exception:
            raise

    def do_shutdown(self):
        """Save session and tabs before shutdown."""
        try:
            self.save_session()
            self.save_tabs()
        except Exception:
            pass
        Gtk.Application.do_shutdown(self)

    def register_error_handlers(self):
        self.error_handlers["gtk_warning"] = self.handle_gtk_warning
        self.error_handlers["network_error"] = self.handle_network_error
        self.error_handlers["webview_error"] = self.handle_webview_error
        self.error_handlers["memory_error"] = self.handle_memory_error

    def handle_gtk_warning(self, message):
        return True

    def handle_network_error(self, url, error):
        return True

    def handle_webview_error(self, webview, error):
        return True

    def handle_memory_error(self, error):
        return True

    def toggle_debug_mode(self, action=None, parameter=None):
        self.debug_mode = not self.debug_mode

    def set_logging_level(self):
        pass

    def toggle_adblocker(self, action=None, parameter=None):
        self.adblocker.enabled = not self.adblocker.enabled

    def set_search_engine(self, engine_url):
        self.search_engine = engine_url

    def on_close_current_tab(self, action, parameter):
        current_page = self.notebook.get_current_page()
        if current_page != -1:
            self.on_tab_close_clicked(None, current_page)

    def _close_bookmark_popover(self):
        """Helper to close the bookmarks popover."""
        if hasattr(self, 'bookmark_popover') and self.bookmark_popover:
            self.bookmark_popover.popdown()
    
    def _on_key_pressed(self, controller, keyval, keycode, state):
        """Handle keyboard shortcuts."""
        from gi.repository import Gdk
        ctrl = (state & Gdk.ModifierType.CONTROL_MASK)
        shift = (state & Gdk.ModifierType.SHIFT_MASK)
        if ctrl and shift and keyval == Gdk.KEY_b:
            self.test_bookmarks_menu()
            return True
        return False
        
    def _clear_all_bookmarks(self, button=None):
        """Clear all bookmarks."""
        self.bookmarks.clear()
        self.save_json(BOOKMARKS_FILE, self.bookmarks)
        self.update_bookmarks_menu(self.bookmark_menu)
        self._close_bookmark_popover()

    def create_menubar(self):
        menubar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.bookmark_menu_button = Gtk.MenuButton(label="Bookmarks")
        self.bookmark_menu_button.set_tooltip_text("Show bookmarks")
        self.bookmark_popover = Gtk.Popover()
        self.bookmark_popover.set_size_request(300, -1)
        if not hasattr(self, 'bookmark_menu') or self.bookmark_menu is None:
            self.bookmark_menu = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        self.update_bookmarks_menu(self.bookmark_menu)
        self.bookmark_popover.set_child(self.bookmark_menu)
        self.bookmark_menu_button.set_popover(self.bookmark_popover)
        self.bookmark_popover.connect("closed", lambda popover: popover.set_visible(False))
        self.safe_append(menubar, self.bookmark_menu_button)
        if hasattr(self, 'window') and self.window:
            shortcut_controller = Gtk.EventControllerKey()
            shortcut_controller.connect("key-pressed", self._on_key_pressed)
            self.window.add_controller(shortcut_controller)
        download_button = Gtk.Button(label="Downloads")
        download_button.set_tooltip_text("Open Downloads Folder")
        download_button.connect("clicked", self.on_downloads_clicked)
        self.safe_append(menubar, download_button)
        about_button = Gtk.Button(label="About")
        about_button.connect("clicked", self.on_about)
        self.safe_append(menubar, about_button)
        return menubar

    def on_downloads_clicked(self, button):
        """Open the downloads folder in the system file manager."""
        downloads_dir = GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_DOWNLOAD)
        if not downloads_dir:
            downloads_dir = os.path.expanduser("~/Downloads")
        try:
            import subprocess
            subprocess.Popen(["xdg-open", downloads_dir])
        except Exception:
            self.show_error_message("Failed to open downloads folder.")

    def on_search_activate(self, search_entry):
        """Handle search/URL entry with enhanced features.
        Supports:
        - Direct URL loading with auto-correction
        - Search with default search engine
        - Search engine shortcuts (e.g., 'g searchterm' for Google)
        - Common URL typos correction
        """
        query = search_entry.get_text().strip()
        if not query:
            return
        search_engines = {
            'g': 'https://www.google.com/search?q={}',
            'ddg': 'https://duckduckgo.com/?q={}',
            'yt': 'https://www.youtube.com/results?search_query={}',
            'gh': 'https://github.com/search?q={}'
        }
        if ' ' in query:
            prefix = query.split(' ', 1)[0].lower()
            if prefix in search_engines:
                search_term = query.split(' ', 1)[1]
                search_url = search_engines[prefix].format(requests.utils.quote(search_term))
                self.load_url(search_url)
                return
        if self.is_valid_url(query):
            self.load_url(query)
            return
        corrected_url = self.attempt_url_correction(query)
        if corrected_url and self.is_valid_url(corrected_url):
            self.load_url(corrected_url)
            return
        search_url = f"https://duckduckgo.com/?q={requests.utils.quote(query)}"
        self.load_url(search_url)
        
    def attempt_url_correction(self, url):
        """Attempt to correct common URL typos."""
        url = url.lower()
        if not (url.startswith('http://') or url.startswith('https://')):
            url = 'https://' + url
        corrections = {
            '.con': '.com',
            '.comm': '.com',
            '.cmo': '.com',
            '.cim': '.com',
            'www,': 'www.',
            'ww.' : 'www.',
            'wwww.' : 'www.'
        }
        for typo, fix in corrections.items():
            if typo in url:
                url = url.replace(typo, fix)
        return url if '.' in url.split('//')[-1] else None

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
            webview = self.get_current_webview()
            if webview:
                webview.load_uri(url)
                self.url_entry.set_text(url)
                self.update_history(url)
        except Exception:
            self.show_error_message(f"Error loading URL: {traceback.format_exc()}")

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
            return
        if url not in self.bookmarks:
            self.bookmarks.append(url)
            self.save_json(BOOKMARKS_FILE, self.bookmarks)
            self.update_bookmarks_menu(self.bookmark_menu)
            return True
        return False

    def update_bookmarks_menu(self, menu_box):
        """Update the bookmarks menu with current bookmarks."""
        children = menu_box.observe_children()
        for i in range(children.get_n_items()):
            child = children.get_item(i)
            menu_box.remove(child)
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scrolled.set_propagate_natural_height(True)
        scrolled.set_max_content_height(400)
        bookmarks_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        bookmarks_box.set_margin_top(5)
        bookmarks_box.set_margin_bottom(5)
        bookmarks_box.set_margin_start(5)
        bookmarks_box.set_margin_end(5)
        scrolled.set_child(bookmarks_box)
        self.safe_append(menu_box, scrolled)
        for bookmark in self.bookmarks:
            if isinstance(bookmark, str) and bookmark.startswith(("http://", "https://")):
                row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
                row.set_margin_top(2)
                row.set_margin_bottom(2)
                display_text = bookmark
                if len(display_text) > 40:
                    display_text = display_text[:37] + "..."                    
                bookmark_button = Gtk.Button(label=display_text, hexpand=True, halign=Gtk.Align.START)
                bookmark_button.set_tooltip_text(bookmark)
                bookmark_button.connect("clicked", 
                    lambda btn, url=bookmark: (self.load_url(url), self._close_bookmark_popover())
                )               
                delete_button = Gtk.Button(icon_name="user-trash-symbolic")
                delete_button.set_tooltip_text("Remove bookmark")
                delete_button.add_css_class("flat")
                delete_button.connect("clicked", 
                    lambda btn, url=bookmark: (self.delete_bookmark(url), self._close_bookmark_popover())
                )              
                self.safe_append(row, bookmark_button)
                self.safe_append(row, delete_button)
                self.safe_append(bookmarks_box, row)
        if self.bookmarks:
            self.safe_append(bookmarks_box, Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL))
            clear_button = Gtk.Button(label="Clear All Bookmarks")
            clear_button.add_css_class("destructive-action")
            clear_button.connect("clicked", self._clear_all_bookmarks)
            self.safe_append(bookmarks_box, clear_button)

    def delete_bookmark(self, bookmark):
        """Remove a bookmark."""
        if bookmark in self.bookmarks:
            self.bookmarks.remove(bookmark)
            self.save_json(BOOKMARKS_FILE, self.bookmarks)
            self.update_bookmarks_menu(self.bookmark_menu)
        else:
            pass

    def update_history(self, url):
        """Add URL to browser history."""
        if url and url.startswith(("http://", "https://")):
            self.history.append({"url": url, "timestamp": time.time()})
            self.history = self.history[-HISTORY_LIMIT:]
            self.save_json(HISTORY_FILE, self.history)

    def load_json(self, filename):
        """Load JSON data from file."""
        try:
            if os.path.exists(filename):
                with open(filename, "r") as f:
                    return json.load(f)
        except Exception:
            return []

    def save_json(self, filename, data):
        """Save JSON data to file."""
        try:
            with open(filename, "w") as f:
                json.dump(data, f)
        except Exception:
            pass

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
        about.set_website("https://github.com/shadowyfigure/shadow-browser-")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        image_path = os.path.join(script_dir, "background.png")
        try:
            if os.path.exists(image_path):
                pixbuf = GdkPixbuf.Pixbuf.new_from_file(image_path)
                texture = Gdk.Texture.new_for_pixbuf(pixbuf)
                about.set_logo(texture)
            else:
                about.set_logo_icon_name("web-browser")
        except Exception:
            pass
        about.present()

    def on_back_clicked(self, button):
        """Handle back button click."""
        webview = self.get_current_webview()
        if webview and webview.can_go_back():
            webview.go_back()

    def on_new_tab_clicked(self, button):
        """Handle New Tab button click."""
        self.add_new_tab(self.home_url)

    def safe_append(self, container, widget):
        """Append widget to container after unparenting if needed to avoid GTK warnings."""
        if widget.get_parent() is not None:
            try:
                widget.unparent()
            except Exception:
                pass
        container.append(widget)

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
        tab = Tab(url, webview)
        tab.label_widget = label
        def on_close_clicked(button, tab=tab):
            try:
                tab_index = self.tabs.index(tab)
                self.on_tab_close_clicked(button, tab_index)
            except ValueError:
                pass
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        self.safe_append(box, label)
        self.safe_append(box, close_button)
        index = self.notebook.append_page(scrolled_window, box)
        self.notebook.set_current_page(index)
        self.tabs.append(tab)
        close_button.connect("clicked", on_close_clicked)
        webview.connect("load-changed", self.on_load_changed)
        webview.connect("notify::title", self.on_title_changed)
        webview.connect("decide-policy", self.on_decide_policy)

    def on_tab_close_clicked(self, button, tab_index):
        """Close the tab at the given index."""
        if 0 <= tab_index < len(self.tabs):
            tab = self.tabs[tab_index]
            webview = tab.webview
            if webview is None:
                self.tabs.pop(tab_index)
                self.notebook.remove_page(tab_index)
                return
            notebook_page_num = None
            for page_index in range(self.notebook.get_n_pages()):
                page = self.notebook.get_nth_page(page_index)
                if isinstance(page, Gtk.ScrolledWindow):
                    child = page.get_child()
                    if child == webview or (isinstance(child, Gtk.Viewport) and child.get_child() == webview):
                        notebook_page_num = page_index
                        break
            if notebook_page_num is not None:
                page = self.notebook.get_nth_page(notebook_page_num)
                if page:
                    if isinstance(page, Gtk.ScrolledWindow):
                        child = page.get_child()
                        if isinstance(child, Gtk.Viewport):
                            webview = child.get_child()
                        else:
                            webview = child
                    self.notebook.remove_page(notebook_page_num)
                    if webview:
                        try:
                            webview.unparent()
                        except Exception:
                            pass
                    try:
                        page.unparent()
                    except Exception:
                        pass
            removed_tab = self.tabs.pop(tab_index)
            try:
                if removed_tab.webview:
                    removed_tab.webview.disconnect_by_func(self.on_load_changed)
                    removed_tab.webview.disconnect_by_func(self.on_title_changed)
                    removed_tab.webview.disconnect_by_func(self.on_decide_policy)
            except Exception:
                pass

    def on_load_changed(self, webview, load_event):
        """Handle load state changes."""
        from gi.repository import WebKit
        try:
            if load_event == WebKit.LoadEvent.COMMITTED:
                current_webview = self.get_current_webview()
                if webview == current_webview:
                    self.url_entry.set_text(webview.get_uri() or "")
                GLib.idle_add(self.download_spinner.start)
                GLib.idle_add(lambda: self.download_spinner.set_visible(True))
            elif load_event == WebKit.LoadEvent.FINISHED:
                GLib.idle_add(self.download_spinner.stop)
                GLib.idle_add(lambda: self.download_spinner.set_visible(False))
        except Exception:
            pass

    def on_title_changed(self, webview, param):
        """Update tab label when page title changes."""
        try:
            max_length = 10
            title = webview.get_title() or "Untitled"
            if len(title) > max_length:
                title = title[:max_length - 3] + "..."
            for i, tab in enumerate(self.tabs):
                if tab.webview == webview and tab.label_widget is not None:
                    tab.label_widget.set_text(title)
                    break
        except Exception:
            pass

    def on_webview_create(self, webview, navigation_action, window_features=None):
        """Handle creation of new webviews."""
        try:
            if window_features is None:
                return None
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
            is_popup = False
            try:
                if window_features is not None and hasattr(window_features, "get") and callable(window_features.get):
                    try:
                        is_popup = window_features.get("popup", False)
                    except Exception:
                        is_popup = False
            except Exception:
                is_popup = False
            if is_popup:
                self.open_popup_window(new_webview, window_features)
            else:
                self.add_webview_to_tab(new_webview)
            return new_webview
        except Exception:
            return None
    BLOCKED_INTERNAL_URLS = ["about:blank", "about:srcdoc", "blob:", "data:", "about:debug"]
    allow_about_blank = False

    def is_internal_url_blocked(self, url, is_main_frame):
        """
        Determine if an internal URL should be blocked.
        Args:
            url (str): The URL to check.
            is_main_frame (bool): Whether the request is for the main frame.
        Returns:
            bool: True if the URL should be blocked, False otherwise.
        """
        if not url:
            return False
        if url.startswith("about:blank") and not self.allow_about_blank:
            return True 
        if url in self.BLOCKED_INTERNAL_URLS:
            return True
        if not is_main_frame and url.startswith(("about:", "data:", "blob:")):
            return True
        return False

    def _handle_navigation_action(self, webview, decision, navigation_action):
        """Handle navigation action policy decision."""
        try:
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
            is_main_frame = True
            if hasattr(navigation_action, "get_frame"):
                frame = navigation_action.get_frame()
                if hasattr(frame, "is_main_frame"):
                    try:
                        is_main_frame = frame.is_main_frame()
                    except Exception:
                        pass
            if self.is_internal_url_blocked(requested_url, is_main_frame):
                decision.ignore()
                return True
            if requested_url.startswith(("about:", "data:", "blob:", "_data:")):
                if not is_main_frame:
                    decision.ignore()
                    return True
                decision.use()
                return True
            parsed = urlparse(requested_url)
            if parsed.scheme not in ("http", "https"):
                decision.ignore()
                return True
            if not is_main_frame:
                top_level_url = webview.get_uri()
                if top_level_url:
                    top_host = urlparse(top_level_url).hostname
                    req_host = parsed.hostname
                    if top_host and req_host and top_host != req_host:
                        decision.ignore()
                        return True
            if self.adblocker.is_blocked(requested_url):
                decision.ignore()
                return True
            if requested_url.lower().endswith(tuple(DOWNLOAD_EXTENSIONS)):
                self.start_manual_download(requested_url)
                decision.ignore()
                return True
            decision.use()
            return True
        except Exception:
            decision.ignore()
            return True

    def _handle_new_window_action(self, webview, decision):
        """Handle new window action policy decision."""
        try:
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
            if url.lower() == "about:blank":
                decision.ignore()
                return True
            if url.lower() == "javascript:void(0)":
                decision.ignore()
                return True
            if url.lower().endswith(tuple(DOWNLOAD_EXTENSIONS)):
                self.start_manual_download(url)
                decision.ignore()
                return True
            user_content_manager = webview.get_user_content_manager()
            new_webview = WebKit.WebView(user_content_manager=user_content_manager)
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
        except Exception:
            decision.ignore()
            return True

    def on_decide_policy(self, webview, decision, decision_type):
        """Handle navigation and new window actions, manage downloads, enforce policies, and apply adblock rules."""
        try:
            from gi.repository import WebKit
            if decision_type == WebKit.PolicyDecisionType.NAVIGATION_ACTION:
                return self._handle_navigation_action(webview, decision, decision.get_navigation_action())
            elif decision_type == WebKit.PolicyDecisionType.NEW_WINDOW_ACTION:
                return self._handle_new_window_action(webview, decision)
            else:
                decision.use()
                return True
        except Exception:
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
        def sanitize_filename(filename):
            """Sanitize and clean up the filename."""
            filename = re.sub(r'[?#].*$', '', filename)
            filename = re.sub(r'[?&][^/]+$', '', filename)
            filename = re.sub(r'[^\w\-_. ]', '_', filename).strip()
            return filename or 'download'

        def get_filename_from_url(parsed_url):
            """Extract and clean filename from URL path."""
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
            """Get appropriate file extension from content type."""
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
            try:
                parsed_url = urlparse(url)
                if not parsed_url.scheme or not parsed_url.netloc:
                    GLib.idle_add(
                        lambda: self.show_error_message("Invalid URL format"),
                        priority=GLib.PRIORITY_DEFAULT,
                    )
                    return
                headers = {
                    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
                with requests.get(url, stream=True, timeout=30, headers=headers) as response:
                    response.raise_for_status()
                    content_disposition = response.headers.get("content-disposition", "")
                    filename = None
                    if content_disposition:
                        filename_match = re.search(
                            r'filename[^;=]*=([^;\n]*)', 
                            content_disposition, 
                            flags=re.IGNORECASE
                        )
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
                    downloads_dir = GLib.get_user_special_dir(
                        GLib.UserDirectory.DIRECTORY_DOWNLOAD
                    ) or os.path.expanduser("~/Downloads")
                    os.makedirs(downloads_dir, exist_ok=True)
                    base_name, ext = os.path.splitext(filename)
                    counter = 1
                    while os.path.exists(os.path.join(downloads_dir, filename)):
                        filename = f"{base_name}_{counter}{ext}"
                        counter += 1
                    filepath = os.path.join(downloads_dir, filename)
                    total_size = int(response.headers.get("content-length", 0))
                    downloaded = 0
                    progress_info = {
                        "filename": filename,
                        "total_size": total_size,
                        "downloaded": downloaded,
                        "cancelled": False,
                        "thread_id": threading.current_thread().ident,
                    }
                    self.download_manager.add_progress_bar(progress_info)
                    try:
                        with open(filepath, 'wb') as f:
                            for chunk in response.iter_content(chunk_size=8192):
                                if progress_info["cancelled"]:
                                    break
                                if chunk:
                                    f.write(chunk)
                                    downloaded += len(chunk)
                                    progress = (
                                        downloaded / total_size if total_size > 0 else 0
                                    )
                                    GLib.idle_add(
                                        self.download_manager.update_progress,
                                        progress_info,
                                        progress,
                                    )
                            if not progress_info["cancelled"]:
                                GLib.idle_add(
                                    self.download_manager.download_finished,
                                    progress_info
                                )
                    except Exception:
                        GLib.idle_add(
                            self.download_manager.download_failed,
                            progress_info,
                            "Error writing to file",
                        )
                    finally:
                        GLib.idle_add(
                            self.download_manager.cleanup_download,
                            progress_info["filename"],
                        )
            except requests.exceptions.RequestException:
                GLib.idle_add(
                    self.download_manager.download_failed,
                    None,
                    "Download request failed",
                )
            except Exception:
                GLib.idle_add(
                    self.download_manager.download_failed,
                    None,
                    "Unexpected download error",
                )
        thread = threading.Thread(
            target=download_thread, daemon=True, name=f"download_{url}"
        )
        thread.start()
        return thread.ident

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
        except Exception:
            pass

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
            "return true;"
            "}"
            "}"
            "return false;"
            "})();"
        )
        webview = self.get_current_webview()
        if webview:
            webview.evaluate_javascript(js_code, self.js_callback)

        def js_callback(self, webview, result):
            try:
                if result is None:
                    return
                webview.evaluate_javascript_finish(result)
            except Exception:
                pass

    def test_js_execution(self):
        webview = self.get_current_webview()
        if webview:
            js_code = "console.log('Test JS execution in webview'); 'JS executed';"
            webview.evaluate_javascript(js_code, self.js_callback)

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
        tab = Tab(url, new_webview)
        def on_close_clicked(button, tab=tab):
            try:
                tab_index = self.tabs.index(tab)
                self.on_tab_close_clicked(button, tab_index)
            except ValueError:
                pass
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        self.safe_append(box, label)
        self.safe_append(box, close_button)
        index = self.notebook.append_page(scrolled_window, box)
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
        tab = Tab(webview.get_uri(), webview)
        def on_close_clicked(button, tab=tab):
            try:
                tab_index = self.tabs.index(tab)
                self.on_tab_close_clicked(button, tab_index)
            except ValueError:
                pass
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        self.safe_append(box, label)
        self.safe_append(box, close_button)
        index = self.notebook.append_page(scrolled_window, box)
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
        if webview.get_parent() is not None:
            parent = webview.get_parent()
            if parent and hasattr(parent, "remove"):
                parent.remove(webview)
        self.safe_append(vbox, webview)
        close_button = Gtk.Button.new_from_icon_name("window-close")
        close_button.set_size_request(24, 24)
        close_button.set_tooltip_text("Close popup")
        close_button.connect("clicked", lambda btn: window.destroy())
        if close_button.get_parent() is not None:
            parent = close_button.get_parent()
            if parent and hasattr(parent, "remove"):
                parent.remove(close_button)
        self.safe_append(vbox, close_button)
        window.set_child(vbox)
        window.show()

    def load_html_with_bootstrap(self, html):
        """
        Load HTML content into the current webview with Bootstrap CSS linked in the head.
        If Bootstrap CSS link is not present, it will be injected.
        """
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

        
    def inject_remove_malicious_links(self):
        try:
            with open("remove_malicious_links.js", "r") as f:
                script_source = f.read()
            script = WebKit.UserScript.new(
                script_source,
                WebKit.UserContentInjectedFrames.ALL_FRAMES,
                WebKit.UserScriptInjectionTime.END,
            )
            self.content_manager.add_script(script)
        except Exception:
            pass
        
    def inject_nonce_respecting_script(self):
        try:
            with open("bootstrap_nonce_script.js", "r") as f:
                script_source = f.read()
            user_script = WebKit.UserScript.new(
                script_source,
                WebKit.UserContentInjectedFrames.ALL_FRAMES,
                WebKit.UserScriptInjectionTime.END,
                [],
                []
            )
            self.content_manager.add_script(user_script)
        except Exception:
            pass

def main():
    """Main entry point for the application."""
    app = ShadowBrowser()
    return app.run(None)

if __name__ == "__main__":
    import sys
    sys.exit(main())


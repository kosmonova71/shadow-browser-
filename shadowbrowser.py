import os
import ssl
import gi
import time
import re
import socket
import threading
import shutil
import subprocess
from urllib.parse import urlparse, urlunparse
import datetime
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from stem.control import Controller
import urllib.request
import json

try:
    gi.require_version("Gtk", "4.0")
    gi.require_version("WebKit", "6.0")
    gi.require_version("Adw", "1")
    gi.require_version("GdkPixbuf", "2.0")
    gi.require_version("Gdk", "4.0")
    from gi.repository import Gtk, GLib, WebKit, GdkPixbuf, Gdk
except (ValueError, ImportError):
    exit(1)

def safe_widget_append(container, widget, logger=None):
    """
    Safely append a widget to a container, handling any necessary unparenting.    
    Args:
        container: The GTK container to append to
        widget: The widget to append
        logger: Optional logger instance for debugging       
    Returns:
        bool: True if append was successful, False otherwise
    """
    if not container or not widget:
        if logger:
            logger.warning(f"Invalid container or widget: container={container}, widget={widget}")
        return False      
    try:
        current_parent = widget.get_parent()
        if current_parent is not None and current_parent != container:
            try:
                if hasattr(widget, 'get_parent') and widget.get_parent() is not None:
                    if hasattr(current_parent, 'get_child') or hasattr(current_parent, 'get_first_child'):
                        widget.unparent()
                        if logger:
                            logger.debug(f"Unparented widget from {current_parent}")
            except Exception as e:
                if logger:
                    logger.warning(f"Failed to unparent widget: {e}", exc_info=True)
        container.append(widget)
        if logger:
            logger.debug(f"Appended {widget} to {container}")
        return True
    except Exception as e:
        if logger:
            logger.error(f"Failed to append widget to container: {e}", exc_info=True)
        return False

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
        self.lock = threading.Lock()
        self.ensure_download_directory()
        self.on_download_start_callback = None
        self.on_download_finish_callback = None

    def safe_append(self, container, widget):
        """
        Safely append a widget to a container using the shared utility function.
        
        Args:
            container: The GTK container to append to
            widget: The widget to append
            
        Returns:
            bool: True if append was successful, False otherwise
        """
        return safe_widget_append(container, widget)

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
            with self.lock:
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
            pass
            self.show_error_message(f"Download failed: {str(e)}")
            return False

    def add_progress_bar(self, progress_info):
        """Add progress bar for manual downloads."""
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
            self.safe_append(hbox, label)
            self.safe_append(hbox, progress)
            self.safe_append(self.box, hbox)

    def update_progress(self, progress_info, progress):
        """Update progress for manual downloads."""
        with self.lock:
            info = self.downloads.get(progress_info["filename"])
            if info:
                info["progress"].set_fraction(progress)
                info["progress"].set_text(f"{progress * 100:.1f}%")
                info["label"].set_text(f"Downloading {progress_info['filename']}")

    def download_finished(self, progress_info):
        """Handle manual download finished."""
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
        """Handle manual download failure."""
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
        """Clean up download UI elements."""
        with self.lock:
            info = self.downloads.pop(download_key, None)
            if info:
                try:
                    parent = info["hbox"].get_parent()
                    if parent and hasattr(parent, "remove"):
                        # Check if the parent is still valid
                        if info["hbox"].get_parent() == parent:
                            parent.remove(info["hbox"])
                except Exception:
                    pass

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
        try:
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
        except Exception:
            pass

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
        """Loads and caches ad blocking patterns from EasyList."""
        if (
            os.path.exists(self.cache_file)
            and (time.time() - os.path.getmtime(self.cache_file)) < self.cache_max_age
        ):
            with open(self.cache_file, "r", encoding="utf-8") as f:
                lines = [
                    line.strip() for line in f if line and not line.startswith("!")
                ]
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
            return [
                line.strip()
                for line in response.text.splitlines()
                if line and not line.startswith("!")
            ]
        except requests.exceptions.RequestException:
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
            except re.error:
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
        """
        if csp_policy is None:
            csp_policy = "default-src 'self'; script-src 'self' https://trusted.com;"
        import re
        sanitized_csp = re.sub(
            r"\bmanifest-src[^;]*;?", "", csp_policy, flags=re.IGNORECASE
        ).strip()
        if sanitized_csp.endswith(";"):
            sanitized_csp = sanitized_csp[:-1].strip()
        csp_script = f"""
        (function() {{
            var meta = document.createElement('meta');
            meta.httpEquiv = 'Content-Security-Policy';
            meta.content = '{sanitized_csp}';
            document.getElementsByTagName('head')[0].appendChild(meta);
        }})();
        """
        script = WebKit.UserScript.new(
            csp_script,
            WebKit.UserContentInjectedFrames.TOP_FRAME,
            WebKit.UserScriptInjectionTime.START,
        )
        webview.get_user_content_manager().add_script(script)

    def report_csp_violation(self, report):
        report_url = "http://127.0.0.1:9000/"  # your CSP report server
        data = json.dumps({"csp-report": report}).encode("utf-8")
        req = urllib.request.Request(
            report_url,
            data=data,
            headers={"Content-Type": "application/csp-report"}
        )
        try:
            with urllib.request.urlopen(req) as _:
                pass
        except Exception:
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

    def attach_csp_listener(self, webview):
        manager = webview.get_user_content_manager()
        manager.connect("console-message-received", self.on_console_message)

    def on_console_message(self, manager, message):
        msg_text = message.get_text()
        if "Refused to load" in msg_text or "CSP" in msg_text:
            report = {"message": msg_text, "source": "console"}
            self.on_csp_violation(report)


class SocialTrackerBlocker:
    def __init__(self):
        self.blocklist = ["twitter.com"]

    def block_trackers(self, webview, url):
        parsed_url = urlparse(url)
        if any(domain in parsed_url.netloc for domain in self.blocklist):
            return False
        return True

class TorManager:
    def __init__(self, tor_port=9050, control_port=9051, password=None):
        self.tor_port = tor_port
        self.control_port = control_port
        self.password = password or ""
        self.process = None
        self.controller = None
        self.data_dir = os.path.join(os.path.expanduser("~"), ".shadowbrowser_tor")
        self.torrc_path = os.path.join(self.data_dir, "torrc")
        self.tor_data_dir = os.path.join(self.data_dir, "data")
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.tor_data_dir, exist_ok=True)
        self.is_running_flag = False
        self._create_torrc()

    def _create_torrc(self):
        """Create a torrc configuration file."""
        try:
            with open(self.torrc_path, 'w') as f:
                f.write(f"SOCKSPort {self.tor_port if self.tor_port else 'auto'}\n")
                f.write(f"ControlPort {self.control_port if self.control_port else 'auto'}\n")
                f.write(f"DataDirectory {self.tor_data_dir}\n")
                f.write("AvoidDiskWrites 1\n")
                f.write("Log notice stdout\n")
                f.write("ClientOnly 1\n")
                f.write("CookieAuthentication 1\n")
                f.write("ExitPolicy reject *:*\n")
                f.write("SafeLogging 1\n")
            return True
        except Exception:
            pass
            return False

    def start(self):
        """Start the Tor process with proper error handling and port fallback."""
        try:
            if not shutil.which("tor"):
                pass
                return False
            ports_to_try = [
                (self.tor_port, self.control_port),  
                (9052, 9053),  
                (9054, 9055),  
                (0, 0),        
            ]
            for tor_port, control_port in ports_to_try:
                try:
                    self.tor_port = tor_port
                    self.control_port = control_port
                    self._create_torrc()                   
                    self.process = subprocess.Popen(
                        ["tor", "-f", self.torrc_path],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        universal_newlines=True
                    )                   
                    start_time = time.time()
                    while time.time() - start_time < 30:
                        if self.process.poll() is not None:
                            output, _ = self.process.communicate()
                            pass
                            break                           
                        try:
                            controller = Controller.from_port(port=control_port if control_port != 0 else 9051)
                            controller.authenticate()
                            self.controller = controller
                            
                            socks_ports = controller.get_conf('SocksPort', multiple=True)
                            if socks_ports:
                                try:
                                    self.tor_port = int(socks_ports[0].split(':')[0])
                                except (ValueError, IndexError):
                                    self.tor_port = tor_port if tor_port != 0 else 9050                           
                            control_ports = controller.get_conf('ControlPort', multiple=True)
                            if control_ports:
                                try:
                                    self.control_port = int(control_ports[0])
                                except (ValueError, IndexError):
                                    self.control_port = control_port if control_port != 0 else 9051                           
                            self.is_running_flag = True
                            break                           
                        except Exception:
                            time.sleep(0.5)
                    self.stop()                
                except Exception:
                    self.stop()
                    continue           
            return False        
        except Exception:
            self.stop()
            return False

    def stop(self):
        """Stop the Tor process and clean up resources."""
        success = True        
        if hasattr(self, 'controller') and self.controller:
            try:
                if self.controller.is_alive():
                    self.controller.close()
            except Exception:
                success = False
            finally:
                self.controller = None       
        if hasattr(self, 'process') and self.process:
            try:
                if self.process.poll() is None:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        try:
                            self.process.kill()
                            self.process.wait()
                        except Exception:
                            success = False
            except Exception:
                success = False
            finally:
                self.process = None      
        self.is_running_flag = False
        return success

    def is_running(self):
        """Check if Tor is running."""
        if not self.is_running_flag:
            return False           
        try:
            if self.controller and self.controller.is_alive():
                return True
            return False
        except Exception:
            self.is_running_flag = False
            return False

    def new_identity(self):
        """Request a new Tor circuit."""
        try:
            if self.controller and self.controller.is_alive():
                self.controller.signal("NEWNYM")
                return True
            return False
        except Exception:
            return False

    def _print_bootstrap_lines(self, line):
        """Print Tor bootstrap progress."""
        if "Bootstrapped" in line:
            pass

class Tab:
    def __init__(self, url, webview):
        self.url = url
        self.webview = webview
        self.label_widget = None

class ShadowBrowser(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="com.shadowyfigure.shadowbrowser")
        self.debug_mode = False
        self.webview = WebKit.WebView()
        self.content_manager = WebKit.UserContentManager()
        self.adblocker = AdBlocker()
        self.social_tracker_blocker = SocialTrackerBlocker()
        self.setup_webview_settings(self.webview)
        self.webview.connect("create", self.on_webview_create)
        self.bookmarks = self.load_json(BOOKMARKS_FILE)
        self.history = self.load_json(HISTORY_FILE)
        self.tabs = []
        self.tabs_lock = threading.Lock()
        self.blocked_urls = []
        self.window = None
        self.notebook = Gtk.Notebook()
        self.url_entry = Gtk.Entry()
        self.home_url = "https://duckduckgo.com/"
        self.theme = "dark"
        self.tor_enabled = True
        self.tor_manager = TorManager()
        if self.tor_enabled:
            try:
                if self.tor_manager.start():
                    pass
                else:
                    pass
            except Exception:
                self.tor_enabled = False
        self.download_manager = DownloadManager(None)
        self.active_downloads = 0
        self.context = ssl.create_default_context()
        self.error_handlers = {}
        self.register_error_handlers()
        self.download_spinner = Gtk.Spinner()
        self.download_spinner.set_visible(False)
        self.bookmark_menu = None
        self.setup_security_policies()
        self.download_manager.on_download_start_callback = self.on_download_start
        self.download_manager.on_download_finish_callback = self.on_download_finish
        try:
            self.adblocker.inject_to_webview(self.content_manager)
            self.inject_nonce_respecting_script()
            self.inject_remove_malicious_links()
            self.inject_adware_cleaner()
            self.disable_biometrics_in_webview()
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

    def create_secure_webview(self):
        """
        Create a new secure WebView with all necessary scripts and handlers.
        Returns:
            WebKit.WebView: A configured WebView instance
        """
        try:
            content_manager = WebKit.UserContentManager()            
            webview = WebKit.WebView(user_content_manager=content_manager)
            webview.set_hexpand(True)
            webview.set_vexpand(True)
            webview._content_manager = content_manager
            self.setup_webview_settings(webview)
            self._register_webview_message_handlers(webview)
            self.adblocker.inject_to_webview(content_manager)
            self.inject_nonce_respecting_script()
            self.inject_remove_malicious_links()
            self.inject_adware_cleaner()
            self.disable_biometrics_in_webview(webview)
            self.inject_mouse_event_script()
            self.adblocker.enable_csp(webview)
            webview.connect("create", self.on_webview_create)
            return webview            
        except Exception:
            pass
            webview = WebKit.WebView()
            webview.set_hexpand(True)
            webview.set_vexpand(True)
            return webview
    
    def _register_webview_message_handlers(self, webview):
        """
        Register message handlers for a WebView.       
        Args:
            webview: The WebView to register handlers for
        """
        if not hasattr(webview, '_content_manager'):
            return
        content_manager = webview._content_manager
        try:
            content_manager.register_script_message_handler("voidLinkClicked")
            handler_id = content_manager.connect(
                "script-message-received::voidLinkClicked",
                self.on_void_link_clicked
            )
            if not hasattr(webview, '_handler_ids'):
                webview._handler_ids = []
            webview._handler_ids.append((content_manager, handler_id))
        except Exception:
            pass

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
        """Setup comprehensive security policies for the browser."""
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
                webview.get_settings().set_javascript_can_open_windows_automatically(
                    False
                )
                return True
        return False

    def block_social_trackers(self, webview, decision, decision_type):
        """Block social media trackers."""
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
        """
        Convert a UUID string to a short base64url token.
        """
        import base64
        import uuid
        try:
            u = uuid.UUID(uuid_str)
            b = u.bytes
            token = base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")
            return token
        except Exception:
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

    def replace_uuid(self, match):
        original = match.group(0)
        uuid_str = match.group(1)
        token = self.uuid_to_token(uuid_str)
        replaced = original.replace(uuid_str, token)
        return replaced

    def on_webview_console_message(self, webview, level, message, line, source_id):
        pass

    def on_console_message_received(self, user_content_manager, js_message):
        pass

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
            // Observe DOM changes to detect skip button dynamically
            const observer = new MutationObserver(() => {
                clickSkip();
            });
            observer.observe(document.body, { childList: true, subtree: true });
            // Also run periodically as fallback
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
        """
        Process a clicked URL with the given metadata.       
        Args:
            url: The URL that was clicked
            metadata: Additional metadata about the click event
        """
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
    
    def on_void_link_clicked(self, user_content_manager, js_message):
        """
        Handle clicks on void links and other clickable elements that don't have direct hrefs.       
        Args:
            user_content_manager: The WebKit.UserContentManager that received the message
            js_message: The message containing click data from JavaScript
        """
        try:
            if hasattr(js_message, 'get_js_value'):
                message_data = js_message.get_js_value()
                if hasattr(message_data, 'to_dict') and callable(getattr(message_data, 'to_dict')):
                    message_data = message_data.to_dict()
                elif isinstance(message_data, str):
                    message_data = json.loads(message_data)
                url = None
                metadata = {}
                if isinstance(message_data, dict):
                    url = message_data.get('url', '')
                    metadata = message_data
                    if not url and 'message' in message_data:
                        url = message_data['message']
                elif isinstance(message_data, str):
                    url = message_data
                    metadata = {'url': url}
                if url and url != "about:blank":
                    GLib.idle_add(self._process_clicked_url, url, metadata)
                    return
                    try:
                        message_data = json.loads(message_data)
                    except json.JSONDecodeError:
                        pass
            else:
                message_data = js_message
            url = None
            metadata = {}
            if isinstance(message_data, dict):
                url = message_data.get('url', '')
                metadata = message_data
                if not url and 'message' in message_data:
                    url = message_data['message']
            elif isinstance(message_data, str):
                url = message_data
                metadata = {'url': url}
            elif hasattr(message_data, 'is_string') and message_data.is_string():
                url = message_data.to_string()
                metadata = {'url': url}
            if url and url != "about:blank":
                GLib.idle_add(self._process_clicked_url, url, metadata)
                return
        except Exception :
            pass
    
    def setup_webview_settings(self, webview):
        """Configure WebView settings for security, compatibility, and performance."""
        settings = webview.get_settings()
        settings.set_property("enable-developer-extras", self.debug_mode)
        settings.set_enable_javascript(True)
        settings.set_enable_developer_extras(self.debug_mode)
        settings.set_enable_media(True)
        settings.set_enable_media_stream(True)
        settings.set_enable_media_capabilities(True)
        settings.set_enable_mediasource(True)
        settings.set_enable_encrypted_media(True)       
        try:
            if hasattr(WebKit, 'HardwareAccelerationPolicy'):
                if hasattr(WebKit.HardwareAccelerationPolicy, 'ON'):
                    settings.set_hardware_acceleration_policy(WebKit.HardwareAccelerationPolicy.ON)
                elif hasattr(WebKit.HardwareAccelerationPolicy, 'ALWAYS'):
                    settings.set_hardware_acceleration_policy(WebKit.HardwareAccelerationPolicy.ALWAYS)           
            if hasattr(settings, 'set_enable_hardware_accelerated_video_decode'):
                settings.set_enable_hardware_accelerated_video_decode(True)
        except Exception:
            pass       
        settings.set_enable_webgl(True)
        settings.set_enable_webaudio(True)
        settings.set_enable_smooth_scrolling(True)
        settings.set_enable_fullscreen(True)
        settings.set_allow_file_access_from_file_urls(False)
        settings.set_allow_universal_access_from_file_urls(False)
        settings.set_allow_modal_dialogs(False)
        settings.set_javascript_can_access_clipboard(False)
        settings.set_javascript_can_open_windows_automatically(False)
        settings.set_media_playback_requires_user_gesture(True)      
        webview.set_settings(settings)        
        webview.connect("load-changed", self.inject_security_headers)
        webview.connect("decide-policy", self.block_social_trackers)
        content_manager = webview.get_user_content_manager()
        try:
            content_manager.register_script_message_handler("consoleMessage")
            content_manager.connect(
                "script-message-received::consoleMessage", self.on_console_message_received
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
                    // Fail silently
                }
            }
            const levels = ['log', 'warn', 'error', 'info', 'debug'];
            levels.forEach(function(level) {
                const original = console[level];
                console[level] = function() {
                    sendMessage(level, arguments);
                    if (original.apply) {
                        original.apply(console, arguments);
                    } else {
                        original(arguments);
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
        content_manager.add_script(script)
        return webview

    def inject_mouse_event_script(self):
        """Injects JavaScript to capture mouse events in webviews."""
        script = WebKit.UserScript.new(
            """
            (function() {
                console.log('[DEBUG] Mouse event handler script loaded');
                function logDebug(message, obj) {
                    console.log('[DEBUG] ' + message, obj || '');
                }
                function handleClick(e) {
                    // Debug the click event
                    console.log('[DEBUG] Click event detected on:', e.target);
                    
                    // Check if this is a left mouse button click
                    if (e.button !== 0) {
                        logDebug('Not a left-click, ignoring');
                        return;
                    }                   
                    // Handle both link clicks and elements with click handlers
                    let target = e.target;
                    logDebug('Click target:', target);
                    // Try to find the closest anchor or clickable element
                    let link = target.closest('a, [onclick], [data-href], [data-link], [data-url], [role="button"]');
                    if (!link && target.matches && !target.matches('a')) {
                        // If no link found, check if the target itself is clickable
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
                            // Prevent default only if we're handling it
                            if (link.getAttribute('data-handled') === 'true') {
                                logDebug('Link already handled, preventing default');
                                e.preventDefault();
                                e.stopPropagation();
                                return false;
                            }
                            // Check for data-url or try to find a URL in the element
                            let dataUrl = link.getAttribute('data-url') || 
                                       link.getAttribute('data-href') || 
                                       link.getAttribute('data-link') ||
                                       link.href;
                            // If still no URL, check child elements
                            if (!dataUrl) {
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
                            if (dataUrl) {
                                // Mark as handled to prevent duplicate processing
                                link.setAttribute('data-handled', 'true');                                
                                // Prepare the message
                                const message = {
                                    url: dataUrl,
                                    href: link.href || '',
                                    text: (link.innerText || link.textContent || '').trim(),
                                    hasOnClick: hasOnClick,
                                    tagName: link.tagName,
                                    className: link.className || '',
                                    id: link.id || ''
                                };
                               logDebug('Sending message to Python:', message);
                                // Send message to Python side
                                try {
                                    if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.voidLinkClicked) {
                                        window.webkit.messageHandlers.voidLinkClicked.postMessage(message);
                                        logDebug('Message sent successfully');
                                        
                                        // Prevent default if we're handling the click
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
                // Add click event listener with capturing phase
                document.addEventListener('click', handleClick, {capture: true, passive: false});
                // Also handle mousedown for better compatibility
                document.addEventListener('mousedown', function(e) {
                    // Only handle left mouse button
                    if (e.button === 0) {
                        handleClick(e);
                    }
                }, {capture: true, passive: false});              
                // Handle dynamically added content
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
                // The main script will handle the rest
            })();
            """,
            WebKit.UserContentInjectedFrames.ALL_FRAMES,
            WebKit.UserScriptInjectionTime.END,
            [],
            []
        )        
        self.content_manager.add_script(script)
        self.content_manager.add_script(end_script)

    def create_toolbar(self):
        if hasattr(self, "toolbar") and self.toolbar is not None:
            if self.toolbar.get_parent() is not None:
                return self.toolbar
            else:
                self.toolbar = None
        self.toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self.toolbar.set_margin_start(6)
        self.toolbar.set_margin_end(6)
        self.toolbar.set_margin_top(6)
        self.toolbar.set_margin_bottom(6)

        def icon_button(icon_name, callback):
            image = Gtk.Image.new_from_icon_name(icon_name)
            button = Gtk.Button()
            button.set_child(image)
            button.connect("clicked", callback)
            return button
        self.toolbar.append(icon_button("go-previous-symbolic", self.on_back_clicked))
        self.toolbar.append(icon_button("go-next-symbolic", self.on_forward_clicked))
        self.toolbar.append(icon_button("view-refresh-symbolic", self.on_refresh_clicked))
        self.toolbar.append(icon_button("go-home-symbolic", lambda b: self.load_url(self.home_url)))
        self.url_entry = Gtk.Entry(placeholder_text="Enter URL")
        self.url_entry.connect("activate", self.on_go_clicked)
        self.toolbar.append(self.url_entry)
        self.toolbar.append(icon_button("go-jump-symbolic", self.on_go_clicked))
        self.toolbar.append(icon_button("bookmark-new-symbolic", self.on_add_bookmark_clicked))
        self.toolbar.append(icon_button("tab-new-symbolic", self.on_new_tab_clicked))
        if hasattr(self, 'download_spinner') and self.download_spinner:
            self.download_spinner.set_halign(Gtk.Align.END)
            self.download_spinner.set_valign(Gtk.Align.CENTER)
            self.download_spinner.set_margin_start(10)
            self.download_spinner.set_margin_end(10)
            self.download_spinner.set_visible(False)
            self.toolbar.append(self.download_spinner)
        try:
            self.tor_status_button = icon_button("network-transmit-receive-symbolic", self.on_tor_status_clicked)
            self.tor_status_button.set_tooltip_text("Tor is disabled")
            self.tor_status_button.set_opacity(0.5)
            self.tor_status_button.set_margin_start(10)
            self.tor_status_button.set_margin_end(10)
            self.tor_status_button.set_margin_top(5)
            self.tor_status_button.set_margin_bottom(5)
            self.toolbar.append(self.tor_status_button)
            self.update_tor_status_indicator()
        except Exception:
            pass
        return self.toolbar

    def safe_show_popover(self, popover):
        """Safely show a Gtk.Popover, avoiding multiple popups or broken state."""
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
        """Show the bookmarks menu."""
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
                        return
                child = child.get_next_sibling()

    def update_bookmarks_menu(self, menu_container):
        """Update the bookmarks menu UI with current bookmarks."""
        try:
            if not menu_container:
                return                
            try:
                child = menu_container.get_first_child()
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
            for bookmark_url in self.bookmarks:
                try:
                    hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
                    hbox.set_halign(Gtk.Align.FILL)
                    hbox.set_hexpand(True)                   
                    display_text = bookmark_url[:30] + "..." if len(bookmark_url) > 30 else bookmark_url                    
                    button = Gtk.Button(label=display_text)
                    button.set_halign(Gtk.Align.START)
                    button.set_hexpand(True)
                    button.set_tooltip_text(bookmark_url)
                    button.connect("clicked", lambda btn, url=bookmark_url: self.load_url(url))                    
                    delete_button = Gtk.Button()
                    delete_button.set_icon_name("edit-delete-symbolic")
                    delete_button.set_tooltip_text("Delete bookmark")
                    delete_button.add_css_class("destructive-action")                    
                    delete_button.connect("clicked", self._on_delete_bookmark_clicked, bookmark_url)                   
                    hbox.append(button)
                    hbox.append(delete_button)                    
                    menu_container.append(hbox)
                except Exception:
                    pass                    
            try:
                separator = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
                menu_container.append(separator)
            except Exception:
                pass               
            try:
                clear_button = Gtk.Button(label="Clear All Bookmarks")
                clear_button.set_halign(Gtk.Align.CENTER)
                clear_button.connect("clicked", self._clear_all_bookmarks)
                menu_container.append(clear_button)
            except Exception:
                pass
        except Exception:
            pass

    def do_startup(self):
        Gtk.Application.do_startup(self)

    def do_activate(self):
        """Create and show the main window."""
        try:
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
            self.safe_append(vbox, menubar)           
            toolbar = self.create_toolbar()
            self.safe_append(vbox, toolbar)           
            self.safe_append(vbox, self.notebook)            
            self.download_manager.parent_window = self.window
            self.download_manager.show()
            self.safe_append(vbox, self.download_manager.box)           
            if not self.window.get_child():
                self.window.set_child(vbox)           
            if not hasattr(self, '_window_signals_connected'):
                self.window.connect("close-request", self.on_window_destroy)
                self._window_signals_connected = True           
            if len(self.tabs) == 0:
                self.add_new_tab(self.home_url)           
            self.window.present()
        except Exception:
            pass

    def do_shutdown(self):
        """Save session and tabs before shutdown."""
        try:
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
        self.set_logging_level()

    def set_logging_level(self):
        pass

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
        
    def _on_delete_bookmark_clicked(self, button, url):
        """Handle click on the delete bookmark button."""
        if url in self.bookmarks:
            self.bookmarks.remove(url)
            self.save_json(BOOKMARKS_FILE, self.bookmarks)
            self.update_bookmarks_menu(self.bookmark_menu)
            self._close_bookmark_popover()

    def _clear_all_bookmarks(self, button=None):
        """Clear all bookmarks."""
        self.bookmarks.clear()
        self.save_json(BOOKMARKS_FILE, self.bookmarks)
        self.update_bookmarks_menu(self.bookmark_menu)
        self._close_bookmark_popover()
    
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
            self.bookmark_menu_button = Gtk.MenuButton(label="Bookmarks")
            self.bookmark_menu_button.set_tooltip_text("Show bookmarks")            
            if hasattr(self, 'bookmark_popover') and self.bookmark_popover:
                try:
                    self.bookmark_popover.popdown()
                except Exception:
                    pass                    
            self.bookmark_popover = Gtk.Popover()
            self.bookmark_popover.set_size_request(300, -1)  # Fixed width, auto height
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
            self.bookmark_popover.connect("closed", lambda popover: popover.set_visible(False))
            self.safe_append(menubar, self.bookmark_menu_button)
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
            self.safe_append(menubar, download_button)
        except Exception:
            pass
        try:
            settings_button = Gtk.Button(label="Settings")
            settings_button.set_tooltip_text("Open settings dialog")
            settings_button.connect("clicked", lambda x: self.on_settings_clicked(x))
            self.safe_append(menubar, settings_button)
        except Exception:
            pass            
        try:
            clear_data_button = Gtk.Button(label="Clear Data")
            clear_data_button.set_tooltip_text("Clear browsing data")
            clear_data_button.connect("clicked", lambda x: self.create_clear_data_dialog().present())
            self.safe_append(menubar, clear_data_button)
        except Exception:
            pass            
        try:
            about_button = Gtk.Button(label="About")
            about_button.connect("clicked", self.on_about)
            self.safe_append(menubar, about_button)
        except Exception:
            pass            
        return menubar

    def on_settings_clicked(self, button):
        """Open the settings dialog."""
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
        save_button.connect("clicked", self.on_settings_save)
        cancel_button.connect("clicked", lambda btn: self.settings_dialog.response(Gtk.ResponseType.CANCEL))
        self.settings_dialog.connect("response", self.on_settings_dialog_response)       
        self.settings_dialog.present()

    def on_settings_dialog_response(self, dialog, response_id):
        if response_id == Gtk.ResponseType.ACCEPT or response_id == Gtk.ResponseType.OK:
            self.on_settings_save(None)
        if dialog and dialog.is_visible():
            dialog.set_visible(False)
        if dialog:
            dialog.destroy()
        if hasattr(self, 'settings_dialog') and self.settings_dialog == dialog:
            self.settings_dialog = None

    def on_settings_save(self, button):
        try:
            self.adblocker.enabled = self.adblock_toggle.get_active()
            self.incognito_mode = self.incognito_toggle.get_active()
            self.anti_fingerprinting_enabled = self.anti_fp_toggle.get_active()
            self.search_engine = self.search_engine_entry.get_text().strip()
            self.home_url = self.home_page_entry.get_text().strip()      
            with self.tabs_lock:
                for tab in self.tabs:
                    if hasattr(tab, 'webview') and tab.webview:
                        GLib.idle_add(tab.webview.reload)
        except Exception:
            pass
        finally:
            pass

    def toggle_tor(self, enabled):
        """Toggle Tor on or off.
        Args:
            enabled (bool): Whether to enable or disable Tor
        Returns:
            bool: True if the operation was successful, False otherwise
        """
        try:
            if enabled:
                if not hasattr(self, 'tor_manager') or not self.tor_manager:
                    self.tor_manager = TorManager()
                if self.tor_manager.start():
                    tor_proxy = f"socks5h://127.0.0.1:{self.tor_manager.tor_port}"
                    os.environ['http_proxy'] = tor_proxy
                    os.environ['https_proxy'] = tor_proxy
                    os.environ['all_proxy'] = tor_proxy
                    self.tor_enabled = True
                    GLib.idle_add(self.update_tor_status_indicator)
                    return True
                else:
                    GLib.idle_add(self.update_tor_status_indicator)
                    return False
            else:
                self.tor_enabled = False
                if hasattr(self, 'tor_manager') and self.tor_manager:
                    self.tor_manager.stop()
                os.environ.pop('http_proxy', None)
                os.environ.pop('https_proxy', None)
                os.environ.pop('all_proxy', None)
                self.home_url = "https://duckduckgo.com/"
                GLib.idle_add(self.update_tor_status_indicator)
                return True
        except Exception:
            pass
            GLib.idle_add(self.update_tor_status_indicator)
            return False

    def on_tor_toggled(self, toggle_button):
        enabled = toggle_button.get_active()
        if self.toggle_tor(enabled):
            with self.tabs_lock:
                for tab in self.tabs:
                    if hasattr(tab, 'webview'):
                        GLib.idle_add(tab.webview.reload)
            if enabled:
                GLib.timeout_add(1000, self.update_tor_status_indicator)
        else:
            toggle_button.set_active(not enabled)
            self.show_error_message("Failed to toggle Tor. Please check the logs for more details.")
            self.update_tor_status_indicator()

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
            self.tor_status_button.add(new_icon)
            self.tor_status_icon = new_icon
        self.tor_status_icon.set_tooltip_text(tooltip)
        if hasattr(self.tor_status_icon.props, 'opacity'):
            self.tor_status_icon.props.opacity = opacity       
        self.tor_status_button.show_all()
    
    def on_tor_status_clicked(self, widget):
        new_state = not (self.tor_enabled and hasattr(self, 'tor_manager') and 
                       self.tor_manager and self.tor_manager.is_running())
        self.toggle_tor(new_state)       
        if new_state:
            GLib.timeout_add(1000, self.update_tor_status_indicator)
        return True

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

    def on_clear_data_confirm(self, dialog):
        if self.cookies_check.get_active():
            self.clear_cookies()
        if self.cache_check.get_active():
            self.clear_cache()
        if self.passwords_check.get_active():
            self.clear_passwords()
        if self.history_check.get_active():
            self.clear_history()
        dialog.close()

    def on_clear_data_response(self, dialog, response_id):
        if response_id == Gtk.ResponseType.ACCEPT:
            if self.cookies_check.get_active():
                self.clear_cookies()
            if self.cache_check.get_active():
                self.clear_cache()
            if self.passwords_check.get_active():
                self.clear_passwords()
            if self.history_check.get_active():
                self.clear_history()
            self.show_message("Data Cleared", "The selected browsing data has been cleared.")
        dialog.destroy()
    
    def clear_cookies(self):
        try:
            context = WebKit.WebContext.get_default()
            cookie_manager = context.get_cookie_manager()
            if cookie_manager:
                cookie_manager.delete_all_cookies()
        except AttributeError:
            try:
                cookie_manager = WebKit.CookieManager.get_default()
                if cookie_manager:
                    cookie_manager.delete_all_cookies()
            except AttributeError:
                pass
        except Exception:
            pass

    def clear_cache(self):
        try:
            context = WebKit.WebContext.get_default()
            if context:
                if hasattr(context, 'clear_cache'):
                    context.clear_cache()
                elif hasattr(context, 'clear_cache_storage'):
                    context.clear_cache_storage()
        except Exception:
            pass
        
    def clear_passwords(self):
        try:
            context = WebKit.WebContext.get_default()
            if context and hasattr(context, 'clear_credentials'):
                context.clear_credentials()
        except Exception:
            pass
        
    def clear_history(self):
        if hasattr(self, 'history'):
            self.history.clear()            
            try:
                self.save_json(HISTORY_FILE, [])
                dialog = Gtk.MessageDialog(
                    transient_for=self.window,
                    message_type=Gtk.MessageType.INFO,
                    buttons=Gtk.ButtonsType.OK,
                    text="Browsing history has been cleared"
                )
                dialog.connect("response", lambda d, r: d.destroy())
                dialog.present()
            except Exception:
                pass

    def on_downloads_clicked(self, button):
        downloads_dir = GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_DOWNLOAD)
        if not downloads_dir:
            downloads_dir = os.path.expanduser("~/Downloads")
        try:
            import subprocess
            subprocess.Popen(["xdg-open", downloads_dir])
        except Exception:
            pass

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
            pass

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
            pass
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
        """
        Safely append a widget to a container using the shared utility function.
        Args:
            container: The GTK container to append to
            widget: The widget to append
        Returns:
            bool: True if append was successful, False otherwise
        """
        return safe_widget_append(container, widget)

    def add_new_tab(self, url):
        """Add a new tab with a webview loading the specified URL."""
        try:
            webview = self.create_secure_webview()
            if webview is None:
                return                
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
            tab.close_button = close_button

            def on_close_clicked(button, tab=tab):
                try:
                    if tab in self.tabs:
                        tab_index = self.tabs.index(tab)
                        self.on_tab_close_clicked(button, tab_index)
                except ValueError:
                    pass
                except Exception:
                    pass
            box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
            self.safe_append(box, label)
            self.safe_append(box, close_button)            
            if not self.notebook:
                pass
                return
            index = self.notebook.append_page(scrolled_window, box)
            self.notebook.set_current_page(index)    
            self.tabs.append(tab)            
            try:
                close_button.connect("clicked", on_close_clicked)
                webview.connect("load-changed", self.on_load_changed)
                webview.connect("notify::title", self.on_title_changed)
                webview.connect("decide-policy", self.on_decide_policy)
            except Exception:
                pass                
        except Exception:
            pass

    def on_tab_close_clicked(self, button, tab_index):
        """Close the tab at the given index."""
        try:
            if 0 <= tab_index < len(self.tabs):
                tab = self.tabs[tab_index]
                webview = tab.webview
                notebook_page_num = None               
                for page_index in range(self.notebook.get_n_pages()):
                    page = self.notebook.get_nth_page(page_index)
                    if isinstance(page, Gtk.ScrolledWindow):
                        child = page.get_child()
                        if child == webview or (
                            isinstance(child, Gtk.Viewport) and child.get_child() == webview
                        ):
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
                        try:
                            if webview:
                                try:
                                    if hasattr(webview, 'disconnect_by_func'):
                                        webview.disconnect_by_func(self.on_load_changed)
                                except Exception:
                                    pass
                                try:
                                    if hasattr(webview, 'disconnect_by_func'):
                                        webview.disconnect_by_func(self.on_title_changed)
                                except Exception:
                                    pass
                                try:
                                    if hasattr(webview, 'disconnect_by_func'):
                                        webview.disconnect_by_func(self.on_decide_policy)
                                except Exception:
                                    pass
                                try:
                                    if hasattr(webview, 'disconnect_by_func'):
                                        webview.disconnect_by_func(self.on_webview_create)
                                except Exception:
                                    pass
                        except Exception:
                            pass               
                        if notebook_page_num < self.notebook.get_n_pages():
                            self.notebook.remove_page(notebook_page_num)               
                        if webview and hasattr(webview, 'get_parent'):
                            try:
                                parent = webview.get_parent()
                                if parent and webview in parent:
                                    parent.remove(webview)
                            except Exception:
                                pass                       
                        if page and hasattr(page, 'get_parent') and page.get_parent() == self.notebook:
                            try:
                                self.notebook.remove(page)
                            except Exception:
                                pass
                                pass                       
                        try:
                            parent = page.get_parent()
                            if parent and hasattr(parent, "remove") and page.get_parent() == parent:
                                parent.remove(page)
                        except Exception:
                            pass              
                removed_tab = self.tabs.pop(tab_index)               
                try:
                    if hasattr(removed_tab, 'webview'):
                        removed_tab.webview = None
                    if hasattr(removed_tab, 'label_widget'):
                        removed_tab.label_widget = None
                except Exception:
                    pass
                
        except Exception:
            pass

    def on_load_changed(self, webview, load_event):
        """Handle load state changes."""
        from gi.repository import WebKit, GLib
        try:
            if not hasattr(self, 'download_spinner') or not self.download_spinner:
                return                
            if load_event == WebKit.LoadEvent.COMMITTED:
                current_webview = self.get_current_webview()
                if webview == current_webview:
                    if hasattr(self, 'url_entry') and self.url_entry:
                        current_url = webview.get_uri() or ""
                        self.url_entry.set_text(current_url)                       
                        for tab in self.tabs:
                            if tab.webview == webview:
                                tab.url = current_url
                                if tab.label_widget and not webview.get_title():
                                    tab.label_widget.set_text(self.extract_tab_title(current_url))
                                break               
                GLib.idle_add(self.download_spinner.start)
                GLib.idle_add(lambda: self.download_spinner.set_visible(True))                
            elif load_event == WebKit.LoadEvent.FINISHED:
                current_url = webview.get_uri() or ""
                if hasattr(self, 'url_entry') and self.url_entry and webview == self.get_current_webview():
                    self.url_entry.set_text(current_url)                
                for tab in self.tabs:
                    if tab.webview == webview:
                        tab.url = current_url
                        if tab.label_widget and not webview.get_title():
                            tab.label_widget.set_text(self.extract_tab_title(current_url))
                        break               
                GLib.idle_add(self.download_spinner.stop)
                GLib.idle_add(lambda: self.download_spinner.set_visible(False))                
                if current_url and not current_url.startswith(('about:', 'data:')):
                    self.update_history(current_url)                   
        except Exception:
            pass

    def on_title_changed(self, webview, param):
        """Update tab label when page title changes."""
        try:
            max_length = 10
            title = webview.get_title() or "Untitled"
            if len(title) > max_length:
                title = title[: max_length - 3] + "..."
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
            new_webview = WebKit.WebView(
                settings=webview.get_settings(), 
                user_content_manager=webview.get_user_content_manager()
            )
            new_webview.set_hexpand(True)
            new_webview.set_vexpand(True)           
            if not hasattr(new_webview, '_signals_connected'):
                new_webview.connect("create", self.on_webview_create)
                new_webview.connect("decide-policy", self.on_decide_policy)
                new_webview._signals_connected = True                
            is_popup = False
            try:
                if (
                    window_features is not None
                    and hasattr(window_features, "get")
                    and callable(window_features.get)
                ):
                    try:
                        is_popup = window_features.get("popup", False)
                    except Exception:
                        pass
            except Exception:
                pass
            if is_popup:
                self.open_popup_window(new_webview, window_features)
            else:
                self.add_webview_to_tab(new_webview)
            return new_webview
        except Exception:
            return None

    BLOCKED_INTERNAL_URLS = [
        "about:blank",
        "about:srcdoc",
        "blob:",
        "data:",
        "about:debug",
    ]
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
        if not is_main_frame and url.startswith(("about:", "data:", "blob:", "_blank", "_data:")):
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
            if requested_url.startswith(("about:", "data:", "blob:", "_data:", "_blank", "_parent", "_self", "_top", "_window")):
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
                webview.evaluate_javascript(
                    cleanup_js,
                    -1,
                    None,
                    None,
                    None,
                    None
                )
            except Exception:
                pass
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
        except Exception:
            pass
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
            pass
            decision.ignore()
            return True

    def on_decide_policy(self, webview, decision, decision_type):
        """Handle navigation and new window actions, manage downloads, enforce policies, and apply adblock rules."""
        try:
            from gi.repository import WebKit

            if decision_type == WebKit.PolicyDecisionType.NAVIGATION_ACTION:
                return self._handle_navigation_action(
                    webview, decision, decision.get_navigation_action()
                )
            elif decision_type == WebKit.PolicyDecisionType.NEW_WINDOW_ACTION:
                return self._handle_new_window_action(webview, decision)
            else:
                decision.use()
                return True
        except Exception:
            pass
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
        from urllib.parse import urlparse, unquote, parse_qs

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
                    block_size = 8192
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
                        with open(filepath, "wb") as f:
                            for chunk in response.iter_content(block_size):
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
                                self.download_manager.download_finished, progress_info
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
                title = title[: max_length - 3] + "..."
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

    def safe_window_cleanup(self):
        """Ensure proper window cleanup to prevent GTK warnings."""
        if hasattr(self, 'window') and self.window:
            try:
                if hasattr(self.window, 'disconnect_by_func'):
                    try:
                        self.window.disconnect_by_func(self.on_window_destroy)
                    except Exception:
                        pass              
                if self.window.get_child():
                    child = self.window.get_child()
                    if child:
                        try:
                            self.window.remove(child)
                        except Exception:
                            pass                
                self.window.destroy()
                self.window = None
            except Exception:
                pass

    def cleanup_widgets(self):
        """Clean up all widgets to prevent GTK warnings."""
        for tab in self.tabs[:]:
            if hasattr(tab, 'webview') and tab.webview:
                try:
                    tab.webview.disconnect_by_func(self.on_load_changed)
                    tab.webview.disconnect_by_func(self.on_title_changed)
                    tab.webview.disconnect_by_func(self.on_decide_policy)
                    tab.webview.disconnect_by_func(self.on_webview_create)
                except Exception:
                    pass
                tab.webview = None
            if hasattr(tab, 'label_widget'):
                tab.label_widget = None       
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

    def disconnect_all_signals(self):
        """Disconnect all signals to prevent GTK warnings."""
        for webview in [tab.webview for tab in self.tabs if hasattr(tab, 'webview')]:
            try:
                webview.disconnect_by_func(self.on_load_changed)
                webview.disconnect_by_func(self.on_title_changed)
                webview.disconnect_by_func(self.on_decide_policy)
                webview.disconnect_by_func(self.on_webview_create)
            except Exception:
                pass

    def on_window_destroy(self, window):
        """Handle window closure with proper cleanup."""
        try:
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
        except Exception:
            pass
        finally:
            self.quit()

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
        """Open a URL in a new tab."""
        try:
            if not url or not isinstance(url, str):
                return                
            if url.startswith("javascript:") or url == "about:blank":
                return               
            new_webview = self.create_secure_webview()
            if new_webview is None:
                return               
            new_webview.load_uri(url)            
            scrolled_window = Gtk.ScrolledWindow()
            scrolled_window.set_vexpand(True)
            scrolled_window.set_child(new_webview)            
            label = Gtk.Label(label=self.extract_tab_title(url))            
            close_button = Gtk.Button.new_from_icon_name("window-close")
            close_button.set_size_request(24, 24)
            close_button.set_tooltip_text("Close tab")           
            tab = Tab(url, new_webview)
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
            new_webview.connect("load-changed", self.on_load_changed)
            new_webview.connect("notify::title", self.on_title_changed)
            new_webview.connect("decide-policy", self.on_decide_policy)
            new_webview.connect("create", self.on_webview_create)            
        except Exception:
            pass

    def add_webview_to_tab(self, webview):
        """Add a webview to a new tab."""
        try:
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
        except Exception:
            pass

    def open_popup_window(self, webview, window_features):
        """Open a popup window with the given webview."""
        try:
            window = Gtk.Window(title="Popup")
            window.set_transient_for(self.window)
            window.set_destroy_with_parent(True)
            window.set_modal(False)
            if window_features:
                default_width = int(window_features.get_width() or 800)
                default_height = int(window_features.get_height() or 600)
                window.set_default_size(default_width, default_height)           
            vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)            
            if hasattr(webview, 'get_parent') and webview.get_parent() is not None:
                parent = webview.get_parent()
                if parent and hasattr(parent, "remove") and webview.get_parent() == parent:
                    try:
                        parent.remove(webview)
                    except Exception:
                        pass            
            self.safe_append(vbox, webview)           
            close_button = Gtk.Button.new_from_icon_name("window-close")
            close_button.set_size_request(24, 24)
            close_button.set_tooltip_text("Close popup")            
            window._webview = webview
            window._close_button = close_button
            window._vbox = vbox
                    
            def on_popup_destroy(widget):
                try:
                    if hasattr(window, '_webview'):
                        window._webview = None
                    if hasattr(window, '_close_button'):
                        window._close_button = None
                    if hasattr(window, '_vbox'):
                        window._vbox = None
                except Exception:
                    pass            
            window.connect("destroy", on_popup_destroy)
            close_button.connect("clicked", lambda btn: window.destroy())           
            if hasattr(close_button, 'get_parent') and close_button.get_parent() is not None:
                parent = close_button.get_parent()
                if parent and hasattr(parent, "remove") and close_button.get_parent() == parent:
                    try:
                        parent.remove(close_button)
                    except Exception:
                        pass           
            self.safe_append(vbox, close_button)
            window.set_child(vbox)            
            if not hasattr(self, '_popup_windows'):
                self._popup_windows = []
            self._popup_windows.append(window)
            
            def cleanup_window_reference(widget):
                try:
                    if hasattr(self, '_popup_windows'):
                        if window in self._popup_windows:
                            self._popup_windows.remove(window)
                except Exception:
                    pass           
            window.connect("destroy", cleanup_window_reference)
            window.present()
        except Exception:
            pass

    def load_html_with_bootstrap(self, html):
        """
        Load HTML content into the current webview with Bootstrap CSS linked in the head.
        If Bootstrap CSS link is not present, it will be injected.
        """
        try:
            webview = self.get_current_webview()
            if not webview:
                return
        except Exception:
            pass

    def inject_css_adblock(self):
        """Inject CSS to hide ad elements."""
        try:
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
        except Exception:
            pass

    def inject_adware_cleaner(self):
        """Enhanced ad-blocker that preserves media players while blocking ads."""
        script_source = """
        (function() {
            // Media player selectors to preserve
            const playerSelectors = [
                '[class*="player" i]',
                '[id*="player" i]',
                '[class*="video" i]',
                '[id*="video" i]',
                '[class*="media" i]',
                '[id*="media" i]',
                'video', 'audio', 'object', 'embed',
            ];
            // Whitelist of classes that should never be removed
            const whitelistedClasses = [
                'java', 'javaplayer', 'javaplugin', 'jvplayer', 'jwplayer',
                'video', 'player', 'mediaplayer', 'html5-video-player',
                'vjs-', 'mejs-', 'flowplayer', 'plyr', 'mediaelement',
                'shaka-', 'dash-', 'hls-', 'video-js', 'youtube', 'vimeo'
            ];
            // Ad patterns to block
            const blockedSelectors = [
                // Ad iframes
                'iframe[src*="ads" i]',
                'iframe[src*="doubleclick" i]',
                'iframe[src*="googlesyndication" i]',
                'iframe[src*="adservice" i]',
                // Ad containers
                'div[class*="ad-" i]:not([class*="add" i])',
                'div[id*="ad-" i]:not([id*="add" i])',
                'div[class*="ad_" i]',
                'div[class*="ads-" i]',
                'div[class*="advertisement" i]',
                'div[class*="ad-container" i]',
                'div[class*="ad_wrapper" i]',
                'div[class*="ad-wrapper" i]',
                // Popups and overlays
                'div[class*="popup" i]',
                'div[class*="overlay" i]',
                'div[class*="modal" i]',
                'div[class*="lightbox" i]'
            ];            
            function isInPlayer(element) {
                return playerSelectors.some(selector => 
                    element.matches(selector) || element.closest(selector)
                );
            }            
            function removeAds() {
                blockedSelectors.forEach(selector => {
                    try {
                        document.querySelectorAll(selector).forEach(el => {
                            if (el.offsetParent !== null && !isInPlayer(el)) {
                                el.remove();
                            }
                        });
                    } catch (e) {
                        console.warn('Error in ad blocker:', e);
                    }
                });
            }            
            // Run on page load and when DOM changes
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
        try:
            script = WebKit.UserScript.new(
                script_source,
                WebKit.UserContentInjectedFrames.ALL_FRAMES,
                WebKit.UserScriptInjectionTime.END,
            )
            self.content_manager.add_script(script)
        except Exception:
            pass

    def inject_remove_malicious_links(self):
        """Inject malicious link remover JavaScript."""
        script_source = """
        // Remove or neutralize potentially malicious links
        function sanitizeLinks() {
            const links = document.querySelectorAll('a[href^="javascript:"]:not([href^="javascript:void(0)"])');
            links.forEach(link => {
                link.removeAttribute('onclick');
                link.removeAttribute('onmousedown');
                link.href = '#';
                link.title = 'Potentially harmful link blocked';
            });
        }       
        // Run on page load and when DOM changes
        document.addEventListener('DOMContentLoaded', sanitizeLinks);
        const observer = new MutationObserver(sanitizeLinks);
        observer.observe(document.body, { childList: true, subtree: true });
        """        
        try:
            script = WebKit.UserScript.new(
                script_source,
                WebKit.UserContentInjectedFrames.ALL_FRAMES,
                WebKit.UserScriptInjectionTime.END,
            )
            self.content_manager.add_script(script)
        except Exception:
            pass

    def inject_nonce_respecting_script(self):
        """Inject nonce-respecting script for CSP compatibility."""
        script_source = """
        // This script respects CSP nonce if present
        (function() {
            const scripts = document.querySelectorAll('script[nonce]');
            if (scripts.length > 0) {
                const nonce = scripts[0].nonce || scripts[0].getAttribute('nonce');
                if (nonce) {
                    const meta = document.createElement('meta');
                    meta.httpEquiv = "Content-Security-Policy";
                    meta.content = `script-src 'nonce-${nonce}' 'strict-dynamic' 'unsafe-inline' 'self'`;
                    document.head.appendChild(meta);
                }
            }
        })();
        """        
        try:
            script = WebKit.UserScript.new(
                script_source,
                WebKit.UserContentInjectedFrames.ALL_FRAMES,
                WebKit.UserScriptInjectionTime.START,
            )
            self.content_manager.add_script(script)
        except Exception:
            pass

    def disable_biometrics_in_webview(self, webview):
        """
        Injects JavaScript into the WebKitGTK WebView to block WebAuthn biometric prompts.
        This disables navigator.credentials.get/create with publicKey options.
        """
        try:
            script = """
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
            user_script = WebKit.UserScript.new(
                script,
                WebKit.UserContentInjectedFrames.TOP_FRAME,
                WebKit.UserScriptInjectionTime.START,
                [], []
            )
            webview.get_user_content_manager().add_script(user_script)
        except Exception:
            pass

    def block_biometric_apis(self, webview: WebKit.WebView):
        """
        Blocks WebAuthn biometric APIs and navigator.sendBeacon() in WebKitGTK browser.        
        This method injects JavaScript to prevent fingerprinting through WebAuthn and
        blocks the sendBeacon API which can be used for tracking. It provides a clean
        rejection message without cluttering the console with warnings.       
        Args:
            webview: The WebKit.WebView instance to apply the blocking to
        """
        try:
            if not webview or not hasattr(webview, 'get_user_content_manager'):
                return                
            script = """
            (function() {
                // Block WebAuthn
                if (navigator.credentials) {
                    const originalGet = navigator.credentials.get;
                    const originalCreate = navigator.credentials.create;                   
                    // Store original console.warn to suppress our own messages
                    const originalWarn = console.warn;
                    const originalError = console.error;                   
                    // Only show our warning once per page load
                    let warningShown = false;                
                    // Function to show warning only once
                    function showWarningOnce(message) {
                        if (!warningShown) {
                            originalWarn.call(console, "[Shadow Browser] " + message);
                            warningShown = true;
                        }
                    }                   
                    // Override credentials.get
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
                    // Override credentials.create
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
                    // Restore original console methods
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
                // Block navigator.sendBeacon silently
                const originalSendBeacon = navigator.sendBeacon;
                navigator.sendBeacon = function() {
                    // Silently block without logging to avoid console spam
                    return false;
                };                
                // Make it harder to detect our sendBeacon override
                Object.defineProperty(navigator, 'sendBeacon', {
                    value: navigator.sendBeacon,
                    writable: false,
                    configurable: false
                });               
            })();
            """           
            try:
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
            except Exception:
                pass
        except Exception:
            pass

    def DNT(self):
        """Inject Do Not Track header."""
        try:
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
        except Exception:
            pass
          
    def _create_http_session(self):
        """
        Create a configured requests session with retries, timeouts, and optional Tor routing.        
        Returns:
            requests.Session: Configured session object
        """
        try:
            session = requests.Session()
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
                pool_maxsize=10
            )
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            session.timeout = 30            
            if self.tor_enabled and hasattr(self, 'tor_manager') and self.tor_manager.is_running():
                proxy_url = f'socks5h://127.0.0.1:{self.tor_manager.tor_port}'
                session.proxies = {
                    'http': proxy_url,
                    'https': proxy_url
                }               
                try:
                    test_url = 'https://check.torproject.org/api/ip'
                    response = session.get(test_url, timeout=10)
                    if 'IsTor' not in response.json().get('IsTor', ''):
                        self.tor_enabled = False
                except Exception:
                    pass            
            return session            
        except ImportError:
            pass
        except Exception:
            pass

def main():
    """Main entry point for the Shadow Browser."""
    try:
        app = ShadowBrowser()
        return app.run(None)
    except Exception:
        pass

if __name__ == "__main__":
    main()

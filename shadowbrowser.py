import gi
import os
import json
import requests
import ssl
import socket
import time
import re
import threading
import traceback
import uuid
from urllib.parse import urlparse, urlunparse
from python.logging_config import setup_logging
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

gi.require_version("Gtk", "4.0")
gi.require_version("WebKit", "6.0")
from gi.repository import Gtk, WebKit, Gdk, GdkPixbuf, GLib, Gio, GObject

from cryptography.x509.oid import ExtensionOID
from cryptography import x509
from cryptography.hazmat.backends import default_backend

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

class DownloadManager:
    def __init__(self, parent_window):
        self.parent_window = parent_window
        self.box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.downloads = {}
        self.download_thread = None

    def add_webview(self, webview):
        webview.connect("download-starting", self.on_download_starting)

    def on_download_starting(self, webview, download):
        request = download.get_request()
        if request is None:
            logger.warning("Download request is None; skipping.")
            return
        uri = request.get_uri()
        if not uri:
            logger.warning("Download URI is empty; skipping.")
            return
        filename = os.path.basename(uri)
        logger.info(f"Starting download for {filename} from {uri}")
        self.downloads[download] = {
            "download": download,
            "filename": filename,
            "progress": 0,
            "status": "Downloading",
            "filepath": None,
        }
        download.connect("decide-destination", self.on_decide_destination)
        download.connect("finished", self.on_finished)
        download.connect("failed", self.on_failed)
        thread = threading.Thread(target=self.update_progress, args=(download,))
        thread.start()

    def on_download_started(self, webview, download):
        download.connect("decide-destination", self.on_decide_destination)
        download.connect("finished", self.on_finished)
        download.connect("failed", self.on_failed)
        self.set_download_destination(download)
        filename = os.path.basename(download.get_request().get_uri())
        label = Gtk.Label(label=f"Downloading {filename}")
        self.box.append(label)
        self.downloads[download] = label
        self.show()

    def on_decide_destination(self, download, suggested_filename):
        downloads_dir = GLib.get_user_special_dir(
            GLib.UserDirectory.DIRECTORY_DOWNLOAD
        ) or os.path.expanduser("~/Downloads")
        filename = suggested_filename or os.path.basename(
            download.get_request().get_uri()
        )
        filepath = os.path.join(downloads_dir, filename)
        logger.info(f"Setting download destination to: {filepath}")
        download.set_destination(filepath)
        if hasattr(download, "accept"):
            download.accept()
        elif hasattr(download, "start"):
            download.start()

    def set_download_destination(self, download):
        downloads_dir = GLib.get_user_special_dir(
            GLib.UserDirectory.DIRECTORY_DOWNLOAD
        ) or os.path.expanduser("~/Downloads")
        filename = os.path.basename(download.get_request().get_uri())
        filepath = os.path.join(downloads_dir, filename)
        logger.info(f"Setting download destination to: {filepath}")
        download.set_destination(filepath)

    def on_decided(self, download):
        download.accept()

    def on_progress_changed(self, download):
        progress = download.get_estimated_progress()
        filename = os.path.basename(download.get_destination_uri() or "")
        print(f"Progress: {progress * 100:.1f}% - {filename}")

    def on_finished(self, download):
        label = self.downloads.get(download)
        if label:
            destination = download.get_destination() or ""
            logger.info(f"Download finished: {os.path.basename(destination)}")
            label.set_text(f"Finished: {os.path.basename(destination)}")
            GLib.timeout_add_seconds(2, lambda: self._cleanup_wrapper(download))

    def _cleanup_wrapper(self, download):
        self.cleanup_download(download)
        return False

    def on_failed(self, download, error):
        label = self.downloads.get(download)
        if label:
            logger.error(f"Download failed: {error.message}")
            label.set_text(f"Failed: {error.message}")
            GLib.timeout_add_seconds(2, lambda: self.cleanup_download(download))
        else:
            print("Download failed but label not found")

    def cleanup_download(self, download):
        label = self.downloads.pop(download, None)
        if label:
            self.box.remove(label)
            return False

    def show(self):
        if not hasattr(self, "download_area"):
            downloads_dir = GLib.get_user_special_dir(
                GLib.UserDirectory.DIRECTORY_DOWNLOAD
            ) or os.path.expanduser("~/Downloads")
            self.download_area = Gtk.ScrolledWindow()
            self.download_area.set_policy(
                Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC
            )
            self.download_area.set_max_content_height(200)
            self.download_area.set_min_content_height(0)
            self.download_area.set_child(self.box)
            self.download_area.set_vexpand(False)
            parent_window = self.parent_window
            parent_window.get_child().append(self.download_area)

    def on_cancelled(self, download):
        label = self.downloads.get(download)
        if label:
            logger.info(
                f"Download cancelled: {os.path.basename(download.get_destination_uri())}"
            )
            label.set_text(
                f"Cancelled: {os.path.basename(download.get_destination_uri())}"
            )
        GLib.timeout_add_seconds(2, lambda: self.cleanup_download(download))

    def on_download_requested(self, webview, download):
        if hasattr(self, "download_manager"):
            self.download_manager.on_download_started(webview, download)
        else:
            downloads_dir = GLib.get_user_special_dir(
                GLib.UserDirectory.DIRECTORY_DOWNLOAD
            ) or os.path.expanduser("~/Downloads")
            filename = os.path.basename(download.get_request().get_uri())
            filepath = os.path.join(downloads_dir, filename)
            download.set_destination_uri(f"file://{filepath}")
            download.accept()

    def update_progress(self, download):
        if not download:
            return
        while True:
            try:
                progress = download.get_progress()
                if progress is None:
                    break
                fraction = progress.get_fraction()
                if fraction >= 1.0:
                    break
                GLib.idle_add(self.refresh_ui, download)
                time.sleep(0.5)
            except Exception as e:
                print(f"Error updating progress for download: {e}")
                break

    def refresh_ui(self, download):
        # Placeholder for UI refresh logic
        return False

    def _on_navigation_allowed(self, ad_blocker, url):
        download_extensions = [
            ".3gp",
            ".7z",
            ".aac",
            ".apk",
            ".appimage",
            ".avi",
            ".bat",
            ".bin",
            ".bmp",
            ".bz2",
            ".c",
            ".cmd",
            ".cpp",
            ".cs",
            ".deb",
            ".dmg",
            ".dll",
            ".doc",
            ".docx",
            ".eot",
            ".exe",
            ".flac",
            ".flv",
            ".gif",
            ".gz",
            ".h",
            ".ico",
            ".img",
            ".iso",
            ".jar",
            ".java",
            ".jpeg",
            ".jpg",
            ".js",
            ".lua",
            ".lz",
            ".lzma",
            ".m4a",
            ".mkv",
            ".mov",
            ".mp3",
            ".mp4",
            ".mpg",
            ".mpeg",
            ".msi",
            ".odp",
            ".ods",
            ".odt",
            ".ogg",
            ".otf",
            ".pdf",
            ".php",
            ".pkg",
            ".pl",
            ".png",
            ".pps",
            ".ppt",
            ".pptx",
            ".ps1",
            ".py",
            ".rar",
            ".rb",
            ".rpm",
            ".rtf",
            ".run",
            ".sh",
            ".so",
            ".svg",
            ".tar",
            ".tar.bz2",
            ".tar.gz",
            ".tbz2",
            ".tgz",
            ".tiff",
            ".ttf",
            ".txt",
            ".vhd",
            ".vmdk",
            ".wav",
            ".webm",
            ".webp",
            ".wma",
            ".woff",
            ".woff2",
            ".wmv",
            ".xls",
            ".xlsx",
            ".zip",
        ]
        if any(url.lower().endswith(ext) for ext in download_extensions):
            logging.info(f"Allowing download URL through ad blocker: {url}")
        self.add_history_entry(url)

class SocialTrackerBlocker:
    def __init__(self):
        self.blocklist = ["facebook.com", "twitter.com", "google.com"]

    def block_trackers(self, webview, url):
        parsed_url = urlparse(url)
        if any(domain in parsed_url.netloc for domain in self.blocklist):
            logger.info(f"Blocking tracker from {parsed_url.netloc}")
            return False
        return True

class AdBlocker:
    def __init__(self):
        self.blocked_patterns = []
        self.enabled = True
        self.block_list_url = "https://easylist.to/easylist/easylist.txt"
        self.cache_file = "easylist_cache.txt"
        self.cache_max_age = 86400
        self.load_block_lists()

    def inject_to_webview(self, user_content_manager):
        self.inject_adblock_script_to_ucm(user_content_manager)

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
                pattern = re.escape(line)
                pattern = pattern.replace(r"\*", ".*")
                pattern = pattern.replace(r"\^", r"[^a-zA-Z0-9_\-%\.]")
                pattern = pattern.replace(r"\|", "")
                if line.startswith("||"):
                    pattern = r"^https?://([a-z0-9-]+\.)?" + re.escape(line[2:])
                elif line.startswith("|"):
                    pattern = r"^" + re.escape(line[1:])
                elif line.endswith("|"):
                    pattern = re.escape(line[:-1]) + r"$"
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
        webview.connect("decide-policy", self.on_decide_policy)

    def on_decide_policy(self, webview, decision, decision_type):
        if decision_type == WebKit.PolicyDecisionType.NAVIGATION_ACTION:
            navigation_action = decision.get_navigation_action()
            request = navigation_action.get_request()
            requested_url = request.get_uri()
            if requested_url is None:
                logger.warning("Navigation request URL is None.")
                decision.ignore()
                return True
            if self.is_blocked_url(requested_url):
                decision.ignore()
                logger.warning(f"Blocked URL: {requested_url}")
                return True
            decision.use()
            return False

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

    def create_secure_webview(self):
        data_manager = WebKit.WebsiteDataManager()
        cookie_manager = data_manager.get_cookie_manager()
        cookie_manager.set_accept_policy(WebKit.CookieAcceptPolicy.NEVER)
        context = WebKit.WebContext.new_with_website_data_manager(data_manager)
        webview = WebKit.WebView.new_with_context(context)
        return webview

    def block_insecure_scripts(self, url):
        if "http://" in url:
            self.get_current_webview().get_settings().set_enable_javascript(False)
            logger.warning(f"JavaScript disabled for insecure page: {url}")

    def load_content_filters(self):
        try:
            filter_data = WebKit.UserContentFilter.new_from_bytes(
                "adblock-filter",
                WebKit.UserContentFilterFlags.NONE,
                b'{"filters": [{"url-filter": ".*ad.*"}]}',
            )
            self.content_manager.add_filter(filter_data)
            logger.info("Content filters loaded.")
        except Exception as e:
            logger.error(f"Error loading content filters: {e}")

    def enable_tracking_protection(self):
        webview = self.get_current_webview()
        if webview:
            webview.get_settings().set_property("enable-private-browsing", True)
        cookie_manager = WebKit.CookieManager.get_default()
        cookie_manager.set_accept_policy(WebKit.CookieAcceptPolicy.NEVER)

    def clear_data(self):
        """Clear session data including history and cookies."""
        self.delete_history()
        self.secure_cookies()
        logger.info("Browsing data cleared on shutdown, except bookmarks.")

    def do_shutdown(self):
        self.clear_data()
        self.save_session()
        logger.info("Application is shutting down. Session state saved.")

    def on_window_destroy(self, window):
        self.do_shutdown()
        Gtk.main_quit()

    def enable_do_not_track(self):
        self.webview.get_settings().set_property("enable-private-browsing", True)

    def block_popups(self):
        self.webview.connect("decide-policy", self.on_decide_policy)

    def check_certificate_validity(self, url):
        """Check the validity of a certificate for the given URL."""
        try:
            cert = self.fetch_certificate_from_url(url)
            ocsp_url = self.extract_ocsp_url(cert)
            response = requests.get(ocsp_url)
            response.raise_for_status()
            logger.info("OCSP response received and validated.")
        except requests.RequestException as e:
            logger.error(f"Network error checking OCSP for {url}: {e}")
        except Exception as e:
            logger.error(f"Error checking certificate validity: {e}")

    def enable_do_not_track_corrected(self):
        webview = self.get_current_webview()
        if webview:
            webview.get_settings().set_property("enable-private-browsing", True)

    def block_popups_corrected(self):
        webview = self.get_current_webview()
        if webview:
            webview.connect("decide-policy", self.on_decide_policy)

    def fetch_certificate_from_url(self, url):
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 443
        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                with self.context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                    return cert
        except Exception as e:
            logger.error(f"Error fetching certificate from {url}: {e}")
            return None

    def extract_ocsp_url(self, cert):
        try:
            aia = cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            ).value
            for access in aia:
                if access.access_method == x509.AuthorityInformationAccessOID.OCSP:
                    return access.access_location.value
        except Exception:
            return None

    def is_valid_url(self, url):
        if not isinstance(url, str):
            return False
        regex = re.compile(
            r"^(?:http|ftp)s?://"
            r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+"
            r"[A-Z]{2,6}\.?|"
            r"localhost|"
            r"\d{1,3}(?:\.\d{1,3}){3}|"
            r"\[?[A-F0-9]*:[A-F0-9:]+\]?)"
            r"(?::\d+)?"
            r"(?:/?|[/?]\S+)$",
            re.IGNORECASE,
        )
        return re.match(regex, url) is not None

    def create_secure_context(self):
        data_manager = WebKit.WebsiteDataManager.new_ephemeral()
        context = WebKit.WebContext.new_with_website_data_manager(data_manager)
        cookie_manager = WebKit.WebContext.get_default().get_cookie_manager()
        cookie_manager.set_accept_policy(WebKit.CookieAcceptPolicy.NEVER)
        return context

    def _on_navigation_allowed(self, ad_blocker, url):
        if any(url.lower().endswith(ext) for ext in DOWNLOAD_EXTENSIONS):
            logging.info(f"Allowing download URL through ad blocker: {url}")
        self.add_history_entry(url)

    def apply_theme(self):
        settings = Gtk.Settings.get_default()
        settings.set_property("gtk-application-prefer-dark-theme", self.theme == "dark")

    def inject_adblock_script_to_ucm(self, user_content_manager):
        """
        Injects JavaScript into UserContentManager to block ads and handle special links.
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
            observer.observe(document.body, { childList: true, subtree: true });
        })();
        """
        custom_script = r"""
        document.addEventListener('click', function(event) {
            let target = event.target;
            while (target && target.tagName !== 'A') {
                target = target.parentElement;
            }
            if (target && target.tagName === 'A') {
                const href = target.getAttribute('href');
                if (href && href.trim().toLowerCase() === 'javascript:void(0)') {
                    event.preventDefault();
                    event.stopPropagation();
                    const url = target.getAttribute('data-url');
                    if (url) {
                        window.open(url, '_blank');
                    } else {
                        console.warn('No data-url specified for this link.');
                    }
                }
            }
        }, true);
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

    def inject_element_hiding_script(self, content_manager):
        """Injects CSS to hide ad elements and JS to handle special links."""
        css = """
        .ad, [class*="ad-container"], [id*="ad-container"],
        [class*="advert"], [id*="advert"],
        [class*="banner"], [id*="banner"],
        [class*="promo"], [id*="promo"],
        [class*="sponsor"], [id*="sponsor"],
        [class*="popup"], [id*="popup"] {
            display: none !important;
        }
        """
        style_script = WebKit.UserScript.new(
            f"""
            (function() {{
                var style = document.createElement('style');
                style.type = 'text/css';
                style.innerHTML = `{css}`;
                document.head.appendChild(style);
            }})();
            """,
            WebKit.UserContentInjectedFrames.ALL_FRAMES,
            WebKit.UserScriptInjectionTime.START,
            None,
            None,
        )
        content_manager.add_script(style_script)
        # Updated JavaScript for handling clicks on <a href="javascript:void(0)">
        js_code = """
        document.addEventListener("DOMContentLoaded", function() {
            document.addEventListener("click", function(event) {
                let target = event.target;
                while (target && target.tagName !== "A") {
                    target = target.parentElement; // Traverse up to find the anchor tag
                }
                if (target && target.tagName === "A") {
                    const href = target.getAttribute("href");
                    const urlToOpen = target.getAttribute("data-url"); // Assuming you have a data attribute for the URL
                    // Check if the href is "javascript:void(0)"
                    if (href === "javascript:void(0)") {
                        event.preventDefault(); // Prevent the default action
                        event.stopPropagation(); // Stop the event from bubbling up

                        // Open the URL in a new tab/window
                        if (urlToOpen) {
                            window.open(urlToOpen, '_blank'); // Open the specified URL
                            console.log(`Opened URL: ${urlToOpen}`);
                        } else {
                            console.warn("No URL specified to open.");
                        }
                    }
                }
            }, true);
        });
        """
        script = WebKit.UserScript.new(
            js_code,
            WebKit.UserContentInjectedFrames.ALL_FRAMES,
            WebKit.UserScriptInjectionTime.START,
        )
        content_manager.add_script(script)
        print("AdBlocker scripts injected.")

    def inject_script(self):
        js_code = """
        document.addEventListener('click', function(event) {
            let target = event.target;
            while (target && target.tagName !== 'A') {
                target = target.parentElement;
            }
            if (target && target.tagName === 'A') {
                const href = target.getAttribute('href');
                if (href && href.trim().toLowerCase().replace(/\\s+/g, '') === 'javascript:void(0)') {
                    event.preventDefault();
                    const url = target.getAttribute('data-url');
                    if (url && url.startsWith('http')) {
                        window.open(url, '_blank');
                    }
                }
            }
        });
        """
        webview = self.get_current_webview()
        if webview:
            def noop_callback(webview, result, user_data):
                try:
                    webview.evaluate_javascript_finish(result)
                except Exception as e:
                    print(f"JavaScript injection failed: {e}")
            webview.evaluate_javascript(js_code, noop_callback, None)

class Tab:
    def __init__(self, url, webview):
        self.url = url
        self.webview = webview
        self.label_widget = None

class ShadowBrowser(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="com.example.The Shadow Browser")
        self.bookmarks = self.load_json(BOOKMARKS_FILE)
        self.history = self.load_json(HISTORY_FILE)
        self.tabs = []
        self.blocked_urls = []
        self.window = None
        self.notebook = Gtk.Notebook()
        self.url_entry = Gtk.Entry()
        self.home_url = "https://duckduckgo.com/"
        self.theme = "dark"
        self.download_manager = None
        self.content_manager = WebKit.UserContentManager()
        self.context = ssl.create_default_context()
        self.adblocker = AdBlocker()
        self.social_blocker = SocialTrackerBlocker()
        self.debug_mode = True
        self.error_handlers = {}
        self.register_error_handlers()
        self.adblocker.inject_to_webview = self.adblocker.inject_to_webview
        self.ad_blocker = AdBlocker() 
        self.webview = WebKit.WebView()
        self.user_content_manager = self.webview.get_user_content_manager()
        self.ad_blocker.inject_to_webview(self.user_content_manager) 

    def get_current_webview(self):
        current_page = self.notebook.get_current_page()
        if current_page != -1 and current_page < len(self.tabs):
            return self.tabs[current_page].webview
        return None

    def get_toolbar(self):
        if hasattr(self, "toolbar"):
            return self.toolbar
        return None

    def create_toolbar(self):
        if hasattr(self, "toolbar") and self.toolbar is not None:
            return self.toolbar
        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.toolbar = toolbar
        return toolbar

    def safe_get_child(self, widget):
        try:
            return widget.get_child()
        except AttributeError:
            return None

    def do_startup(self):
        """Called when the application is starting up."""
        Gtk.Application.do_startup(self)
        action = Gio.SimpleAction.new("about", None)
        action.connect("activate", self.on_about)
        self.add_action(action)

    def do_activate(self):
        """Called when the application is activated."""
        Gtk.Application.do_activate(self)
        self.window = Gtk.ApplicationWindow(application=self)
        self.window.set_title("Shadow Browser")
        self.window.set_default_size(1024, 768)
        self.window.connect("destroy", self.on_window_destroy)
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.window.set_child(vbox)
        vbox.append(self.create_menubar())
        vbox.append(self.create_toolbar())
        vbox.append(self.notebook)
        self.download_manager = DownloadManager(self.window)
        if hasattr(self.download_manager, "box"):
            self.download_area = Gtk.ScrolledWindow()
            self.download_area.set_policy(
                Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC
            )
            self.download_area.set_max_content_height(200)
            self.download_area.set_min_content_height(0)
            self.download_area.set_child(self.download_manager.box)
            self.download_area.set_vexpand(False)
            vbox.append(self.download_area)
        if not self.tabs:
            self.add_new_tab(self.home_url)
        self.apply_theme()
        self.window.present()

    def do_shutdown(self):
        """Called when the application is shutting down."""
        try:
            self.save_session()
            self.save_tabs()
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
        Gtk.Application.do_shutdown(self)

    def register_error_handlers(self):
        """Register handlers for common errors."""
        self.error_handlers["gtk_warning"] = self.handle_gtk_warning
        self.error_handlers["network_error"] = self.handle_network_error
        self.error_handlers["webview_error"] = self.handle_webview_error
        self.error_handlers["memory_error"] = self.handle_memory_error

    def handle_gtk_warning(self, message):
        """Handle GTK warnings."""
        logger.warning(f"GTK Warning: {message}")
        return True

    def handle_network_error(self, url, error):
        """Handle network connection errors."""
        logger.warning(f"Network error loading {url}: {error}")
        return True

    def handle_webview_error(self, webview, error):
        """Handle WebKit webview errors."""
        logger.warning(f"WebView error: {error}")
        return True

    def handle_memory_error(self, error):
        """Handle memory-related errors."""
        logger.warning(f"Memory error: {error}")
        return True

    def toggle_debug_mode(self, action, parameter):
        """Toggle debug mode on/off."""
        self.debug_mode = not self.debug_mode
        logger.info(f"Debug mode: {'enabled' if self.debug_mode else 'disabled'}")

    def create_menubar(self):
        """Create the main application menu bar."""
        menubar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        bookmark_menu_button = Gtk.MenuButton(label="Bookmarks")
        bookmark_popover = Gtk.Popover()
        self.bookmark_menu = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.update_bookmarks_menu(self.bookmark_menu)
        bookmark_popover.set_child(self.bookmark_menu)
        bookmark_menu_button.set_popover(bookmark_popover)
        menubar.append(bookmark_menu_button)
        about_button = Gtk.Button(label="About")
        about_button.connect("clicked", self.on_about)
        menubar.append(about_button)
        return menubar

    def create_toolbar(self):
        """Create the browser toolbar with navigation buttons and URL entry."""
        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        buttons = [
            ("go-previous-symbolic", "Back", self.on_back_clicked),
            ("go-next-symbolic", "Forward", self.on_forward_clicked),
            ("go-home-symbolic", "Home", lambda w: self.load_url(self.home_url)),
            (
                "view-refresh-symbolic",
                "Refresh",
                lambda w: self.get_current_webview().reload(),
            ),
            (
                "bookmark-new-symbolic",
                "Bookmark",
                lambda w: self.add_bookmark(self.get_current_webview().get_uri()),
            ),
            ("tab-new-symbolic", "New Tab", self.on_new_tab_clicked),
        ]
        for icon, tooltip, callback in buttons:
            button = Gtk.Button()
            image = Gtk.Image.new_from_icon_name(icon)
            button.set_child(image)
            button.set_tooltip_text(tooltip)
            button.connect("clicked", callback)
            toolbar.append(button)
        self.url_entry = Gtk.Entry()
        self.url_entry.set_hexpand(True)
        toolbar.append(self.url_entry)
        self.search_entry = Gtk.SearchEntry()
        self.search_entry.set_placeholder_text("Search or enter URL")
        self.search_entry.connect("activate", self.on_search_activate)
        toolbar.append(self.search_entry)
        go_button = Gtk.Button(label="Go")
        go_button.connect("clicked", self.on_go_clicked)
        toolbar.append(go_button)
        return toolbar

    def on_search_activate(self, search_entry):
        """Handle search entry activation."""
        query = search_entry.get_text().strip()
        if not query:
            return
        if self.is_valid_url(query):
            self.load_url(query)
        else:
            search_url = f"https://duckduckgo.com/?q={requests.utils.quote(query)}"
            self.load_url(search_url)

    def is_valid_url(self, url):
        """Check if the provided string is a valid URL."""
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

    def get_current_webview(self):
        """Get the currently active webview."""
        current_page = self.notebook.get_current_page()
        if current_page != -1 and current_page < len(self.tabs):
            return self.tabs[current_page].webview
        return None

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

    def on_new_tab_clicked(self, button):
        """Handle New Tab button click."""
        self.add_new_tab(self.home_url)

    def add_new_tab(self, url):
        """Add a new browser tab with the specified URL."""
        try:
            webview = WebKit.WebView()
            self.setup_webview_settings(webview)
            scrolled_window = Gtk.ScrolledWindow()
            scrolled_window.set_vexpand(True)
            scrolled_window.set_child(webview)
            tab = Tab(url, webview)
            self.tabs.append(tab)
            label_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
            label = Gtk.Label(label="Loading...")
            close_button = Gtk.Button()
            close_button.set_icon_name("window-close-symbolic")
            close_button.connect(
                "clicked",
                lambda x: self.close_tab(self.notebook.page_num(scrolled_window)),
            )
            label_box.append(label)
            label_box.append(close_button)
            index = self.notebook.append_page(scrolled_window, label_box)
            self.notebook.set_current_page(index)
            webview.connect("load-changed", self.on_load_changed)
            webview.connect("notify::title", self.on_title_changed)
            webview.connect("decide-policy", self.on_decide_policy)
            tab.label_widget = label
            webview.load_uri(url)
            return index
        except Exception as e:
            logger.error(f"Error adding new tab: {e}")
            return -1

    def setup_webview_settings(self, webview):
        """Configure WebView settings."""
        if not webview:
            return
        settings = webview.get_settings()
        settings.set_property("enable-javascript", True)
        settings.set_property("allow-file-access-from-file-urls", False)
        settings.set_property("allow-universal-access-from-file-urls", False)
        settings.set_property("enable-developer-extras", True)

    def on_load_changed(self, webview, load_event):
        """Handle webview load events."""
        if load_event == WebKit.LoadEvent.FINISHED:
            url = webview.get_uri()
            current_webview = self.get_current_webview()
            #self.ad_blocker.inject_script_example(self.user_content_manager)
            if current_webview and current_webview == webview:
                self.url_entry.set_text(url or "")
            #self.inject_script()

    def on_title_changed(self, webview, param):
        """Update tab label when page title changes."""
        title = webview.get_title() or "Untitled"
        for i, tab in enumerate(self.tabs):
            if tab.webview == webview and tab.label_widget is not None:
                tab.label_widget.set_text(title)
                break

    def close_tab(self, index):
        """Close the tab at the specified index."""
        if 0 <= index < len(self.tabs):
            self.tabs.pop(index)
            self.notebook.remove_page(index)
            if len(self.tabs) == 0:
                self.add_new_tab(self.home_url)

    def on_decide_policy(self, webview, decision, decision_type):
        """Handle navigation policy decisions."""
        if decision_type == WebKit.PolicyDecisionType.NAVIGATION_ACTION:
            navigation_action = decision.get_navigation_action()
            request = navigation_action.get_request()
            url = request.get_uri()
            if self.is_blocked_url(url):
                decision.ignore()
                logger.warning(f"Blocked navigation to: {url}")
                return True

        elif decision_type == WebKit.PolicyDecisionType.NEW_WINDOW_ACTION:
            navigation_action = decision.get_navigation_action()
            request = navigation_action.get_request()
            url = request.get_uri()
            self.add_new_tab(url)
            decision.ignore()
            return True
        decision.use()
        return True

    def is_blocked_url(self, url):
        """Check if URL should be blocked."""
        for blocked in self.blocked_urls:
            if blocked in url:
                return True
        return False

    def on_back_clicked(self, button):
        """Navigate back in the current tab."""
        webview = self.get_current_webview()
        if webview and webview.can_go_back():
            webview.go_back()

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

    def extract_tab_title(self, url):
        """Extract a display title from a URL."""
        try:
            parsed = urlparse(url)
            return parsed.netloc or "New Tab"
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

    def on_about(self, button):
        """Show the about dialog."""
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
            "for (let link of links) {"
            "if (link.getAttribute('data-url') === '" + data_url + "') {"
            "['mousedown', 'mouseup', 'click'].forEach(eventType => {"
            "let event = new MouseEvent(eventType, { view: window, bubbles: true, cancelable: true, button: 0 });"
            "link.dispatchEvent(event);"
            "});"
            "console.log('Simulated click on data-url: " + data_url + "');"
            "return true;"
            "}"
            "}"
            "console.warn('No link found with data-url: " + data_url + "');"
            "return false;"
            "})();"
        )
        webview = self.get_current_webview()
        if webview:
            webview.evaluate_javascript(js_code, self.js_callback)

            def js_callback(webview, result):
                try:
                    value = webview.evaluate_javascript_finish(result)
                    print(f"JS evaluation result: {value}")
                except Exception as e:
                    print(f"JS evaluation error: {e}")
            webview.evaluate_javascript(js_code, js_callback)

    def js_callback(self, webview, result):
        try:
            value = webview.evaluate_javascript_finish(result)
        except Exception as e:
            logger.error(f"JavaScript evaluation error: {e}")

if __name__ == "__main__":
    app = ShadowBrowser()
    app.run(None)

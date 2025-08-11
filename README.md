# Shadow Browser

Shadow Browser is a privacy-focused web browser built using Python, GTK4, and WebKit6. It offers a lightweight, secure, and customizable browsing experience with features designed to enhance user privacy and control.

## Features

- Tabbed browsing with easy tab management
- Bookmark and history management with JSON-based storage
- Built-in ad blocker using EasyList patterns
- Secure WebView settings with JavaScript, media, and WebGL support
- Download manager with progress tracking and file conflict handling
- Session saving and restoring for tabs and browsing state
- Custom JavaScript injection for enhanced privacy and functionality
- Content Security Policy (CSP) enforcement and mixed content blocking
- Support for handling special links like `javascript:void(0)` with custom handlers
- Dark theme support with GTK4 native theming

## Installation

### Prerequisites

- Python 3.8 or higher
- GTK 4 and its Python bindings (`python3-gi` with GTK4 support)
- WebKit2GTK 6.0 and its Python bindings
- Cryptography library for SSL certificate handling
- Requests library for HTTP requests

On Debian/Ubuntu-based systems, you can install dependencies with:

```bash
sudo apt update
sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-webkit2-6.0 gir1.2-gdkpixbuf-2.0 gir1.2-glib-2.0 python3-requests python3-cryptography
```

On Fedora-based systems, you can install dependencies with:

```bash
sudo dnf install python3-gobject gtk4 webkit2gtk6 gdk-pixbuf2 glib2 python3-requests python3-cryptography
```

On Arch Linux, you can install dependencies with:

```bash
sudo pacman -S python-gobject gtk4 webkit2gtk gdk-pixbuf2 glib2 python-requests python-cryptography
```

### Clone the repository

```bash
git clone https://github.com/shadowyfigure/shadow-browser.git
cd shadow-browser
```

## Usage

Run the browser with:

```bash
python3 shadowbrowser.py
```

The browser will open with a default homepage (DuckDuckGo). Use the toolbar to navigate, open new tabs, add bookmarks, and manage downloads.

## Configuration

- Bookmarks, history, session, and tabs are saved in JSON files in the working directory.

## License

This project is licensed under the MIT License.

## Author

Andrew Power
https://github.com/shadowyfigure/shadow-browser

Works fine on most sites a few minor issues.
On my dt do's list.

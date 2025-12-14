# Shadow Browser

A privacy-focused web browser built with Python, GTK4, and WebKitGTK.
Experimental Browser not recomended for daily use.

## Features

- **Privacy & Security**: Built-in ad-blocker, SSL certificate validation, and enhanced security controls
- **Modern UI**: Clean GTK4 interface with tabbed browsing
- **Download Management**: Robust download manager with progress tracking
- **Bookmarks & History**: Full bookmark
- **Hardware Acceleration**: VAAPI support for video playback - shuttering issue with some livesteam sites.
- **Tor Integration**: Optional Tor browsing capabilities

## Requirements

- Python 3.8+
- GTK4
- WebKitGTK 6.0
- GStreamer 1.0
- PyGObject 3.42.0+
- cryptography 41.0.0+
- stem 1.8.0+ (for Tor support)
- requests 2.31.0+
- urllib3 2.0.0+

## Installation

### Ubuntu/Debian
```bash
git clone <repository-url>
cd shadowbrowser
pip install -r requirements.txt
sudo apt-get install python3-gi python3-gi-cairo gir1.2-gtk-4.0 gir1.2-webkit2-4.1 gir1.2-gstreamer-1.0
python shadowbrowser.py
```

### Fedora/RHEL/CentOS
```bash
git clone <repository-url>
cd shadowbrowser
pip install -r requirements.txt
sudo dnf install python3-gobject python3-cairo gtk4 webkitgtk6 gstreamer1 gstreamer1-plugins-good
python shadowbrowser.py
```

### Arch Linux
```bash
git clone <repository-url>
cd shadowbrowser
pip install -r requirements.txt
sudo pacman -S python-gobject gtk4 webkit2gtk-4.1 gstreamer gst-plugins-good
python shadowbrowser.py
```

### openSUSE
```bash
git clone <repository-url>
cd shadowbrowser
pip install -r requirements.txt
sudo zypper install python3-gobject python3-cairo gtk4 webkitgtk6 gstreamer gstreamer-plugins-good
python shadowbrowser.py
```

### macOS
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install python@3.11 gtk4 webkit2gtk gstreamer gst-plugins-good

# Clone and run
git clone <repository-url>
cd shadowbrowser
pip3 install -r requirements.txt
python3 shadowbrowser.py
```

### Windows
```bash
# Install MSYS2 from https://www.msys2.org/

# In MSYS2 terminal:
pacman -Syu
pacman -S mingw-w64-x86_64-python3 mingw-w64-x86_64-gtk4 mingw-w64-x86_64-webkit2gtk-4.1 mingw-w64-x86_64-gstreamer mingw-w64-x86_64-gst-plugins-good

# Clone and run:
git clone <repository-url>
cd shadowbrowser
python -m pip install -r requirements.txt
python shadowbrowser.py
```

### Solus
```bash
git clone <repository-url>
cd shadowbrowser
pip install -r requirements.txt
sudo eopkg install python3-gobject python3-cairo gtk4 webkit2gtk-4.1 gstreamer gstreamer-plugins-good
python shadowbrowser.py
```

### Void Linux
```bash
git clone <repository-url>
cd shadowbrowser
pip install -r requirements.txt
sudo xbps-install -S python3-gobject python3-cairo gtk4 webkit2gtk-4.1 gstreamer1 gst-plugins-good1
python shadowbrowser.py
```

### Alpine Linux
```bash
git clone <repository-url>
cd shadowbrowser
pip install -r requirements.txt
sudo apk add py3-gobject3 py3-cairo gtk4 webkit2gtk-4.1 gstreamer gst-plugins-good
python shadowbrowser.py
```

## Configuration

- Cache settings (size, location)
- Network preferences (user agent, timeouts)
- Security options (JavaScript, plugins, WebGL)
- UI settings (window size, zoom level, dark mode)
- Extension preferences
- GStreamer hardware acceleration options

## Usage

### Basic Navigation
- Use the address bar to enter URLs
- Navigate with back/forward buttons
- Open new tabs with Ctrl+T

### Privacy Features
- Ad-blocking is enabled by default using EasyList
- SSL certificate validation warns about expired or invalid certificates
- Enhanced tracking protection

### Downloads
- Downloads are automatically saved to your Downloads folder
- Progress bars show download status
- Download history is maintained

### Bookmarks & History
- Bookmark pages with Ctrl+D
- View browsing history with Ctrl+H
- Bookmarks and history are automatically saved

## Security Features

- **SSL Certificate Validation**: Checks certificate expiration and validity
- **Content Security Policy**: Enforces strict CSP headers
- **Ad Blocking**: Blocks ads and trackers using EasyList
- **JavaScript Control**: Configurable JavaScript execution

## Tor Integration
1. Ensure Tor is installed and running

```
## Support

For issues, feature requests, or questions, please open an issue on the project repository.

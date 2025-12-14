# Shadow Browser

A privacy-focused web browser built with Python, GTK4, and WebKitGTK. Shadow Browser emphasizes security, privacy, and performance while providing a modern browsing experience.

## Features

- **Privacy & Security**: Built-in ad-blocker, SSL certificate validation, and enhanced security controls
- **Modern UI**: Clean GTK4 interface with tabbed browsing
- **Download Management**: Robust download manager with progress tracking
- **Session Management**: Automatic session saving and restoration
- **Bookmarks & History**: Full bookmark and browsing history support
- **Hardware Acceleration**: VAAPI support for video playback
- **Tor Integration**: Optional Tor browsing capabilities
- **Extensible**: Plugin architecture for custom extensions

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

Shadow Browser uses a YAML configuration file located at `~/.config/shadowbrowser/config.yaml`. The configuration includes:

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
- **Plugin Management**: Controlled plugin activation

## Tor Integration

Shadow Browser includes optional Tor support through the `torbrowser.py` module. To use Tor browsing:

1. Ensure Tor is installed and running
2. Launch with Tor mode:
```bash
python torbrowser.py
```

## Development

### Project Structure
- `shadowbrowser.py` - Main browser application
- `config.py` - Configuration management
- `utils.py` - Utility functions
- `vaapi_manager.py` - Hardware acceleration management
- `js_obfuscation_improved.py` - JavaScript handling utilities
- `test_*.py` - Test files

### Testing
Run tests with:
```bash
python test.py
python test_blocking.py
python test_webkitgtk_fixes.py
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Troubleshooting

### Common Issues

**WebKitGTK not found**:
- Ubuntu/Debian: `sudo apt-get install gir1.2-webkit2-4.1`
- Fedora: `sudo dnf install webkitgtk6`
- Arch: `sudo pacman -S webkit2gtk-4.1`
- macOS: `brew install webkit2gtk`
- Windows (MSYS2): `pacman -S mingw-w64-x86_64-webkit2gtk-4.1`

**GTK4 not available**:
- Ubuntu/Debian: `sudo apt-get install libgtk-4-dev gir1.2-gtk-4.0`
- Fedora: `sudo dnf install gtk4`
- Arch: `sudo pacman -S gtk4`
- macOS: `brew install gtk4`
- Windows (MSYS2): `pacman -S mingw-w64-x86_64-gtk4`

**Python GI bindings missing**:
- Ubuntu/Debian: `sudo apt-get install python3-gi python3-gi-cairo`
- Fedora: `sudo dnf install python3-gobject python3-cairo`
- Arch: `sudo pacman -S python-gobject`
- macOS: `brew install python@3.11` (includes GI bindings)
- Windows (MSYS2): `pacman -S mingw-w64-x86_64-python3`

**GStreamer issues**:
- Ubuntu/Debian: `sudo apt-get install gir1.2-gstreamer-1.0 gstreamer1.0-plugins-good`
- Fedora: `sudo dnf install gstreamer1 gstreamer1-plugins-good`
- Arch: `sudo pacman -S gstreamer gst-plugins-good`
- macOS: `brew install gstreamer gst-plugins-good`
- Windows (MSYS2): `pacman -S mingw-w64-x86_64-gstreamer mingw-w64-x86_64-gst-plugins-good`

**Hardware acceleration issues**:
- Check VAAPI driver installation
- Update graphics drivers
- Disable hardware acceleration in config if needed

### Platform-Specific Issues

**macOS**:
- If GTK fails to initialize, try: `export GTK_PATH=$(brew --prefix gtk4)/lib/gtk-4.0`
- For display issues, ensure XQuartz is installed and running
- Use `python3` instead of `python` to avoid system Python conflicts

**Windows (MSYS2)**:
- Run from MSYS2 MinGW 64-bit shell, not regular CMD/PowerShell
- Ensure MSYS2 is updated: `pacman -Syu`
- If fonts look wrong, install: `pacman -S mingw-w64-x86_64-fontconfig`

**Linux (General)**:
- For Wayland users, GTK4 should work natively
- On X11, ensure X11 server is running properly
- Check for missing theme packages if UI looks incorrect

**Permission Issues**:
- Ensure Python has access to create cache directories
- Check permissions for `~/.config/shadowbrowser/` and `~/.cache/shadowbrowser/`

### Debug Mode

Enable debug logging by setting the log level in the configuration:
```yaml
logging:
  level: DEBUG
```

## Configuration File Example

```yaml
cache:
  directory: ~/.cache/shadowbrowser
  max_size: 536870912  # 512MB
  media_cache_size: 268435456  # 256MB

network:
  user_agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36
  timeout: 30
  max_redirects: 10

security:
  enable_javascript: true
  enable_plugins: false
  enable_webgl: true
  enable_webrtc: true
  block_third_party_cookies: true

ui:
  default_width: 1280
  default_height: 800
  zoom_level: 1.0
  dark_mode: true

extensions:
  adblock: true
  privacy_badger: true
  https_everywhere: true

gstreamer:
  enable_hardware_accel: true
  vaapi_driver: iHD
  debug_level: WARNING
```

## Support

For issues, feature requests, or questions, please open an issue on the project repository.

# ShadowBrowser

A secure and private web browser built with Python, GTK 4, and WebKit.

## Features

- **Privacy Focused**: Built with privacy in mind, blocking trackers and protecting your data
- **Secure by Default**: Implements modern security practices and content security policies
- **Lightweight**: Minimal resource usage compared to mainstream browsers
- **Customizable**: Theme support and configurable settings
- **Modern UI**: Clean, intuitive interface using GTK 4
- **Biometric Protection**: Blocks WebAuthn and biometric authentication for enhanced privacy
- **Anti-Fingerprinting**: Prevents tracking through browser fingerprinting techniques
- **Download Manager**: Built-in download management with progress tracking
- **Tor Integration**: Optional Tor support with status indicator
- **Ad Blocking**: Advanced ad and tracker blocking using EasyList
- **Media Optimization**: Enhanced support for video and audio playback

## Requirements

- Python 3.8+
- GTK 4.0
- WebKitGTK 6.0
- GStreamer (for media playback)
- Python packages (automatically installed):
  - PyGObject
  - cryptography
  - requests
  - stem (for Tor support)

## Installation

### Linux (Debian/Ubuntu)

1. Install system dependencies:
   ```bash
   sudo apt update
   sudo apt install python3-gi gir1.2-webkit2-4.0 gir1.2-gtk-4.0 gir1.2-gtksource-4 \
                  gir1.2-gstreamer-1.0 gstreamer1.0-plugins-good \
                  gstreamer1.0-plugins-bad gstreamer1.0-libav
   ```

2. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/shadowbrowser.git
   cd shadowbrowser
   ```

3. Install Python dependencies:
   ```bash
   pip install --user -r requirements.txt
   ```

4. (Optional) Run the setup script to create a desktop entry:
   ```bash
   python setup.py
   ```

### Linux (Fedora)

1. Install system dependencies:
   ```bash
   sudo dnf install python3-gobject webkit2gtk4.0 gtk4 gtksourceview4 \
                   gstreamer1 gstreamer1-plugins-good gstreamer1-plugins-bad \
                   gstreamer1-plugins-libav
   ```

2. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/shadowbrowser.git
   cd shadowbrowser
   ```

3. Install Python dependencies:
   ```bash
   pip install --user -r requirements.txt
   ```

4. (Optional) Run the setup script to create a desktop entry:
   ```bash
   python setup.py
   ```

### Linux (Arch Linux)

1. Install system dependencies:
   ```bash
   sudo pacman -S python-gobject webkit2gtk gtk4 gtksourceview4 \
                 gstreamer gst-plugins-good gst-plugins-bad gst-libav
   ```

2. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/shadowbrowser.git
   cd shadowbrowser
   ```

3. Install Python dependencies:
   ```bash
   pip install --user -r requirements.txt
   ```

4. (Optional) Run the setup script to create a desktop entry:
   ```bash
   python setup.py
   ```

## Usage

### Running the Browser

```bash
python -m browser
```

### Command Line Options

- `--new-window`: Open in a new window
- `--new-tab`: Open in a new tab
- `--private`: Start in private browsing mode
- `--help`: Show help message
- `--version`: Show version information

### Keyboard Shortcuts

- `Ctrl+T`: New tab
- `Ctrl+W`: Close current tab
- `Ctrl+Tab`: Next tab
- `Ctrl+Shift+Tab`: Previous tab
- `Ctrl+L`: Focus address bar
- `F5` or `Ctrl+R`: Reload page
- `Ctrl+H`: Show history
- `Ctrl+B`: Show bookmarks
- `Ctrl+D`: Add current page to bookmarks
- `Ctrl+Q`: Quit

## Download Manager

ShadowBrowser includes a built-in download manager that provides:

- **Progress Tracking**: Real-time download progress with speed and ETA
- **Resume Support**: Ability to pause and resume downloads
- **Security Checks**: Automatic scanning for malicious content
- **Organization**: Downloads are organized by type and date
- **Integration**: Seamless integration with the browser interface

Downloads can be managed directly from the browser's download panel, accessible from the menu bar.

## Settings and Configuration

The browser includes a settings dialog accessible from the menu, allowing you to:

- Configure privacy and security options
- Manage ad blocking and tracker lists
- Enable or disable Tor integration
- Customize themes and appearance
- Set keyboard shortcuts and behavior
- Manage downloads and media playback options

Use the settings dialog to tailor the browser to your preferences and enhance your browsing experience.

## Features

### Privacy

- Built-in ad and tracker blocking
- Third-party cookie blocking
- Fingerprinting protection
- Secure DNS (with support for DNS-over-HTTPS)
- Tor integration (optional)

### Security

- Content Security Policy (CSP) support
- HTTP Strict Transport Security (HSTS)
- Mixed content blocking
- Certificate pinning
- Secure password management
- WebAuthn and biometric authentication blocking
- Enhanced ad and tracker blocking using EasyList
- Anti-fingerprinting measures
- Tor integration with status indicator and control

### Customization

- Light and dark themes
- Custom CSS support
- Extensible architecture
- Configurable user agent

## Development

### Project Structure

```
shadowbrowser/
├── browser/               # Main package
│   ├── core/              # Core functionality
│   │   ├── __init__.py
│   │   ├── window.py      # Main window implementation
│   │   └── tabs.py        # Tab management
│   ├── shadow/            # Shadow submodule with enhanced features
│   │   ├── __init__.py
│   │   └── shadowbrowser.py
│   ├── __main__.py        # Application entry point
│   └── __init__.py
├── config.py             # Configuration and constants
├── logger.py             # Logging configuration
├── security.py           # Security utilities
├── rate_limiter.py       # Rate limiting
├── setup.py              # Installation script
└── README.md             # This file
```
### Project Structure


### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the GPL-3.0 License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- WebKitGTK for the rendering engine
- GTK for the UI toolkit
- The Python community for awesome libraries

(function() {
    // Only proceed if we're in a secure context
    if (!window.isSecureContext) {
        return;
    }

    // Function to safely get a nonce
    function getNonce() {
        // First try: Check for existing nonce on scripts
        const scripts = document.getElementsByTagName('script');
        for (let i = 0; i < scripts.length; i++) {
            if (scripts[i].nonce) {
                return scripts[i].nonce;
            }
        }

        // Second try: Check meta CSP header
        const metaTags = document.getElementsByTagName('meta');
        for (let i = 0; i < metaTags.length; i++) {
            const meta = metaTags[i];
            if (meta.httpEquiv.toLowerCase() === 'content-security-policy' && meta.content) {
                const match = meta.content.match(/script-src[^;]*'nonce-([^']+)'/);
                if (match && match[1]) {
                    return match[1];
                }
            }
        }

        return null;
    }

    // Get the nonce
    const nonce = getNonce();
    
    // Only inject if we have a valid nonce
    if (nonce) {
        try {
            const script = document.createElement('script');
            script.nonce = nonce;
            script.textContent = `
                // Your script content here
                console.log("Nonce-respecting script loaded successfully");
            `;
            (document.head || document.documentElement).appendChild(script);
        } catch (e) {
            // Silently fail in production, log in debug mode
            if (window.console && console.warn) {
                console.warn('Failed to inject script with nonce:', e);
            }
        }
    }
    // No else - fail silently if no nonce found
})();

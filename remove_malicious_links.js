(function() {
    // Remove empty <a> tags with href="#" and target="_blank" and no meaningful content
    document.querySelectorAll('a[target="_blank"][href="#"]').forEach(el => {
        if (!el.textContent.trim()) {
            el.remove();
            console.log("Removed suspicious empty anchor tag:", el);
        }
    });
})();

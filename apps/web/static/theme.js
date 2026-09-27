// Apply the saved palette before stylesheets can paint the default theme.
(() => {
  const themes = new Set(['classic', 'dark', 'light', 'medium-light', 'cibc-red', 'orange', 'grafana-compact']);
  try {
    const width = Number(localStorage.getItem('podpilot-sidebar-width'));
    if (width >= 200 && width <= 480) document.documentElement.style.setProperty('--sidebar-user-width', `${width}px`);
    const saved = localStorage.getItem('podpilot-color-theme');
    if (themes.has(saved)) document.documentElement.dataset.theme = saved;
  } catch (_error) { /* Keep the default when preference storage is unavailable. */ }
})();

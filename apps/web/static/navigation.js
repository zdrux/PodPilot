(() => {
  const initializers = new Map();
  let scopes = [];
  function mount(initialize) {
    const controller = new AbortController();
    const cleanup = [];
    const timers = new Set();
    const page = {
      cleanup: callback => cleanup.push(callback),
      on(target, type, callback, options = {}) {
        target.addEventListener(type, callback, {
          ...(typeof options === 'boolean' ? {capture: options} : options), signal: controller.signal
        });
      },
      fetch(url, options = {}) {
        return fetch(url, {...options, signal: controller.signal});
      },
      timeout(callback, delay) {
        if (controller.signal.aborted) return;
        const id = window.setTimeout(() => { timers.delete(id); callback(); }, delay);
        timers.add(id); return id;
      },
      interval(callback, delay) {
        if (controller.signal.aborted) return;
        const id = window.setInterval(callback, delay); timers.add(id); return id;
      },
      events(url) {
        const source = new EventSource(url);
        cleanup.push(() => source.close()); return source;
      }
    };
    scopes.push(() => {
      controller.abort();
      timers.forEach(id => { clearTimeout(id); clearInterval(id); });
      cleanup.forEach(callback => callback());
    });
    initialize(page);
  }
  window.PodPilotPage = {register(name, initialize) {
    if (initializers.has(name)) return;
    initializers.set(name, initialize); mount(initialize);
  }};

  const positions = new Map();
  let currentURL = location.href;
  let navigation;
  let sequence = 0;
  const main = () => document.querySelector('.shell > .main');
  function remember() {
    const root = main();
    if (!root) return;
    const elements = [root, ...root.querySelectorAll('*')];
    positions.set(currentURL, {
      window: [scrollX, scrollY],
      scroll: elements.flatMap((node, index) => node.scrollTop || node.scrollLeft ? [[index, node.scrollLeft, node.scrollTop]] : []),
      details: [...root.querySelectorAll('details')].map(node => node.open)
    });
    if (positions.size > 30) positions.delete(positions.keys().next().value);
  }
  function restore(url) {
    const saved = positions.get(url);
    const root = main();
    if (saved) {
      root.querySelectorAll('details').forEach((node, i) => { if (i < saved.details.length) node.open = saved.details[i]; });
      const elements = [root, ...root.querySelectorAll('*')];
      saved.scroll.forEach(([index, x, y]) => elements[index]?.scrollTo(x, y));
    }
    window.scrollTo(...(saved?.window || [0, 0]));
  }
  function updateSidebar(next) {
    const sidebar = document.querySelector('.sidebar');
    const nav = sidebar.querySelector('.nav-list');
    const nextNav = next.querySelector('.nav-list');
    const offsets = [sidebar.scrollLeft, sidebar.scrollTop, nav?.scrollLeft, nav?.scrollTop];
    if (nav && nextNav) {
      nav.replaceChildren(...nextNav.childNodes);
      nextNav.replaceWith(nav);
    }
    sidebar.replaceChildren(...next.childNodes);
    sidebar.scrollTo(offsets[0], offsets[1]);
    nav?.scrollTo(offsets[2], offsets[3]);
  }
  async function navigate(url, historyNavigation = false) {
    const ticket = ++sequence;
    navigation?.abort();
    navigation = new AbortController();
    remember();
    main()?.setAttribute('aria-busy', 'true');
    try {
      const response = await fetch(url, {signal: navigation.signal, credentials: 'same-origin', headers: {'X-PodPilot-Navigation': '1'}});
      const target = new URL(response.url);
      if (!response.ok || target.origin !== location.origin || !response.headers.get('content-type')?.includes('text/html')) throw new Error('Full navigation required');
      const next = new DOMParser().parseFromString(await response.text(), 'text/html');
      if (ticket !== sequence) return;
      const nextMain = next.querySelector('.shell > .main');
      const nextSidebar = next.querySelector('.sidebar');
      if (!nextMain || !nextSidebar || target.pathname.startsWith('/session/')) throw new Error('Full navigation required');
      // Only initialize application-owned scripts; never execute response markup as code.
      scopes.forEach(dispose => dispose()); scopes = [];
      document.body.className = next.body.className;
      document.title = next.title;
      const csrf = document.querySelector('meta[name="podpilot-csrf"]');
      if (csrf) csrf.content = next.querySelector('meta[name="podpilot-csrf"]')?.content || '';
      nextMain.querySelectorAll('script').forEach(script => script.remove());
      main().replaceWith(nextMain);
      updateSidebar(nextSidebar);
      if (!historyNavigation) history.pushState(null, '', target.href);
      else if (target.href !== location.href) history.replaceState(null, '', target.href);
      currentURL = target.href;
      initializers.forEach(initialize => mount(initialize));
      restore(currentURL);
      const heading = main().querySelector('h1, h2');
      if (heading) { heading.setAttribute('tabindex', '-1'); heading.focus({preventScroll: true}); }
    } catch (error) {
      if (error.name !== 'AbortError' && ticket === sequence) location.assign(url);
    } finally {
      if (ticket === sequence) main()?.removeAttribute('aria-busy');
    }
  }
  window.PodPilotPage.navigate = navigate;
  document.addEventListener('click', event => {
    const link = event.target.closest?.('.sidebar a[href]');
    if (!link || event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || link.target || link.hasAttribute('download')) return;
    const url = new URL(link.href);
    if (url.origin !== location.origin || url.pathname.startsWith('/session/') || url.hash) return;
    event.preventDefault();
    if (main()?.querySelector('form[data-navigation-dirty="true"]') && !window.confirm('Leave this page and discard unsaved changes?')) return;
    void navigate(url.href);
  });
  document.addEventListener('input', event => {
    const form = event.target.closest?.('.main form');
    if (form) form.dataset.navigationDirty = 'true';
  });
  window.addEventListener('popstate', () => { void navigate(location.href, true); });
  window.addEventListener('pagehide', () => { navigation?.abort(); scopes.forEach(dispose => dispose()); });
  history.scrollRestoration = 'manual';
})();

(() => {
  const feedback = document.getElementById('incident-feedback');
  async function post(url, payload) {
    const response = await fetch(url, {method: 'POST', headers: {'Content-Type': 'application/json',
      'X-PodPilot-CSRF': document.querySelector('meta[name="podpilot-csrf"]')?.content || ''},
      body: JSON.stringify(payload || {})});
    const result = await response.json();
    if (!response.ok) throw new Error(typeof result.detail === 'string' ? result.detail : 'Request failed.');
    return result;
  }
  document.querySelectorAll('[data-incident-post]').forEach(button => button.addEventListener('click', async () => {
    button.disabled = true;
    try {
      const result = await post(button.dataset.incidentPost);
      if (result.url) { window.location.assign(result.url); return; }
      feedback.textContent = result.checks ? result.checks.join(' · ') : 'Investigation queued. Refresh to see progress.';
    } catch (error) { feedback.textContent = error.message; }
    finally { button.disabled = false; }
  }));

  const tabsRoot = document.querySelector('[data-incident-tabs]');
  if (tabsRoot) {
    const tabs = Array.from(tabsRoot.querySelectorAll('[data-incident-tab]'));
    const panels = Array.from(tabsRoot.querySelectorAll('[data-incident-tab-panel]'));
    function activate(panelId, updateHash = false) {
      const selected = tabs.find(tab => tab.dataset.incidentTab === panelId);
      if (!selected) return;
      tabs.forEach(tab => {
        const active = tab === selected;
        tab.setAttribute('aria-selected', String(active));
        tab.tabIndex = active ? 0 : -1;
      });
      panels.forEach(panel => { panel.hidden = panel.id !== panelId; });
      if (updateHash) history.replaceState(null, '', '#' + panelId);
    }
    tabs.forEach((tab, index) => {
      tab.addEventListener('click', () => activate(tab.dataset.incidentTab, true));
      tab.addEventListener('keydown', event => {
        if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
        event.preventDefault();
        let next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 :
          (index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
        tabs[next].focus(); activate(tabs[next].dataset.incidentTab, true);
      });
    });
    function revealEvidence(target, updateHash = true) {
      if (!target) return;
      const panel = target.closest('[data-incident-tab-panel]');
      if (panel) activate(panel.id, false);
      target.open = true;
      if (updateHash) history.replaceState(null, '', '#' + target.id);
      requestAnimationFrame(() => {
        target.scrollIntoView({behavior: 'smooth', block: 'center'});
        target.classList.add('evidence-highlight');
        window.setTimeout(() => target.classList.remove('evidence-highlight'), 1800);
      });
    }
    tabsRoot.querySelectorAll('[data-evidence-link]').forEach(link => link.addEventListener('click', event => {
      event.preventDefault();
      revealEvidence(document.getElementById(link.hash.slice(1)));
    }));
    const initialTarget = location.hash ? document.getElementById(location.hash.slice(1)) : null;
    if (initialTarget?.matches('[data-incident-tab-panel]')) activate(initialTarget.id, false);
    else if (initialTarget?.matches('details')) revealEvidence(initialTarget, false);
  }

  let incidentBoard = document.querySelector('[data-incident-dashboard]');
  if (incidentBoard) {
    let timer;
    let interactionUntil = 0;
    document.addEventListener('pointerdown', event => {
      if (event.target.closest?.('[data-incident-dashboard]')) {
        interactionUntil = Date.now() + 1500;
      }
    }, true);
    function scheduleActivityRefresh() {
      const delay = incidentBoard.dataset.activeIncidents === '0' ? 12000 : 4000;
      timer = window.setTimeout(refreshActivity, delay);
    }
    function openIds(root, attribute) {
      return new Set(Array.from(root.querySelectorAll(`details[${attribute}][open]`))
        .map(item => item.getAttribute(attribute)));
    }
    function restoreOpen(root, attribute, values) {
      root.querySelectorAll(`details[${attribute}]`).forEach(item => {
        item.open = values.has(item.getAttribute(attribute));
      });
    }
    async function refreshActivity() {
      if (document.hidden || Date.now() < interactionUntil) {
        scheduleActivityRefresh();
        return;
      }
      const expandedIncidents = openIds(incidentBoard, 'data-incident-activity-id');
      const expandedSpecialists = openIds(incidentBoard, 'data-specialist-activity-id');
      try {
        const response = await fetch(window.location.href, {
          headers: {'X-PodPilot-Activity-Refresh': '1'}, cache: 'no-store'
        });
        if (!response.ok) throw new Error('Incident activity refresh failed.');
        const documentCopy = new DOMParser().parseFromString(await response.text(), 'text/html');
        const replacement = documentCopy.querySelector('[data-incident-dashboard]');
        if (replacement && Date.now() >= interactionUntil && replacement.innerHTML !== incidentBoard.innerHTML) {
          incidentBoard.replaceWith(replacement);
          incidentBoard = replacement;
          restoreOpen(incidentBoard, 'data-incident-activity-id', expandedIncidents);
          restoreOpen(incidentBoard, 'data-specialist-activity-id', expandedSpecialists);
        }
      } catch (_error) {
        // The visible data remains usable; the next bounded poll retries automatically.
      }
      scheduleActivityRefresh();
    }
    scheduleActivityRefresh();
    window.addEventListener('pagehide', () => window.clearTimeout(timer), {once: true});
  }

  const form = document.getElementById('incident-connection-form');
  if (!form) return;
  function visibility() {
    document.querySelectorAll('[data-connection-kinds]').forEach(section => {
      section.hidden = !section.dataset.connectionKinds.split(' ').includes(form.elements.kind.value);
    });
  }
  form.elements.kind.addEventListener('change', visibility); visibility();
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const data = new FormData(form);
    const lines = name => String(data.get(name) || '').split('\n').map(s => s.trim()).filter(Boolean);
    const button = form.querySelector('[type="submit"]'); button.disabled = true;
    try {
      const result = await post('/api/v1/incident-connections', {
        id: data.get('id') || null, kind: form.elements.kind.value, name: data.get('name'),
        cluster_id: data.get('cluster_id') || null, token: data.get('token'), webhook_token: data.get('webhook_token'),
        enabled: data.has('enabled'), namespace: data.get('namespace'), projects: lines('projects'),
        target_cluster_ids: data.getAll('target_cluster_ids'), destination_names: JSON.parse(data.get('destination_names') || '{}'),
        url: data.get('url'), monitoring_url: data.get('monitoring_url'), api_prefix: data.get('api_prefix'), repositories: lines('repositories'),
        custom_ca_pem: data.get('custom_ca_pem') || null, allowed_alerts: data.getAll('allowed_alerts')
      });
      window.location.assign('/settings/connectors?edit=' + encodeURIComponent(result.id));
    } catch (error) { feedback.textContent = error.message; }
    finally { button.disabled = false; }
  });
})();

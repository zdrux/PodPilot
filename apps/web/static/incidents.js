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

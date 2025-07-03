async function fetchData() {
  const resp = await fetch('/api/v1/live-macs');
  if (!resp.ok) {
    document.getElementById('content').innerText = 'Authentication required.';
    return;
  }
  const data = await resp.json();
  document.getElementById('content').innerText = JSON.stringify(data, null, 2);
}

window.onload = fetchData;

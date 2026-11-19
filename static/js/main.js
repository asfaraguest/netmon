/* ============================================================
   TIKWatch — main.js  (shared across all pages)
   ============================================================ */

// Global 401 session-expiration guard for API fetches
(() => {
  const origFetch = window.fetch;
  window.fetch = function(...args) {
    return origFetch.apply(this, args).then(resp => {
      if (resp.status === 401 && !window.location.pathname.startsWith('/login')) {
        window.location.href = '/login?next=' + encodeURIComponent(window.location.pathname);
      }
      return resp;
    });
  };
})();

// ---- Socket.IO setup ----
const socket = io({ transports: ['polling', 'websocket'] });

socket.on('connect', () => {
  const el = document.getElementById('sb-conn');
  if (el) el.innerHTML = '<i class="bi bi-wifi text-success"></i> Connected';
});
socket.on('disconnect', () => {
  const el = document.getElementById('sb-conn');
  if (el) el.innerHTML = '<i class="bi bi-wifi-off text-danger"></i> Disconnected';
});
socket.on('connect_error', () => {
  const el = document.getElementById('sb-conn');
  if (el) el.innerHTML = '<i class="bi bi-exclamation-triangle text-warning"></i> Reconnecting…';
});

// --- Dispatch init data to page handlers ---
socket.on('init_data', (data) => {
  if (typeof window.onInitData === 'function') window.onInitData(data);
  if (data.stats) updateSidebarStats(data.stats);
});

socket.on('stats_update', (stats) => {
  updateSidebarStats(stats);
  if (typeof window.onStatsUpdate === 'function') window.onStatsUpdate(stats);
});

socket.on('device_status_update', (dev) => {
  if (typeof window.onDeviceStatusUpdate === 'function') window.onDeviceStatusUpdate(dev);
  if (typeof window.onDeviceUpdate       === 'function') window.onDeviceUpdate(dev);
});

socket.on('device_added', (dev) => {
  if (typeof window.onDeviceUpdate === 'function') window.onDeviceUpdate(dev);
});
socket.on('device_updated', (dev) => {
  if (typeof window.onDeviceStatusUpdate === 'function') window.onDeviceStatusUpdate(dev);
  if (typeof window.onDeviceUpdate       === 'function') window.onDeviceUpdate(dev);
});
socket.on('device_deleted', (data) => {
  if (typeof window.onDeviceUpdate === 'function') window.onDeviceUpdate(data);
});

socket.on('new_alert', (alert) => {
  if (typeof window.onNewAlert === 'function') window.onNewAlert(alert);
  showToast(alert.message, alert.severity === 'critical' ? 'danger' : (alert.severity || 'info'), 5000);
});

socket.on('alert_acked', (d) => {
  if (typeof window.onAlertAcked === 'function') window.onAlertAcked(d);
});
socket.on('all_alerts_acked', () => {
  if (typeof window.onAllAlertsAcked === 'function') window.onAllAlertsAcked();
});
socket.on('alert_update', (d) => {
  if (typeof window.onAlertUpdate === 'function') window.onAlertUpdate(d);
});

socket.on('scan_progress', (d) => {
  if (typeof window.onScanProgress === 'function') window.onScanProgress(d);
});
socket.on('scan_complete', (d) => {
  if (typeof window.onScanComplete === 'function') window.onScanComplete(d);
});
socket.on('scan_started', (d) => {
  if (typeof window.onScanStarted === 'function') window.onScanStarted(d);
});
socket.on('scan_error', (d) => {
  showToast('Scan error: ' + d.error, 'danger');
  if (typeof window.onScanError === 'function') window.onScanError(d);
});
socket.on('device_found', (d) => {
  if (typeof window.onDeviceFound === 'function') window.onDeviceFound(d);
});
socket.on('unifi_sync_complete', (d) => {
  if (typeof window.onUnifiSync === 'function') window.onUnifiSync(d);
});

// ---- Sidebar stats ----
function updateSidebarStats(s) {
  if (!s) return;
  setEl('sb-up',   s.up      ?? '—');
  setEl('sb-down', s.down    ?? '—');
  setEl('sb-warn', s.warning ?? '—');
  setEl('sb-unk',  s.unknown ?? '—');
}

// ---- Clock ----
function updateClock() {
  const timeEl = document.getElementById('sb-time');
  const dateEl = document.getElementById('sb-date');
  const now = new Date();
  if (timeEl) timeEl.textContent = now.toLocaleTimeString();
  if (dateEl) {
    dateEl.textContent = now.toLocaleDateString(undefined, { 
      weekday: 'short', 
      day: 'numeric', 
      month: 'short', 
      year: 'numeric' 
    });
  }
}
setInterval(updateClock, 1000);
updateClock();

// ============================================================
// DOM helpers
// ============================================================
function setEl(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}
function esc(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatBandwidth(bps) {
  if (bps === null || bps === undefined || isNaN(bps) || bps === '') return '—';
  const val = parseFloat(bps);
  if (val === 0) return '0 bps';
  const commaFormatted = Math.round(val).toLocaleString('id-ID');
  if (val >= 1000000000) {
    const formattedVal = (val / 1000000000).toLocaleString('id-ID', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
    return `${formattedVal} Gbps (${commaFormatted} bps)`;
  }
  if (val >= 1000000) {
    const formattedVal = (val / 1000000).toLocaleString('id-ID', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
    return `${formattedVal} Mbps (${commaFormatted} bps)`;
  }
  if (val >= 1000) {
    const formattedVal = (val / 1000).toLocaleString('id-ID', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
    return `${formattedVal} Kbps (${commaFormatted} bps)`;
  }
  return `${Math.round(val).toLocaleString('id-ID')} bps`;
}

function formatPercent(val) {
  if (val === null || val === undefined || isNaN(val) || val === '') return '—';
  return `${parseFloat(val).toLocaleString('id-ID', { minimumFractionDigits: 1, maximumFractionDigits: 1 })}%`;
}

function formatTemp(val) {
  if (val === null || val === undefined || isNaN(val) || val === '') return '—';
  return `${parseFloat(val).toLocaleString('id-ID', { minimumFractionDigits: 1, maximumFractionDigits: 1 })}°C`;
}

function relTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts.replace ? ts.replace(' ', 'T') : ts);
  const diff = (Date.now() - d.getTime()) / 1000;
  if (isNaN(diff)) return ts;
  if (diff < 5)    return 'just now';
  if (diff < 60)   return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400)return `${Math.floor(diff/3600)}h ago`;
  return `${Math.floor(diff/86400)}d ago`;
}

function statusBadge(status) {
  const map = {
    up:      ['up',      'check-circle-fill', 'Online'],
    down:    ['down',    'x-circle-fill',     'Offline'],
    warning: ['warning', 'exclamation-circle-fill', 'Warning'],
    unknown: ['unknown', 'question-circle-fill', 'Unknown'],
  };
  const [cls, icon, label] = map[status] || map.unknown;
  return `<span class="status-dot ${cls}">
    <i class="bi bi-${icon}"></i>${label}
  </span>`;
}

function iconClass(type) {
  const map = {
    router:       'diagram-3-fill',
    switch:       'hdd-rack-fill',
    server:       'server-fill',
    access_point: 'wifi',
    firewall:     'shield-fill',
    printer:      'printer-fill',
    camera:       'camera-video-fill',
    ups:          'battery-charging',
    unifi:        'diagram-2-fill',
    unknown:      'hdd-fill',
    device:       'hdd-fill',
  };
  return map[type] || 'hdd-fill';
}

// ============================================================
// Toast notifications
// ============================================================
function showToast(msg, type = 'info', duration = 3500) {
  const stack = document.getElementById('toast-stack');
  if (!stack) return;
  const id  = 'toast-' + Date.now();
  const div = document.createElement('div');
  div.className = `nm-toast ${type}`;
  div.id = id;
  const iconMap = { success:'check-circle-fill', danger:'x-circle-fill', warning:'exclamation-triangle-fill', info:'info-circle-fill' };
  div.innerHTML = `<i class="bi bi-${iconMap[type]||'info-circle-fill'}"></i><span>${esc(msg)}</span>`;
  stack.appendChild(div);
  setTimeout(() => { div.style.opacity = '0'; div.style.transition = 'opacity 0.4s'; setTimeout(() => div.remove(), 400); }, duration);
}

// ============================================================
// Alert banner
// ============================================================
function showBanner(msg) {
  const el = document.getElementById('alert-banner');
  const tx = document.getElementById('alert-banner-text');
  if (!el || !tx) return;
  tx.textContent = msg;
  el.classList.remove('d-none');
}
function dismissBanner() {
  const el = document.getElementById('alert-banner');
  if (el) el.classList.add('d-none');
}

// ============================================================
// Global Device Details Real-time Polling & Charting
// ============================================================
let detailModal;
let detailPollInterval = null;
let activeDetailDeviceId = null;
let activeDetailDeviceType = null;
let trafficChartInstance = null;
let latencyChartInstance = null;
let interfaceTrafficData = {};
let chartLabels = [];
let chartRxData = [];
let chartTxData = [];

document.addEventListener('DOMContentLoaded', () => {
  const modalEl = document.getElementById('detailModal');
  if (modalEl) {
    detailModal = new bootstrap.Modal(modalEl);
    modalEl.addEventListener('hidden.bs.modal', () => {
      closeDetailModal();
    });
  }
});

function openDeviceDetail(id) {
  // Reset tabs to default (Monitoring)
  const monTab = document.getElementById('det-tab-monitor');
  if (monTab) {
    const tabTrigger = new bootstrap.Tab(monTab);
    tabTrigger.show();
  }

  activeDetailDeviceId = id;
  const targetId = id; // Guard against race conditions
  renderStateTimeline(id);
  interfaceTrafficData = {};
  chartLabels = [];
  chartRxData = [];
  chartTxData = [];
  
  // UI-BUG-10: Reset interface and clients containers to standard default immediately
  const rtHeader = document.querySelector('#detailModal h6.m-0');
  if (rtHeader) {
    rtHeader.innerHTML = '<i class="bi bi-activity me-2 text-accent"></i>Real-time Traffic';
  }
  const legIn = document.getElementById('det-traffic-in');
  const legOut = document.getElementById('det-traffic-out');
  const legInWrapper = legIn ? legIn.closest('div') : null;
  const legOutWrapper = legOut ? legOut.closest('div') : null;
  if (legInWrapper) {
    const labelSpan = legInWrapper.querySelector('.text-xs');
    if (labelSpan && labelSpan.firstChild) labelSpan.firstChild.textContent = 'Inbound: ';
  }
  if (legIn) legIn.textContent = '0 bps';
  if (legOut) legOut.textContent = '0 bps';
  if (legOutWrapper) legOutWrapper.style.display = 'block';

  const selectWrapper = document.getElementById('det-iface-select-wrapper');
  if (selectWrapper) selectWrapper.style.removeProperty('display');
  const interfacesCard = document.getElementById('det-interfaces-card');
  if (interfacesCard) {
    interfacesCard.style.removeProperty('display');
    const cardTitle = interfacesCard.querySelector('h6');
    if (cardTitle) {
      cardTitle.innerHTML = '<i class="bi bi-ethernet me-2 text-accent"></i>Interface Status';
    }
  }

  const select = document.getElementById('det-iface-select');
  if (select) select.innerHTML = '<option value="">Loading ports…</option>';
  
  const cpuBar = document.getElementById('det-cpu-bar');
  if (cpuBar) cpuBar.style.width = '0%';
  const cpuVal = document.getElementById('det-cpu-val');
  if (cpuVal) cpuVal.textContent = '—';
  
  const memBar = document.getElementById('det-mem-bar');
  if (memBar) memBar.style.width = '0%';
  const memVal = document.getElementById('det-mem-val');
  if (memVal) memVal.textContent = '—';
  
  const tempBar = document.getElementById('det-temp-bar');
  if (tempBar) tempBar.style.width = '0%';
  const tempVal = document.getElementById('det-temp-val');
  if (tempVal) tempVal.textContent = '—';
  
  const tbody = document.getElementById('det-interfaces-tbody');
  if (tbody) tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-4"><i class="bi bi-arrow-repeat spin me-1"></i>Loading interface data…</td></tr>';
  
  // UI-BUG-02: Safely destroy existing charts before opening
  if (trafficChartInstance) {
    trafficChartInstance.destroy();
    trafficChartInstance = null;
  }
  const chartCanvas = document.getElementById('trafficChart');
  if (chartCanvas) {
    const existingTraffic = Chart.getChart(chartCanvas);
    if (existingTraffic) existingTraffic.destroy();
  }

  if (latencyChartInstance) {
    latencyChartInstance.destroy();
    latencyChartInstance = null;
  }
  const latCanvas = document.getElementById('latencyChart');
  if (latCanvas) {
    const existingLat = Chart.getChart(latCanvas);
    if (existingLat) existingLat.destroy();
  }

  const startPolling = () => {
    initChart();
    if (detailModal) detailModal.show();
    fetchRealtimeStats();
    if (detailPollInterval) clearInterval(detailPollInterval);
    detailPollInterval = setInterval(fetchRealtimeStats, 3000);
  };

  // Try to find the device locally first
  let dev = null;
  if (typeof allDevices !== 'undefined' && Array.isArray(allDevices)) {
    dev = allDevices.find(x => x.id === id);
  }

  if (dev) {
    activeDetailDeviceType = dev.type;
    populateBasicFields(dev);
    startPolling();
  } else {
    // Fetch device info
    fetch(`/api/devices/${id}`)
      .then(r => r.json())
      .then(data => {
        // UI-BUG-03: Guard against race conditions when switching devices
        if (activeDetailDeviceId !== targetId) return;
        activeDetailDeviceType = data.type;
        populateBasicFields(data);
        startPolling();
      })
      .catch(err => console.error("Error loading device metadata:", err));
  }
}

function populateBasicFields(dev) {
  if (!dev) return;
  const title = document.getElementById('det-title');
  if (title) title.textContent = dev.name;
  
  const statusBadgeEl = document.getElementById('det-status-badge');
  if (statusBadgeEl) {
    statusBadgeEl.className = `badge bg-${dev.status === 'up' ? 'success' : 'danger'}`;
    statusBadgeEl.textContent = dev.status === 'up' ? 'ONLINE' : 'OFFLINE';
  }
  
  const ipEl = document.getElementById('det-ip');
  if (ipEl) ipEl.textContent = dev.ip;
  
  const vendorModelEl = document.getElementById('det-vendor-model');
  if (vendorModelEl) vendorModelEl.textContent = `${dev.vendor || 'Unknown'} ${dev.model || '—'}`;
  
  const sysNameEl = document.getElementById('det-sys-name');
  if (sysNameEl) sysNameEl.textContent = dev.sys_name || '—';
  
  const uptimeEl = document.getElementById('det-uptime');
  if (uptimeEl) uptimeEl.textContent = dev.uptime || '—';
  
  const descEl = document.getElementById('det-desc');
  if (descEl) descEl.textContent = dev.description || '—';
}

function closeDetailModal() {
  if (detailPollInterval) {
    clearInterval(detailPollInterval);
    detailPollInterval = null;
  }

  if (trafficChartInstance) {
    trafficChartInstance.destroy();
    trafficChartInstance = null;
  }
  const chartCanvas = document.getElementById('trafficChart');
  if (chartCanvas) {
    const existingTraffic = Chart.getChart(chartCanvas);
    if (existingTraffic) existingTraffic.destroy();
  }

  if (latencyChartInstance) {
    latencyChartInstance.destroy();
    latencyChartInstance = null;
  }
  const latCanvas = document.getElementById('latencyChart');
  if (latCanvas) {
    const existingLat = Chart.getChart(latCanvas);
    if (existingLat) existingLat.destroy();
  }

  activeDetailDeviceId = null;
}

function initChart() {
  const chartCanvas = document.getElementById('trafficChart');
  if (!chartCanvas) return;
  
  if (trafficChartInstance) {
    trafficChartInstance.destroy();
    trafficChartInstance = null;
  }
  const existingChart = Chart.getChart(chartCanvas);
  if (existingChart) existingChart.destroy();
  
  const ctx = chartCanvas.getContext('2d');
  const now = new Date();
  for (let i = 9; i >= 0; i--) {
    const t = new Date(now.getTime() - i * 3000);
    chartLabels.push(t.toLocaleTimeString());
    chartRxData.push(0);
    chartTxData.push(0);
  }

  const isLight = document.body.classList.contains('light-theme');
  const tickColor = isLight ? '#6e6e73' : '#8b949e';
  const gridColor = isLight ? 'rgba(0, 0, 0, 0.06)' : 'rgba(255, 255, 255, 0.05)';
  
  trafficChartInstance = new Chart(ctx, {
    type: 'line',
    data: {
      labels: chartLabels,
      datasets: [
        {
          label: 'Inbound (Download)',
          data: chartRxData,
          borderColor: '#58a6ff',
          backgroundColor: 'rgba(88, 166, 255, 0.1)',
          fill: true,
          tension: 0.4,
          borderWidth: 2,
          pointRadius: 2
        },
        {
          label: 'Outbound (Upload)',
          data: chartTxData,
          borderColor: '#bc8cff',
          backgroundColor: 'rgba(188, 140, 255, 0.1)',
          fill: true,
          tension: 0.4,
          borderWidth: 2,
          pointRadius: 2
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        x: {
          grid: { display: false },
          ticks: { color: tickColor, font: { size: 10 } }
        },
        y: {
          grid: { color: gridColor },
          ticks: {
            color: tickColor,
            font: { size: 10 },
            callback: function(value) {
              return formatBandwidthSimple(value);
            }
          }
        }
      }
    }
  });
}

function formatBandwidthSimple(bps) {
  if (bps === 0) return '0 bps';
  const val = parseFloat(bps);
  if (val >= 1000000000) return `${(val / 1000000000).toFixed(1)} Gbps`;
  if (val >= 1000000) return `${(val / 1000000).toFixed(1)} Mbps`;
  if (val >= 1000) return `${(val / 1000).toFixed(1)} Kbps`;
  return `${val.toFixed(0)} bps`;
}

function fetchRealtimeStats() {
  if (!activeDetailDeviceId) return;
  const targetId = activeDetailDeviceId;
  
  fetch(`/api/devices/${targetId}/realtime_stats`)
    .then(r => r.json())
    .then(res => {
      if (res.status !== 'success' || activeDetailDeviceId !== targetId) return;
      
      const uptimeEl = document.getElementById('det-uptime');
      if (uptimeEl && res.uptime) uptimeEl.textContent = res.uptime;
      
      const titleEl = document.getElementById('det-title');
      if (titleEl && res.sys_name) titleEl.textContent = res.sys_name;
      
      const descEl = document.getElementById('det-desc');
      if (descEl && res.description) descEl.textContent = res.description;
      
      updateResourceProgress('det-cpu-bar', 'det-cpu-val', res.cpu_usage, '%');
      updateResourceProgress('det-mem-bar', 'det-mem-val', res.memory_usage, '%');
      updateResourceProgress('det-temp-bar', 'det-temp-val', res.temperature, '°C');

      if (res.latency_ms !== null && res.latency_ms !== undefined) {
        const latVal = document.getElementById('det-lat-val');
        if (latVal) latVal.textContent = `${res.latency_ms} ms`;
      }
      if (res.packet_loss !== null && res.packet_loss !== undefined) {
        const lossVal = document.getElementById('det-loss-val');
        if (lossVal) lossVal.textContent = `${res.packet_loss}%`;
        const lossEl = document.getElementById('det-loss-badge');
        if (lossEl) {
          lossEl.className = `badge ms-1 text-xs ${res.packet_loss > 0 ? 'bg-danger text-white' : ''}`;
        }
      }

      const isClientDev = res.client_count !== null && res.client_count !== undefined;
      const rtHeader = document.querySelector('#detailModal h6.m-0');
      if (rtHeader) {
        rtHeader.innerHTML = isClientDev
          ? '<i class="bi bi-people-fill me-2 text-accent"></i>Connected Clients'
          : '<i class="bi bi-activity me-2 text-accent"></i>Real-time Traffic';
      }
      
      const legIn = document.getElementById('det-traffic-in');
      const legOut = document.getElementById('det-traffic-out');
      const legInWrapper = legIn ? legIn.closest('div') : null;
      const legOutWrapper = legOut ? legOut.closest('div') : null;
      
      if (isClientDev) {
        if (legIn) {
          legIn.textContent = `${Math.round(res.client_count)} clients`;
          if (legInWrapper) {
            const labelSpan = legInWrapper.querySelector('.text-xs');
            if (labelSpan) labelSpan.firstChild.textContent = 'Clients: ';
          }
        }
        if (legOutWrapper) legOutWrapper.style.display = 'none';
        
        const selectWrapper = document.getElementById('det-iface-select-wrapper');
        const interfacesCard = document.getElementById('det-interfaces-card');
        const tbody = document.getElementById('det-interfaces-tbody');
        
        if (selectWrapper) selectWrapper.style.setProperty('display', 'none', 'important');
        if (interfacesCard) {
          interfacesCard.style.setProperty('display', 'block', 'important');
          
          // Update title to Connected Clients List
          const cardTitle = interfacesCard.querySelector('h6');
          if (cardTitle) {
            cardTitle.innerHTML = '<i class="bi bi-people-fill me-2 text-accent"></i>Connected Clients List';
          }
          
          // Update headers
          const thead = interfacesCard.querySelector('thead');
          if (thead) {
            thead.innerHTML = `
              <tr>
                <th class="border-0">Client Name</th>
                <th class="border-0">IP Address</th>
                <th class="border-0">Connection</th>
                <th class="border-0">Signal</th>
                <th class="border-0">MAC Address</th>
              </tr>
            `;
          }
          
          // Render clients in tbody
          if (tbody) {
            const clients = res.clients || [];
            if (clients.length === 0) {
              tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-3">No clients connected.</td></tr>';
            } else {
              tbody.innerHTML = clients.map(c => `
                <tr>
                  <td class="fw-500">${esc(c.name)}</td>
                  <td class="mono-sm">${esc(c.ip)}</td>
                  <td><span class="badge bg-secondary text-xs">${esc(c.essid)}</span></td>
                  <td class="mono-sm">${c.signal !== null ? `${c.signal} dBm` : '—'}</td>
                  <td class="mono-sm text-muted">${esc(c.mac)}</td>
                </tr>
              `).join('');
            }
          }
        }
        
        if (trafficChartInstance) {
          const timeStr = new Date().toLocaleTimeString();
          trafficChartInstance.data.datasets[0].label = 'Clients';
          trafficChartInstance.data.datasets[1].hidden = true;
          trafficChartInstance.options.scales.y.ticks.callback = function(val) { return val; };
          
          chartLabels.push(timeStr);
          chartRxData.push(res.client_count);
          chartTxData.push(0);
          
          if (chartLabels.length > 10) {
            chartLabels.shift();
            chartRxData.shift();
            chartTxData.shift();
          }
          trafficChartInstance.update('none');
        }
        return;
      } else {
        if (legOutWrapper) legOutWrapper.style.display = 'block';
        if (legInWrapper) {
          const labelSpan = legInWrapper.querySelector('.text-xs');
          if (labelSpan) labelSpan.firstChild.textContent = 'Inbound: ';
        }
        if (trafficChartInstance) {
          trafficChartInstance.data.datasets[0].label = 'Inbound (Download)';
          trafficChartInstance.data.datasets[1].hidden = false;
          trafficChartInstance.options.scales.y.ticks.callback = function(value) {
            return formatBandwidthSimple(value);
          };
        }
        
        // Restore standard interface headers
        const interfacesCard = document.getElementById('det-interfaces-card');
        if (interfacesCard) {
          const cardTitle = interfacesCard.querySelector('h6');
          if (cardTitle) {
            cardTitle.innerHTML = '<i class="bi bi-ethernet me-2 text-accent"></i>Interface Status';
          }
          const thead = interfacesCard.querySelector('thead');
          if (thead) {
            thead.innerHTML = `
              <tr>
                <th class="border-0">Port Name</th>
                <th class="border-0">Status</th>
                <th class="border-0">Port Speed</th>
                <th class="border-0">Received (Rx)</th>
                <th class="border-0">Transmitted (Tx)</th>
              </tr>
            `;
          }
        }
      }
      
      const interfaces = res.interfaces || [];
      const select = document.getElementById('det-iface-select');
      const tbody = document.getElementById('det-interfaces-tbody');
      const selectWrapper = document.getElementById('det-iface-select-wrapper');
      const interfacesCard = document.getElementById('det-interfaces-card');
      
      const typeLower = String(activeDetailDeviceType || '').toLowerCase();
      const titleText = String(document.getElementById('det-title')?.textContent || '').toLowerCase();
      const modelText = String(document.getElementById('det-vendor-model')?.textContent || '').toLowerCase();
      
      const hasInterfaces = interfaces.length > 0;
      
      const showPortList = (
        hasInterfaces && !new Set(['printer', 'camera', 'ups', 'server']).has(activeDetailDeviceType || '')
      );
      
      // Show interface selector only for routers/switches with multiple ports
      if (selectWrapper) {
        selectWrapper.style.setProperty('display', (showPortList && hasInterfaces) ? 'flex' : 'none', 'important');
      }
      // Show interface table only for routers/switches
      if (interfacesCard) {
        interfacesCard.style.setProperty('display', (showPortList && hasInterfaces) ? 'block' : 'none', 'important');
      }
      
      if (!showPortList || !hasInterfaces) {
        // Non-router/switch or no interfaces: sum all traffic for global chart
        if (hasInterfaces) {
          const globalIface = {
            index: 9999,
            name: 'Global Traffic',
            rx_bytes: interfaces.reduce((sum, item) => sum + (item.rx_bytes || 0), 0),
            tx_bytes: interfaces.reduce((sum, item) => sum + (item.tx_bytes || 0), 0)
          };
          updateChartData(globalIface);
        }
        return;
      }
      
      if (!select || !tbody) return;
      
      if (interfaces.length === 0) {
        select.innerHTML = '<option value="">No interfaces</option>';
        tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-3">No ports found on this device. Make sure SNMP is enabled and working.</td></tr>';
        return;
      }
      
      const prevSelectedIdx = select.value;
      const existingRows = tbody.querySelectorAll('tr[data-index]');
      const isInitialBuild = (existingRows.length !== interfaces.length);
      
      if (isInitialBuild) {
        // Build select options
        let optHtml = '';
        interfaces.forEach(iface => {
          const isSelected = (prevSelectedIdx === String(iface.index)) ? 'selected' : '';
          const statusLabel = iface.status === 'up' ? '🟢' : '🔴';
          optHtml += `<option value="${iface.index}" ${isSelected}>${statusLabel} ${esc(iface.name)}</option>`;
        });
        select.innerHTML = optHtml;
        
        // Build table body
        tbody.innerHTML = interfaces.map(iface => `
          <tr data-index="${iface.index}" onclick="selectInterface(${iface.index})" style="cursor: pointer;" class="${prevSelectedIdx === String(iface.index) ? 'table-active' : ''}">
            <td class="fw-500">${esc(iface.name)}</td>
            <td>${iface.status === 'up' ? '<span class="text-success fw-600">UP</span>' : '<span class="text-danger">DOWN</span>'}</td>
            <td class="mono-sm">${formatBandwidthSimple(iface.speed)}</td>
            <td class="mono-sm text-muted">${(iface.rx_bytes || 0).toLocaleString()} B</td>
            <td class="mono-sm text-muted">${(iface.tx_bytes || 0).toLocaleString()} B</td>
          </tr>
        `).join('');
      } else {
        // Update existing elements inline to prevent layout shifts/scroll resets
        interfaces.forEach(iface => {
          const row = tbody.querySelector(`tr[data-index="${iface.index}"]`);
          if (row) {
            // Update status text
            const statusCell = row.cells[1];
            const statusHtml = iface.status === 'up' ? '<span class="text-success fw-600">UP</span>' : '<span class="text-danger">DOWN</span>';
            if (statusCell.innerHTML !== statusHtml) statusCell.innerHTML = statusHtml;
            
            // Update speed text
            const speedText = formatBandwidthSimple(iface.speed);
            if (row.cells[2].textContent !== speedText) row.cells[2].textContent = speedText;
            
            // Update Rx Bytes text
            const rxText = `${(iface.rx_bytes || 0).toLocaleString()} B`;
            if (row.cells[3].textContent !== rxText) row.cells[3].textContent = rxText;
            
            // Update Tx Bytes text
            const txText = `${(iface.tx_bytes || 0).toLocaleString()} B`;
            if (row.cells[4].textContent !== txText) row.cells[4].textContent = txText;
          }
        });
      }
      
      let activeIdx = parseInt(select.value);
      if (isNaN(activeIdx) && interfaces.length > 0) {
        activeIdx = interfaces[0].index;
        select.value = activeIdx;
      }
      
      const activeIface = interfaces.find(x => x.index === activeIdx);
      if (activeIface) {
        updateChartData(activeIface);
      }
    })
    .catch(err => console.error("Error fetching realtime stats:", err));
}

function updateResourceProgress(barId, valId, val, unit) {
  const bar = document.getElementById(barId);
  const text = document.getElementById(valId);
  if (!bar || !text) return;
  
  if (val !== null && val !== undefined) {
    const fVal = parseFloat(val);
    bar.style.width = `${Math.min(100, Math.max(0, fVal))}%`;
    text.textContent = `${fVal.toFixed(1)}${unit}`;
  } else {
    bar.style.width = '0%';
    text.textContent = '—';
  }
}

function selectInterface(idx) {
  const select = document.getElementById('det-iface-select');
  if (select) {
    select.value = idx;
    onInterfaceChange();
  }
}

function onInterfaceChange() {
  const select = document.getElementById('det-iface-select');
  const tbody = document.getElementById('det-interfaces-tbody');
  if (!select || !tbody) return;
  
  const activeIdx = select.value;
  
  Array.from(tbody.rows).forEach(row => {
    const rowIdx = row.dataset.index;
    if (rowIdx === String(activeIdx)) {
      row.classList.add('table-active');
    } else {
      row.classList.remove('table-active');
    }
  });
  
  // Reset chart rolling datasets for the new interface to avoid draw lines connecting previous metrics
  if (trafficChartInstance) {
    chartRxData.fill(0);
    chartTxData.fill(0);
    trafficChartInstance.update('none');
  }
}

function updateChartData(iface) {
  const now = new Date();
  const timeStr = now.toLocaleTimeString();
  const currentTimestamp = now.getTime();
  
  let rxSpeed = 0;
  let txSpeed = 0;
  
  const ifName = iface.name;
  const history = interfaceTrafficData[ifName];
  
  if (history) {
    const dt = (currentTimestamp - history.time) / 1000.0;
    if (dt >= 1.0) {
      let is64bit = (history.rx > 4294967295 || iface.rx_bytes > 4294967295 ||
                     history.tx > 4294967295 || iface.tx_bytes > 4294967295);
      
      let diffRx = iface.rx_bytes - history.rx;
      let diffTx = iface.tx_bytes - history.tx;
      
      if (diffRx < 0) {
        if (is64bit) {
          diffRx = 0;
        } else {
          if (history.rx > 3000000000) {
            diffRx += Math.pow(2, 32);
          } else {
            diffRx = 0;
          }
        }
      }
      
      if (diffTx < 0) {
        if (is64bit) {
          diffTx = 0;
        } else {
          if (history.tx > 3000000000) {
            diffTx += Math.pow(2, 32);
          } else {
            diffTx = 0;
          }
        }
      }
      
      if (diffRx >= 0 && diffTx >= 0) {
        rxSpeed = (diffRx * 8) / dt;
        txSpeed = (diffTx * 8) / dt;
        
        // Spike protection: ignore values that are physically impossible (e.g. > 100 Gbps)
        if (rxSpeed > 100e9) rxSpeed = 0;
        if (txSpeed > 100e9) txSpeed = 0;
      }
    }
  }
  
  interfaceTrafficData[ifName] = {
    rx: iface.rx_bytes,
    tx: iface.tx_bytes,
    time: currentTimestamp
  };
  
  const txIn = document.getElementById('det-traffic-in');
  if (txIn) txIn.textContent = formatBandwidth(rxSpeed);
  const txOut = document.getElementById('det-traffic-out');
  if (txOut) txOut.textContent = formatBandwidth(txSpeed);
  
  if (trafficChartInstance) {
    chartLabels.push(timeStr);
    chartRxData.push(rxSpeed);
    chartTxData.push(txSpeed);
    
    if (chartLabels.length > 10) {
      chartLabels.shift();
      chartRxData.shift();
      chartTxData.shift();
    }
    
    trafficChartInstance.update('none');
  }
}



// ---- Day/Night (Light/Dark) Theme Toggle ----
document.addEventListener('DOMContentLoaded', () => {
  const themeToggleBtn = document.getElementById('theme-toggle-btn');
  if (!themeToggleBtn) return;

  const toggleIcon = document.getElementById('toggle-icon');
  const toggleText = document.getElementById('toggle-text');
  const themeIndicator = document.getElementById('theme-icon-indicator');

  function updateChartsTheme(isLight) {
    const tickColor = isLight ? '#6e6e73' : '#8b949e';
    const gridColor = isLight ? 'rgba(0, 0, 0, 0.06)' : 'rgba(255, 255, 255, 0.05)';

    // Update all registered Chart.js instances across the entire page (UI-BUG-04)
    if (typeof Chart !== 'undefined' && Chart.instances) {
      Object.values(Chart.instances).forEach(chart => {
        try {
          if (chart && chart.options && chart.options.scales) {
            if (chart.options.scales.x && chart.options.scales.x.ticks) {
              chart.options.scales.x.ticks.color = tickColor;
            }
            if (chart.options.scales.y) {
              if (chart.options.scales.y.ticks) chart.options.scales.y.ticks.color = tickColor;
              if (chart.options.scales.y.grid) chart.options.scales.y.grid.color = gridColor;
            }
            if (chart.options.plugins && chart.options.plugins.tooltip) {
              chart.options.plugins.tooltip.backgroundColor = isLight ? 'rgba(255, 255, 255, 0.95)' : 'rgba(20, 20, 20, 0.95)';
              chart.options.plugins.tooltip.titleColor = isLight ? '#1d1d1f' : '#f5f5f7';
              chart.options.plugins.tooltip.bodyColor = isLight ? '#4b5563' : '#8b949e';
              chart.options.plugins.tooltip.borderColor = isLight ? '#e4e4e7' : '#30363d';
            }
            chart.update('none');
          }
        } catch (e) {
          // ignore charts that cannot be dynamically updated
        }
      });
    }
  }

  function updateThemeUI(isLight) {
    if (isLight) {
      document.body.classList.add('light-theme');
      if (toggleIcon) {
        toggleIcon.className = 'bi bi-moon-stars-fill';
      }
      if (toggleText) {
        toggleText.textContent = 'Dark';
      }
      if (themeIndicator) {
        themeIndicator.className = 'bi bi-sun-fill text-warning';
      }
    } else {
      document.body.classList.remove('light-theme');
      if (toggleIcon) {
        toggleIcon.className = 'bi bi-brightness-high-fill';
      }
      if (toggleText) {
        toggleText.textContent = 'Light';
      }
      if (themeIndicator) {
        themeIndicator.className = 'bi bi-moon-stars-fill';
      }
    }
    updateChartsTheme(isLight);
  }

  // Initial check based on class applied by fast-path script in body
  const isLight = document.body.classList.contains('light-theme');
  updateThemeUI(isLight);

  themeToggleBtn.addEventListener('click', () => {
    const isCurrentlyLight = document.body.classList.contains('light-theme');
    const newLight = !isCurrentlyLight;
    localStorage.setItem('theme', newLight ? 'light' : 'dark');
    updateThemeUI(newLight);
  });

  // UI-BUG-07: Auto close mobile sidebar when navigating on mobile
  document.querySelectorAll('.sidebar-nav .nav-item').forEach(item => {
    item.addEventListener('click', () => {
      if (window.innerWidth < 768) {
        window.toggleMobileSidebar(true);
      }
    });
  });
});

// UI-BUG-07: Centralized mobile sidebar toggle helper
window.toggleMobileSidebar = function(forceClose = false) {
  const sb = document.getElementById('sidebar');
  const overlay = document.getElementById('sidebar-overlay');
  if (!sb || !overlay) return;
  
  if (forceClose) {
    sb.classList.remove('show');
    overlay.classList.remove('show');
  } else {
    const isShowing = sb.classList.contains('show');
    if (isShowing) {
      sb.classList.remove('show');
      overlay.classList.remove('show');
    } else {
      sb.classList.add('show');
      overlay.classList.add('show');
    }
  }
};

window.showConfirm = function(title, message, onConfirm) {
  const overlay = document.createElement('div');
  overlay.className = 'custom-confirm-overlay';
  
  const dialog = document.createElement('div');
  dialog.className = 'custom-confirm-dialog';
  
  const icon = document.createElement('div');
  icon.className = 'custom-confirm-icon';
  icon.innerHTML = '<i class="bi bi-exclamation-triangle-fill"></i>';
  
  const titleEl = document.createElement('h3');
  titleEl.className = 'custom-confirm-title';
  titleEl.textContent = title;
  
  const messageEl = document.createElement('p');
  messageEl.className = 'custom-confirm-message';
  messageEl.textContent = message;
  
  const buttons = document.createElement('div');
  buttons.className = 'custom-confirm-buttons';
  
  const btnCancel = document.createElement('button');
  btnCancel.className = 'btn-nm btn-confirm-cancel';
  btnCancel.textContent = 'Cancel';
  btnCancel.onclick = () => {
    overlay.classList.remove('active');
    setTimeout(() => overlay.remove(), 200);
  };
  
  const btnConfirm = document.createElement('button');
  btnConfirm.className = 'btn-nm btn-confirm-danger';
  btnConfirm.textContent = 'Confirm';
  btnConfirm.onclick = () => {
    overlay.classList.remove('active');
    setTimeout(() => {
      overlay.remove();
      if (typeof onConfirm === 'function') onConfirm();
    }, 200);
  };
  
  buttons.appendChild(btnCancel);
  buttons.appendChild(btnConfirm);
  
  dialog.appendChild(icon);
  dialog.appendChild(titleEl);
  dialog.appendChild(messageEl);
  dialog.appendChild(buttons);
  overlay.appendChild(dialog);
  
  document.body.appendChild(overlay);
  
  setTimeout(() => {
    overlay.classList.add('active');
  }, 10);
};

window.showLoading = function(message = 'Processing...') {
  let overlay = document.getElementById('global-loading-overlay');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id = 'global-loading-overlay';
    overlay.className = 'custom-loading-overlay';
    
    const dialog = document.createElement('div');
    dialog.className = 'custom-loading-dialog';
    
    const spinner = document.createElement('div');
    spinner.className = 'custom-spinner';
    
    const messageEl = document.createElement('div');
    messageEl.id = 'global-loading-message';
    messageEl.className = 'custom-loading-message';
    
    dialog.appendChild(spinner);
    dialog.appendChild(messageEl);
    overlay.appendChild(dialog);
    document.body.appendChild(overlay);
  }
  
  const msgEl = document.getElementById('global-loading-message');
  if (msgEl) msgEl.textContent = message;
  
  setTimeout(() => {
    overlay.classList.add('active');
  }, 10);
};

window.hideLoading = function() {
  const overlay = document.getElementById('global-loading-overlay');
  if (overlay) {
    overlay.classList.remove('active');
  }
};

window.loadBlackBoxForensics = function() {
  if (!activeDetailDeviceId) return;
  
  const emptyEl = document.getElementById('det-bb-empty');
  const resultEl = document.getElementById('det-bb-result');
  const historyTbody = document.getElementById('det-bb-history-tbody');
  
  if (historyTbody) {
    historyTbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-3"><i class="bi bi-arrow-repeat spin me-1"></i>Loading forensics data…</td></tr>';
  }
  
  fetch(`/api/devices/${activeDetailDeviceId}/downtime_forensics`)
    .then(r => r.json())
    .then(res => {
      if (res.status !== 'success' || !activeDetailDeviceId) return;
      
      // Update Latest Analysis Box
      if (!res.analysis) {
        if (emptyEl) emptyEl.style.display = 'block';
        if (resultEl) resultEl.style.display = 'none';
      } else {
        if (emptyEl) emptyEl.style.display = 'none';
        if (resultEl) resultEl.style.display = 'block';
        
        const rootCauseEl = document.getElementById('det-bb-root-cause');
        const confidenceEl = document.getElementById('det-bb-confidence');
        const narrationEl = document.getElementById('det-bb-narration');
        const alertBoxEl = document.getElementById('det-bb-alert-box');
        
        if (rootCauseEl) rootCauseEl.textContent = res.analysis.root_cause || 'Koneksi Terputus';
        if (confidenceEl) confidenceEl.textContent = `${res.analysis.confidence || 70}%`;
        if (narrationEl) narrationEl.textContent = res.analysis.narration || '';
        
        // Dynamic border color based on root cause
        if (alertBoxEl) {
          const rc = (res.analysis.root_cause || '').toLowerCase();
          if (rc.includes('mati lampu') || rc.includes('power loss')) {
            alertBoxEl.style.borderColor = '#ffc107'; // yellow
            alertBoxEl.style.background = 'rgba(255, 193, 7, 0.03)';
          } else if (rc.includes('overload') || rc.includes('crash')) {
            alertBoxEl.style.borderColor = '#dc3545'; // red
            alertBoxEl.style.background = 'rgba(220, 53, 69, 0.03)';
          } else if (rc.includes('kabel') || rc.includes('link')) {
             alertBoxEl.style.borderColor = '#0d6efd'; // blue
             alertBoxEl.style.background = 'rgba(13, 110, 253, 0.03)';
          } else if (rc.includes('snmp')) {
             alertBoxEl.style.borderColor = '#bc8cff'; // purple
             alertBoxEl.style.background = 'rgba(188, 140, 255, 0.03)';
          } else {
            alertBoxEl.style.borderColor = '#17a2b8'; // cyan
            alertBoxEl.style.background = 'rgba(23, 162, 184, 0.03)';
          }
        }
      }
      
      // Update History Table
      if (historyTbody) {
        const history = res.history || [];
        if (history.length === 0) {
          historyTbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-3">Tidak ada riwayat downtime.</td></tr>';
        } else {
          historyTbody.innerHTML = history.map(item => {
            const isOngoing = (item.up_time === null || item.up_time === undefined || item.up_time === '—');
            const dur = isOngoing
              ? `<span class="text-warning fw-600">${formatDowntimeDuration(item.duration_sec)} (Ongoing)</span>`
              : formatDowntimeDuration(item.duration_sec);
            const reboot = isOngoing
              ? '<span class="text-muted text-xs">—</span>'
              : (item.reboot_detected
                ? '<span class="badge bg-danger text-xs px-2 py-0.5">YA</span>'
                : '<span class="badge bg-secondary text-xs px-2 py-0.5">TIDAK</span>');
              
            return `
              <tr>
                <td class="mono-sm text-secondary">${fmtDowntimeTime(item.down_time)}</td>
                <td class="mono-sm text-secondary">${isOngoing ? (item.snmp_pattern === 'snmp_failed' ? '<span class="badge" style="background:#bc8cff;color:#000;">SNMP FAILED</span>' : '<span class="badge bg-danger">OFFLINE</span>') : fmtDowntimeTime(item.up_time)}</td>
                <td class="mono-sm text-secondary">${dur}</td>
                <td>${reboot}</td>
                <td class="text-xs fw-500 text-white">${esc(item.justification)}</td>
              </tr>
            `;
          }).join('');
        }
      }
    })
    .catch(err => {
      console.error("Error loading downtime forensics:", err);
      if (historyTbody) {
        historyTbody.innerHTML = '<tr><td colspan="5" class="text-center text-danger py-3">Gagal mengambil data.</td></tr>';
      }
    });
};

function formatDowntimeDuration(sec) {
  if (!sec || sec <= 0) return '0s';
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  if (m < 60) return `${m}m ${s}s`;
  const h = Math.floor(m / 60);
  const remM = m % 60;
  return `${h}j ${remM}m`;
}

function fmtDowntimeTime(ts) {
  if (!ts || ts === '—') return '—';
  try {
    const d = new Date(ts.replace(' ', 'T'));
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
  } catch(e) {
    return ts;
  }
}

// ============================================================
// State Timeline & Ping Latency (Grafana-style observability)
// ============================================================

window.renderStateTimeline = function(deviceId) {
  const container = document.getElementById('det-state-timeline');
  if (!container) return;
  container.innerHTML = '<div class="text-muted text-xs p-1">Loading timeline…</div>';
  
  fetch(`/api/devices/${deviceId}/timeline?hours=24`)
    .then(r => r.json())
    .then(data => {
      container.innerHTML = '';
      if (!Array.isArray(data) || data.length === 0) {
        container.innerHTML = '<div class="text-muted text-xs p-1">No timeline data</div>';
        return;
      }
      data.forEach(item => {
        const block = document.createElement('div');
        block.className = `state-block st-${item.status || 'up'}`;
        block.title = item.tooltip || `${item.time}: ${item.status}`;
        container.appendChild(block);
      });
    })
    .catch(err => {
      console.error("Error rendering timeline:", err);
      container.innerHTML = '<div class="text-muted text-xs p-1">Timeline unavailable</div>';
    });
};

window.loadLatencyChart = function() {
  if (!activeDetailDeviceId) return;
  const canvas = document.getElementById('latencyChart');
  if (!canvas) return;
  const targetId = activeDetailDeviceId;

  // Destroy previous instance immediately if existing
  if (latencyChartInstance) {
    latencyChartInstance.destroy();
    latencyChartInstance = null;
  }
  const existingChart = Chart.getChart(canvas);
  if (existingChart) existingChart.destroy();

  fetch(`/api/devices/${targetId}/latency?hours=24`)
    .then(r => r.json())
    .then(points => {
      if (activeDetailDeviceId !== targetId) return;
      if (latencyChartInstance) {
        latencyChartInstance.destroy();
        latencyChartInstance = null;
      }
      const existingAfterFetch = Chart.getChart(canvas);
      if (existingAfterFetch) existingAfterFetch.destroy();
      
      const isLight = document.body.classList.contains('light-theme');
      const tickColor = isLight ? '#6e6e73' : '#8b949e';
      const gridColor = isLight ? 'rgba(0, 0, 0, 0.06)' : 'rgba(255, 255, 255, 0.05)';
      
      let labels = [];
      let data = [];
      if (Array.isArray(points) && points.length > 0) {
        labels = points.map(p => {
          const d = new Date(p.ts);
          return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        });
        data = points.map(p => p.latency_ms);
        
        const sum = data.reduce((a, b) => a + b, 0);
        const avg = (sum / data.length).toFixed(1);
        const avgEl = document.getElementById('det-lat-avg-badge');
        if (avgEl) avgEl.textContent = `Avg: ${avg} ms`;
      } else {
        labels = ['Sekarang'];
        data = [0];
      }

      const ctx = canvas.getContext('2d');
      latencyChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
          labels: labels,
          datasets: [{
            label: 'Latency (ms)',
            data: data,
            borderColor: '#ff9500',
            backgroundColor: 'rgba(255, 149, 0, 0.12)',
            fill: true,
            tension: 0.35,
            borderWidth: 2,
            pointRadius: data.length > 50 ? 0 : 2
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false },
            tooltip: {
              callbacks: {
                label: function(c) { return `${c.parsed.y} ms`; }
              }
            }
          },
          scales: {
            x: {
              grid: { display: false },
              ticks: { color: tickColor, font: { size: 10 } }
            },
            y: {
              grid: { color: gridColor },
              ticks: {
                color: tickColor,
                font: { size: 10 },
                callback: function(v) { return `${v} ms`; }
              },
              beginAtZero: true
            }
          }
        }
      });
    })
    .catch(err => console.error("Error loading latency chart:", err));
};

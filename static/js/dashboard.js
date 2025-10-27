// dados fictícios para protótipo do dashboard
document.addEventListener('DOMContentLoaded', function () {
  const dashboardContainer = document.querySelector('.dashboard-frame');
  if (!dashboardContainer) {
    return;
  }

  const setTextContentIfPresent = (id, value) => {
    const element = document.getElementById(id);
    if (element) {
      element.textContent = value;
    }
  };

  // populate KPIs (fictitious)
  setTextContentIfPresent('kpi-total', 342);
  setTextContentIfPresent('kpi-high', 78);
  setTextContentIfPresent('kpi-medium', 190);
  setTextContentIfPresent('kpi-low', 74);

  // Bar chart - vulnerabilities by severity (fictitious)
  const sevCtx = document.getElementById('sevBar');
  if (sevCtx) {
    new Chart(sevCtx.getContext('2d'), {
      type: 'bar',
      data: {
        labels: ['Critical','High','Medium','Low'],
        datasets:[{
          label:'Count',
          data:[12,78,190,74],
          backgroundColor:['#ef4444','#f97316','#8b5cf6','#06b6d4']
        }]
      },
      options:{
        plugins:{ legend:{ display:false }},
        scales:{ x:{ ticks:{ color:'#9ca3af' } }, y:{ ticks:{ color:'#9ca3af' }, grid:{ color:'rgba(255,255,255,0.02)' } } }
      }
    });
  }

  // Donut chart - by type
  const typeCtx = document.getElementById('typeDonut');
  if (typeCtx) {
    new Chart(typeCtx.getContext('2d'), {
      type: 'doughnut',
      data: {
        labels: ['Web','Network','Database','Application'],
        datasets:[{ data:[40,25,20,15], backgroundColor:['#f97316','#ef4444','#3b82f6','#06b6d4'] }]
      },
      options:{ plugins:{ legend:{ position:'right', labels:{ color:'#9ca3af' } } } }
    });
  }

  // trend line (fictitious)
  const trendCtx = document.getElementById('trendLine');
  if (trendCtx) {
    new Chart(trendCtx.getContext('2d'), {
      type:'line',
      data:{
        labels:[1,2,3,4,5,6,7],
        datasets:[{ label:'Vuln delta', data:[-10,20,5,60,20,80,110], borderColor:'#60a5fa', backgroundColor:'rgba(96,165,250,0.08)', fill:true, tension:0.3 }]
      },
      options:{ plugins:{ legend:{ display:false } }, scales:{ x:{ ticks:{ color:'#9ca3af' } }, y:{ ticks:{ color:'#9ca3af' } } } }
    });
  }

  // progress (line)
  const ctxP = document.getElementById('progressChart');
  if (ctxP) {
    new Chart(ctxP.getContext('2d'), {
      type: 'line',
      data: {
        labels: ['6w','5w','4w','3w','2w','1w'],
        datasets: [{
          label: 'Hosts testados',
          data: [14, 22, 30, 36, 40, 44],
          borderColor: '#3b82f6',
          backgroundColor: 'rgba(59,130,246,0.12)',
          fill: true,
          tension: 0.35,
          pointRadius: 3,
        }]
      },
      options: {
        plugins: { legend: { display: false }},
        scales: {
          x: { grid: { display: false }, ticks: { color: '#9ca3af' } },
          y: { ticks: { color: '#9ca3af' }, grid: { color: 'rgba(255,255,255,0.02)' } }
        }
      }
    });
  }

  // priority donut
  const ctxD = document.getElementById('priorityDonut');
  if (ctxD) {
    new Chart(ctxD.getContext('2d'), {
      type: 'doughnut',
      data: {
        labels: ['Critical','High','Medium','Low','Info'],
        datasets: [{
          data: [2,8,18,12,4],
          backgroundColor: ['#ef4444','#f59e0b','#8b5cf6','#06b6d4','#94a3b8'],
          hoverOffset: 6
        }]
      },
      options: {
        plugins: { legend: { position: 'right', labels: { color: '#9ca3af' } } }
      }
    });
  }

  // test cases bar
  const ctxB = document.getElementById('testsBar');
  if (ctxB) {
    new Chart(ctxB.getContext('2d'), {
      type: 'bar',
      data: {
        labels: ['Tested','Passed','Failed','Queued'],
        datasets: [{
          label: 'Count',
          data: [101, 72, 19, 8],
          backgroundColor: ['#3b82f6','#10b981','#ef4444','#f59e0b']
        }]
      },
      options: {
        plugins: { legend: { display: false }},
        scales: {
          x: { ticks: { color: '#9ca3af' }, grid: { display: false } },
          y: { ticks: { color: '#9ca3af' }, grid: { color: 'rgba(255,255,255,0.02)' } }
        }
      }
    });
  }

  // Optionally: populate recent scans from server via fetch (placeholder)
  // fetch('/api/projects/summary/').then(r=>r.json()).then(data => { ... })

});
/* MTTD / MTTR charts — severity breakdown (bar) + monthly trend (line),
   rendered with Chart.js. */

const Metrics = (() => {
  let report = null;
  let severityChart = null;
  let trendChart = null;

  const CHART_GRID = 'rgba(31,39,51,0.6)';
  const CHART_TEXT = '#7C8798';

  async function init() {
    report = await API.metrics();
    renderSeverityChart();
    renderTrendChart();
    return report;
  }

  function renderSeverityChart() {
    const ctx = document.getElementById('chart-severity');
    const order = ['Critical', 'High', 'Medium', 'Low'];
    const labels = order.filter((s) => report.by_severity[s]);
    const mttd = labels.map((s) => report.by_severity[s].mttd_mean);
    const mttr = labels.map((s) => report.by_severity[s].mttr_mean);

    severityChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels,
        datasets: [
          { label: 'MTTD', data: mttd, backgroundColor: '#5B9BD5' },
          { label: 'MTTR', data: mttr, backgroundColor: '#F5A623' },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { labels: { color: CHART_TEXT, font: { size: 10 } } },
        },
        scales: {
          x: { ticks: { color: CHART_TEXT, font: { size: 10 } }, grid: { color: CHART_GRID } },
          y: { ticks: { color: CHART_TEXT, font: { size: 10 } }, grid: { color: CHART_GRID } },
        },
      },
    });
  }

  function renderTrendChart() {
    const ctx = document.getElementById('chart-trend');
    const trend = report.monthly_trend;
    const labels = trend.map((t) => t.month);
    const mttd = trend.map((t) => t.mttd_mean);
    const mttr = trend.map((t) => t.mttr_mean);

    trendChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels,
        datasets: [
          { label: 'MTTD', data: mttd, borderColor: '#5B9BD5', backgroundColor: 'transparent', tension: 0.3, pointRadius: 2 },
          { label: 'MTTR', data: mttr, borderColor: '#F5A623', backgroundColor: 'transparent', tension: 0.3, pointRadius: 2 },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { labels: { color: CHART_TEXT, font: { size: 10 } } },
        },
        scales: {
          x: { ticks: { color: CHART_TEXT, font: { size: 9 }, maxRotation: 45 }, grid: { color: CHART_GRID } },
          y: { ticks: { color: CHART_TEXT, font: { size: 10 } }, grid: { color: CHART_GRID } },
        },
      },
    });
  }

  return { init, get: () => report };
})();

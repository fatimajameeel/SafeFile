// static/js/verdict_distribution_pie.js
// Builds the "Verdict Distribution" pie chart on the SOC dashboard

document.addEventListener("DOMContentLoaded", function () {
  // 1) Read data passed from Flask (from kpi_stats.verdict_distribution)
  const data = window.verdictData || [];

  // If there is no data (no scans in last 7 days), don't draw the chart.
  if (!Array.isArray(data) || data.length === 0) {
    console.warn("No verdictData available – skipping Verdict Distribution chart.");
    return;
  }

  // 2) Find the canvas in the HTML
  const canvas = document.getElementById("verdictDistributionChart");
  if (!canvas) {
    console.warn("verdictDistributionChart canvas not found.");
    return;
  }
  const ctx = canvas.getContext("2d");

  // 3) Build labels and values arrays for Chart.js

  // Legend text: "Safe 86.0%", "Suspicious 7.0%", etc.
  const labels = data.map(item => `${item.label} ${item.percent}%`);

  // Slice sizes: counts per category
  const counts = data.map(item => item.count);


  // Safe       -> green
  // Suspicious -> yellow/orange
  // Malicious  -> red
  const backgroundColors = data.map(item => pickColorForVerdict(item.label));

  // 4) Create the pie chart
  new Chart(ctx, {
    type: "pie",
    data: {
      labels: labels,
      datasets: [
        {
          data: counts,
          backgroundColor: backgroundColors,
          borderWidth: 1,
          borderColor: "#ffffff"
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "right",
          labels: {
            usePointStyle: true,
            boxWidth: 10,
            font: {
              size: 11
            }
          }
        },
        tooltip: {
          callbacks: {
            // Tooltip line, e.g. "Safe: 120 (86.0%)"
            label: function (context) {
              const index = context.dataIndex;
              const item = data[index];
              return `${item.label}: ${item.count} (${item.percent}%)`;
            }
          }
        }
      }
    }
  });
});


// Helper: map verdict labels to theme colors
function pickColorForVerdict(label) {
  const lower = label.toLowerCase();

  if (lower.includes("safe")) {
    // Green (same as KPI safe vibe)
    return "#40c561ff";
  }
  if (lower.includes("suspicious")) {
    // Yellow / orange (suspicious)
    return "#f7cc1fff";
  }
  if (lower.includes("malicious")) {
    // Red (malicious)
    return "#f75c54ff";
  }
  if (lower.includes("unknown")) {
    // Neutral grey for unknown/others
    return "#C4C1E0";
  }

  // Fallback: soft purple
  return "#7C6FE6";
}

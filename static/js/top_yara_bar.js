// static/js/top_yara_bar.js

document.addEventListener("DOMContentLoaded", function () {
  // 1) Get the canvas element
  const canvas = document.getElementById("topYaraChart");
  if (!canvas) return; // safety: if the element is missing, do nothing

  const ctx = canvas.getContext("2d");

  // 2) Read the data that we exposed in soc_home.html
  const raw = window.topYaraData || {};
  const labels = raw.labels || [];
  const counts = raw.counts || [];

  // If there is no data yet, don't try to draw the chart
  if (!labels.length) {
    // Optional: show a small message instead of a blank box
    ctx.font = "12px system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI'";
    ctx.fillStyle = "#8a88b3";
    ctx.textAlign = "center";
    ctx.fillText("No YARA rule hits yet", canvas.width / 2, canvas.height / 2);
    return;
  }

  // 3) Build the Chart.js config
  new Chart(ctx, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [
        {
          label: "YARA rule hits",
          data: counts,

          // Gradient fill: orange at the top, purple at the bottom
          backgroundColor: function (context) {
            const chart = context.chart;
            const { ctx, chartArea } = chart;

            // chartArea is undefined on the first pass, so guard against it
            if (!chartArea) {
              return "#6C4FE8"; // fallback solid color
            }

            const gradient = ctx.createLinearGradient(
              0,
              chartArea.top,
              0,
              chartArea.bottom
            );
            gradient.addColorStop(0, "#ff7a45"); // orange
            gradient.addColorStop(1, "#4b2e83"); // deep purple
            return gradient;
          },

          borderRadius: 10,
          borderSkipped: false,
          maxBarThickness: 90,
        },
      ],
    },

    options: {
      responsive: true,
      maintainAspectRatio: false, // let the card's CSS control the height

      plugins: {
        legend: {
          display: false, // we don't need a legend; title already explains it
        },
        tooltip: {
          callbacks: {
            label: function (context) {
              const value = context.parsed.y || 0;
              return `${value} hit${value === 1 ? "" : "s"}`;
            },
          },
        },
      },

      scales: {
        x: {
          grid: {
            display: false,
          },
          ticks: {
            color: "#5a568a",
            maxRotation: 35,
            minRotation: 35, // slight angle so long rule names fit
            font: {
              size: 11,
            },
          },
        },
        y: {
          beginAtZero: true,
          grid: {
            color: "rgba(138, 136, 179, 0.2)",
            drawBorder: false,
          },
          ticks: {
            color: "#8a88b3",
            stepSize: 1,
            precision: 0, // keep it as whole numbers
          },
        },
      },
    },
  });
});

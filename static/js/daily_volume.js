// static/js/daily_volume_bar.js

document.addEventListener("DOMContentLoaded", function () {
  const canvas = document.getElementById("dailyVolumeChart");
  if (!canvas) return; // if the canvas doesn't exist on this page, just stop

  const ctx = canvas.getContext("2d");

  // 1) Get the data that Flask exposed in soc_home.html
  const raw = window.dailyVolumeData || {};
  const labels = raw.labels || [];   // e.g. ["Dec 03", "Dec 04", ...]
  const counts = raw.counts || [];   // e.g. [5, 12, 8, 20, ...]

  // 2) If there is no data, show a friendly message instead of an empty chart
  if (!labels.length) {
    ctx.font = "12px system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI'";
    ctx.fillStyle = "#8a88b3";
    ctx.textAlign = "center";
    ctx.fillText("No scans in the last 7 days", canvas.width / 2, canvas.height / 2);
    return;
  }

  // 3) Build the horizontal bar chart
  new Chart(ctx, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [
        {
          label: "Files scanned",
          data: counts,

          // Solid purple-ish bars that match your theme
          borderColor: "rgba(255, 107, 53, 1)",
          backgroundColor: "rgba(255, 138, 96, 1)",
          borderWidth: 1.2,

          borderRadius: 10,
          borderSkipped: false,
          maxBarThickness: 35, // controls "fatness" of each bar
        },
      ],
    },
    options: {
      indexAxis: "y",              //  this makes it horizontal
      responsive: true,
      maintainAspectRatio: false,  // let CSS control height

      plugins: {
        legend: {
          display: false, // title already explains it
        },
        tooltip: {
          callbacks: {
            // Tooltip text: "Dec 03: 12 files"
            label: function (context) {
              const value = context.parsed.x || 0;
              return `${value} file${value === 1 ? "" : "s"}`;
            },
          },
        },
      },

      scales: {
        y: {
          grid: {
            display: false,
          },
          ticks: {
            color: "#5a568a",
            font: {
              size: 11,
            },
          },
        },
        x: {
          beginAtZero: true,
          grid: {
            color: "rgba(138, 136, 179, 0.2)",
            drawBorder: false,
          },
          ticks: {
            color: "#8a88b3",
            precision: 0,  // whole numbers only
            stepSize: 1,   // 0,1,2,3...
          },
        },
      },
    },
  });
});

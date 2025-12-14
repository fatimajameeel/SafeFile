// soc_home.js
// This script builds the Threat Activity chart on the SOC Dashboard

document.addEventListener("DOMContentLoaded", function () {

    // 1) Chart data coming from Flask
    const chartPoints = window.chartPoints || [];

    const labels = chartPoints.map(point => point.label);
    const totalData = chartPoints.map(point => point.total);
    const alertData = chartPoints.map(point => point.alerts);

    // 2) Find the canvas
    const canvas = document.getElementById("threatActivityChart");
    if (!canvas) {
        console.warn("Chart canvas not found — skipping Threat Activity chart.");
        return;
    }

    const ctx = canvas.getContext("2d");

    // 3) Build the chart
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: "Alerts",
                    data: alertData,
                    fill: true,
                    tension: 0.4,
                    borderWidth: 2,
                    borderColor: "rgba(255, 107, 53, 1)",
                    backgroundColor: "rgba(255, 107, 53, 0.15)"
                },
                {
                    label: "Total Scans",
                    data: totalData,
                    fill: false,
                    tension: 0.4,
                    borderWidth: 2,
                    borderColor: "rgba(88, 86, 214, 1)",
                    pointRadius: 3,
                    pointBackgroundColor: "rgba(88, 86, 214, 1)"
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: { mode: "index", intersect: false }
            },
            scales: {
                x: { grid: { display: false } },
                y: {
                    beginAtZero: true,
                    grid: { color: "rgba(226, 220, 255, 0.7)" },
                }
            }
        }
    });

});

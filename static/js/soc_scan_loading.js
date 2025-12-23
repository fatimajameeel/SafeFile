document.addEventListener("DOMContentLoaded", () => {
  const overlay = document.getElementById("scanOverlay");
  const showOverlay = () => { if (overlay) overlay.hidden = false; };

  // Show overlay when the "Scan Files" form is submitted
  document.querySelectorAll("form.scan-form").forEach((form) => {
    form.addEventListener("submit", () => showOverlay());
  });
});

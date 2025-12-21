document.addEventListener("DOMContentLoaded", () => {
  const table = document.getElementById("filesTable");
  const form = document.getElementById("scanForm");
  if (!table || !form) return;

  table.addEventListener("click", (e) => {
    const btn = e.target.closest(".remove-btn");
    if (!btn) return;

    const row = btn.closest("tr");
    const displayName = row.querySelector(".file-name-cell")?.textContent?.trim();
    if (!displayName) return;

    // Remove matching hidden input
    const hidden = form.querySelector(`input[name="files_to_scan"][data-display="${CSS.escape(displayName)}"]`);
    if (hidden) hidden.remove();

    // Remove row from table
    row.remove();

    // If no more hidden inputs, disable scan button (nice UX)
    const remaining = form.querySelectorAll(`input[name="files_to_scan"]`).length;
    const scanBtn = form.querySelector(`button[type="submit"]`);
    if (scanBtn && remaining === 0) {
      scanBtn.disabled = true;
      scanBtn.textContent = "No files selected";
      scanBtn.style.opacity = "0.6";
      scanBtn.style.cursor = "not-allowed";
    }
  });
});

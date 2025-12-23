document.addEventListener("DOMContentLoaded", () => {
  const overlay = document.getElementById("scanOverlay");

  const dropzone = document.querySelector(".upload-dropzone");
  const dropInput = document.getElementById("dropInput");
  const dropForm = document.getElementById("dropForm");

  const fileForm = document.getElementById("fileForm");
  const folderForm = document.getElementById("folderForm");
  const fileInput = document.getElementById("fileInput");
  const folderInput = document.getElementById("folderInput");

  const showOverlay = () => {
    if (overlay) overlay.hidden = false;
  };

  // ---------------- Drag & Drop ----------------
  if (dropzone && dropInput && dropForm) {
    dropzone.addEventListener("click", () => dropInput.click());

    dropzone.addEventListener("dragover", (e) => {
      e.preventDefault();
      dropzone.classList.add("is-dragover");
    });

    dropzone.addEventListener("dragleave", () => {
      dropzone.classList.remove("is-dragover");
    });

    dropzone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropzone.classList.remove("is-dragover");

      if (!e.dataTransfer.files || e.dataTransfer.files.length === 0) return;

      dropInput.files = e.dataTransfer.files;

      showOverlay();
      dropForm.requestSubmit ? dropForm.requestSubmit() : dropForm.submit();
    });
  }

  // Prevent browser opening the file if dropped outside dropzone
  ["dragover", "drop"].forEach((evt) => {
    window.addEventListener(evt, (e) => e.preventDefault());
  });

  // ---------------- Upload File button ----------------
  if (fileInput && fileForm) {
    fileInput.addEventListener("change", () => {
      if (!fileInput.files || fileInput.files.length === 0) return;

      showOverlay();
      fileForm.requestSubmit ? fileForm.requestSubmit() : fileForm.submit();
    });
  }

  // ---------------- Upload Folder button ----------------
  if (folderInput && folderForm) {
    folderInput.addEventListener("change", () => {
      if (!folderInput.files || folderInput.files.length === 0) return;

      showOverlay();
      folderForm.requestSubmit ? folderForm.requestSubmit() : folderForm.submit();
    });
  }
});

// ---------------------------------------------------------
// Auto-scroll to results after the page reloads with results
// ---------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  const results = document.getElementById("scanResults");
  if (!results) return; // no results on this page load

  // Smooth scroll so the user immediately sees the output
  results.scrollIntoView({
    behavior: "smooth",
    block: "start",
  });

});

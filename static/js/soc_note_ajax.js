// static/js/soc_note_ajax.js
document.addEventListener("DOMContentLoaded", () => {
  const forms = document.querySelectorAll(".note-form");
  if (!forms.length) return;

  forms.forEach((form) => {
    form.addEventListener("submit", async (e) => {
      e.preventDefault(); // stop full page reload

      const fileId = form.dataset.fileId;
      const textarea = form.querySelector(".note-textarea");
      const saveBtn = form.querySelector(".note-save-btn");

      const noteText = (textarea.value || "").trim();

      // Find the card so we can scroll + collapse it
      const card = document.querySelector(`.file-card[data-file-id="${fileId}"]`);

      // Disable button while saving (prevents double-click spam)
      if (saveBtn) {
        saveBtn.disabled = true;
        saveBtn.style.opacity = "0.7";
        saveBtn.style.cursor = "not-allowed";
      }

      try {
        const res = await fetch("/soc/note", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            file_id: fileId,
            note_text: noteText,
          }),
        });

        const data = await res.json();

        if (!res.ok || !data.ok) {
          const msg = data?.error || "Failed to save note.";
          throw new Error(msg);
        }

        // -------------------------------
        // Update the page WITHOUT reload
        // -------------------------------
        if (card) {
          const display = card.querySelector(".note-display");
          const noNotes = card.querySelector(".no-notes");
          const noteBlock = card.querySelector(".note-block");
          const noteTextEl = card.querySelector(".note-block .note-text");
          const updatedAtEl = card.querySelector(".note-updated-at");

          // Hide "No notes" message
          if (noNotes) noNotes.style.display = "none";

          // Show the block
          if (noteBlock) noteBlock.style.display = "block";

          // Update text
          if (noteTextEl) noteTextEl.textContent = data.note_text || "";

          // Update timestamp
          if (updatedAtEl) {
            if (data.updated_at) {
              updatedAtEl.textContent = `Last updated: ${data.updated_at}`;
              updatedAtEl.style.display = "block";
            } else {
              updatedAtEl.style.display = "none";
            }
          }

          // C) Auto-scroll back to the edited file
          card.scrollIntoView({ behavior: "smooth", block: "start" });

 
        //   card.open = true;
        }

        // B) SweetAlert success message
        Swal.fire({
          icon: "success",
          title: "Saved",
          text: "Your note was saved successfully.",
          confirmButtonColor: "#6d28d9",
        });

      } catch (err) {
        Swal.fire({
          icon: "error",
          title: "Save failed",
          text: err.message || "Something went wrong.",
          confirmButtonColor: "#6d28d9",
        });
      } finally {
        // Re-enable button
        if (saveBtn) {
          saveBtn.disabled = false;
          saveBtn.style.opacity = "1";
          saveBtn.style.cursor = "pointer";
        }
      }
    });
  });
});

document.addEventListener("DOMContentLoaded", () => {
    const table = document.getElementById("filesTable");
    const form = document.getElementById("scanForm");
    if (!table || !form) return;

    table.addEventListener("click", (e) => {
        // 1. Check if clicked element is the remove button
        const btn = e.target.closest(".remove-btn");
        if (!btn) return;

        // 2. Get the specific filename from the attribute we added
        const filenameToDelete = btn.getAttribute("data-saved-name");
        const row = btn.closest("tr");

        if (!filenameToDelete) {
            console.error("No filename found on delete button");
            return;
        }

        // 3. Send AJAX request to Python to delete the file from disk
        fetch('/soc/delete_file', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: 'filename=' + encodeURIComponent(filenameToDelete)
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                console.log("Server deleted:", filenameToDelete);

                
                
                // Remove matching hidden input using the VALUE (more robust than display name)
                const hidden = form.querySelector(`input[name="files_to_scan"][value="${CSS.escape(filenameToDelete)}"]`);
                if (hidden) hidden.remove();

                // Remove row from table
                if (row) row.remove();

                // Update UI State (Disable button if empty)
                const remaining = form.querySelectorAll(`input[name="files_to_scan"]`).length;
                const scanBtn = form.querySelector(`button[name="action"][value="scan"]`); // targeted selector
                
                if (scanBtn && remaining === 0) {
                    scanBtn.disabled = true;
                    scanBtn.textContent = "No files selected";
                    scanBtn.style.opacity = "0.6";
                    scanBtn.style.cursor = "not-allowed";
                    
                    //  Hide the whole table container if empty
                    const container = document.querySelector('.folder-results');
                    if (container) container.style.display = 'none';
                }
                // --- END UI CLEANUP ---

            } else {
                alert("Error deleting file: " + data.message);
            }
        })
        .catch(err => {
            console.error("Deletion error:", err);
            alert("Could not contact server to delete file.");
        });
    });
});
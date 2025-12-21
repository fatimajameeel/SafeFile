document.addEventListener("DOMContentLoaded", () => {
  const logoutBtn = document.getElementById("logoutBtn");
  if (!logoutBtn) return;

  logoutBtn.addEventListener("click", (e) => {
    e.preventDefault();

    Swal.fire({
      title: "Logout ?",
      text: "Are you sure you want to log out?",
      icon: "question",
      showCancelButton: true,
      confirmButtonText: "Yes",
      cancelButtonText: "No",
      confirmButtonColor: "#6d28d9",
      cancelButtonColor: "#d1d5db",
      reverseButtons: true
    }).then((result) => {
      if (result.isConfirmed) {
        window.location.href = "/logout";
      }
    });
  });
});

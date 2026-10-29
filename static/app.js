document.addEventListener("submit", function (e) {
    var msg = e.target.getAttribute("data-confirm");
    if (msg && !confirm(msg)) {
        e.preventDefault();
    }
});
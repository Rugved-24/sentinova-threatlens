(() => {
  const stored = localStorage.getItem("threatlens-theme");
  const theme = stored === "light" || stored === "dark" ? stored : "dark";
  document.documentElement.dataset.theme = theme;
  document.documentElement.classList.toggle("dark", theme === "dark");
})();

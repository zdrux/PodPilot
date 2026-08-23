(() => {
  const renderTime = document.querySelector("#render-time");
  if (!renderTime) return;

  const parsed = new Date(renderTime.dateTime);
  if (Number.isNaN(parsed.valueOf())) return;

  renderTime.textContent = new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "medium",
    timeZone: "UTC",
  }).format(parsed) + " UTC";
})();

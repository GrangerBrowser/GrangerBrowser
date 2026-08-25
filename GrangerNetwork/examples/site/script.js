document.documentElement.dataset.granger = "hosted";
fetch("/data.json")
  .then((response) => response.json())
  .then((data) => {
    document.documentElement.dataset.hostingJson = data.status;
  })
  .catch(() => {
    document.documentElement.dataset.hostingJson = "failed";
  });

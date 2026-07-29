(() => {
  "use strict";

  const account = document.querySelector("#currentAccount");
  if (!account) return;

  fetch("/oauth2/userinfo", {
    credentials: "same-origin",
    cache: "no-store",
    headers: { Accept: "application/json" },
  })
    .then((response) => {
      if (!response.ok) throw new Error("userinfo unavailable");
      return response.json();
    })
    .then((user) => {
      account.textContent =
        user.email || user.preferredUsername || user.user || "已登录用户";
    })
    .catch(() => {
      account.textContent = "已登录用户";
    });
})();

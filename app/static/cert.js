(function () {
  var metaEl = document.getElementById("cert-meta");
  var list = document.getElementById("log");
  if (!metaEl || !list) return;

  var meta;
  try {
    meta = JSON.parse(metaEl.textContent);
  } catch (e) {
    return;
  }

  var timer = null;
  var LABELS = {
    pending: "待申请", issuing: "申请中", active: "有效",
    error: "失败", expired: "已过期", revoked: "已吊销"
  };

  function addEvent(item) {
    if (list.querySelector(".muted")) list.innerHTML = "";
    var li = document.createElement("li");
    li.className = "lvl-" + item.level;
    li.dataset.id = item.id;
    var time = document.createElement("span");
    time.className = "time";
    time.textContent = (item.created_at || "").slice(11, 19);
    var lvl = document.createElement("span");
    lvl.className = "lvl";
    lvl.textContent = item.level;
    li.appendChild(time);
    li.appendChild(lvl);
    li.appendChild(document.createTextNode(item.message));
    list.insertBefore(li, list.firstChild);
  }

  function paintStatus(status, remaining) {
    var box = document.getElementById("status");
    if (!box) return;
    box.textContent = (LABELS[status] || status) + (status === "active" && remaining ? " · 剩 " + remaining + " 天" : "");
    box.className = "badge " + (status === "active" ? "ok" : (status === "issuing" || status === "pending") ? "busy" : status === "error" ? "bad" : "muted");
  }

  function running(status) {
    return status === "issuing" || status === "pending";
  }

  function finished() {
    // Reload once so validity dates, file links and badges come from the new state.
    window.location.reload();
  }

  function tick() {
    fetch("/certificates/" + meta.id + "/events?after=" + meta.after, { credentials: "same-origin" })
      .then(function (response) {
        if (!response.ok) throw new Error("HTTP " + response.status);
        return response.json();
      })
      .then(function (data) {
        data.events.forEach(addEvent);
        if (data.events.length) meta.after = data.events[data.events.length - 1].id;
        var hint = document.getElementById("hint");
        if (hint) hint.textContent = "状态：" + (LABELS[data.status] || data.status) +
          (data.error ? "（" + data.error.slice(0, 120) + "）" : "");
        if (running(data.status)) {
          timer = setTimeout(tick, 3000);
        } else if (running(meta.status)) {
          finished();
        } else {
          paintStatus(data.status);
          timer = null;
        }
      })
      .catch(function () {
        timer = setTimeout(tick, 8000);
      });
  }

  var initial = list.querySelector("li[data-id]");
  if (initial) meta.after = Math.max(meta.after, parseInt(initial.dataset.id, 10) || 0);
  if (running(meta.status)) tick();
})();

(() => {
  "use strict";

  const rawConfig = window.ORYX_PORTAL_CONFIG || {};
  const parsedRoomCount = Number.parseInt(rawConfig.roomCount, 10);
  const roomCount = Number.isInteger(parsedRoomCount)
    ? Math.min(Math.max(parsedRoomCount, 1), 100)
    : 10;
  const streamPrefix = /^[A-Za-z0-9_-]+$/.test(rawConfig.streamPrefix || "")
    ? rawConfig.streamPrefix
    : "stream";
  const STREAM_BASE = "/live";
  const RETRY_DELAY_MS = 8000;
  const OVERVIEW_START_GAP_MS = 220;

  const rooms = Array.from({ length: roomCount }, (_, index) => {
    const number = String(index + 1).padStart(2, "0");
    const stream = `${streamPrefix}${number}`;
    return { id: `room${number}`, name: `直播间${number}`, stream, url: `${STREAM_BASE}/${stream}.m3u8` };
  });

  const elements = {
    overviewView: document.querySelector("#overviewView"),
    focusView: document.querySelector("#focusView"),
    roomGrid: document.querySelector("#roomGrid"),
    roomList: document.querySelector("#roomList"),
    refreshButton: document.querySelector("#refreshButton"),
    backButton: document.querySelector("#backButton"),
    previousButton: document.querySelector("#previousButton"),
    nextButton: document.querySelector("#nextButton"),
    soundButton: document.querySelector("#soundButton"),
    fullscreenButton: document.querySelector("#fullscreenButton"),
    focusTitle: document.querySelector("#focusTitle"),
    focusVideo: document.querySelector("#focusVideo"),
    focusStage: document.querySelector("#focusStage"),
    focusStatus: document.querySelector("#focusStatus"),
    focusStreamName: document.querySelector("#focusStreamName"),
    focusPlaceholder: document.querySelector("#focusPlaceholder"),
    liveCount: document.querySelector("#liveCount"),
    roomCount: document.querySelector("#roomCount"),
    sidebarCount: document.querySelector("#sidebarCount"),
    clock: document.querySelector("#clock"),
    toast: document.querySelector("#toast"),
  };

  const sessions = new Map();
  const roomStates = new Map(rooms.map((room) => [room.id, "connecting"]));
  const pendingStarts = new Set();
  let selectedIndex = 0;
  let currentView = "overview";
  let toastTimer = null;

  function renderRoomGrid() {
    elements.roomGrid.innerHTML = rooms.map((room, index) => `
      <li class="room-card" data-room-card="${room.id}">
        <div class="video-shell">
          <video id="overview-video-${room.id}" playsinline autoplay muted preload="metadata" aria-label="${room.name}直播画面"></video>
          <div class="video-shade"></div>
          <span class="status status-connecting card-status" data-status-for="${room.id}">
            <span class="status-dot" aria-hidden="true"></span><span class="status-text">连接中</span>
          </span>
          <button class="card-open" type="button" data-open-room="${index}" aria-label="打开${room.name}">
            <span>查看大画面 ↗</span>
          </button>
        </div>
        <div class="room-meta">
          <span class="room-title"><strong>${room.name}</strong><small>LIVE CHANNEL ${String(index + 1).padStart(2, "0")}</small></span>
          <code>${room.stream}</code>
        </div>
      </li>`).join("");
    elements.roomGrid.querySelectorAll("[data-open-room]").forEach((button) => {
      button.addEventListener("click", () => enterFocus(Number(button.dataset.openRoom)));
    });
  }

  function renderRoomList() {
    elements.roomList.innerHTML = rooms.map((room, index) => `
      <button class="room-list-button" type="button" data-select-room="${index}" data-room-list="${room.id}" data-state="connecting">
        <span class="room-number">${String(index + 1).padStart(2, "0")}</span>
        <span>${room.name}</span><span class="mini-dot" aria-hidden="true"></span>
      </button>`).join("");
    elements.roomList.querySelectorAll("[data-select-room]").forEach((button) => {
      button.addEventListener("click", () => switchFocusedRoom(Number(button.dataset.selectRoom)));
    });
  }

  function setStatus(room, state, label) {
    roomStates.set(room.id, state);
    document.querySelectorAll(`[data-status-for="${room.id}"]`).forEach((status) => {
      status.className = `status status-${state} card-status`;
      const text = status.querySelector(".status-text");
      if (text) text.textContent = label;
    });
    const listButton = document.querySelector(`[data-room-list="${room.id}"]`);
    if (listButton) listButton.dataset.state = state;
    if (currentView === "focus" && rooms[selectedIndex].id === room.id) {
      elements.focusStatus.className = `status status-${state}`;
      const text = elements.focusStatus.querySelector(".status-text");
      if (text) text.textContent = label;
      elements.focusPlaceholder.classList.toggle("is-hidden", state === "live");
      if (state !== "live") {
        elements.focusPlaceholder.querySelector("strong").textContent =
          state === "connecting" ? "正在连接直播信号" : "该直播间暂未开播";
        elements.focusPlaceholder.querySelector("small").textContent = "页面会在后台自动重试";
      }
    }
    elements.liveCount.textContent = String([...roomStates.values()].filter((value) => value === "live").length);
  }

  function clearPendingStarts() {
    pendingStarts.forEach((timer) => window.clearTimeout(timer));
    pendingStarts.clear();
  }
  function destroySession(key) {
    const session = sessions.get(key);
    if (!session) return;
    session.stopped = true;
    if (session.retryTimer) window.clearTimeout(session.retryTimer);
    if (session.hls) session.hls.destroy();
    session.nativeListeners.forEach(([event, listener]) => session.video.removeEventListener(event, listener));
    session.video.pause();
    session.video.removeAttribute("src");
    session.video.load();
    sessions.delete(key);
  }
  function destroyAllSessions() {
    clearPendingStarts();
    [...sessions.keys()].forEach(destroySession);
  }
  function scheduleRetry(session) {
    if (session.stopped || session.retryTimer) return;
    session.retryTimer = window.setTimeout(() => {
      if (sessions.get(session.key) === session) attachStream(session.key, session.video, session.room);
    }, RETRY_DELAY_MS);
  }
  function markPlaying(session) {
    if (session.stopped) return;
    setStatus(session.room, "live", "直播中");
    session.video.play().catch(() => {});
  }
  function attachNativeHls(session) {
    const onReady = () => markPlaying(session);
    const onError = () => {
      if (session.stopped) return;
      setStatus(session.room, "offline", "未开播");
      scheduleRetry(session);
    };
    session.nativeListeners.push(["loadedmetadata", onReady], ["canplay", onReady], ["error", onError]);
    session.nativeListeners.forEach(([event, listener]) => session.video.addEventListener(event, listener));
    session.video.src = session.room.url;
    session.video.load();
  }
  function attachStream(key, video, room) {
    destroySession(key);
    setStatus(room, "connecting", "连接中");
    const session = { key, video, room, hls: null, retryTimer: null, stopped: false, mediaRecoveries: 0, nativeListeners: [] };
    sessions.set(key, session);
    video.muted = true;
    video.playsInline = true;
    if (window.Hls && window.Hls.isSupported()) {
      const hls = new window.Hls({
        lowLatencyMode: true, enableWorker: true, backBufferLength: 30,
        liveSyncDurationCount: 2, liveMaxLatencyDurationCount: 5, maxLiveSyncPlaybackRate: 1.5,
        manifestLoadingTimeOut: 8000, manifestLoadingMaxRetry: 1,
        levelLoadingTimeOut: 8000, fragLoadingTimeOut: 12000,
      });
      session.hls = hls;
      hls.attachMedia(video);
      hls.on(window.Hls.Events.MEDIA_ATTACHED, () => { if (!session.stopped) hls.loadSource(room.url); });
      hls.on(window.Hls.Events.MANIFEST_PARSED, () => markPlaying(session));
      hls.on(window.Hls.Events.FRAG_LOADED, () => markPlaying(session));
      hls.on(window.Hls.Events.ERROR, (_event, data) => {
        if (session.stopped || !data.fatal) return;
        if (data.type === window.Hls.ErrorTypes.MEDIA_ERROR && session.mediaRecoveries < 1) {
          session.mediaRecoveries += 1;
          setStatus(room, "connecting", "恢复中");
          hls.recoverMediaError();
          return;
        }
        setStatus(room, "offline", "未开播");
        scheduleRetry(session);
      });
      return;
    }
    if (video.canPlayType("application/vnd.apple.mpegurl")) {
      attachNativeHls(session);
      return;
    }
    setStatus(room, "error", "不支持 HLS");
  }

  function startOverview() {
    currentView = "overview";
    destroyAllSessions();
    elements.focusView.hidden = true;
    elements.overviewView.hidden = false;
    rooms.forEach((room, index) => {
      setStatus(room, "connecting", "连接中");
      const timer = window.setTimeout(() => {
        pendingStarts.delete(timer);
        if (currentView !== "overview") return;
        const video = document.querySelector(`#overview-video-${room.id}`);
        if (video) attachStream(`overview-${room.id}`, video, room);
      }, index * OVERVIEW_START_GAP_MS);
      pendingStarts.add(timer);
    });
  }
  function updateFocusUi() {
    const room = rooms[selectedIndex];
    elements.focusTitle.textContent = room.name;
    elements.focusStreamName.textContent = room.stream;
    elements.focusVideo.setAttribute("aria-label", `${room.name}直播画面`);
    elements.roomList.querySelectorAll("[data-select-room]").forEach((button) => {
      button.classList.toggle("is-active", Number(button.dataset.selectRoom) === selectedIndex);
    });
  }
  function resetSound() {
    elements.focusVideo.muted = true;
    elements.soundButton.textContent = "开启声音";
  }
  function enterFocus(index) {
    currentView = "focus";
    selectedIndex = index;
    destroyAllSessions();
    resetSound();
    updateFocusUi();
    elements.overviewView.hidden = true;
    elements.focusView.hidden = false;
    window.scrollTo({ top: 0, behavior: "smooth" });
    attachStream("focus", elements.focusVideo, rooms[selectedIndex]);
  }
  function switchFocusedRoom(index) {
    if (currentView !== "focus") return;
    selectedIndex = (index + rooms.length) % rooms.length;
    resetSound();
    updateFocusUi();
    attachStream("focus", elements.focusVideo, rooms[selectedIndex]);
  }
  function showToast(message) {
    window.clearTimeout(toastTimer);
    elements.toast.textContent = message;
    elements.toast.classList.add("is-visible");
    toastTimer = window.setTimeout(() => elements.toast.classList.remove("is-visible"), 3200);
  }
  function toggleSound() {
    elements.focusVideo.muted = !elements.focusVideo.muted;
    elements.soundButton.textContent = elements.focusVideo.muted ? "开启声音" : "关闭声音";
    if (!elements.focusVideo.muted) {
      elements.focusVideo.play().catch(() => showToast("浏览器阻止了自动播放，请点击播放器中的播放按钮"));
    }
  }
  function toggleFullscreen() {
    if (!document.fullscreenElement) {
      elements.focusStage.requestFullscreen?.().catch(() => showToast("当前浏览器无法进入全屏模式"));
    } else {
      document.exitFullscreen?.();
    }
  }
  function updateClock() {
    const now = new Date();
    elements.clock.dateTime = now.toISOString();
    elements.clock.textContent = new Intl.DateTimeFormat("zh-CN", {
      month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
    }).format(now);
  }
  elements.roomCount.textContent = String(roomCount);
  elements.sidebarCount.textContent = `${roomCount} 路`;
  elements.refreshButton.addEventListener("click", () => {
    startOverview();
    showToast("正在重新连接全部直播间");
  });
  elements.backButton.addEventListener("click", startOverview);
  elements.previousButton.addEventListener("click", () => switchFocusedRoom(selectedIndex - 1));
  elements.nextButton.addEventListener("click", () => switchFocusedRoom(selectedIndex + 1));
  elements.soundButton.addEventListener("click", toggleSound);
  elements.fullscreenButton.addEventListener("click", toggleFullscreen);
  document.addEventListener("fullscreenchange", () => {
    elements.fullscreenButton.textContent = document.fullscreenElement ? "退出全屏" : "全屏播放";
  });
  document.addEventListener("keydown", (event) => {
    if (currentView !== "focus") return;
    if (event.key === "Escape" && !document.fullscreenElement) startOverview();
    if (event.key === "ArrowLeft") switchFocusedRoom(selectedIndex - 1);
    if (event.key === "ArrowRight") switchFocusedRoom(selectedIndex + 1);
  });
  window.addEventListener("beforeunload", destroyAllSessions);

  renderRoomGrid();
  renderRoomList();
  updateClock();
  window.setInterval(updateClock, 1000);
  startOverview();
})();

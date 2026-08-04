(() => {
  "use strict";

  const PAGE_SIZE = 20;
  const EMAIL_LOCAL_PART = /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+$/i;
  const FALLBACK_EMAIL_DOMAIN = "example.com";

  const state = {
    me: null,
    csrfToken: "",
    allowedEmailDomain: FALLBACK_EMAIL_DOMAIN,
    canManageAdmins: false,
    activeTab: "users",
    users: {
      items: [],
      total: 0,
      page: 1,
      pageSize: PAGE_SIZE,
      q: "",
      status: "",
      requestId: 0,
    },
    access: {
      items: [],
      total: 0,
      page: 1,
      pageSize: PAGE_SIZE,
      outcome: "",
      loaded: false,
      requestId: 0,
    },
    audit: {
      items: [],
      total: 0,
      page: 1,
      pageSize: PAGE_SIZE,
      loaded: false,
      requestId: 0,
    },
    confirmTask: null,
    returnFocus: null,
    toastTimer: null,
    workspaceMaxHeight: 0,
    workspaceResizeTimer: null,
  };

  const elements = {
    app: document.querySelector("#app"),
    forbiddenView: document.querySelector("#forbiddenView"),
    globalError: document.querySelector("#globalError"),
    globalErrorMessage: document.querySelector("#globalErrorMessage"),
    retryButton: document.querySelector("#retryButton"),
    sessionIdentity: document.querySelector("#sessionIdentity"),
    sessionAvatar: document.querySelector("#sessionAvatar"),
    sessionEmail: document.querySelector("#sessionEmail"),
    metricAuthorized: document.querySelector("#metricAuthorized"),
    metricDisabled: document.querySelector("#metricDisabled"),
    metricOnline: document.querySelector("#metricOnline"),
    metricDenied: document.querySelector("#metricDenied"),
    overviewUpdated: document.querySelector("#overviewUpdated"),
    refreshOverview: document.querySelector("#refreshOverview"),
    workspace: document.querySelector(".workspace"),
    tabList: document.querySelector(".tab-list"),
    tabButtons: [...document.querySelectorAll("[data-tab]")],
    tabPanels: [...document.querySelectorAll("[data-panel]")],
    openAddDialog: document.querySelector("#openAddDialog"),
    addDialog: document.querySelector("#addDialog"),
    addUserForm: document.querySelector("#addUserForm"),
    addEmails: document.querySelector("#addEmails"),
    emailHelp: document.querySelector("#emailHelp"),
    addFormError: document.querySelector("#addFormError"),
    submitAddUsers: document.querySelector("#submitAddUsers"),
    confirmDialog: document.querySelector("#confirmDialog"),
    confirmForm: document.querySelector("#confirmForm"),
    confirmTitle: document.querySelector("#confirmTitle"),
    confirmMessage: document.querySelector("#confirmMessage"),
    confirmAction: document.querySelector("#confirmAction"),
    userFilters: document.querySelector("#userFilters"),
    userSearch: document.querySelector("#userSearch"),
    userStatus: document.querySelector("#userStatus"),
    resetUserFilters: document.querySelector("#resetUserFilters"),
    userRows: document.querySelector("#userRows"),
    userResultSummary: document.querySelector("#userResultSummary"),
    userPagination: document.querySelector("#userPagination"),
    accessOutcome: document.querySelector("#accessOutcome"),
    accessRows: document.querySelector("#accessRows"),
    accessResultSummary: document.querySelector("#accessResultSummary"),
    accessPagination: document.querySelector("#accessPagination"),
    auditRows: document.querySelector("#auditRows"),
    auditResultSummary: document.querySelector("#auditResultSummary"),
    auditPagination: document.querySelector("#auditPagination"),
    toast: document.querySelector("#toast"),
  };

  class ApiError extends Error {
    constructor(message, status) {
      super(message);
      this.name = "ApiError";
      this.status = status;
    }
  }

  function escapeHtml(value) {
    return String(value ?? "").replace(
      /[&<>'"]/g,
      (character) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          "'": "&#39;",
          '"': "&quot;",
        })[character],
    );
  }

  function unwrapData(payload) {
    if (payload && typeof payload === "object" && payload.data) {
      return payload.data;
    }
    return payload || {};
  }

  function normalizeCollection(payload, keys) {
    const source = unwrapData(payload);
    if (Array.isArray(source)) {
      return {
        items: source,
        total: source.length,
        page: 1,
        pageSize: source.length || PAGE_SIZE,
      };
    }
    const matchedKey = keys.find((key) => Array.isArray(source[key]));
    const items = Array.isArray(source.items)
      ? source.items
      : matchedKey
        ? source[matchedKey]
        : [];
    return {
      items,
      total: Number(source.total ?? source.totalCount ?? items.length) || 0,
      page: Number(source.page) || 1,
      pageSize: Number(source.pageSize) || PAGE_SIZE,
    };
  }

  function redirectToLogin() {
    const returnTo = encodeURIComponent(
      `${window.location.pathname}${window.location.search}${window.location.hash}`,
    );
    window.location.replace(`/oauth2/start?rd=${returnTo}`);
  }

  async function apiRequest(path, options = {}) {
    const method = (options.method || "GET").toUpperCase();
    const headers = new Headers(options.headers || {});
    headers.set("Accept", "application/json");
    if (options.body && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }
    if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
      headers.set("X-CSRF-Token", state.csrfToken);
    }

    let response;
    try {
      response = await window.fetch(path, {
        ...options,
        method,
        headers,
        credentials: "same-origin",
        cache: "no-store",
      });
    } catch {
      throw new ApiError("无法连接权限服务，请检查网络后重试。", 0);
    }

    if (response.status === 401) {
      redirectToLogin();
      throw new ApiError("登录状态已失效", 401);
    }
    if (response.status === 403) {
      showForbidden();
      throw new ApiError("当前账号没有管理员权限", 403);
    }
    if (!response.ok) {
      let message = `请求失败（HTTP ${response.status}）`;
      try {
        const body = await response.json();
        message =
          body?.error?.message ||
          body?.message ||
          (typeof body?.error === "string" ? body.error : message);
      } catch {
        const body = await response.text();
        if (body.trim()) message = body.trim().slice(0, 180);
      }
      throw new ApiError(message, response.status);
    }
    if (response.status === 204) return null;
    const contentType = response.headers.get("content-type") || "";
    return contentType.includes("application/json")
      ? response.json()
      : response.text();
  }

  function setButtonBusy(button, busy, busyLabel) {
    if (!button) return;
    if (busy) {
      button.dataset.label = button.textContent;
      button.textContent = busyLabel;
      button.disabled = true;
      button.setAttribute("aria-busy", "true");
    } else {
      button.textContent = button.dataset.label || button.textContent;
      button.disabled = false;
      button.removeAttribute("aria-busy");
      delete button.dataset.label;
    }
  }

  function showToast(message, type = "success") {
    window.clearTimeout(state.toastTimer);
    elements.toast.textContent = message;
    elements.toast.classList.toggle("is-error", type === "error");
    elements.toast.classList.add("is-visible");
    state.toastTimer = window.setTimeout(() => {
      elements.toast.classList.remove("is-visible");
    }, 3600);
  }

  function setGlobalError(message) {
    elements.globalErrorMessage.textContent = message || "请稍后重试。";
    elements.globalError.hidden = false;
  }

  function clearGlobalError() {
    elements.globalError.hidden = true;
  }

  function showForbidden() {
    elements.app.hidden = true;
    elements.forbiddenView.hidden = false;
    document.title = "无权访问 · 观看权限管理";
  }

  function formatDate(value, includeSeconds = false) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "—";
    const options = {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    };
    if (includeSeconds) options.second = "2-digit";
    return new Intl.DateTimeFormat("zh-CN", options).format(date);
  }

  function getReadableIdentity(user, fallback = "已登录用户") {
    for (const candidate of [user?.displayName, user?.name]) {
      const value = String(candidate || "").trim();
      if (value && !/^\d+$/.test(value)) return value;
    }

    const email = String(user?.email || "").trim();
    const localPart = email.split("@")[0].trim();
    return localPart || email || fallback;
  }

  function isSuperAdmin(user) {
    return user?.isSuperAdmin === true;
  }

  function isDynamicAdmin(user) {
    return user?.isAdmin === true && !isSuperAdmin(user);
  }

  function isActiveUser(user) {
    return ["authorized", "active"].includes(
      String(user?.status || "authorized").toLowerCase(),
    );
  }

  function normalizeEmailDomain(value) {
    const domain = String(value || "")
      .trim()
      .toLowerCase()
      .replace(/^@+/, "");
    return /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(domain)
      ? domain
      : FALLBACK_EMAIL_DOMAIN;
  }

  function isAllowedEmail(email) {
    const separator = email.lastIndexOf("@");
    if (separator <= 0) return false;
    const localPart = email.slice(0, separator);
    const domain = email.slice(separator + 1).toLowerCase();
    return (
      EMAIL_LOCAL_PART.test(localPart) && domain === state.allowedEmailDomain
    );
  }

  function statusView(user) {
    const status = String(user.status || "authorized").toLowerCase();
    const statuses = {
      authorized: { key: "authorized", label: "已授权" },
      active: { key: "authorized", label: "已授权" },
      disabled: { key: "disabled", label: "已禁用" },
      expired: { key: "disabled", label: "已禁用" },
      archived: { key: "archived", label: "已归档" },
    };
    return statuses[status] || { key: "archived", label: status || "未知" };
  }

  function outcomeView(outcome) {
    const key = String(outcome || "").toLowerCase();
    if (["allowed", "allow", "success", "authorized"].includes(key)) {
      return { key: "allowed", label: "允许" };
    }
    return { key: "denied", label: "拒绝" };
  }

  function actionLabel(action) {
    const labels = {
      add: "添加用户",
      create: "添加用户",
      batch_add: "批量添加",
      disable: "禁用",
      restore: "恢复",
      enable: "恢复",
      archive: "归档",
      grant_admin: "设为管理员",
      revoke_admin: "取消管理员",
      update_expiry: "历史权限变更",
      set_expiry: "历史权限变更",
    };
    return labels[action] || action || "权限变更";
  }

  function formatAuditDetail(rawDetail) {
    if (rawDetail === null || rawDetail === undefined || rawDetail === "") return "—";

    let detail = rawDetail;
    if (typeof rawDetail === "string") {
      try {
        detail = JSON.parse(rawDetail);
      } catch {
        return rawDetail;
      }
    }

    if (Array.isArray(detail)) return JSON.stringify(detail);
    if (detail && typeof detail === "object") {
      const sanitized = Object.fromEntries(
        Object.entries(detail).filter(([key]) => key.toLowerCase() !== "expiresat"),
      );
      return Object.keys(sanitized).length ? JSON.stringify(sanitized) : "—";
    }
    return String(detail);
  }

  function renderLoadingRow(target, columns, label) {
    target.innerHTML = `<tr class="state-row"><td colspan="${columns}"><span class="spinner" aria-hidden="true"></span>${escapeHtml(label)}</td></tr>`;
  }

  function renderEmptyRow(target, columns, title, description) {
    target.innerHTML = `<tr class="state-row"><td colspan="${columns}"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(description)}</span></td></tr>`;
  }

  function renderErrorRow(target, columns, message, retryTarget) {
    target.innerHTML = `<tr class="state-row"><td colspan="${columns}"><strong>加载失败</strong><span>${escapeHtml(message)}</span><button class="row-action" type="button" data-retry="${retryTarget}">重新加载</button></td></tr>`;
  }

  function renderPagination(target, collection, type) {
    const totalPages = Math.max(1, Math.ceil(collection.total / collection.pageSize));
    const currentPage = Math.min(collection.page, totalPages);
    if (collection.total === 0) {
      target.innerHTML = "";
      return;
    }
    target.innerHTML = `
      <span class="pagination-summary">共 ${collection.total} 条 · 第 ${currentPage} / ${totalPages} 页</span>
      <button class="page-button" type="button" data-page-type="${type}" data-page="${currentPage - 1}" ${currentPage <= 1 ? "disabled" : ""}>上一页</button>
      <button class="page-button" type="button" data-page-type="${type}" data-page="${currentPage + 1}" ${currentPage >= totalPages ? "disabled" : ""}>下一页</button>`;
  }

  async function loadMe() {
    const payload = await apiRequest("/api/me");
    const me = unwrapData(payload);
    if (me.role !== "admin") {
      showForbidden();
      return false;
    }
    state.me = me;
    state.csrfToken = String(me.csrfToken || "");
    state.allowedEmailDomain = normalizeEmailDomain(me.allowedEmailDomain);
    state.canManageAdmins = me.canManageAdmins === true;
    elements.addEmails.placeholder = `name@${state.allowedEmailDomain}\nanother@${state.allowedEmailDomain}`;
    elements.emailHelp.textContent = `仅接受 @${state.allowedEmailDomain} 邮箱，重复地址会自动去重。`;
    const readableIdentity = getReadableIdentity(me, "管理员");
    const email = String(me.email || "").trim();
    const identity = email || readableIdentity;
    elements.sessionEmail.textContent = identity;
    elements.sessionIdentity.title =
      email && readableIdentity !== email ? `${readableIdentity} · ${email}` : identity;
    elements.sessionAvatar.textContent = readableIdentity.charAt(0).toUpperCase() || "管";
    elements.sessionIdentity.hidden = false;
    return true;
  }

  async function loadOverview() {
    const metrics = [
      elements.metricAuthorized,
      elements.metricDisabled,
      elements.metricOnline,
      elements.metricDenied,
    ];
    metrics.forEach((element) => element.setAttribute("data-loading", "true"));
    elements.refreshOverview.disabled = true;
    try {
      const payload = await apiRequest("/api/admin/overview");
      const data = unwrapData(payload);
      elements.metricAuthorized.textContent = String(Number(data.authorized) || 0);
      elements.metricDisabled.textContent = String(Number(data.disabled) || 0);
      elements.metricOnline.textContent = String(Number(data.online) || 0);
      elements.metricDenied.textContent = String(Number(data.deniedRecent) || 0);
      elements.overviewUpdated.textContent = `更新于 ${formatDate(new Date(), true)}`;
      clearGlobalError();
    } catch (error) {
      if (error.status !== 401 && error.status !== 403) {
        elements.overviewUpdated.textContent = "概览读取失败";
        setGlobalError(error.message);
      }
    } finally {
      metrics.forEach((element) => element.removeAttribute("data-loading"));
      elements.refreshOverview.disabled = false;
    }
  }

  function renderUsers() {
    const users = state.users.items;
    if (!users.length) {
      const filtered = Boolean(state.users.q || state.users.status);
      renderEmptyRow(
        elements.userRows,
        5,
        filtered ? "没有匹配的用户" : "还没有观看用户",
        filtered ? "请调整搜索条件后重试。" : "点击“添加观看用户”录入第一个账号。",
      );
      elements.userResultSummary.textContent = filtered ? "查询结果为空" : "共 0 位用户";
      renderPagination(elements.userPagination, state.users, "users");
      scheduleWorkspaceHeightCapture();
      return;
    }

    elements.userRows.innerHTML = users
      .map((user) => {
        const status = statusView(user);
        const email = user.email || "—";
        const name = getReadableIdentity(user, "未知用户");
        const userId = user.id ?? email;
        const superAdmin = isSuperAdmin(user);
        const dynamicAdmin = isDynamicAdmin(user);
        const active = isActiveUser(user);
        const lastSeen = formatDate(user.lastSeenAt);
        let actions = "";
        if (superAdmin) {
          actions = '<span class="immutable-note">由系统配置</span>';
        } else if (dynamicAdmin) {
          actions = state.canManageAdmins
            ? `<button class="row-action is-danger" type="button" data-user-action="revoke_admin" data-user-id="${escapeHtml(userId)}">取消管理员</button>`
            : '<span class="immutable-note">仅超级管理员可调整</span>';
        } else {
          const actionButtons = [];
          if (active) {
            if (state.canManageAdmins) {
              actionButtons.push(`<button class="row-action" type="button" data-user-action="grant_admin" data-user-id="${escapeHtml(userId)}">设为管理员</button>`);
            }
            actionButtons.push(`<button class="row-action is-danger" type="button" data-user-action="disable" data-user-id="${escapeHtml(userId)}">禁用</button>`);
          } else {
            actionButtons.push(`<button class="row-action" type="button" data-user-action="restore" data-user-id="${escapeHtml(userId)}">恢复</button>`);
          }
          if (String(user.status || "").toLowerCase() !== "archived") {
            actionButtons.push(`<button class="row-action is-danger" type="button" data-user-action="archive" data-user-id="${escapeHtml(userId)}">归档</button>`);
          }
          actions = actionButtons.join("");
        }
        return `
          <tr>
            <td class="user-cell">
              <strong>${escapeHtml(name)}</strong>
              <span>${escapeHtml(email)}</span>
              ${superAdmin ? '<small class="admin-label admin-label-super">超级管理员</small>' : ""}
              ${dynamicAdmin ? '<small class="admin-label">管理员</small>' : ""}
            </td>
            <td><span class="status-badge status-${status.key}">${status.label}</span></td>
            <td>${escapeHtml(lastSeen)}<span class="cell-subtext">${escapeHtml(user.lastIp || "无 IP 记录")}</span></td>
            <td>${Number(user.loginCount) || 0}<span class="cell-subtext">首次 ${escapeHtml(formatDate(user.firstSeenAt))}</span></td>
            <td><div class="action-list">${actions}</div></td>
          </tr>`;
      })
      .join("");
    elements.userResultSummary.textContent = `共 ${state.users.total} 位用户`;
    renderPagination(elements.userPagination, state.users, "users");
    scheduleWorkspaceHeightCapture();
  }

  async function loadUsers() {
    const requestId = ++state.users.requestId;
    renderLoadingRow(elements.userRows, 5, "正在加载用户");
    elements.userResultSummary.textContent = "正在加载用户…";
    elements.userPagination.innerHTML = "";
    const query = new URLSearchParams({
      page: String(state.users.page),
      pageSize: String(state.users.pageSize),
    });
    if (state.users.q) query.set("q", state.users.q);
    if (state.users.status) query.set("status", state.users.status);
    try {
      const payload = await apiRequest(`/api/admin/users?${query}`);
      if (requestId !== state.users.requestId) return;
      Object.assign(state.users, normalizeCollection(payload, ["users"]));
      renderUsers();
      clearGlobalError();
    } catch (error) {
      if (requestId !== state.users.requestId || [401, 403].includes(error.status)) return;
      elements.userResultSummary.textContent = "用户列表加载失败";
      renderErrorRow(elements.userRows, 5, error.message, "users");
      scheduleWorkspaceHeightCapture();
    }
  }

  function renderAccessEvents() {
    const events = state.access.items;
    if (!events.length) {
      renderEmptyRow(elements.accessRows, 4, "暂无访问记录", "当前筛选范围内没有记录。");
      elements.accessResultSummary.textContent = "共 0 条记录";
      renderPagination(elements.accessPagination, state.access, "access");
      scheduleWorkspaceHeightCapture();
      return;
    }
    elements.accessRows.innerHTML = events
      .map((event) => {
        const result = outcomeView(event.outcome);
        const email = String(event.email || "").trim();
        const name = getReadableIdentity(event, "未知账号");
        const showEmail = email && email !== name;
        return `
          <tr>
            <td class="user-cell"><strong>${escapeHtml(name)}</strong>${showEmail ? `<span>${escapeHtml(email)}</span>` : ""}</td>
            <td><span class="status-badge status-${result.key}">${result.label}</span></td>
            <td>${escapeHtml(event.ip || "—")}</td>
            <td>${escapeHtml(formatDate(event.createdAt, true))}</td>
          </tr>`;
      })
      .join("");
    elements.accessResultSummary.textContent = `共 ${state.access.total} 条记录`;
    renderPagination(elements.accessPagination, state.access, "access");
    scheduleWorkspaceHeightCapture();
  }

  async function loadAccessEvents() {
    const requestId = ++state.access.requestId;
    state.access.loaded = true;
    renderLoadingRow(elements.accessRows, 4, "正在加载访问记录");
    elements.accessResultSummary.textContent = "正在加载访问记录…";
    elements.accessPagination.innerHTML = "";
    const query = new URLSearchParams({
      page: String(state.access.page),
      pageSize: String(state.access.pageSize),
    });
    if (state.access.outcome) query.set("outcome", state.access.outcome);
    try {
      const payload = await apiRequest(`/api/admin/access-events?${query}`);
      if (requestId !== state.access.requestId) return;
      Object.assign(state.access, normalizeCollection(payload, ["events", "accessEvents"]));
      renderAccessEvents();
    } catch (error) {
      if (requestId !== state.access.requestId || [401, 403].includes(error.status)) return;
      elements.accessResultSummary.textContent = "访问记录加载失败";
      renderErrorRow(elements.accessRows, 4, error.message, "access");
      scheduleWorkspaceHeightCapture();
    }
  }

  function renderAuditEvents() {
    const events = state.audit.items;
    if (!events.length) {
      renderEmptyRow(elements.auditRows, 5, "暂无操作记录", "管理员尚未进行权限变更。");
      elements.auditResultSummary.textContent = "共 0 条记录";
      renderPagination(elements.auditPagination, state.audit, "audit");
      scheduleWorkspaceHeightCapture();
      return;
    }
    elements.auditRows.innerHTML = events
      .map((event) => {
        const detail = formatAuditDetail(event.detail);
        return `
          <tr>
            <td>${escapeHtml(event.actorEmail || "—")}</td>
            <td>${escapeHtml(event.targetEmail || "—")}</td>
            <td>${escapeHtml(actionLabel(event.action))}</td>
            <td>${escapeHtml(detail)}</td>
            <td>${escapeHtml(formatDate(event.createdAt, true))}</td>
          </tr>`;
      })
      .join("");
    elements.auditResultSummary.textContent = `共 ${state.audit.total} 条记录`;
    renderPagination(elements.auditPagination, state.audit, "audit");
    scheduleWorkspaceHeightCapture();
  }

  async function loadAuditEvents() {
    const requestId = ++state.audit.requestId;
    state.audit.loaded = true;
    renderLoadingRow(elements.auditRows, 5, "正在加载操作审计");
    elements.auditResultSummary.textContent = "正在加载操作审计…";
    elements.auditPagination.innerHTML = "";
    const query = new URLSearchParams({
      page: String(state.audit.page),
      pageSize: String(state.audit.pageSize),
    });
    try {
      const payload = await apiRequest(`/api/admin/audit-events?${query}`);
      if (requestId !== state.audit.requestId) return;
      Object.assign(state.audit, normalizeCollection(payload, ["events", "auditEvents"]));
      renderAuditEvents();
    } catch (error) {
      if (requestId !== state.audit.requestId || [401, 403].includes(error.status)) return;
      elements.auditResultSummary.textContent = "操作审计加载失败";
      renderErrorRow(elements.auditRows, 5, error.message, "audit");
      scheduleWorkspaceHeightCapture();
    }
  }

  function loadActivePanel() {
    if (state.activeTab === "users") return loadUsers();
    if (state.activeTab === "access") return loadAccessEvents();
    return loadAuditEvents();
  }

  function captureWorkspaceHeight({ reset = false } = {}) {
    if (!elements.workspace) return;
    if (reset) {
      state.workspaceMaxHeight = 0;
      elements.workspace.style.minHeight = "";
    }

    const height = Math.ceil(elements.workspace.getBoundingClientRect().height);
    if (height > state.workspaceMaxHeight) {
      state.workspaceMaxHeight = height;
      elements.workspace.style.minHeight = `${height}px`;
    }
  }

  function scheduleWorkspaceHeightCapture() {
    window.requestAnimationFrame(() => captureWorkspaceHeight());
  }

  function resetWorkspaceHeightAfterResize() {
    window.clearTimeout(state.workspaceResizeTimer);
    state.workspaceResizeTimer = window.setTimeout(() => {
      captureWorkspaceHeight({ reset: true });
    }, 160);
  }

  function activateTab(name, moveFocus = false) {
    if (!['users', 'access', 'audit'].includes(name)) name = "users";
    captureWorkspaceHeight();
    state.activeTab = name;
    elements.tabButtons.forEach((button) => {
      const active = button.dataset.tab === name;
      button.classList.toggle("is-active", active);
      button.setAttribute("aria-selected", String(active));
      button.tabIndex = active ? 0 : -1;
      if (active && moveFocus) button.focus();
    });
    elements.tabPanels.forEach((panel) => {
      panel.hidden = panel.dataset.panel !== name;
    });
    window.history.replaceState(null, "", `#${name}`);
    scheduleWorkspaceHeightCapture();
    if (name === "access" && !state.access.loaded) loadAccessEvents();
    if (name === "audit" && !state.audit.loaded) loadAuditEvents();
  }

  function findUser(userId) {
    return state.users.items.find(
      (user) => String(user.id ?? user.email) === String(userId),
    );
  }

  function openDialog(dialog, trigger) {
    state.returnFocus = trigger || document.activeElement;
    if (typeof dialog.showModal === "function") dialog.showModal();
    else dialog.setAttribute("open", "");
  }

  function closeDialog(dialog) {
    if (typeof dialog.close === "function") dialog.close();
    else dialog.removeAttribute("open");
    const returnFocus = state.returnFocus;
    state.returnFocus = null;
    window.setTimeout(() => returnFocus?.focus?.(), 0);
  }

  function askForConfirmation({ title, message, label, task, trigger, tone = "danger" }) {
    state.confirmTask = task;
    elements.confirmTitle.textContent = title;
    elements.confirmMessage.textContent = message;
    elements.confirmAction.textContent = label;
    elements.confirmAction.className = `button ${tone === "primary" ? "button-primary" : "button-danger"}`;
    openDialog(elements.confirmDialog, trigger);
  }

  async function patchUser(user, action, trigger) {
    if (!user || isSuperAdmin(user)) return;
    if (
      (action === "grant_admin" && (!state.canManageAdmins || isDynamicAdmin(user) || !isActiveUser(user))) ||
      (action === "revoke_admin" && (!state.canManageAdmins || !isDynamicAdmin(user))) ||
      (!["grant_admin", "revoke_admin"].includes(action) && isDynamicAdmin(user))
    ) {
      return;
    }
    setButtonBusy(trigger, true, "处理中…");
    try {
      await apiRequest(`/api/admin/users/${encodeURIComponent(user.id ?? user.email)}`, {
        method: "PATCH",
        body: JSON.stringify({ action }),
      });
      const successLabels = {
        disable: "已禁用该用户",
        restore: "已恢复该用户的观看权限",
        archive: "已归档该用户",
        grant_admin: "已设为管理员",
        revoke_admin: "已取消管理员权限",
      };
      showToast(successLabels[action] || "权限已更新");
      state.audit.loaded = false;
      await Promise.all([loadUsers(), loadOverview()]);
    } catch (error) {
      if (![401, 403].includes(error.status)) showToast(error.message, "error");
    } finally {
      setButtonBusy(trigger, false);
    }
  }

  function handleUserAction(button) {
    const user = findUser(button.dataset.userId);
    if (!user || isSuperAdmin(user)) return;
    const action = button.dataset.userAction;
    if (action === "grant_admin") {
      if (!state.canManageAdmins || isDynamicAdmin(user) || !isActiveUser(user)) return;
      askForConfirmation({
        title: "设为管理员",
        message: `授予后，${user.email} 可以进入管理后台并维护观看用户。`,
        label: "确认设为管理员",
        tone: "primary",
        trigger: button,
        task: () => patchUser(user, "grant_admin", button),
      });
      return;
    }
    if (action === "revoke_admin") {
      if (!state.canManageAdmins || !isDynamicAdmin(user)) return;
      askForConfirmation({
        title: "取消管理员",
        message: `取消后，${user.email} 将无法继续进入管理后台，但仍保留观看权限。`,
        label: "确认取消",
        trigger: button,
        task: () => patchUser(user, "revoke_admin", button),
      });
      return;
    }
    if (isDynamicAdmin(user)) return;
    if (action === "restore") {
      patchUser(user, "restore", button);
      return;
    }
    if (action === "disable") {
      askForConfirmation({
        title: "禁用观看权限",
        message: `禁用后，${user.email} 的页面和播放请求会在短时间内被拒绝。`,
        label: "确认禁用",
        trigger: button,
        task: () => patchUser(user, "disable", button),
      });
      return;
    }
    if (action === "archive") {
      askForConfirmation({
        title: "归档用户",
        message: `归档 ${user.email} 后仍会保留历史访问及审计记录，之后可以恢复。`,
        label: "确认归档",
        trigger: button,
        task: () => patchUser(user, "archive", button),
      });
    }
  }

  function parseEmails(value) {
    const candidates = value
      .split(/[\n,;]+/)
      .map((email) => email.trim().toLowerCase())
      .filter(Boolean);
    return [...new Set(candidates)];
  }

  async function submitUsers(event) {
    event.preventDefault();
    const emails = parseEmails(elements.addEmails.value);
    const invalid = emails.filter((email) => !isAllowedEmail(email));
    if (!emails.length) {
      elements.addFormError.textContent = "请至少填写一个邮箱地址。";
      elements.addFormError.hidden = false;
      elements.addEmails.focus();
      return;
    }
    if (invalid.length) {
      elements.addFormError.textContent = `以下邮箱无效或不属于 @${state.allowedEmailDomain}：${invalid.slice(0, 3).join("、")}${invalid.length > 3 ? " 等" : ""}`;
      elements.addFormError.hidden = false;
      elements.addEmails.focus();
      return;
    }
    elements.addFormError.hidden = true;
    setButtonBusy(elements.submitAddUsers, true, "正在添加…");
    try {
      const payload = await apiRequest("/api/admin/users", {
        method: "POST",
        body: JSON.stringify({ emails }),
      });
      const result = unwrapData(payload);
      const summary =
        result.summary && typeof result.summary === "object"
          ? result.summary
          : result;
      const added = Number(summary.added ?? summary.created ?? emails.length) || 0;
      const existing = Number(summary.existing ?? summary.skipped ?? 0) || 0;
      const invalidCount = Number(summary.invalid ?? 0) || 0;
      closeDialog(elements.addDialog);
      elements.addUserForm.reset();
      const resultParts = [`已添加 ${added} 位观看用户`];
      if (existing > 0) resultParts.push(`${existing} 位已存在`);
      if (invalidCount > 0) resultParts.push(`${invalidCount} 个地址无效`);
      showToast(resultParts.join("，"));
      state.users.page = 1;
      state.audit.loaded = false;
      await Promise.all([loadUsers(), loadOverview()]);
    } catch (error) {
      if (![401, 403].includes(error.status)) {
        elements.addFormError.textContent = error.message;
        elements.addFormError.hidden = false;
      }
    } finally {
      setButtonBusy(elements.submitAddUsers, false);
    }
  }

  async function submitConfirmation(event) {
    event.preventDefault();
    const task = state.confirmTask;
    if (!task) return;
    state.confirmTask = null;
    closeDialog(elements.confirmDialog);
    await task();
  }

  function handlePagination(event) {
    const button = event.target.closest("[data-page-type]");
    if (!button || button.disabled) return;
    const page = Number(button.dataset.page);
    if (!Number.isInteger(page) || page < 1) return;
    const type = button.dataset.pageType;
    state[type].page = page;
    if (type === "users") loadUsers();
    if (type === "access") loadAccessEvents();
    if (type === "audit") loadAuditEvents();
  }

  function bindEvents() {
    elements.openAddDialog.addEventListener("click", (event) => {
      elements.addFormError.hidden = true;
      openDialog(elements.addDialog, event.currentTarget);
      elements.addEmails.focus();
    });
    document.querySelectorAll("[data-close-dialog]").forEach((button) => {
      button.addEventListener("click", () => {
        const dialog = document.querySelector(`#${button.dataset.closeDialog}`);
        if (dialog) closeDialog(dialog);
      });
    });
    [elements.addDialog, elements.confirmDialog].forEach((dialog) => {
      dialog.addEventListener("click", (event) => {
        if (event.target === dialog) closeDialog(dialog);
      });
    });
    elements.addUserForm.addEventListener("submit", submitUsers);
    elements.confirmForm.addEventListener("submit", submitConfirmation);
    elements.userFilters.addEventListener("submit", (event) => {
      event.preventDefault();
      state.users.q = elements.userSearch.value.trim();
      state.users.status = elements.userStatus.value;
      state.users.page = 1;
      loadUsers();
    });
    elements.resetUserFilters.addEventListener("click", () => {
      elements.userFilters.reset();
      state.users.q = "";
      state.users.status = "";
      state.users.page = 1;
      loadUsers();
    });
    elements.userStatus.addEventListener("change", () => {
      state.users.status = elements.userStatus.value;
      state.users.q = elements.userSearch.value.trim();
      state.users.page = 1;
      loadUsers();
    });
    elements.userRows.addEventListener("click", (event) => {
      const action = event.target.closest("[data-user-action]");
      if (action) handleUserAction(action);
      const retry = event.target.closest('[data-retry="users"]');
      if (retry) loadUsers();
    });
    elements.accessRows.addEventListener("click", (event) => {
      if (event.target.closest('[data-retry="access"]')) loadAccessEvents();
    });
    elements.auditRows.addEventListener("click", (event) => {
      if (event.target.closest('[data-retry="audit"]')) loadAuditEvents();
    });
    elements.userPagination.addEventListener("click", handlePagination);
    elements.accessPagination.addEventListener("click", handlePagination);
    elements.auditPagination.addEventListener("click", handlePagination);
    elements.accessOutcome.addEventListener("change", () => {
      state.access.outcome = elements.accessOutcome.value;
      state.access.page = 1;
      loadAccessEvents();
    });
    elements.refreshOverview.addEventListener("click", loadOverview);
    elements.retryButton.addEventListener("click", () => {
      clearGlobalError();
      Promise.all([loadOverview(), loadActivePanel()]);
    });
    elements.tabList.addEventListener("click", (event) => {
      const button = event.target.closest("[data-tab]");
      if (button) activateTab(button.dataset.tab);
    });
    elements.tabList.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      const current = elements.tabButtons.findIndex((button) => button.dataset.tab === state.activeTab);
      let next = current;
      if (event.key === "ArrowLeft") next = (current - 1 + elements.tabButtons.length) % elements.tabButtons.length;
      if (event.key === "ArrowRight") next = (current + 1) % elements.tabButtons.length;
      if (event.key === "Home") next = 0;
      if (event.key === "End") next = elements.tabButtons.length - 1;
      activateTab(elements.tabButtons[next].dataset.tab, true);
    });
    window.addEventListener("resize", resetWorkspaceHeightAfterResize);
  }

  async function initialize() {
    bindEvents();
    try {
      const isAdmin = await loadMe();
      if (!isAdmin) return;
      const initialTab = window.location.hash.slice(1);
      activateTab(["users", "access", "audit"].includes(initialTab) ? initialTab : "users");
      await Promise.all([loadOverview(), loadUsers()]);
    } catch (error) {
      if (![401, 403].includes(error.status)) setGlobalError(error.message);
    } finally {
      elements.app.setAttribute("aria-busy", "false");
    }
  }

  initialize();
})();

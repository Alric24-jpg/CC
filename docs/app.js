(() => {
  "use strict";
  const API_BASE = String(window.TEMPDROP_CONFIG?.API_BASE_URL || "http://127.0.0.1:8000").replace(/\/+$/, "");
  const apiConfigSecure = !(window.location.protocol === "https:" && !API_BASE.startsWith("https://"));
  const MAX_BYTES = 100 * 1024 * 1024;
  const MAX_FILES = 20;
  const CODE_PATTERN = /^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{12}$/;
  const $ = (selector) => document.querySelector(selector);

  const fileInput = $("#file-input");
  const dropzone = $("#dropzone");
  const fileList = $("#file-list");
  const fileListWrap = $("#file-list-wrap");
  const uploadButton = $("#upload-button");
  const uploadError = $("#upload-error");
  const downloadError = $("#download-error");
  let selectedFiles = [];
  let createdExpiry = null;
  let countdownInterval = null;
  let toastTimeout = null;

  function formatBytes(bytes) {
    if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
    const units = ["B", "KB", "MB", "GB"];
    const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    const amount = bytes / (1024 ** index);
    return `${amount.toFixed(index === 0 || amount >= 10 ? 0 : 1)} ${units[index]}`;
  }

  function showMessage(element, message) {
    element.textContent = message;
    element.classList.remove("hidden");
  }
  function clearMessage(element) {
    element.textContent = "";
    element.classList.add("hidden");
  }
  function showToast(message) {
    const toast = $("#toast");
    toast.textContent = message;
    toast.classList.add("show");
    window.clearTimeout(toastTimeout);
    toastTimeout = window.setTimeout(() => toast.classList.remove("show"), 2300);
  }

  async function apiErrorMessage(response) {
    try {
      const data = await response.json();
      return typeof data.detail === "string" ? data.detail : `Request failed (${response.status}).`;
    } catch {
      return `Request failed (${response.status}). Check the backend URL and connection.`;
    }
  }

  function updateSelectedFiles() {
    const total = selectedFiles.reduce((sum, file) => sum + file.size, 0);
    fileList.replaceChildren();
    selectedFiles.forEach((file, index) => {
      const item = document.createElement("li");
      item.className = "file-item";
      const icon = document.createElement("span");
      icon.className = "file-icon";
      icon.setAttribute("aria-hidden", "true");
      icon.textContent = file.name.split(".").pop().slice(0, 3).toUpperCase() || "FILE";
      const info = document.createElement("span");
      info.className = "file-info";
      const name = document.createElement("strong");
      name.textContent = file.name;
      name.title = file.name;
      const size = document.createElement("small");
      size.textContent = formatBytes(file.size);
      info.append(name, size);
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "remove-file";
      remove.setAttribute("aria-label", `Remove ${file.name}`);
      remove.textContent = "×";
      remove.addEventListener("click", () => {
        selectedFiles.splice(index, 1);
        updateSelectedFiles();
      });
      item.append(icon, info, remove);
      fileList.append(item);
    });

    fileListWrap.classList.toggle("hidden", selectedFiles.length === 0);
    $("#file-count-label").textContent = `${selectedFiles.length} file${selectedFiles.length === 1 ? "" : "s"} selected`;
    $("#file-total-label").textContent = `${formatBytes(total)} / 100 MB`;
    $("#size-meter-fill").style.width = `${Math.min(100, (total / MAX_BYTES) * 100)}%`;
    const hasValidFiles = selectedFiles.length > 0 && selectedFiles.length <= MAX_FILES && total <= MAX_BYTES;
    uploadButton.disabled = !hasValidFiles || !apiConfigSecure;
    if (!apiConfigSecure) {
      showMessage(uploadError, "Configuration needed: set docs/config.js to your HTTPS backend tunnel URL before uploading.");
    } else if (selectedFiles.length > MAX_FILES) {
      showMessage(uploadError, `Choose ${MAX_FILES} files or fewer.`);
    } else if (total > MAX_BYTES) {
      showMessage(uploadError, "The combined file size exceeds 100 MB. Remove one or more files.");
    } else {
      clearMessage(uploadError);
    }
  }

  function addFiles(files) {
    const existing = new Set(selectedFiles.map((file) => `${file.name}:${file.size}:${file.lastModified}`));
    for (const file of files) {
      const key = `${file.name}:${file.size}:${file.lastModified}`;
      if (!existing.has(key)) selectedFiles.push(file);
      existing.add(key);
    }
    updateSelectedFiles();
  }

  fileInput.addEventListener("change", () => {
    addFiles(Array.from(fileInput.files || []));
    fileInput.value = "";
  });
  ["dragenter", "dragover"].forEach((eventName) => dropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropzone.classList.add("dragover");
  }));
  ["dragleave", "drop"].forEach((eventName) => dropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropzone.classList.remove("dragover");
  }));
  dropzone.addEventListener("drop", (event) => addFiles(Array.from(event.dataTransfer?.files || [])));

  document.querySelectorAll(".mode-tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      const mode = tab.dataset.mode;
      document.querySelectorAll(".mode-tab").forEach((other) => {
        const active = other === tab;
        other.classList.toggle("active", active);
        other.setAttribute("aria-selected", String(active));
      });
      $("#send-panel").classList.toggle("hidden", mode !== "send");
      $("#receive-panel").classList.toggle("hidden", mode !== "receive");
    });
  });

  $("#upload-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    clearMessage(uploadError);
    if (!selectedFiles.length) {
      showMessage(uploadError, "Select at least one file first.");
      return;
    }
    const total = selectedFiles.reduce((sum, file) => sum + file.size, 0);
    if (selectedFiles.length > MAX_FILES || total > MAX_BYTES) {
      updateSelectedFiles();
      return;
    }

    const formData = new FormData();
    selectedFiles.forEach((file) => formData.append("files", file, file.name));
    uploadButton.disabled = true;
    uploadButton.querySelector("span:first-child").textContent = "Encrypting and uploading…";

    try {
      const response = await fetch(`${API_BASE}/api/transfers`, {
        method: "POST",
        body: formData,
        cache: "no-store",
        credentials: "omit",
      });
      if (!response.ok) throw new Error(await apiErrorMessage(response));
      const result = await response.json();
      $("#result-code").textContent = result.transfer_code;
      $("#result-pin").textContent = result.pin;
      createdExpiry = new Date(result.expires_at).getTime();
      $("#upload-result").classList.remove("hidden");
      dropzone.classList.add("hidden");
      fileListWrap.classList.add("hidden");
      $(".size-meter").classList.add("hidden");
      uploadButton.classList.add("hidden");
      $(".microcopy").classList.add("hidden");
      startCountdown();
      $("#upload-result").scrollIntoView({ behavior: "smooth", block: "nearest" });
    } catch (error) {
      showMessage(uploadError, error instanceof Error ? error.message : "Upload failed. Try again.");
      uploadButton.disabled = false;
    } finally {
      uploadButton.querySelector("span:first-child").textContent = "Upload and create PIN";
    }
  });

  function startCountdown() {
    window.clearInterval(countdownInterval);
    const tick = () => {
      const seconds = Math.max(0, Math.ceil((createdExpiry - Date.now()) / 1000));
      const hours = Math.floor(seconds / 3600);
      const minutes = Math.floor((seconds % 3600) / 60);
      const remainder = seconds % 60;
      $("#expiry-countdown").textContent = seconds > 0
        ? `${hours}:${String(minutes).padStart(2, "0")}:${String(remainder).padStart(2, "0")} remaining`
        : "Expired — files are being deleted";
      if (seconds <= 0) window.clearInterval(countdownInterval);
    };
    tick();
    countdownInterval = window.setInterval(tick, 1000);
  }

  document.querySelectorAll("[data-copy]").forEach((button) => {
    button.addEventListener("click", async () => {
      const value = button.dataset.copy === "code" ? $("#result-code").textContent : $("#result-pin").textContent;
      try {
        await navigator.clipboard.writeText(value);
        showToast(`${button.dataset.copy === "code" ? "Transfer code" : "PIN"} copied.`);
      } catch {
        showToast("Copy is unavailable in this browser. Select and copy the value manually.");
      }
    });
  });

  $("#new-transfer-button").addEventListener("click", () => {
    window.clearInterval(countdownInterval);
    createdExpiry = null;
    selectedFiles = [];
    updateSelectedFiles();
    $("#upload-result").classList.add("hidden");
    dropzone.classList.remove("hidden");
    $(".size-meter").classList.remove("hidden");
    uploadButton.classList.remove("hidden");
    $(".microcopy").classList.remove("hidden");
    uploadButton.disabled = true;
    $("#result-code").textContent = "—";
    $("#result-pin").textContent = "—";
    clearMessage(uploadError);
    window.scrollTo({ top: 0, behavior: "smooth" });
  });

  $("#transfer-code-input").addEventListener("input", (event) => {
    const value = event.target.value.toUpperCase().replace(/[^23456789ABCDEFGHJKLMNPQRSTUVWXYZ]/g, "").slice(0, 12);
    event.target.value = value;
  });
  $("#pin-input").addEventListener("input", (event) => {
    event.target.value = event.target.value.replace(/\D/g, "").slice(0, 4);
  });

  $("#download-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    clearMessage(downloadError);
    if (!apiConfigSecure) {
      showMessage(downloadError, "Configuration needed: set docs/config.js to your HTTPS backend tunnel URL before downloading.");
      return;
    }
    const code = $("#transfer-code-input").value.trim().toUpperCase();
    const pin = $("#pin-input").value;
    if (!CODE_PATTERN.test(code)) {
      showMessage(downloadError, "Enter the 12-character transfer code.");
      return;
    }
    if (!/^\d{4}$/.test(pin)) {
      showMessage(downloadError, "Enter the four-digit PIN.");
      return;
    }

    const button = $("#download-button");
    button.disabled = true;
    button.querySelector("span:first-child").textContent = "Verifying and preparing ZIP…";
    try {
      const response = await fetch(`${API_BASE}/api/transfers/${encodeURIComponent(code)}/download`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pin }),
        cache: "no-store",
        credentials: "omit",
      });
      if (!response.ok) throw new Error(await apiErrorMessage(response));
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `TempDrop_${code}.zip`;
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
      showToast("Download started. The ZIP is ready in your downloads.");
      $("#pin-input").value = "";
    } catch (error) {
      showMessage(downloadError, error instanceof Error ? error.message : "Download failed. Check the code, PIN, and expiry.");
    } finally {
      button.disabled = false;
      button.querySelector("span:first-child").textContent = "Verify and download ZIP";
    }
  });

  // An HTTPS frontend must not silently send files to a plaintext API endpoint.
  if (!apiConfigSecure) {
    showMessage(uploadError, "Configuration needed: set docs/config.js to your HTTPS backend tunnel URL before uploading.");
    showMessage(downloadError, "Configuration needed: set docs/config.js to your HTTPS backend tunnel URL before downloading.");
    uploadButton.disabled = true;
    $("#download-button").disabled = true;
  }
})();

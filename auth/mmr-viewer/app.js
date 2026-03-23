const fileInput = document.querySelector("#fileInput");
const loadSampleButton = document.querySelector("#loadSampleButton");
const renderJsonButton = document.querySelector("#renderJsonButton");
const resetButton = document.querySelector("#resetButton");
const jsonInput = document.querySelector("#jsonInput");
const statusText = document.querySelector("#statusText");

const rootHash = document.querySelector("#rootHash");
const leafCount = document.querySelector("#leafCount");
const mountainCount = document.querySelector("#mountainCount");
const peakCount = document.querySelector("#peakCount");
const baggingCount = document.querySelector("#baggingCount");
const peaksStrip = document.querySelector("#peaksStrip");
const mountainsCanvas = document.querySelector("#mountainsCanvas");
const eventList = document.querySelector("#eventList");
const detailsCard = document.querySelector("#detailsCard");

const demoStore = {
  events: [
    { device_id: "DEV-001", decision: "registered", weight: 248, timestamp: "2026-03-24T10:00:00Z" },
    { device_id: "DEV-002", decision: "registered", weight: 252, timestamp: "2026-03-24T10:02:00Z" },
    { device_id: "DEV-003", decision: "registered", weight: 241, timestamp: "2026-03-24T10:03:30Z" },
    { device_id: "DEV-001", decision: "authenticated", weight: 248, timestamp: "2026-03-24T10:05:00Z" },
    { device_id: "DEV-004", decision: "registered", weight: 255, timestamp: "2026-03-24T10:07:00Z" },
    { device_id: "DEV-003", decision: "rejected", weight: 241, timestamp: "2026-03-24T10:09:00Z" },
    { device_id: "DEV-005", decision: "registered", weight: 244, timestamp: "2026-03-24T10:12:00Z" }
  ]
};

let activeNodeElement = null;

fileInput.addEventListener("change", handleFileUpload);
loadSampleButton.addEventListener("click", () => {
  jsonInput.value = JSON.stringify(demoStore, null, 2);
  renderFromInput("Loaded demo MMR event set.");
});
renderJsonButton.addEventListener("click", () => renderFromInput("Rendered JSON input."));
resetButton.addEventListener("click", resetViewer);

resetViewer();

async function handleFileUpload(event) {
  const [file] = event.target.files ?? [];
  if (!file) {
    return;
  }
  const text = await file.text();
  jsonInput.value = text;
  renderFromInput(`Loaded ${file.name}.`);
}

async function renderFromInput(successPrefix) {
  try {
    const parsed = JSON.parse(jsonInput.value);
    const events = normalizeEvents(parsed);
    if (events.length === 0) {
      throw new Error("No events found.");
    }
    const model = await buildMMRModel(events);
    renderModel(model);
    setStatus(`${successPrefix} ${events.length} event(s) mapped into ${model.mountains.length} mountain(s).`, "ok");
  } catch (error) {
    setStatus(error.message, "error");
  }
}

function normalizeEvents(parsed) {
  const rawEvents = Array.isArray(parsed) ? parsed : parsed?.events;
  if (!Array.isArray(rawEvents)) {
    throw new Error("Expected an array of events or an object with an events array.");
  }

  return rawEvents.map((event, index) => {
    if (!event || typeof event !== "object") {
      throw new Error(`Event ${index} is not an object.`);
    }
    const normalized = {
      device_id: String(event.device_id ?? "").trim(),
      decision: String(event.decision ?? "").trim(),
      weight: Number(event.weight ?? 0),
      timestamp: toISOString(event.timestamp)
    };

    if (!normalized.device_id || !normalized.decision || !normalized.timestamp) {
      throw new Error(`Event ${index} is missing device_id, decision, or timestamp.`);
    }
    return normalized;
  });
}

function toISOString(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "";
  }
  return date.toISOString();
}

async function buildMMRModel(events) {
  const leafHashes = [];
  for (const event of events) {
    leafHashes.push(await hashEvent(event));
  }

  const mountains = [];
  let offset = 0;
  let remaining = leafHashes.length;
  let mountainIndex = 0;
  while (remaining > 0) {
    const size = largestPowerOfTwoLE(remaining);
    const mountainLeaves = leafHashes.slice(offset, offset + size);
    const levels = await buildMerkleLevels(
      mountainLeaves,
      events.slice(offset, offset + size),
      offset,
      mountainIndex
    );
    mountains.push({
      index: mountainIndex,
      start: offset,
      end: offset + size,
      size,
      levels,
      peakHash: levels[levels.length - 1][0].hash
    });
    offset += size;
    remaining -= size;
    mountainIndex += 1;
  }

  const peaks = mountains.map((mountain) => mountain.peakHash);
  const root = await bagPeaks(peaks);

  return { events, leafHashes, mountains, peaks, root };
}

async function hashEvent(event) {
  const encoded = new TextEncoder().encode(JSON.stringify(event));
  const buffer = await crypto.subtle.digest("SHA-256", encoded);
  return toHex(buffer);
}

async function hashPair(leftHex, rightHex) {
  const leftBytes = fromHex(leftHex);
  const rightBytes = fromHex(rightHex);
  const merged = new Uint8Array(leftBytes.length + rightBytes.length);
  merged.set(leftBytes);
  merged.set(rightBytes, leftBytes.length);
  const buffer = await crypto.subtle.digest("SHA-256", merged);
  return toHex(buffer);
}

async function buildMerkleLevels(leafHashes, events, globalOffset, mountainIndex) {
  const levels = [];
  let currentLevel = leafHashes.map((hash, leafOffset) => ({
    hash,
    type: "leaf",
    localIndex: leafOffset,
    globalIndex: globalOffset + leafOffset,
    event: events[leafOffset]
  }));

  levels.push(currentLevel);

  while (currentLevel.length > 1) {
    const nextLevel = [];
    for (let i = 0; i < currentLevel.length; i += 2) {
      const left = currentLevel[i];
      const right = currentLevel[i + 1];
      nextLevel.push({
        hash: null,
        type: "internal",
        left,
        right,
        localIndex: i / 2,
        mountainIndex
      });
    }
    levels.push(nextLevel);
    currentLevel = nextLevel;
  }

  return resolveLevelHashes(levels);
}

async function bagPeaks(peaks) {
  if (peaks.length === 0) {
    return "0".repeat(64);
  }

  let root = peaks[peaks.length - 1];
  for (let i = peaks.length - 2; i >= 0; i -= 1) {
    root = await hashPair(peaks[i], root);
  }
  return root;
}

async function resolveLevelHashes(levels) {
  for (let levelIndex = 1; levelIndex < levels.length; levelIndex += 1) {
    for (const node of levels[levelIndex]) {
      node.hash = await hashPair(node.left.hash, node.right.hash);
    }
  }
  return levels;
}

function renderModel(model) {
  rootHash.textContent = model.root;
  leafCount.textContent = String(model.events.length);
  mountainCount.textContent = String(model.mountains.length);
  peakCount.textContent = String(model.peaks.length);
  baggingCount.textContent = String(Math.max(model.peaks.length - 1, 0));

  renderPeaks(model);
  renderEvents(model);
  renderMountains(model);
  detailsCard.className = "details-card empty-state";
  detailsCard.textContent = "No node selected.";
}

function renderPeaks(model) {
  if (model.peaks.length === 0) {
    peaksStrip.innerHTML = '<div class="empty-state">No peaks.</div>';
    return;
  }

  peaksStrip.innerHTML = "";
  model.peaks.forEach((peak, index) => {
    const card = document.createElement("article");
    card.className = "peak-card";
    card.innerHTML = `
      <div class="peak-caption">Peak ${index}</div>
      <code>${peak}</code>
    `;
    peaksStrip.appendChild(card);
  });
}

function renderEvents(model) {
  eventList.className = "event-list";
  eventList.innerHTML = "";
  model.events.forEach((event, index) => {
    const item = document.createElement("article");
    item.className = "event-item";
    item.innerHTML = `
      <strong>Leaf ${index} · ${escapeHtml(event.device_id)}</strong>
      <p>${escapeHtml(event.decision)} · weight ${event.weight} · ${escapeHtml(event.timestamp)}</p>
      <code>${shortHash(model.leafHashes[index])}</code>
    `;
    eventList.appendChild(item);
  });
}

function renderMountains(model) {
  mountainsCanvas.className = "mountains-canvas";
  mountainsCanvas.innerHTML = "";

  for (const mountain of model.mountains) {
    const levels = mountain.levels;
    const card = document.createElement("article");
    card.className = "mountain";

    const header = document.createElement("div");
    header.className = "mountain-header";
    header.innerHTML = `
      <h3>Mountain ${mountain.index}</h3>
      <div class="mountain-meta">Leaves ${mountain.start}-${mountain.end - 1} · size ${mountain.size} · peak ${shortHash(levels[levels.length - 1][0].hash)}</div>
    `;
    card.appendChild(header);

    const levelsEl = document.createElement("div");
    levelsEl.className = "mountain-levels";

    for (let levelIndex = levels.length - 1; levelIndex >= 0; levelIndex -= 1) {
      const level = levels[levelIndex];
      const rowWrap = document.createElement("div");

      const tag = document.createElement("div");
      tag.className = "level-tag";
      tag.textContent = levelIndex === 0 ? "Leaves" : `Level ${levelIndex}`;
      rowWrap.appendChild(tag);

      const row = document.createElement("div");
      row.className = "level-row";
      row.style.gridTemplateColumns = `repeat(${level.length}, minmax(120px, 1fr))`;

      level.forEach((node, nodeIndex) => {
        const nodeEl = buildNodeElement(node, levelIndex, nodeIndex, mountain.index);
        row.appendChild(nodeEl);
      });

      rowWrap.appendChild(row);
      levelsEl.appendChild(rowWrap);
    }

    card.appendChild(levelsEl);
    mountainsCanvas.appendChild(card);
  }
}

function buildNodeElement(node, levelIndex, nodeIndex, mountainIndex) {
  const el = document.createElement("button");
  el.type = "button";
  el.className = "node";
  el.innerHTML = `
    <span class="node-title">
      <span>${levelIndex === 0 ? `Leaf ${node.globalIndex}` : `Node ${nodeIndex}`}</span>
      <span class="node-badge">${levelIndex === 0 ? node.event.decision : "peak path"}</span>
    </span>
    <code>${shortHash(node.hash)}</code>
    <div class="node-meta">${levelIndex === 0 ? escapeHtml(node.event.device_id) : `Mountain ${mountainIndex} · level ${levelIndex}`}</div>
  `;

  el.addEventListener("click", () => {
    if (activeNodeElement) {
      activeNodeElement.classList.remove("is-active");
    }
    el.classList.add("is-active");
    activeNodeElement = el;
    renderNodeDetails(node, levelIndex, mountainIndex);
  });

  return el;
}

function renderNodeDetails(node, levelIndex, mountainIndex) {
  detailsCard.className = "details-card";
  const rows = [
    ["Mountain", String(mountainIndex)],
    ["Level", String(levelIndex)],
    ["Hash", `<code>${escapeHtml(node.hash)}</code>`]
  ];

  if (levelIndex === 0) {
    rows.push(["Leaf Index", String(node.globalIndex)]);
    rows.push(["Device", escapeHtml(node.event.device_id)]);
    rows.push(["Decision", escapeHtml(node.event.decision)]);
    rows.push(["Weight", String(node.event.weight)]);
    rows.push(["Timestamp", escapeHtml(node.event.timestamp)]);
  } else {
    rows.push(["Left Child", `<code>${escapeHtml(node.left.hash)}</code>`]);
    rows.push(["Right Child", `<code>${escapeHtml(node.right.hash)}</code>`]);
  }

  detailsCard.innerHTML = `
    <div class="details-grid">
      ${rows
        .map(
          ([key, value]) => `
            <div class="details-key">${key}</div>
            <div class="details-value">${value}</div>
          `
        )
        .join("")}
    </div>
  `;
}

function resetViewer() {
  jsonInput.value = "";
  rootHash.textContent = "No data loaded";
  leafCount.textContent = "0";
  mountainCount.textContent = "0";
  peakCount.textContent = "0";
  baggingCount.textContent = "0";
  peaksStrip.innerHTML = "";
  mountainsCanvas.className = "mountains-canvas empty-state";
  mountainsCanvas.textContent = "Load data to render the structure.";
  eventList.className = "event-list empty-state";
  eventList.textContent = "No events loaded.";
  detailsCard.className = "details-card empty-state";
  detailsCard.textContent = "No node selected.";
  setStatus("Waiting for data.", "");
  if (activeNodeElement) {
    activeNodeElement.classList.remove("is-active");
    activeNodeElement = null;
  }
}

function setStatus(message, state) {
  statusText.textContent = message;
  statusText.className = "status";
  if (state === "error") {
    statusText.classList.add("is-error");
  }
  if (state === "ok") {
    statusText.classList.add("is-ok");
  }
}

function largestPowerOfTwoLE(n) {
  let size = 1;
  while (size * 2 <= n) {
    size *= 2;
  }
  return size;
}

function shortHash(hex) {
  return `${hex.slice(0, 12)}...${hex.slice(-10)}`;
}

function toHex(buffer) {
  return Array.from(new Uint8Array(buffer), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex) {
  const pairs = hex.match(/.{1,2}/g) ?? [];
  return Uint8Array.from(pairs.map((pair) => Number.parseInt(pair, 16)));
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

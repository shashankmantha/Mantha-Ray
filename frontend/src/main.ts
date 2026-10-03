import "bootstrap/dist/css/bootstrap.min.css";
import "./styles.css";

import { api } from "./api";
import { analyzer, objectValue } from "./risk";
import {
  createScanController,
  isTerminalState,
} from "./scanController";
import {
  allSessions,
  appendSession,
  getActiveScanId,
  getSelectedScanId,
  getSession,
  hasSession,
  orderedSessionIds,
  removeHistoricalSessions,
  setSelectedScanId,
} from "./sessionStore";
import type {
  CaseHistoryResponse,
  JsonObject,
  ScanEvent,
  ScanSession,
  ScanState,
  StageName,
  StageStatus,
} from "./types";
import {
  configureArtifactTreePopout,
  renderArtifactTree,
  setArtifactTreePoppedOut,
} from "./ui/artifactTree";
import { element } from "./ui/elements";

const stageOrder: readonly StageName[] = [
  "inventory",
  "clamav",
  "capa",
  "floss",
  "report",
];

const stageLabels: Record<StageName, string> = {
  inventory: "Inventory",
  clamav: "ClamAV",
  capa: "capa",
  floss: "FLOSS",
  report: "Report",
};

const setupView = element<HTMLElement>("setup-view");

const scanView = element<HTMLElement>("scan-view");

const scanList = element<HTMLDivElement>("scan-list");

const scanListEmpty = element<HTMLParagraphElement>(
  "scan-list-empty",
);

const scanCount = element<HTMLSpanElement>("scan-count");

const newScanButton = element<HTMLButtonElement>("new-scan");

const sourceInput = element<HTMLInputElement>("source-path");

const resultsInput = element<HTMLInputElement>("results-path");

const chooseSource = element<HTMLButtonElement>("choose-source");

const chooseResults = element<HTMLButtonElement>("choose-results");

const startButton = element<HTMLButtonElement>("start-scan");

const cancelButton = element<HTMLButtonElement>("cancel-scan");

const openCaseButton = element<HTMLButtonElement>("open-case");

const fatalAlert = element<HTMLDivElement>("fatal-alert");

const serviceBadge = element<HTMLSpanElement>("service-badge");

const progressWrap = element<HTMLElement>("progress-wrap");

const progressMessage = element<HTMLSpanElement>("progress-message");

const progressState = element<HTMLSpanElement>("progress-state");

const resultsSection = element<HTMLElement>("results-section");

const liveActivityPanel = element<HTMLPreElement>(
  "live-activity-panel",
);

const activityAutoscrollButton =
  element<HTMLButtonElement>(
    "activity-autoscroll",
  );

const copyActivityButton =
  element<HTMLButtonElement>(
    "copy-activity",
  );

let activityAutoScroll = true;

function showError(message: string): void {
  fatalAlert.textContent = message;
  fatalAlert.classList.remove("d-none");
}

function clearError(): void {
  fatalAlert.textContent = "";
  fatalAlert.classList.add("d-none");
}

async function establishSession(): Promise<void> {
  const url = new URL(window.location.href);
  const token = url.searchParams.get("token");
  url.searchParams.delete("token");
  window.history.replaceState(
    {},
    "",
    `${url.pathname}${url.search}${url.hash}`,
  );
  if (!token) {
    await api<{ application_name: string }>(
      "/api/config",
    );
    return;
  }
  await api<{ ok: boolean }>("/api/session", {
    method: "POST",
    headers: {
      "X-Mantha-Ray-Token": token,
    },
    body: "{}",
  });
}

async function loadConfiguration(): Promise<void> {
  const config = await api<{
    default_results_directory: string;
  }>("/api/config");
  resultsInput.value = config.default_results_directory;
}

async function checkHealth(): Promise<void> {
  const health = await api<{
    ok: boolean;
    docker_version?: string;
    error?: string;
  }>("/api/health");
  if (health.ok) {
    scanController.setServiceReady(true);
    serviceBadge.textContent =
      `Docker ${health.docker_version ?? "ready"}`;
    serviceBadge.className = "status-chip status-good";
    updateControlState();
    return;
  }
  scanController.setServiceReady(false);
  serviceBadge.textContent = "Docker unavailable";
  serviceBadge.className = "status-chip status-danger";
  updateControlState();
  showError(health.error ?? "Docker preflight failed.");
}

async function selectDirectory(
  purpose: "source" | "results",
  input: HTMLInputElement,
): Promise<void> {
  clearError();
  const response = await api<{ path: string | null }>(
    "/api/dialogs/directory",
    {
      method: "POST",
      body: JSON.stringify({
        purpose,
        current_path: input.value || null,
      }),
    },
  );
  if (response.path) {
    input.value = response.path;
    if (purpose === "results") {
      await loadHistory();
    }
  }
}

function statusText(session: ScanSession): string {
  if (
    session.state.state === "loading"
    || session.state.state === "failed"
  ) {
    return session.state.state;
  }
  const resultStatus = session.state.result?.status;
  if (resultStatus) {
    return resultStatus.replaceAll("_", " ");
  }
  if (session.persistedStatus) {
    return session.persistedStatus.replaceAll("_", " ");
  }
  return session.state.state.replaceAll("_", " ");
}

function statusKind(session: ScanSession): string {
  if (session.state.state === "loading") {
    return "running";
  }
  if (session.state.state === "failed") {
    return "danger";
  }
  const value = session.state.result?.status
    ?? session.persistedStatus
    ?? session.state.state;
  if (
    value === "no_indicators_detected"
    || value === "clean"
    || value === "completed"
  ) {
    return "good";
  }
  if (
    value === "known_detection"
    || value === "high_concern"
    || value === "failed"
  ) {
    return "danger";
  }
  if (value === "cancelled") {
    return "muted";
  }
  if (value === "unknown") {
    return "muted";
  }
  if (value === "needs_review") {
    return "warning";
  }
  return "running";
}

function formatSessionTime(date: Date): string {
  const now = new Date();
  if (
    date.getFullYear() !== now.getFullYear()
    || date.getMonth() !== now.getMonth()
    || date.getDate() !== now.getDate()
  ) {
    return date.toLocaleDateString([], {
      month: "short",
      day: "numeric",
    });
  }
  return date.toLocaleTimeString([], {
    hour: "numeric",
    minute: "2-digit",
  });
}

function renderSessionList(): void {
  scanList.replaceChildren();
  const sessionOrder = orderedSessionIds();
  scanCount.textContent = String(sessionOrder.length);
  scanListEmpty.classList.toggle(
    "d-none",
    sessionOrder.length > 0,
  );
  for (const id of sessionOrder) {
    const session = getSession(id);
    if (!session) {
      continue;
    }
    const button = document.createElement("button");
    button.type = "button";
    button.className = "scan-tab";
    button.dataset.scanId = id;
    button.setAttribute(
      "aria-selected",
      String(getSelectedScanId() === id),
    );
    const dot = document.createElement("span");
    dot.className = `scan-dot scan-dot-${statusKind(session)}`;
    dot.setAttribute("aria-hidden", "true");
    const copy = document.createElement("span");
    copy.className = "scan-tab-copy";
    const title = document.createElement("strong");
    title.textContent = session.label;
    const meta = document.createElement("small");
    meta.textContent =
      `${statusText(session)} · ${formatSessionTime(session.startedAt)}`;
    copy.append(title, meta);
    button.append(dot, copy);
    button.addEventListener("click", () => {
      void selectSession(id);
    });
    scanList.append(button);
  }
}

async function loadHistory(): Promise<void> {
  const resultsDirectory = resultsInput.value;
  removeHistoricalSessions();
  if (!resultsDirectory) {
    renderSessionList();
    return;
  }
  const history = await api<CaseHistoryResponse>(
    "/api/cases",
    {
      method: "POST",
      body: JSON.stringify({
        results_directory: resultsDirectory,
      }),
    },
  );
  const knownCaseIds = new Set(
    Array.from(allSessions())
      .map((session) =>
        session.state.result?.case_id
        ?? session.caseId,
      )
      .filter((value): value is string =>
        typeof value === "string",
      ),
  );
  for (const entry of history.cases) {
    if (knownCaseIds.has(entry.case_id)) {
      continue;
    }
    const id = `case:${entry.case_id}`;
    const startedAt = new Date(entry.created_at);
    const validStartedAt = Number.isNaN(
      startedAt.getTime(),
    )
      ? new Date()
      : startedAt;
    appendSession({
      id,
      label: entry.label,
      sourcePath: entry.source_directory ?? "",
      startedAt: validStartedAt,
      state: {
        scan_id: entry.case_id,
        state: "completed",
        message: "Saved scan results are available.",
        events: [],
        result: null,
        error: null,
      },
      historical: true,
      loaded: false,
      caseId: entry.case_id,
      resultsDirectory,
      persistedStatus: entry.status,
    });
  }
  renderSessionList();
}

function updateControlState(): void {
  const scanning = getActiveScanId() !== null;
  chooseSource.disabled = scanning;
  chooseResults.disabled = scanning;
  newScanButton.disabled = scanning;
  startButton.disabled = scanning || !scanController.isServiceReady();
}

function showSetup(resetSource = false): void {
  clearError();
  setArtifactTreePoppedOut(false);
  setSelectedScanId(null);
  setupView.classList.remove("d-none");
  scanView.classList.add("d-none");
  if (resetSource) {
    sourceInput.value = "";
  }
  renderSessionList();
  updateControlState();
}

async function selectSession(id: string): Promise<void> {
  if (!hasSession(id)) {
    return;
  }
  clearError();
  setArtifactTreePoppedOut(false);
  setSelectedScanId(id);
  setupView.classList.add("d-none");
  scanView.classList.remove("d-none");
  renderSessionList();
  const session = getSession(id);
  if (
    session?.historical
    && !session.loaded
    && session.caseId
  ) {
    session.state.state = "loading";
    session.state.message = "Loading saved report...";
    renderSessionList();
    renderSelectedSession();
    try {
      session.state = await api<ScanState>(
        `/api/cases/${session.caseId}`,
        {
          method: "POST",
          body: JSON.stringify({
            results_directory:
              session.resultsDirectory,
          }),
        },
      );
      session.loaded = true;
      session.persistedStatus =
        session.state.result?.status
        ?? session.persistedStatus;
    } catch (error) {
      const message = error instanceof Error
        ? error.message
        : String(error);
      session.state.state = "failed";
      session.state.error = message;
      session.state.message = message;
    }
    renderSessionList();
  }
  renderSelectedSession();
}

function renderSelectedSession(): void {
  const selectedScanId = getSelectedScanId();
  if (!selectedScanId) {
    return;
  }
  const session = getSession(selectedScanId);
  if (!session) {
    return;
  }
  element("scan-title").textContent = session.label;
  const result = session.state.result;
  element("case-id").textContent = result?.case_id
    ?? session.state.scan_id;
  const verdict = element("verdict-badge");
  verdict.textContent = statusText(session).toUpperCase();
  verdict.className =
    `verdict verdict-${statusKind(session)}`;
  const terminal = isTerminalState(session.state.state);
  progressWrap.classList.toggle("d-none", terminal);
  cancelButton.classList.toggle(
    "d-none",
    session.id !== getActiveScanId(),
  );
  if (!terminal) {
    resultsSection.classList.add("d-none");
    renderProgress(session.state);
    openCaseButton.classList.add("d-none");
    return;
  }
  if (session.state.state === "completed" && result) {
    renderResult(session.state);
    openCaseButton.classList.remove("d-none");
    return;
  }
  resultsSection.classList.add("d-none");
  openCaseButton.classList.add("d-none");
  showError(session.state.error ?? session.state.message);
}

function stageStatusText(status: StageStatus): string {
  switch (status) {
    case "waiting":
      return "Waiting";
    case "running":
      return "Running";
    case "completed":
      return "Completed";
    case "incomplete":
      return "Incomplete";
    case "unavailable":
      return "Unavailable";
    case "error":
      return "Error";
    case "cancelled":
      return "Cancelled";
  }
}

function renderStageTracker(state: ScanState): void {
  for (const stage of stageOrder) {
    const status = state.stages?.[stage] ?? "waiting";
    const row = element<HTMLElement>(
      `stage-${stage}`,
    );
    const statusElement = element<HTMLElement>(
      `stage-${stage}-status`,
    );
    row.className =
      `stage-step stage-state-${status}`;
    row.setAttribute(
      "aria-label",
      `${stageLabels[stage]}: ${stageStatusText(status)}`,
    );
    statusElement.textContent =
      stageStatusText(status);
  }
}


function sanitizeActivityMessage(
  message: string,
): string {
  return message.replace(
    /[\u0000-\u001f\u007f-\u009f]/g,
    "�",
  );
}

function activityEventLine(
  event: ScanEvent,
): string {
  const timestamp = new Date(event.time);

  const displayTime = Number.isNaN(
    timestamp.getTime(),
  )
    ? event.time
    : timestamp.toLocaleTimeString();

  return (
    `[${displayTime}] `
    + sanitizeActivityMessage(event.message)
  );
}

function activityText(
  events: readonly ScanEvent[],
): string {
  if (events.length === 0) {
    return "[waiting] No activity received yet.";
  }

  return events
    .map(activityEventLine)
    .join("\n");
}

function scrollActivityToBottom(): void {
  liveActivityPanel.scrollTop =
    liveActivityPanel.scrollHeight;
}

function setActivityAutoScroll(
  enabled: boolean,
): void {
  activityAutoScroll = enabled;

  activityAutoscrollButton.textContent = enabled
    ? "Auto-scroll: on"
    : "Auto-scroll: paused";

  activityAutoscrollButton.setAttribute(
    "aria-pressed",
    String(enabled),
  );

  if (enabled) {
    scrollActivityToBottom();
  }
}

function renderLiveActivity(
  state: ScanState,
): void {
  liveActivityPanel.textContent = activityText(
    state.events,
  );

  if (activityAutoScroll) {
    scrollActivityToBottom();
  }
}

async function copyLiveActivity(): Promise<void> {
  const output = liveActivityPanel.textContent ?? "";

  if (!output) {
    return;
  }

  const originalLabel =
    copyActivityButton.textContent ?? "Copy";

  try {
    await navigator.clipboard.writeText(output);

    copyActivityButton.textContent = "Copied";

    window.setTimeout(() => {
      copyActivityButton.textContent = originalLabel;
    }, 1500);
  } catch {
    showError(
      "The activity output could not be copied.",
    );
  }
}

activityAutoscrollButton.addEventListener(
  "click",
  () => {
    setActivityAutoScroll(!activityAutoScroll);
  },
);

copyActivityButton.addEventListener(
  "click",
  () => {
    void copyLiveActivity();
  },
);

function renderProgress(state: ScanState): void {
  renderStageTracker(state);

  progressMessage.textContent = state.message;
  progressState.textContent =
    state.state.toUpperCase();

  renderLiveActivity(state);
}



function numberValue(value: unknown): string {
  return typeof value === "number"
    ? value.toLocaleString()
    : "—";
}

function analyzerStatus(
  data: JsonObject | null,
): string {
  if (!data) {
    return "Completed";
  }
  if (data.complete === false) {
    return "Incomplete";
  }
  const value = typeof data.status === "string"
    ? data.status
    : "completed";
  return value
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function analyzerDescription(
  data: JsonObject | null,
  name: "clamav" | "capa" | "floss",
): string {
  if (!data) {
    return "See full report";
  }
  if (typeof data.error === "string" && data.error) {
    return data.error;
  }
  if (name === "clamav") {
    const findings = Array.isArray(data.findings)
      ? data.findings.length
      : 0;
    return findings === 0
      ? "No signature matches"
      : `${findings.toLocaleString()} signature match${findings === 1 ? "" : "es"}`;
  }
   if (name === "capa") {
    const count = data.capability_count
      ?? data.total_capabilities;
    const risk = objectValue(data.risk);
    const score = risk?.score;
    const level = typeof risk?.level === "string"
      ? risk.level.replaceAll("_", " ")
      : null;
    if (typeof count !== "number") {
      return "See full report";
    }
    const matchSummary =
      `${count.toLocaleString()} capability match${count === 1 ? "" : "es"}`;
    return typeof score === "number" && level
      ? `${matchSummary} · risk ${score.toLocaleString()} (${level})`
      : matchSummary;
  }
  const strings = data.extracted_string_count
    ?? data.total_string_count;
  return typeof strings === "number"
    ? `${strings.toLocaleString()} extracted string${strings === 1 ? "" : "s"}`
    : "See full report";
}

function setStage(
  name: "clamav" | "capa" | "floss",
  data: JsonObject | null,
): void {
  const status = analyzerStatus(data);
  const statusCell = element(`${name}-status`);
  statusCell.textContent = status;
  statusCell.className = data?.complete === false
    ? "stage-warning"
    : "stage-good";
  element(`${name}-summary`).textContent =
    analyzerDescription(data, name);
}

function renderResult(state: ScanState): void {
  const result = state.result;
  if (!result) {
    return;
  }

  renderLiveActivity(state);

  
  const report = result.report;
  const summary = objectValue(report.summary) ?? {};
  const clamav = analyzer(report, "clamav");
  const capa = analyzer(report, "capa");
  const floss = analyzer(report, "floss");
  element("metric-files").textContent =
  
    numberValue(summary.regular_files);
  element("metric-hashed").textContent =
    numberValue(summary.hashed_files);
  element("metric-capa").textContent = numberValue(
    capa?.capability_count ?? capa?.total_capabilities,
  );
  element("metric-floss").textContent = numberValue(
    floss?.extracted_string_count ?? floss?.total_string_count,
  );
  renderArtifactTree(result);
  element("inventory-summary").textContent =
    `${numberValue(summary.hashed_files)} files hashed`;
  setStage("clamav", clamav);
  setStage("capa", capa);
  setStage("floss", floss);
  const incompleteReasons = report.incomplete_reasons;
  element("coverage-label").textContent =
    Array.isArray(incompleteReasons) && incompleteReasons.length > 0
      ? `${incompleteReasons.length} coverage gap${incompleteReasons.length === 1 ? "" : "s"}`
      : "All configured stages completed";
  element("report-panel").textContent = result.report_markdown;
  element("activity-panel").textContent = activityText(
    state.events,
  );
  element("json-panel").textContent = JSON.stringify(
    report,
    null,
    2,
  );
  progressWrap.classList.add("d-none");
  resultsSection.classList.remove("d-none");
}

async function openCase(): Promise<void> {
  const selectedScanId = getSelectedScanId();
  if (!selectedScanId) {
    return;
  }
  const session = getSession(selectedScanId);
  if (!session) {
    return;
  }
  try {
    if (session.historical && session.caseId) {
      await api<{ ok: boolean }>(
        `/api/cases/${session.caseId}/open-folder`,
        {
          method: "POST",
          body: JSON.stringify({
            results_directory:
              session.resultsDirectory,
          }),
        },
      );
      return;
    }
    await api<{ ok: boolean }>(
      `/api/scans/${selectedScanId}/open-folder`,
      {
        method: "POST",
        body: "{}",
      },
    );
  } catch (error) {
    showError(
      error instanceof Error ? error.message : String(error),
    );
  }
}

function configureOutputTabs(): void {
  const buttons =
    document.querySelectorAll<HTMLButtonElement>("[data-panel]");
  buttons.forEach((button) => {
    button.addEventListener("click", () => {
      buttons.forEach((item) => {
        item.classList.toggle("active", item === button);
      });
      document
        .querySelectorAll<HTMLElement>(".output-panel")
        .forEach((panel) => {
          panel.classList.toggle(
            "d-none",
            panel.id !== button.dataset.panel,
          );
        });
    });
  });
}

const scanController = createScanController({
  sourcePath: () => sourceInput.value,
  resultsDirectory: () => resultsInput.value,
  clearError,
  showError,
  updateControlState,
  renderSessionList,
  renderSelectedSession,
  selectSession,
  setCancelPending: (pending) => {
    cancelButton.disabled = pending;
  },
});

async function initialize(): Promise<void> {
  updateControlState();
  configureOutputTabs();
  configureArtifactTreePopout();
  renderSessionList();
  newScanButton.addEventListener("click", () => {
    showSetup(true);
  });
  chooseSource.addEventListener("click", () => {
    void selectDirectory("source", sourceInput).catch(
      (error: unknown) => showError(
        error instanceof Error ? error.message : String(error),
      ),
    );
  });
  chooseResults.addEventListener("click", () => {
    void selectDirectory("results", resultsInput).catch(
      (error: unknown) => showError(
        error instanceof Error ? error.message : String(error),
      ),
    );
  });
  startButton.addEventListener(
    "click",
    () => void scanController.startScan(),
  );
  cancelButton.addEventListener(
    "click",
    () => void scanController.cancelScan(),
  );
  openCaseButton.addEventListener("click", () => void openCase());
  try {
    await establishSession();
    await loadConfiguration();
    try {
      await loadHistory();
    } catch (error) {
      showError(
        "Saved scan history could not be loaded. "
        + (
          error instanceof Error
            ? error.message
            : String(error)
        ),
      );
    }
    await checkHealth();
  } catch (error) {
    serviceBadge.textContent = "Session unavailable";
    serviceBadge.className = "status-chip status-danger";
    showError(
      error instanceof Error ? error.message : String(error),
    );
  }
}
void initialize();
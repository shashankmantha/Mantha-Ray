import "bootstrap/dist/css/bootstrap.min.css";
import "./styles.css";


type JsonObject = Record<string, unknown>;


interface ApiErrorBody {
  detail?: unknown;
}


interface ScanEvent {
  time: string;
  message: string;
}


interface ScanResult {
  case_id: string;
  status: string;
  case_directory: string;
  report_path: string;
  report: JsonObject;
  report_markdown: string;
}


interface ScanState {
  scan_id: string;
  state: string;
  message: string;
  events: ScanEvent[];
  result: ScanResult | null;
  error: string | null;
}


interface ScanSession {
  id: string;
  label: string;
  sourcePath: string;
  startedAt: Date;
  state: ScanState;
}


const terminalStates = new Set([
  "completed",
  "failed",
  "cancelled",
]);

const sessions = new Map<string, ScanSession>();
const sessionOrder: string[] = [];

let activeScanId: string | null = null;
let selectedScanId: string | null = null;
let pollTimer: number | null = null;
let serviceReady = false;


function element<T extends HTMLElement>(
  id: string,
): T {
  const found = document.getElementById(id);

  if (found === null) {
    throw new Error(
      `Required element '${id}' was not found.`,
    );
  }

  return found as T;
}


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


async function api<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers ?? {}),
    },
  });

  if (!response.ok) {
    let message =
      `Request failed with status ${response.status}.`;

    try {
      const body = (await response.json()) as ApiErrorBody;

      if (typeof body.detail === "string") {
        message = body.detail;
      } else if (body.detail !== undefined) {
        message = JSON.stringify(body.detail);
      }
    } catch {
      // Retain the bounded generic message.
    }

    throw new Error(message);
  }

  return (await response.json()) as T;
}


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
    serviceReady = true;
    serviceBadge.textContent =
      `Docker ${health.docker_version ?? "ready"}`;
    serviceBadge.className = "status-chip status-good";
    updateControlState();
    return;
  }

  serviceReady = false;
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
  }
}


function pathLabel(path: string): string {
  const normalized = path.replaceAll("\\", "/");
  const pieces = normalized.split("/").filter(Boolean);
  return pieces.at(-1) ?? "Scan";
}


function statusText(session: ScanSession): string {
  const resultStatus = session.state.result?.status;

  if (resultStatus) {
    return resultStatus.replaceAll("_", " ");
  }

  return session.state.state.replaceAll("_", " ");
}


function statusKind(session: ScanSession): string {
  const value = session.state.result?.status
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

  if (value === "needs_review") {
    return "warning";
  }

  return "running";
}


function formatSessionTime(date: Date): string {
  return date.toLocaleTimeString([], {
    hour: "numeric",
    minute: "2-digit",
  });
}


function renderSessionList(): void {
  scanList.replaceChildren();
  scanCount.textContent = String(sessionOrder.length);
  scanListEmpty.classList.toggle(
    "d-none",
    sessionOrder.length > 0,
  );

  for (const id of sessionOrder) {
    const session = sessions.get(id);

    if (!session) {
      continue;
    }

    const button = document.createElement("button");
    button.type = "button";
    button.className = "scan-tab";
    button.dataset.scanId = id;
    button.setAttribute(
      "aria-selected",
      String(selectedScanId === id),
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
    button.addEventListener("click", () => selectSession(id));
    scanList.append(button);
  }
}


function updateControlState(): void {
  const scanning = activeScanId !== null;
  chooseSource.disabled = scanning;
  chooseResults.disabled = scanning;
  newScanButton.disabled = scanning;
  startButton.disabled = scanning || !serviceReady;
}


function showSetup(resetSource = false): void {
  clearError();
  selectedScanId = null;
  setupView.classList.remove("d-none");
  scanView.classList.add("d-none");

  if (resetSource) {
    sourceInput.value = "";
  }

  renderSessionList();
  updateControlState();
}


function selectSession(id: string): void {
  if (!sessions.has(id)) {
    return;
  }

  clearError();
  selectedScanId = id;
  setupView.classList.add("d-none");
  scanView.classList.remove("d-none");
  renderSessionList();
  renderSelectedSession();
}


function renderSelectedSession(): void {
  if (!selectedScanId) {
    return;
  }

  const session = sessions.get(selectedScanId);

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

  const terminal = terminalStates.has(session.state.state);
  progressWrap.classList.toggle("d-none", terminal);
  cancelButton.classList.toggle(
    "d-none",
    session.id !== activeScanId,
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


async function startScan(): Promise<void> {
  clearError();

  if (!sourceInput.value || !resultsInput.value) {
    showError(
      "Choose both a source folder and a results folder.",
    );
    return;
  }

  try {
    const sourcePath = sourceInput.value;
    const state = await api<ScanState>("/api/scans", {
      method: "POST",
      body: JSON.stringify({
        source_directory: sourcePath,
        results_directory: resultsInput.value,
      }),
    });

    const session: ScanSession = {
      id: state.scan_id,
      label: pathLabel(sourcePath),
      sourcePath,
      startedAt: new Date(),
      state,
    };

    sessions.set(session.id, session);
    sessionOrder.unshift(session.id);
    activeScanId = session.id;
    selectedScanId = session.id;
    updateControlState();
    selectSession(session.id);
    schedulePoll(100);
  } catch (error) {
    showError(
      error instanceof Error ? error.message : String(error),
    );
  }
}


async function cancelScan(): Promise<void> {
  if (!activeScanId) {
    return;
  }

  cancelButton.disabled = true;

  try {
    const state = await api<ScanState>(
      `/api/scans/${activeScanId}`,
      { method: "DELETE" },
    );

    updateSession(state);
  } catch (error) {
    showError(
      error instanceof Error ? error.message : String(error),
    );
  } finally {
    cancelButton.disabled = false;
  }
}


function schedulePoll(delay: number): void {
  if (pollTimer !== null) {
    window.clearTimeout(pollTimer);
  }

  pollTimer = window.setTimeout(
    () => void pollScan(),
    delay,
  );
}


async function pollScan(): Promise<void> {
  const scanId = activeScanId;

  if (!scanId) {
    return;
  }

  try {
    const state = await api<ScanState>(
      `/api/scans/${scanId}`,
    );

    updateSession(state);

    if (terminalStates.has(state.state)) {
      finishScan(state);
      return;
    }

    schedulePoll(750);
  } catch (error) {
    activeScanId = null;
    updateControlState();
    showError(
      error instanceof Error ? error.message : String(error),
    );
  }
}


function updateSession(state: ScanState): void {
  const session = sessions.get(state.scan_id);

  if (!session) {
    return;
  }

  session.state = state;
  renderSessionList();

  if (selectedScanId === state.scan_id) {
    renderSelectedSession();
  }
}


function renderProgress(state: ScanState): void {
  progressMessage.textContent = state.message;
  progressState.textContent = state.state.toUpperCase();
}


function finishScan(state: ScanState): void {
  updateSession(state);
  activeScanId = null;
  updateControlState();
  renderSessionList();

  if (selectedScanId === state.scan_id) {
    renderSelectedSession();
  }
}


function objectValue(value: unknown): JsonObject | null {
  if (
    typeof value === "object"
    && value !== null
    && !Array.isArray(value)
  ) {
    return value as JsonObject;
  }

  return null;
}


function numberValue(value: unknown): string {
  return typeof value === "number"
    ? value.toLocaleString()
    : "—";
}


function analyzer(
  report: JsonObject,
  name: string,
): JsonObject | null {
  const direct = objectValue(report[name]);

  if (direct) {
    return direct;
  }

  for (const groupName of [
    "analysis",
    "analyses",
    "analyzers",
  ]) {
    const group = objectValue(report[groupName]);
    const match = group ? objectValue(group[name]) : null;

    if (match) {
      return match;
    }
  }

  return null;
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
    return typeof count === "number"
      ? `${count.toLocaleString()} capability match${count === 1 ? "" : "es"}`
      : "See full report";
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
  element("activity-panel").textContent = state.events
    .map((event) =>
      `${new Date(event.time).toLocaleTimeString()}  ${event.message}`,
    )
    .join("\n");
  element("json-panel").textContent = JSON.stringify(
    report,
    null,
    2,
  );

  progressWrap.classList.add("d-none");
  resultsSection.classList.remove("d-none");
}


async function openCase(): Promise<void> {
  if (!selectedScanId) {
    return;
  }

  try {
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


async function initialize(): Promise<void> {
  updateControlState();
  configureOutputTabs();
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

  startButton.addEventListener("click", () => void startScan());
  cancelButton.addEventListener("click", () => void cancelScan());
  openCaseButton.addEventListener("click", () => void openCase());

  try {
    await establishSession();
    await loadConfiguration();
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

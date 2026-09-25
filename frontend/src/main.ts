import "bootstrap/dist/css/bootstrap.min.css";
import "./styles.css";


type JsonObject = Record<string, unknown>;
type StageName =
  | "inventory"
  | "clamav"
  | "capa"
  | "floss"
  | "report";


type StageStatus =
  | "waiting"
  | "running"
  | "completed"
  | "incomplete"
  | "unavailable"
  | "error"
  | "cancelled";


interface ApiErrorBody {
  detail?: unknown;
}


interface ScanEvent {
  time: string;
  message: string;
}
type ArtifactRisk =
  | "high"
  | "medium"
  | "low"
  | "clean";


type CoverageStatus =
  | "completed"
  | "finding"
  | "incomplete"
  | "unavailable"
  | "not-applicable"
  | "error";


type AnalyzerName =
  | "clamav"
  | "capa"
  | "floss";


interface ArtifactRecord {
  relative_path: string;
  kind: string;
  detected_type: string | null;
  routing_class: string | null;
  state: string | null;
  mode: string | null;
  size_bytes: number | null;
  sha256: string | null;
  review_flags: number;
  error: string | null;
}


interface ArtifactDisplay {
  artifact: ArtifactRecord;
  risk: ArtifactRisk;
  coverage: Record<AnalyzerName, CoverageStatus>;
}


interface ArtifactTreeNode {
  name: string;
  path: string;
  directory: boolean;
  children: Map<string, ArtifactTreeNode>;
  artifact: ArtifactDisplay | null;
  fileCount: number;
  risk: ArtifactRisk;
}

interface ScanResult {
  case_id: string;
  status: string;
  case_directory: string;
  report_path: string;
  report: JsonObject;
  report_markdown: string;
  artifacts?: ArtifactRecord[];
}


interface ScanState {
  scan_id: string;
  state: string;
  message: string;
  events: ScanEvent[];
  stages?: Partial<Record<StageName, StageStatus>>;
  result: ScanResult | null;
  error: string | null;
}


interface CaseHistoryEntry {
  case_id: string;
  status: string;
  created_at: string;
  source_directory: string | null;
  label: string;
}


interface CaseHistoryResponse {
  cases: CaseHistoryEntry[];
  truncated: boolean;
}


interface ScanSession {
  id: string;
  label: string;
  sourcePath: string;
  startedAt: Date;
  state: ScanState;
  historical: boolean;
  loaded: boolean;
  caseId: string | null;
  resultsDirectory: string;
  persistedStatus: string | null;
}


const terminalStates = new Set([
  "completed",
  "failed",
  "cancelled",
]);

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

    if (purpose === "results") {
      await loadHistory();
    }
  }
}


function pathLabel(path: string): string {
  const normalized = path.replaceAll("\\", "/");
  const pieces = normalized.split("/").filter(Boolean);
  return pieces.at(-1) ?? "Scan";
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
    button.addEventListener("click", () => {
      void selectSession(id);
    });
    scanList.append(button);
  }
}


async function loadHistory(): Promise<void> {
  const resultsDirectory = resultsInput.value;

  for (const [id, session] of sessions) {
    if (session.historical) {
      sessions.delete(id);
      const index = sessionOrder.indexOf(id);

      if (index >= 0) {
        sessionOrder.splice(index, 1);
      }
    }
  }

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
    Array.from(sessions.values())
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

    sessions.set(id, {
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
    sessionOrder.push(id);
  }

  renderSessionList();
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


async function selectSession(id: string): Promise<void> {
  if (!sessions.has(id)) {
    return;
  }

  clearError();
  selectedScanId = id;
  setupView.classList.add("d-none");
  scanView.classList.remove("d-none");
  renderSessionList();

  const session = sessions.get(id);

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
      historical: false,
      loaded: true,
      caseId: null,
      resultsDirectory: resultsInput.value,
      persistedStatus: null,
    };

    sessions.set(session.id, session);
    sessionOrder.unshift(session.id);
    activeScanId = session.id;
    selectedScanId = session.id;
    updateControlState();
    void selectSession(session.id);
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

function renderProgress(state: ScanState): void {
  renderStageTracker(state);
  progressMessage.textContent = state.message;
  progressState.textContent =
    state.state.toUpperCase();
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

function analyzerResultMap(
  data: JsonObject | null,
): Map<string, JsonObject> {
  const results = data?.results;
  const mapped = new Map<string, JsonObject>();

  if (!Array.isArray(results)) {
    return mapped;
  }

  for (const value of results) {
    const result = objectValue(value);

    if (
      result
      && typeof result.relative_path === "string"
    ) {
      mapped.set(
        result.relative_path,
        result,
      );
    }
  }

  return mapped;
}


function pathMatches(
  candidate: string,
  relativePath: string,
): boolean {
  const normalized = candidate.replaceAll("\\", "/");

  return (
    normalized === relativePath
    || normalized.endsWith(`/${relativePath}`)
    || normalized.startsWith(`${relativePath}:`)
    || normalized.includes(`/${relativePath}:`)
  );
}


function clamavHasFinding(
  data: JsonObject | null,
  relativePath: string,
): boolean {
  const findings = data?.findings;

  if (!Array.isArray(findings)) {
    return false;
  }

  for (const finding of findings) {
    if (
      typeof finding === "string"
      && pathMatches(finding, relativePath)
    ) {
      return true;
    }

    const object = objectValue(finding);

    if (!object) {
      continue;
    }

    for (const key of [
      "relative_path",
      "path",
      "file",
      "filename",
    ]) {
      const candidate = object[key];

      if (
        typeof candidate === "string"
        && pathMatches(candidate, relativePath)
      ) {
        return true;
      }
    }
  }

  return false;
}


function analyzerCoverage(
  analyzerData: JsonObject | null,
  fileResult: JsonObject | null,
  eligible: boolean,
): CoverageStatus {
  if (!eligible) {
    return "not-applicable";
  }

  if (!analyzerData) {
    return "unavailable";
  }

  if (analyzerData.status === "not_run") {
    return "unavailable";
  }

  if (analyzerData.status === "error") {
    return "error";
  }

  if (fileResult) {
    if (fileResult.status === "error") {
      return "error";
    }

    return fileResult.complete === true
      ? "completed"
      : "incomplete";
  }

  return analyzerData.complete === true
    ? "incomplete"
    : "incomplete";
}


function artifactRisk(
  artifact: ArtifactRecord,
  clamavFinding: boolean,
  capaResult: JsonObject | null,
): ArtifactRisk {
  if (clamavFinding) {
    return "high";
  }

  if (
    artifact.error
    || artifact.review_flags > 0
  ) {
    return "medium";
  }

  const risk = objectValue(capaResult?.risk);

  if (risk) {
    const level = typeof risk.level === "string"
      ? risk.level.toLowerCase()
      : "";

    if (
      risk.high_concern === true
      || level.includes("high")
    ) {
      return "high";
    }

    if (
      risk.review_required === true
      || level === "medium"
      || level === "review"
    ) {
      return "medium";
    }

    if (
      typeof risk.score === "number"
      && risk.score > 0
    ) {
      return "low";
    }
  }

  if (
    typeof capaResult?.capability_count === "number"
    && capaResult.capability_count > 0
  ) {
    return "low";
  }

  return "clean";
}


function artifactDisplayRecords(
  result: ScanResult,
): ArtifactDisplay[] {
  const artifacts = result.artifacts ?? [];
  const report = result.report;
  const clamav = analyzer(report, "clamav");
  const capa = analyzer(report, "capa");
  const floss = analyzer(report, "floss");
  const capaResults = analyzerResultMap(capa);
  const flossResults = analyzerResultMap(floss);

  return artifacts.map((artifact) => {
    const relativePath = artifact.relative_path;
    const capaResult =
      capaResults.get(relativePath) ?? null;
    const flossResult =
      flossResults.get(relativePath) ?? null;
    const hasClamavFinding = clamavHasFinding(
      clamav,
      relativePath,
    );
    const routingClass =
      artifact.routing_class?.toLowerCase() ?? "";
    const regularFile =
      artifact.kind === "regular_file";
    const capaEligible = (
      capaResult !== null
      || ["pe", "elf", "dotnet"].includes(
        routingClass,
      )
    );
    const flossEligible = (
      flossResult !== null
      || ["pe", "dotnet"].includes(
        routingClass,
      )
    );

    let clamavCoverage: CoverageStatus;

    if (!regularFile) {
      clamavCoverage = "not-applicable";
    } else if (hasClamavFinding) {
      clamavCoverage = "finding";
    } else if (!clamav) {
      clamavCoverage = "unavailable";
    } else if (clamav.status === "error") {
      clamavCoverage = "error";
    } else if (clamav.complete === true) {
      clamavCoverage = "completed";
    } else {
      clamavCoverage = "incomplete";
    }

    return {
      artifact,
      risk: artifactRisk(
        artifact,
        hasClamavFinding,
        capaResult,
      ),
      coverage: {
        clamav: clamavCoverage,
        capa: analyzerCoverage(
          capa,
          capaResult,
          regularFile && capaEligible,
        ),
        floss: analyzerCoverage(
          floss,
          flossResult,
          regularFile && flossEligible,
        ),
      },
    };
  });
}


function makeTreeNode(
  name: string,
  path: string,
  directory: boolean,
): ArtifactTreeNode {
  return {
    name,
    path,
    directory,
    children: new Map(),
    artifact: null,
    fileCount: 0,
    risk: "clean",
  };
}


function buildArtifactTree(
  artifacts: ArtifactDisplay[],
): ArtifactTreeNode {
  const root = makeTreeNode(
    "",
    "",
    true,
  );

  for (const display of artifacts) {
    const pieces = display.artifact.relative_path
      .split("/")
      .filter(Boolean);

    let current = root;
    let currentPath = "";

    pieces.forEach((piece, index) => {
      currentPath = currentPath
        ? `${currentPath}/${piece}`
        : piece;

      const finalPiece =
        index === pieces.length - 1;
      let child = current.children.get(piece);

      if (!child) {
        child = makeTreeNode(
          piece,
          currentPath,
          !finalPiece,
        );
        current.children.set(piece, child);
      }

      if (finalPiece) {
        child.directory = false;
        child.artifact = display;
      }

      current = child;
    });
  }

  summarizeTree(root);
  return root;
}


const riskRanks: Record<ArtifactRisk, number> = {
  clean: 0,
  low: 1,
  medium: 2,
  high: 3,
};


function highestRisk(
  first: ArtifactRisk,
  second: ArtifactRisk,
): ArtifactRisk {
  return riskRanks[second] > riskRanks[first]
    ? second
    : first;
}


function summarizeTree(
  node: ArtifactTreeNode,
): void {
  if (!node.directory) {
    node.fileCount = 1;
    node.risk = node.artifact?.risk ?? "clean";
    return;
  }

  node.fileCount = 0;
  node.risk = "clean";

  for (const child of node.children.values()) {
    summarizeTree(child);
    node.fileCount += child.fileCount;
    node.risk = highestRisk(
      node.risk,
      child.risk,
    );
  }
}


function formatBytes(
  bytes: number | null,
): string {
  if (bytes === null) {
    return "Unknown size";
  }

  if (bytes < 1024) {
    return `${bytes} B`;
  }

  if (bytes < 1024 ** 2) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }

  if (bytes < 1024 ** 3) {
    return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  }

  return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
}


function coverageLabel(
  status: CoverageStatus,
): string {
  switch (status) {
    case "completed":
      return "Completed";

    case "finding":
      return "Finding";

    case "incomplete":
      return "Incomplete";

    case "unavailable":
      return "Unavailable";

    case "not-applicable":
      return "Not applicable";

    case "error":
      return "Error";
  }
}


function createRiskBadge(
  risk: ArtifactRisk,
): HTMLSpanElement {
  const badge = document.createElement("span");
  badge.className = `artifact-risk artifact-risk-${risk}`;
  badge.textContent = risk;
  return badge;
}


function createCoverageBadge(
  name: AnalyzerName,
  status: CoverageStatus,
): HTMLSpanElement {
  const badge = document.createElement("span");
  badge.className =
    `tool-badge tool-state-${status}`;
  badge.textContent = name === "clamav"
    ? "ClamAV"
    : name === "floss"
      ? "FLOSS"
      : "capa";
  badge.title =
    `${badge.textContent}: ${coverageLabel(status)}`;
  badge.setAttribute(
    "aria-label",
    badge.title,
  );
  return badge;
}


function sortedTreeChildren(
  node: ArtifactTreeNode,
): ArtifactTreeNode[] {
  return Array.from(node.children.values()).sort(
    (first, second) => {
      if (first.directory !== second.directory) {
        return first.directory ? -1 : 1;
      }

      return first.name.localeCompare(
        second.name,
        undefined,
        {
          numeric: true,
          sensitivity: "base",
        },
      );
    },
  );
}


function renderArtifactNode(
  node: ArtifactTreeNode,
  depth: number,
): HTMLDivElement {
  const wrapper = document.createElement("div");
  wrapper.className = "artifact-node";

  const row = document.createElement("div");
  row.className = node.directory
    ? "artifact-row artifact-directory-row"
    : "artifact-row artifact-file-row";
  row.style.setProperty(
    "--artifact-depth",
    String(depth),
  );

  const pathCell = document.createElement("div");
  pathCell.className = "artifact-path-cell";

  const icon = document.createElement("span");
  icon.className = node.directory
    ? "artifact-icon artifact-icon-directory"
    : "artifact-icon artifact-icon-file";
  icon.textContent = node.directory ? "D" : "F";
  icon.setAttribute("aria-hidden", "true");

  const nameCopy = document.createElement("span");
  nameCopy.className = "artifact-name-copy";

  const name = document.createElement("strong");
  name.textContent = node.name;
  name.title = node.path;

  const metadata = document.createElement("small");

  if (node.directory) {
    metadata.textContent =
      `${node.fileCount.toLocaleString()} `
      + `file${node.fileCount === 1 ? "" : "s"}`;
  } else {
    const artifact = node.artifact?.artifact;
    const details = [
      formatBytes(artifact?.size_bytes ?? null),
      artifact?.detected_type ?? null,
    ].filter(
      (value): value is string =>
        typeof value === "string" && value.length > 0,
    );

    metadata.textContent = details.join(" · ");
  }

  nameCopy.append(name, metadata);

  let children: HTMLDivElement | null = null;

  if (node.directory) {
    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "artifact-toggle";
    toggle.textContent = "▾";
    toggle.setAttribute("aria-expanded", "true");
    toggle.setAttribute(
      "aria-label",
      `Collapse ${node.path}`,
    );

    pathCell.append(toggle, icon, nameCopy);

    children = document.createElement("div");
    children.className = "artifact-children";

    toggle.addEventListener("click", () => {
      if (!children) {
        return;
      }

      const collapsed = !children.hidden;
      children.hidden = collapsed;
      toggle.textContent = collapsed ? "▸" : "▾";
      toggle.setAttribute(
        "aria-expanded",
        String(!collapsed),
      );
      toggle.setAttribute(
        "aria-label",
        `${collapsed ? "Expand" : "Collapse"} ${node.path}`,
      );
    });
  } else {
    const spacer = document.createElement("span");
    spacer.className = "artifact-toggle-spacer";
    pathCell.append(spacer, icon, nameCopy);
  }

  const coverageCell = document.createElement("div");
  coverageCell.className = "artifact-coverage-cell";

  if (node.artifact) {
    for (const analyzerName of [
      "clamav",
      "capa",
      "floss",
    ] as const) {
      const status =
        node.artifact.coverage[analyzerName];

      if (status !== "not-applicable") {
        coverageCell.append(
          createCoverageBadge(
            analyzerName,
            status,
          ),
        );
      }
    }
  } else {
    const summary = document.createElement("span");
    summary.className = "directory-coverage";
    summary.textContent =
      `${node.fileCount.toLocaleString()} inventoried`;
    coverageCell.append(summary);
  }

  const riskCell = document.createElement("div");
  riskCell.className = "artifact-risk-cell";
  riskCell.append(createRiskBadge(node.risk));

  row.append(
    pathCell,
    coverageCell,
    riskCell,
  );
  wrapper.append(row);

  if (children) {
    for (const child of sortedTreeChildren(node)) {
      children.append(
        renderArtifactNode(
          child,
          depth + 1,
        ),
      );
    }

    wrapper.append(children);
  }

  return wrapper;
}


function renderArtifactTree(
  result: ScanResult,
): void {
  const tree = element<HTMLDivElement>(
    "artifact-tree",
  );
  const empty = element<HTMLParagraphElement>(
    "artifact-tree-empty",
  );
  const records = artifactDisplayRecords(result);

  element("artifact-count").textContent =
    `${records.length.toLocaleString()} `
    + `file${records.length === 1 ? "" : "s"}`;

  tree.replaceChildren();

  if (records.length === 0) {
    tree.classList.add("d-none");
    empty.classList.remove("d-none");
    return;
  }

  tree.classList.remove("d-none");
  empty.classList.add("d-none");

  const root = buildArtifactTree(records);

  for (const child of sortedTreeChildren(root)) {
    tree.append(
      renderArtifactNode(
        child,
        0,
      ),
    );
  }
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

  const session = sessions.get(selectedScanId);

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



import { isTerminalState } from "../scanController";
import { analyzer, objectValue } from "../risk";
import {
  getActiveScanId,
  getSelectedScanId,
  getSession,
} from "../sessionStore";
import type { JsonObject, ScanState } from "../types";
import { renderArtifactTree } from "./artifactTree";
import {
  stopButton,
  element,
  openCaseButton,
  progressWrap,
  resultsSection,
} from "./elements";
import {
  activityText,
  renderLiveActivity,
  renderProgress,
} from "./progress";
import { describeResources } from "./resources";
import { showError, statusKind, statusText } from "./shell";

export function renderSelectedSession(): void {
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
  const resources = describeResources(
    result?.report?.resources ?? session.state.resource_profile,
  );
  const resourceLine = element("scan-resources");
  resourceLine.textContent = resources ?? "";
  resourceLine.classList.toggle("d-none", resources === null);
  const verdict = element("verdict-badge");
  verdict.textContent = statusText(session).toUpperCase();
  verdict.className =
    `verdict verdict-${statusKind(session)}`;
  const terminal = isTerminalState(session.state.state);
  progressWrap.classList.toggle("d-none", terminal);
  stopButton.classList.toggle(
    "d-none",
    session.id !== getActiveScanId(),
  );
  const winding = session.state.state === "stopping"
    || session.state.state === "cancelling";
  stopButton.disabled = winding;
  stopButton.textContent = session.state.state === "stopping"
    ? "Stopping and saving the report\u2026"
    : session.state.state === "cancelling"
      ? "Cancelling\u2026"
      : "Stop scan\u2026";
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

function yaraDescription(data: JsonObject): string {
  if (data.status === "unavailable") {
    return "No rule packs installed (mantha-ray packs install)";
  }
  if (data.status === "error" || data.status === "not_run") {
    return typeof data.error === "string" ? data.error : "See full report";
  }
  const counts = objectValue(data.severity_counts) ?? {};
  const matched = typeof data.matched_files === "number" ? data.matched_files : 0;
  const bundle = objectValue(data.bundle);
  const version = typeof bundle?.version === "string"
    ? ` · bundle ${bundle.version}${bundle.verified === true ? "" : " (unsigned)"}`
    : "";
  const found = matched === 0
    ? "No rule matches"
    : `${matched.toLocaleString()} file${matched === 1 ? "" : "s"} matched · `
      + (["threat", "suspicious", "info"] as const)
        .filter((s) => typeof counts[s] === "number" && (counts[s] as number) > 0)
        .map((s) => `${(counts[s] as number).toLocaleString()} ${s}`)
        .join(", ");
  const issues = typeof data.error === "string" && data.error ? `; ${data.error}` : "";
  return `${found}${version}${issues}`;
}

function analyzerDescription(
  data: JsonObject | null,
  name: "clamav" | "yara" | "capa" | "floss",
): string {
  if (!data) {
    return name === "yara" ? "Not part of this scan (older case)" : "See full report";
  }
  if (name === "yara") {
    return yaraDescription(data);
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
  name: "clamav" | "yara" | "capa" | "floss",
  data: JsonObject | null,
): void {
  const status = name === "yara" && !data ? "Not run" : analyzerStatus(data);
  const statusCell = element(`${name}-status`);
  statusCell.textContent = status;
  statusCell.className = data?.complete === false
    && data.status !== "unavailable"
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
  const yara = analyzer(report, "yara");
  const capa = analyzer(report, "capa");
  const floss = analyzer(report, "floss");
  element("metric-files").textContent =
  
    numberValue(summary.regular_files);
  element("metric-yara").textContent =
    yara && yara.status !== "unavailable"
      ? numberValue(yara.matched_files)
      : "—";
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
  setStage("yara", yara);
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

export function configureOutputTabs(): void {
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
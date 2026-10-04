// Application shell: alerts, service badge, scan sidebar, view
// switching, and general control state.

import {
  getActiveScanId,
  getSelectedScanId,
  getSession,
  orderedSessionIds,
  setSelectedScanId,
} from "../sessionStore";
import type { ScanSession } from "../types";
import { setArtifactTreePoppedOut } from "./artifactTree";
import {
  chooseResults,
  chooseSource,
  fatalAlert,
  newScanButton,
  scanCount,
  scanList,
  scanListEmpty,
  scanView,
  serviceBadge,
  setupView,
  sourceInput,
  startButton,
} from "./elements";

export interface ShellHooks {
  /** Called when a scan is clicked in the sidebar. */
  selectSession(id: string): void;
  /** Whether the Docker preflight has succeeded. */
  isServiceReady(): boolean;
}

let shellHooks: ShellHooks | null = null;

export function configureShell(hooks: ShellHooks): void {
  shellHooks = hooks;
}

function hooks(): ShellHooks {
  if (!shellHooks) {
    throw new Error("The application shell was not configured.");
  }
  return shellHooks;
}

export function setServiceBadge(
  text: string,
  kind: "good" | "danger",
): void {
  serviceBadge.textContent = text;
  serviceBadge.className = `status-chip status-${kind}`;
}

export function showError(message: string): void {
  fatalAlert.textContent = message;
  fatalAlert.classList.remove("d-none");
}

export function clearError(): void {
  fatalAlert.textContent = "";
  fatalAlert.classList.add("d-none");
}

export function statusText(session: ScanSession): string {
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

export function statusKind(session: ScanSession): string {
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

export function renderSessionList(): void {
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
      hooks().selectSession(id);
    });
    scanList.append(button);
  }
}

export function updateControlState(): void {
  const scanning = getActiveScanId() !== null;
  chooseSource.disabled = scanning;
  chooseResults.disabled = scanning;
  newScanButton.disabled = scanning;
  startButton.disabled = scanning || !hooks().isServiceReady();
}

export function showSetup(resetSource = false): void {
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
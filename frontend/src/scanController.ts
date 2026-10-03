

import { api } from "./api";
import {
  getActiveScanId,
  getSelectedScanId,
  getSession,
  prependSession,
  setActiveScanId,
  setSelectedScanId,
} from "./sessionStore";
import type { ScanSession, ScanState } from "./types";

const terminalStates = new Set([
  "completed",
  "failed",
  "cancelled",
]);

export function isTerminalState(state: string): boolean {
  return terminalStates.has(state);
}

export interface ScanControllerUi {
  /** Current value of the source folder input. */
  sourcePath(): string;
  /** Current value of the results folder input. */
  resultsDirectory(): string;
  clearError(): void;
  showError(message: string): void;
  updateControlState(): void;
  renderSessionList(): void;
  renderSelectedSession(): void;
  selectSession(id: string): Promise<void>;
  /** Disable the cancel button while a cancel request is in flight. */
  setCancelPending(pending: boolean): void;
}

export interface ScanController {
  startScan(): Promise<void>;
  cancelScan(): Promise<void>;
  isServiceReady(): boolean;
  setServiceReady(ready: boolean): void;
}

function pathLabel(path: string): string {
  const normalized = path.replaceAll("\\\\", "/");
  const pieces = normalized.split("/").filter(Boolean);
  return pieces.at(-1) ?? "Scan";
}

export function createScanController(
  ui: ScanControllerUi,
): ScanController {
  let pollTimer: number | null = null;

  let serviceReady = false;

  async function startScan(): Promise<void> {
    ui.clearError();
    if (!ui.sourcePath() || !ui.resultsDirectory()) {
      ui.showError(
        "Choose both a source folder and a results folder.",
      );
      return;
    }
    try {
      const sourcePath = ui.sourcePath();
      const state = await api<ScanState>("/api/scans", {
        method: "POST",
        body: JSON.stringify({
          source_directory: sourcePath,
          results_directory: ui.resultsDirectory(),
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
        resultsDirectory: ui.resultsDirectory(),
        persistedStatus: null,
      };
      prependSession(session);
      setActiveScanId(session.id);
      setSelectedScanId(session.id);
      ui.updateControlState();
      void ui.selectSession(session.id);
      schedulePoll(100);
    } catch (error) {
      ui.showError(
        error instanceof Error ? error.message : String(error),
      );
    }
  }

  async function cancelScan(): Promise<void> {
    const activeScanId = getActiveScanId();
    if (!activeScanId) {
      return;
    }
    ui.setCancelPending(true);
    try {
      const state = await api<ScanState>(
        `/api/scans/${activeScanId}`,
        { method: "DELETE" },
      );
      updateSession(state);
    } catch (error) {
      ui.showError(
        error instanceof Error ? error.message : String(error),
      );
    } finally {
      ui.setCancelPending(false);
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
    const scanId = getActiveScanId();
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
      setActiveScanId(null);
      ui.updateControlState();
      ui.showError(
        error instanceof Error ? error.message : String(error),
      );
    }
  }

  function updateSession(state: ScanState): void {
    const session = getSession(state.scan_id);
    if (!session) {
      return;
    }
    session.state = state;
    ui.renderSessionList();
    if (getSelectedScanId() === state.scan_id) {
      ui.renderSelectedSession();
    }
  }

  function finishScan(state: ScanState): void {
    updateSession(state);
    setActiveScanId(null);
    ui.updateControlState();
    ui.renderSessionList();
    if (getSelectedScanId() === state.scan_id) {
      ui.renderSelectedSession();
    }
  }

  return {
    startScan,
    cancelScan,
    isServiceReady: () => serviceReady,
    setServiceReady: (ready: boolean) => {
      serviceReady = ready;
    },
  };
}
// Saved-case history: listing, conversion into sessions, lazy loading
// of a selected case, and opening a case folder.

import { api } from "./api";
import {
  allSessions,
  appendSession,
  getSelectedScanId,
  getSession,
  hasSession,
  removeHistoricalSessions,
  setSelectedScanId,
} from "./sessionStore";
import type { CaseHistoryResponse, ScanState } from "./types";
import { setArtifactTreePoppedOut } from "./ui/artifactTree";
import { resultsInput, scanView, setupView } from "./ui/elements";
import { renderSelectedSession } from "./ui/results";
import {
  clearError,
  renderSessionList,
  showError,
} from "./ui/shell";

export async function loadHistory(): Promise<void> {
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

export async function selectSession(id: string): Promise<void> {
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

export async function openCase(): Promise<void> {
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
import "bootstrap/dist/css/bootstrap.min.css";
import "./styles.css";

import { api } from "./api";
import { loadHistory, openCase, selectSession } from "./history";
import { createScanController } from "./scanController";
import { configureArtifactTreePopout } from "./ui/artifactTree";
import {
  cancelButton,
  chooseResults,
  chooseSource,
  newScanButton,
  openCaseButton,
  resultsInput,
  sourceInput,
  startButton,
} from "./ui/elements";
import { configureLiveActivity } from "./ui/progress";
import {
  configureOutputTabs,
  renderSelectedSession,
} from "./ui/results";
import {
  clearError,
  configureShell,
  renderSessionList,
  setServiceBadge,
  showError,
  showSetup,
  updateControlState,
} from "./ui/shell";

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
    setServiceBadge(
      `Docker ${health.docker_version ?? "ready"}`,
      "good",
    );
    updateControlState();
    return;
  }
  scanController.setServiceReady(false);
  setServiceBadge("Docker unavailable", "danger");
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

configureShell({
  selectSession: (id) => {
    void selectSession(id);
  },
  isServiceReady: () => scanController.isServiceReady(),
});

async function initialize(): Promise<void> {
  updateControlState();
  configureLiveActivity();
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
    setServiceBadge("Session unavailable", "danger");
    showError(
      error instanceof Error ? error.message : String(error),
    );
  }
}

void initialize();
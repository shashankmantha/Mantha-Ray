// Scan progress: stage tracker and the Live Activity panel.

import type {
  ScanEvent,
  ScanState,
  StageName,
  StageStatus,
} from "../types";
import {
  activityAutoscrollButton,
  copyActivityButton,
  element,
  liveActivityPanel,
  progressMessage,
  progressState,
  queuePanel,
  viewActivityButton,
  viewQueueButton,
} from "./elements";
import { renderQueue } from "./queueView";
import { showError } from "./shell";

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

let activityAutoScroll = true;
let showingQueue = false;
let lastState: ScanState | null = null;

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

export function activityText(
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

export function renderLiveActivity(
  state: ScanState,
): void {
  lastState = state;
  if (showingQueue) {
    const current = renderQueue(queuePanel, state);
    if (activityAutoScroll && current) {
      current.scrollIntoView({ block: "center" });
    }
    return;
  }

  liveActivityPanel.textContent = activityText(
    state.events,
  );

  if (activityAutoScroll) {
    scrollActivityToBottom();
  }
}

function setView(queue: boolean): void {
  showingQueue = queue;
  viewQueueButton.setAttribute("aria-pressed", String(queue));
  viewActivityButton.setAttribute("aria-pressed", String(!queue));
  queuePanel.classList.toggle("d-none", !queue);
  liveActivityPanel.classList.toggle("d-none", queue);
  copyActivityButton.classList.toggle("d-none", queue);
  if (lastState) {
    renderLiveActivity(lastState);
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

export function renderProgress(state: ScanState): void {
  renderStageTracker(state);

  progressMessage.textContent = state.message;
  progressState.textContent =
    state.state.toUpperCase();

  renderLiveActivity(state);
}

export function configureLiveActivity(): void {
  viewActivityButton.addEventListener("click", () => setView(false));
  viewQueueButton.addEventListener("click", () => setView(true));

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
}
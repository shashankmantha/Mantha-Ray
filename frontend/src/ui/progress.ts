// Scan progress: stage tracker and the Live Activity panel.

import { setAttribute, setClassName, setText } from "./dom";
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
  "yara",
  "capa",
  "floss",
  "report",
];

const stageLabels: Record<StageName, string> = {
  inventory: "Inventory",
  clamav: "ClamAV",
  yara: "YARA-X",
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
    setClassName(row, `stage-step stage-state-${status}`);
    setAttribute(
      row,
      "aria-label",
      `${stageLabels[stage]}: ${stageStatusText(status)}`,
    );
    setText(statusElement, stageStatusText(status));
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
  total?: number,
): string {
  if (events.length === 0) {
    return "[waiting] No activity received yet.";
  }

  const lines = events.map(activityEventLine);
  if (typeof total === "number" && total > events.length) {
    lines.unshift(
      `[earlier messages hidden] Showing the newest ${events.length.toLocaleString()} `
      + `of ${total.toLocaleString()} messages; the report has every file's result.`,
    );
  }
  return lines.join("\n");
}

// What the live activity box shows, so new messages can be appended
// instead of redrawing the whole box.
let renderedScanId = "";
let renderedSeq = -1;
const activityHeader = document.createTextNode("");

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

  if (!appendActivity(state)) {
    return;
  }

  if (activityAutoScroll) {
    scrollActivityToBottom();
  }
}

function hiddenNote(shown: number, total: number | undefined): string {
  return typeof total === "number" && total > shown
    ? `[earlier messages hidden] Showing the newest ${shown.toLocaleString()} `
      + `of ${total.toLocaleString()} messages; the report has every file's result.\n`
    : "";
}

/** Show new activity lines; returns whether anything changed. */
function appendActivity(state: ScanState): boolean {
  const events = state.events;
  const numbered = events.length > 0
    && events.every((event) => typeof event.seq === "number");
  const last = events[events.length - 1];
  if (
    state.scan_id === renderedScanId
    && numbered
    && renderedSeq >= 0
    && (last.seq as number) <= renderedSeq
  ) {
    return false;
  }
  if (state.scan_id !== renderedScanId || !numbered || renderedSeq < 0) {
    // A different scan, or saved history without numbers: draw it once.
    renderedScanId = state.scan_id;
    renderedSeq = numbered ? (last.seq as number) : -1;
    if (events.length === 0) {
      liveActivityPanel.textContent = activityText(events);
      return true;
    }
    activityHeader.textContent = hiddenNote(events.length, state.event_count);
    liveActivityPanel.replaceChildren(
      activityHeader,
      ...events.map((event) => document.createTextNode(`${activityEventLine(event)}\n`)),
    );
    return true;
  }
  for (const event of events) {
    if ((event.seq as number) > renderedSeq) {
      liveActivityPanel.append(document.createTextNode(`${activityEventLine(event)}\n`));
    }
  }
  renderedSeq = last.seq as number;
  // Keep the box to the same number of lines the app keeps.
  while (liveActivityPanel.childNodes.length - 1 > events.length) {
    liveActivityPanel.childNodes[1].remove();
  }
  setText(activityHeader, hiddenNote(events.length, state.event_count));
  return true;
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

const stageProgress = element<HTMLElement>("stage-progress");
const stageProgressFill = element<HTMLElement>("stage-progress-fill");
const stageProgressLabel = element<HTMLElement>("stage-progress-label");
const FINISHED_FILE = new Set(["completed", "timed out", "failed", "stopped", "not reached"]);
const YARA_PROGRESS = /YARA-X scanned ([\d,]+) of ([\d,]+) files/;

/** Files finished so far in the running stage, when it reports them. */
function currentProgress(state: ScanState): { stage: StageName; done: number; total: number } | null {
  if (state.state !== "running") {
    return null;
  }
  const stage = stageOrder.find((name) => state.stages?.[name] === "running");
  if (!stage) {
    return null;
  }
  const queue = state.queues?.[stage];
  if (queue && queue.total > 0) {
    const done = queue.items.filter((item) => item && FINISHED_FILE.has(item.status)).length;
    return { stage, done, total: queue.total };
  }
  if (stage === "yara") {
    for (let index = state.events.length - 1; index >= 0; index -= 1) {
      const match = YARA_PROGRESS.exec(state.events[index].message);
      if (match) {
        const done = Number(match[1].replaceAll(",", ""));
        const total = Number(match[2].replaceAll(",", ""));
        return total > 0 ? { stage, done, total } : null;
      }
    }
  }
  return null;
}

function renderStageProgress(state: ScanState): void {
  const progress = currentProgress(state);
  stageProgress.classList.toggle("d-none", progress === null);
  if (progress === null) {
    setText(stageProgressLabel, "");
    return;
  }
  const percent = Math.min(100, Math.round((progress.done / progress.total) * 100));
  const width = `${percent}%`;
  if (stageProgressFill.style.width !== width) {
    stageProgressFill.style.width = width;
  }
  setAttribute(stageProgress, "aria-valuenow", String(percent));
  setText(
    stageProgressLabel,
    `${stageLabels[progress.stage]}: ${progress.done.toLocaleString()} of `
      + `${progress.total.toLocaleString()} files finished`,
  );
}

export function renderProgress(state: ScanState): void {
  renderStageTracker(state);

  setText(progressMessage, state.message);
  setText(progressState, state.state.toUpperCase());
  renderStageProgress(state);

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
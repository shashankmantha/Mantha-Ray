// Queue view: each analyzer's planned file order as a terminal-style list,
// with the file(s) being analyzed marked --current--. Paths come from the
// sample, so everything is written with textContent, never as HTML.

import type { QueueItem, ScanState, StageQueue } from "../types";

const STAGES: ReadonlyArray<[string, string]> = [
  ["capa", "capa"],
  ["floss", "FLOSS"],
];

const MARKERS: Record<string, string> = {
  running: "▶",
  completed: "✓",
  "timed out": "⏱",
  failed: "✗",
  stopped: "■",
  "not reached": "–",
  waiting: "·",
};

function span(className: string, text: string): HTMLSpanElement {
  const node = document.createElement("span");
  node.className = className;
  node.textContent = text;
  return node;
}

function counts(queue: StageQueue): string {
  const tally = new Map<string, number>();
  for (const item of queue.items) {
    if (item) {
      tally.set(item.status, (tally.get(item.status) ?? 0) + 1);
    }
  }
  const order = [
    ["completed", "done"],
    ["running", "running"],
    ["waiting", "waiting"],
    ["timed out", "timed out"],
    ["failed", "failed"],
    ["stopped", "stopped"],
    ["not reached", "not reached"],
  ];
  return order
    .filter(([status]) => tally.get(status))
    .map(([status, label]) => `${tally.get(status)} ${label}`)
    .join(" · ");
}

function itemLine(item: QueueItem): HTMLDivElement {
  const line = document.createElement("div");
  line.className = `queue-line queue-${item.status.replace(" ", "-")}`;
  line.append(span("queue-marker", MARKERS[item.status] ?? "·"));
  const copies = item.copies
    ? ` (+${item.copies} identical ${item.copies === 1 ? "copy" : "copies"})`
    : "";
  line.append(span("queue-path", `${item.path}${copies}`));
  const meta = [item.size, item.mode].filter(Boolean).join(" · ");
  line.append(span("queue-meta", meta));
  if (item.status === "running") {
    line.append(
      span("queue-current", item.detail ? `--current, ${item.detail}--` : "--current--"),
    );
  } else if (item.detail) {
    line.append(span("queue-detail", item.detail));
  }
  return line;
}

/** Rebuild the queue panel; returns the first running line, if any. */
export function renderQueue(
  panel: HTMLElement,
  state: ScanState,
): HTMLElement | null {
  panel.replaceChildren();
  let current: HTMLElement | null = null;
  let any = false;
  for (const [key, label] of STAGES) {
    const queue = state.queues?.[key];
    if (!queue || !queue.total) {
      continue;
    }
    any = true;
    const header = document.createElement("div");
    header.className = "queue-header";
    header.textContent = `${label} — ${queue.total} files · ${counts(queue)}`;
    panel.append(header);
    for (const item of queue.items) {
      if (!item) {
        continue;
      }
      const line = itemLine(item);
      if (item.status === "running" && current === null) {
        current = line;
      }
      panel.append(line);
    }
  }
  if (!any) {
    panel.append(
      span(
        "queue-empty",
        "[waiting] The queue appears when capa or FLOSS starts.",
      ),
    );
  }
  return current;
}

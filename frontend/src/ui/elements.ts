// Typed DOM element lookup and stable element references.
// Missing required elements fail early with a useful error.

export function element<T extends HTMLElement>(
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

export const setupView = element<HTMLElement>("setup-view");

export const scanView = element<HTMLElement>("scan-view");

export const scanList = element<HTMLDivElement>("scan-list");

export const scanListEmpty = element<HTMLParagraphElement>(
  "scan-list-empty",
);

export const scanCount = element<HTMLSpanElement>("scan-count");

export const newScanButton = element<HTMLButtonElement>("new-scan");

export const sourceInput = element<HTMLInputElement>("source-path");

export const resultsInput = element<HTMLInputElement>("results-path");

export const chooseSource = element<HTMLButtonElement>("choose-source");

export const chooseResults = element<HTMLButtonElement>("choose-results");

export const startButton = element<HTMLButtonElement>("start-scan");

export const cancelButton = element<HTMLButtonElement>("cancel-scan");

export const openCaseButton = element<HTMLButtonElement>("open-case");

export const fatalAlert = element<HTMLDivElement>("fatal-alert");

export const serviceBadge = element<HTMLSpanElement>("service-badge");

export const progressWrap = element<HTMLElement>("progress-wrap");

export const progressMessage = element<HTMLSpanElement>("progress-message");

export const progressState = element<HTMLSpanElement>("progress-state");

export const resultsSection = element<HTMLElement>("results-section");

export const liveActivityPanel = element<HTMLPreElement>(
  "live-activity-panel",
);

export const activityAutoscrollButton =
  element<HTMLButtonElement>(
    "activity-autoscroll",
  );

export const copyActivityButton =
  element<HTMLButtonElement>(
    "copy-activity",
  );
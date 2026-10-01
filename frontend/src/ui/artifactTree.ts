
import {
  artifactDisplayRecords,
  highestRisk,
  objectValue,
} from "../risk";
import type {
  AnalyzerName,
  ArtifactDisplay,
  ArtifactRisk,
  ArtifactRiskSource,
  ArtifactTreeNode,
  CoverageStatus,
  JsonObject,
  ScanResult,
} from "../types";
import { element } from "./elements";

let artifactBlock: HTMLElement | null = null;

let artifactPopoutButton: HTMLButtonElement | null = null;

export function setArtifactTreePoppedOut(
  poppedOut: boolean,
): void {
  if (!artifactBlock || !artifactPopoutButton) {
    return;
  }
  artifactBlock.classList.toggle(
    "artifact-block-popped-out",
    poppedOut,
  );
  document.body.classList.toggle(
    "artifact-popout-open",
    poppedOut,
  );
  artifactPopoutButton.setAttribute(
    "aria-pressed",
    String(poppedOut),
  );
  artifactPopoutButton.textContent = poppedOut
    ? "Return to results"
    : "Pop out tree";
}

export function configureArtifactTreePopout(): void {
  artifactBlock = document.querySelector<HTMLElement>(
    ".artifact-block",
  );
  const heading = artifactBlock?.querySelector<HTMLElement>(
    ".block-heading",
  );
  if (!artifactBlock || !heading) {
    return;
  }
  const headerCells = artifactBlock.querySelectorAll<HTMLElement>(
    ".artifact-tree-header span",
  );
  if (headerCells.length >= 3) {
    headerCells[1].textContent = "Analysis coverage";
    headerCells[2].textContent = "Assessment · source";
  }
  const actions = document.createElement("div");
  actions.className = "artifact-heading-actions";
  const legend = heading.querySelector<HTMLElement>(
    ".artifact-legend",
  );
  if (legend) {
    if (!legend.querySelector(".risk-unknown")) {
      const unknown = document.createElement("span");
      unknown.className = "risk-legend risk-unknown";
      unknown.textContent = "Unknown";
      legend.append(unknown);
    }
    actions.append(legend);
  }
  const button = document.createElement("button");
  button.type = "button";
  button.className = "artifact-popout-button";
  button.textContent = "Pop out tree";
  button.setAttribute("aria-pressed", "false");
  button.addEventListener("click", () => {
    setArtifactTreePoppedOut(
      !artifactBlock?.classList.contains(
        "artifact-block-popped-out",
      ),
    );
  });
  actions.append(button);
  heading.append(actions);
  artifactPopoutButton = button;
  document.addEventListener("keydown", (event) => {
    if (
      event.key === "Escape"
      && artifactBlock?.classList.contains(
        "artifact-block-popped-out",
      )
    ) {
      setArtifactTreePoppedOut(false);
      artifactPopoutButton?.focus();
    }
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
    riskSource: null,
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

function summarizeTree(
  node: ArtifactTreeNode,
): void {
  if (!node.directory) {
    node.fileCount = 1;
    node.risk = node.artifact?.risk ?? "clean";
    node.riskSource = node.artifact?.riskSource ?? null;
    return;
  }
  node.fileCount = 0;
  node.risk = "clean";
  node.riskSource = "child";
  for (const child of node.children.values()) {
    summarizeTree(child);
    node.fileCount += child.fileCount;
    const previousRisk: ArtifactRisk = node.risk;
    node.risk = highestRisk(
      node.risk,
      child.risk,
    );
    if (node.risk !== previousRisk) {
      node.riskSource = "child";
    }
  }
  if (
    node.risk === "clean"
    && Array.from(node.children.values()).some(
      (child) => child.risk === "unknown",
    )
  ) {
    node.risk = "unknown";
    node.riskSource = "child";
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

function coverageShortLabel(
  status: CoverageStatus,
): string {
  switch (status) {
    case "completed":
      return "DONE";
    case "finding":
      return "FINDING";
    case "incomplete":
      return "PARTIAL";
    case "unavailable":
      return "UNAVAILABLE";
    case "not-applicable":
      return "N/A";
    case "error":
      return "FAILED";
  }
}

function analyzerLabel(name: AnalyzerName): string {
  if (name === "clamav") {
    return "ClamAV";
  }
  if (name === "floss") {
    return "FLOSS";
  }
  return "capa";
}

function riskSourceLabel(
  source: ArtifactRiskSource,
): string | null {
  switch (source) {
    case "clamav":
    case "capa":
    case "floss":
      return analyzerLabel(source);
    case "inventory":
      return "inventory";
    case "coverage":
      return "coverage";
    case "all-tools":
      return "all tools";
    case "child":
      return "child";
    case null:
      return null;
  }
}

function createRiskBadge(
  risk: ArtifactRisk,
  source: ArtifactRiskSource,
): HTMLSpanElement {
  const badge = document.createElement("span");
  badge.className = `artifact-risk artifact-risk-${risk}`;
  const sourceLabel = riskSourceLabel(source);
  badge.textContent = sourceLabel
    ? `${risk} · ${sourceLabel}`
    : risk;
  return badge;
}

function createCoverageBadge(
  name: AnalyzerName,
  status: CoverageStatus,
): HTMLSpanElement {
  const badge = document.createElement("span");
  badge.className =
    `tool-badge tool-state-${status}`;
  const label = analyzerLabel(name);
  badge.textContent =
    `${label} · ${coverageShortLabel(status)}`;
  badge.title =
    `${label}: ${coverageLabel(status)}`;
  badge.setAttribute(
    "aria-label",
    badge.title,
  );
  return badge;
}

function capaCapabilityNames(
  result: JsonObject | null,
): string[] {
  const capabilities = result?.capabilities;
  if (!Array.isArray(capabilities)) {
    return [];
  }
  const names: string[] = [];
  for (const value of capabilities) {
    const capability = objectValue(value);
    if (
      capability
      && typeof capability.name === "string"
      && !names.includes(capability.name)
    ) {
      names.push(capability.name);
    }
  }
  return names;
}

function artifactAssessmentExplanation(
  display: ArtifactDisplay,
): string {
  if (display.riskSource === "clamav") {
    return "ClamAV reported a signature match for this file.";
  }
  if (display.riskSource === "inventory") {
    return display.artifact.error
      ? `Inventory error: ${display.artifact.error}`
      : `${display.artifact.review_flags.toLocaleString()} inventory review flag${display.artifact.review_flags === 1 ? "" : "s"} recorded.`;
  }
  if (display.riskSource === "capa") {
    const risk = objectValue(display.capaResult?.risk);
    const score = typeof risk?.score === "number"
      ? ` Weighted score: ${risk.score.toLocaleString()}.`
      : "";
    const capabilities = capaCapabilityNames(
      display.capaResult,
    );
    const names = capabilities.length > 0
      ? ` Matches: ${capabilities.slice(0, 3).join(", ")}${capabilities.length > 3 ? ", …" : ""}.`
      : "";
    return `capa capability weighting produced this assessment.${score}${names}`;
  }
  if (display.risk === "unknown") {
    return "One or more applicable analyzers did not complete, so this file cannot be presented as clean.";
  }
  return "No indicators were reported by the analyzers that apply to this file.";
}

function createArtifactDetail(
  display: ArtifactDisplay,
): HTMLDivElement {
  const detail = document.createElement("div");
  detail.className = "artifact-detail";
  detail.hidden = true;
  const heading = document.createElement("strong");
  const source = riskSourceLabel(display.riskSource);
  heading.textContent = source
    ? `${display.risk.toUpperCase()} · ${source}`
    : display.risk.toUpperCase();
  const explanation = document.createElement("p");
  explanation.textContent = artifactAssessmentExplanation(display);
  const coverage = document.createElement("p");
  coverage.className = "artifact-detail-coverage";
  coverage.textContent = (
    Object.entries(display.coverage) as Array<
      [AnalyzerName, CoverageStatus]
    >
  ).map(([name, status]) =>
    `${analyzerLabel(name)} ${coverageShortLabel(status)}`,
  ).join(" · ");
  detail.append(heading, explanation, coverage);
  if (display.artifact.sha256) {
    const hash = document.createElement("code");
    hash.className = "artifact-detail-hash";
    hash.textContent = `SHA-256 ${display.artifact.sha256}`;
    detail.append(hash);
  }
  return detail;
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
  let detail: HTMLDivElement | null = null;
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
    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "artifact-toggle artifact-file-detail-toggle";
    toggle.textContent = "▸";
    toggle.setAttribute("aria-expanded", "false");
    toggle.setAttribute(
      "aria-label",
      `Show details for ${node.path}`,
    );
    if (node.artifact) {
      detail = createArtifactDetail(node.artifact);
      toggle.addEventListener("click", () => {
        if (!detail) {
          return;
        }
        const collapsed = detail.hidden !== false;
        detail.hidden = !collapsed;
        toggle.textContent = collapsed ? "▾" : "▸";
        toggle.setAttribute(
          "aria-expanded",
          String(collapsed),
        );
        toggle.setAttribute(
          "aria-label",
          `${collapsed ? "Hide" : "Show"} details for ${node.path}`,
        );
        row.classList.toggle(
          "artifact-row-expanded",
          collapsed,
        );
      });
    }
    pathCell.append(toggle, icon, nameCopy);
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
      coverageCell.append(
        createCoverageBadge(
          analyzerName,
          status,
        ),
      );
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
  riskCell.append(
    createRiskBadge(
      node.risk,
      node.riskSource,
    ),
  );
  row.append(
    pathCell,
    coverageCell,
    riskCell,
  );
  wrapper.append(row);
  if (detail) {
    wrapper.append(detail);
  }
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

export function renderArtifactTree(
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
// Resource profile picker and Custom form in the setup view.
// The server is the authority: this module shows friendly units and
// catches obvious mistakes early, then asks the server to validate.

import { api } from "../api";
import type {
  ResourceFieldSpec,
  ResourceOptions,
  ResourceProblem,
  ResourceSelection,
  ResourceValidation,
  ResourceValues,
} from "../types";
import { element } from "./elements";

const CUSTOM = "custom";
const STORAGE_KEY = "mantha-ray.resources.v1";
const VALIDATE_DELAY_MS = 250;

interface DisplayField {
  key: string;
  label: string;
  unit: string;
  // canonical value = UI value * scale
  scale: number;
  step: number;
}

interface DisplayGroup {
  title: string;
  hint?: string;
  advanced?: boolean;
  fields: DisplayField[];
}

const GROUPS: DisplayGroup[] = [
  {
    title: "Container",
    fields: [
      { key: "cpus", label: "CPUs", unit: "", scale: 1, step: 0.5 },
      { key: "memory_mib", label: "Memory", unit: "GiB", scale: 1024, step: 0.5 },
      { key: "pids_limit", label: "Process limit", unit: "", scale: 1, step: 1 },
      { key: "tmp_mib", label: "Temporary space", unit: "MiB", scale: 1, step: 64 },
      {
        key: "host_timeout_seconds",
        label: "Overall time limit",
        unit: "h",
        scale: 3600,
        step: 0.5,
      },
    ],
  },
  {
    title: "capa",
    hint: "Capability analysis of executables",
    fields: [
      { key: "max_capa_files", label: "File cap", unit: "files", scale: 1, step: 1 },
      {
        key: "capa_file_timeout_seconds",
        label: "Per-file timeout",
        unit: "min",
        scale: 60,
        step: 0.5,
      },
      {
        key: "capa_total_timeout_seconds",
        label: "Total budget",
        unit: "min",
        scale: 60,
        step: 5,
      },
    ],
  },
  {
    title: "FLOSS",
    hint: "String extraction from Windows executables",
    fields: [
      { key: "max_floss_files", label: "File cap", unit: "files", scale: 1, step: 1 },
      {
        key: "floss_file_timeout_seconds",
        label: "Per-file timeout",
        unit: "min",
        scale: 60,
        step: 0.5,
      },
      {
        key: "floss_total_timeout_seconds",
        label: "Total budget",
        unit: "min",
        scale: 60,
        step: 5,
      },
    ],
  },
  {
    title: "Inventory",
    hint: "Limits on what is read from the folder",
    advanced: true,
    fields: [
      { key: "max_file_count", label: "Maximum files", unit: "files", scale: 1, step: 1 },
      { key: "max_total_gib", label: "Maximum total size", unit: "GiB", scale: 1, step: 1 },
      { key: "max_file_gib", label: "Maximum file size", unit: "GiB", scale: 1, step: 1 },
      { key: "max_depth", label: "Maximum folder depth", unit: "", scale: 1, step: 1 },
    ],
  },
];

const DISPLAY_FIELDS = new Map(
  GROUPS.flatMap((group) => group.fields.map((field) => [field.key, field])),
);

let options: ResourceOptions | null = null;
let mode = "";
let customBase = "";
let customValues: ResourceValues = {};
const clientErrors = new Map<string, string>();
let validation: ResourceValidation | null = null;
let validationSequence = 0;
let validationTimer: number | null = null;
const inputs = new Map<string, HTMLInputElement>();
const fieldErrors = new Map<string, HTMLElement>();

// ---------------------------------------------------------------- format

function trimNumber(value: number): string {
  return String(Math.round(value * 100) / 100);
}

export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) {
    return "—";
  }
  const minutes = Math.round(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  if (hours && rest) {
    return `${hours} h ${rest} min`;
  }
  if (hours) {
    return `${hours} h`;
  }
  if (minutes) {
    return `${minutes} min`;
  }
  return `${Math.round(seconds)} s`;
}

function presetTitle(name: string): string {
  return name ? name[0].toUpperCase() + name.slice(1) : name;
}

function plural(count: number, word: string): string {
  return `${trimNumber(count)} ${word}${count === 1 ? "" : "s"}`;
}

function shortValues(values: ResourceValues): string {
  return [
    plural(values.cpus, "CPU"),
    `${trimNumber(values.memory_mib / 1024)} GiB`,
  ].join(" · ");
}

function describeValues(values: ResourceValues): string {
  return [
    plural(values.cpus, "CPU"),
    `${trimNumber(values.memory_mib / 1024)} GiB memory`,
    `capa ${formatDuration(values.capa_total_timeout_seconds)}`,
    `FLOSS ${formatDuration(values.floss_total_timeout_seconds)}`,
    `stops after ${formatDuration(values.host_timeout_seconds)}`,
  ].join(" · ");
}

function numberField(record: Record<string, unknown>, key: string): number | null {
  const value = record[key];
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

/**
 * One-line description of a profile record from a report or scan state.
 * Report data is treated as untrusted: anything malformed yields null.
 */
export function describeResources(record: unknown): string | null {
  if (typeof record !== "object" || record === null || Array.isArray(record)) {
    return null;
  }
  const data = record as Record<string, unknown>;
  const name = typeof data.profile === "string"
    ? data.profile
    : typeof data.name === "string"
      ? data.name
      : null;
  const base = typeof data.base === "string" ? data.base : null;
  const values = data.values;
  if (!name || typeof values !== "object" || values === null) {
    return null;
  }
  const valueRecord = values as Record<string, unknown>;
  const cpus = numberField(valueRecord, "cpus");
  const memory = numberField(valueRecord, "memory_mib");
  const capa = numberField(valueRecord, "capa_total_timeout_seconds");
  const floss = numberField(valueRecord, "floss_total_timeout_seconds");
  if (cpus === null || memory === null || capa === null || floss === null) {
    return null;
  }
  const title = name === CUSTOM && base
    ? `Custom (based on ${presetTitle(base)})`
    : presetTitle(name);
  const parts = [
    title,
    plural(cpus, "CPU"),
    `${trimNumber(memory / 1024)} GiB`,
    `capa ${formatDuration(capa)}`,
    `FLOSS ${formatDuration(floss)}`,
  ];
  if (typeof data.enforced === "boolean") {
    parts.push(data.enforced ? "limits confirmed" : "limits not confirmed");
  }
  return parts.join(" · ");
}

// --------------------------------------------------------------- storage

function loadSaved(): void {
  if (!options) {
    return;
  }
  let raw: string | null = null;
  try {
    raw = window.localStorage.getItem(STORAGE_KEY);
  } catch {
    return;
  }
  if (!raw) {
    return;
  }
  try {
    const saved = JSON.parse(raw) as Record<string, unknown>;
    const presets = options.catalog.presets;
    if (typeof saved.customBase === "string" && saved.customBase in presets) {
      customBase = saved.customBase;
      customValues = { ...presets[customBase] };
    }
    const values = saved.customValues;
    if (typeof values === "object" && values !== null) {
      for (const [key, value] of Object.entries(values)) {
        if (
          key in options.catalog.fields
          && typeof value === "number"
          && Number.isFinite(value)
        ) {
          customValues[key] = value;
        }
      }
    }
    if (
      typeof saved.mode === "string"
      && (saved.mode === CUSTOM || saved.mode in presets)
    ) {
      mode = saved.mode;
    }
  } catch {
    // Ignore unreadable saved settings.
  }
}

function save(): void {
  try {
    window.localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({ mode, customBase, customValues }),
    );
  } catch {
    // Storage may be unavailable; settings simply aren't remembered.
  }
}

// ------------------------------------------------------------- selection

function currentValues(): ResourceValues | null {
  if (!options) {
    return null;
  }
  return mode === CUSTOM
    ? customValues
    : options.catalog.presets[mode] ?? null;
}

function changedFromBase(): ResourceValues {
  if (!options) {
    return {};
  }
  const base = options.catalog.presets[customBase];
  const changed: ResourceValues = {};
  for (const [key, value] of Object.entries(customValues)) {
    if (base[key] !== value) {
      changed[key] = value;
    }
  }
  return changed;
}

function selectionPayload(): ResourceSelection {
  if (!options) {
    return {};
  }
  if (mode === CUSTOM) {
    const changed = changedFromBase();
    return {
      resource_profile: customBase,
      resource_overrides: Object.keys(changed).length ? changed : null,
    };
  }
  return { resource_profile: mode, resource_overrides: null };
}

/**
 * The selection to send with a new scan, or null when it is invalid.
 * Before options load, an empty selection lets the server use its default.
 */
export function getResourceSelection(): ResourceSelection | null {
  if (!options) {
    return {};
  }
  if (mode === CUSTOM && clientErrors.size > 0) {
    return null;
  }
  if (validation && !validation.ok) {
    return null;
  }
  return selectionPayload();
}

// ------------------------------------------------------------ validation

function scheduleValidation(): void {
  if (validationTimer !== null) {
    window.clearTimeout(validationTimer);
  }
  validationTimer = window.setTimeout(() => {
    validationTimer = null;
    void validate();
  }, VALIDATE_DELAY_MS);
}

async function validate(): Promise<void> {
  if (!options || (mode === CUSTOM && clientErrors.size > 0)) {
    renderMessages();
    return;
  }
  const sequence = ++validationSequence;
  try {
    const result = await api<ResourceValidation>(
      "/api/resource-profiles/validate",
      { method: "POST", body: JSON.stringify(selectionPayload()) },
    );
    if (sequence !== validationSequence) {
      return;
    }
    validation = result;
  } catch (error) {
    if (sequence !== validationSequence) {
      return;
    }
    validation = {
      ok: false,
      profile: null,
      problems: [{
        field: null,
        message: error instanceof Error
          ? error.message
          : "The resource settings could not be checked.",
      }],
      warnings: [],
    };
  }
  renderMessages();
}

function checkInput(field: DisplayField, spec: ResourceFieldSpec): void {
  const input = inputs.get(field.key);
  if (!input) {
    return;
  }
  const raw = input.value.trim();
  const shown = Number(raw);
  if (!raw || !Number.isFinite(shown)) {
    clientErrors.set(field.key, "Enter a number.");
    return;
  }
  const canonical = spec.kind === "int"
    ? Math.round(shown * field.scale)
    : Math.round(shown * field.scale * 100) / 100;
  if (canonical < spec.minimum || canonical > spec.maximum) {
    const unit = field.unit ? ` ${field.unit}` : "";
    clientErrors.set(
      field.key,
      `Must be between ${trimNumber(spec.minimum / field.scale)} `
        + `and ${trimNumber(spec.maximum / field.scale)}${unit}.`,
    );
    return;
  }
  clientErrors.delete(field.key);
  customValues[field.key] = canonical;
}

// --------------------------------------------------------------- render

function renderPresets(): void {
  if (!options) {
    return;
  }
  const container = element<HTMLDivElement>("resource-presets");
  container.replaceChildren();
  const names = [...Object.keys(options.catalog.presets), CUSTOM];
  for (const name of names) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "resource-preset";
    button.setAttribute("role", "radio");
    button.setAttribute("aria-checked", String(name === mode));
    button.dataset.mode = name;
    const title = document.createElement("strong");
    title.textContent = presetTitle(name);
    const detail = document.createElement("small");
    detail.textContent = name === CUSTOM
      ? "Your own limits"
      : shortValues(options.catalog.presets[name]);
    button.append(title, detail);
    button.addEventListener("click", () => {
      selectMode(name);
    });
    container.append(button);
  }
}

function renderCustomForm(): void {
  if (!options) {
    return;
  }
  const container = element<HTMLDivElement>("resource-custom");
  container.replaceChildren();
  inputs.clear();
  fieldErrors.clear();

  const toolbar = document.createElement("div");
  toolbar.className = "resource-toolbar";
  const baseLabel = document.createElement("label");
  baseLabel.className = "resource-base";
  baseLabel.textContent = "Start from ";
  const baseSelect = document.createElement("select");
  baseSelect.className = "form-select form-select-sm";
  for (const name of Object.keys(options.catalog.presets)) {
    const option = document.createElement("option");
    option.value = name;
    option.textContent = presetTitle(name);
    option.selected = name === customBase;
    baseSelect.append(option);
  }
  baseSelect.addEventListener("change", () => {
    resetCustom(baseSelect.value);
  });
  baseLabel.append(baseSelect);
  const reset = document.createElement("button");
  reset.type = "button";
  reset.className = "btn btn-outline-info btn-sm";
  reset.textContent = "Reset values";
  reset.addEventListener("click", () => {
    resetCustom(customBase);
  });
  const changedNote = document.createElement("span");
  changedNote.id = "resource-changed";
  changedNote.className = "resource-changed";
  toolbar.append(baseLabel, reset, changedNote);
  container.append(toolbar);

  for (const group of GROUPS) {
    const fieldset = document.createElement("fieldset");
    fieldset.className = "resource-group";
    const legend = document.createElement("legend");
    legend.textContent = group.title;
    fieldset.append(legend);
    if (group.hint) {
      const hint = document.createElement("p");
      hint.className = "resource-hint";
      hint.textContent = group.hint;
      fieldset.append(hint);
    }
    const grid = document.createElement("div");
    grid.className = "resource-grid";
    for (const field of group.fields) {
      const spec = options.catalog.fields[field.key];
      if (!spec) {
        continue;
      }
      const wrapper = document.createElement("div");
      wrapper.className = "resource-field";
      const id = `resource-${field.key}`;
      const label = document.createElement("label");
      label.htmlFor = id;
      label.textContent = field.label;
      if (field.unit) {
        const unit = document.createElement("span");
        unit.className = "resource-unit";
        unit.textContent = field.unit;
        label.append(" ", unit);
      }
      const input = document.createElement("input");
      input.id = id;
      input.className = "form-control";
      input.type = "number";
      input.inputMode = "decimal";
      input.step = String(field.step);
      input.min = trimNumber(spec.minimum / field.scale);
      input.max = trimNumber(spec.maximum / field.scale);
      input.addEventListener("input", () => {
        checkInput(field, spec);
        save();
        renderFieldStates();
        renderSummary();
        scheduleValidation();
      });
      const error = document.createElement("small");
      error.className = "resource-error";
      error.id = `${id}-error`;
      input.setAttribute("aria-describedby", error.id);
      wrapper.append(label, input, error);
      grid.append(wrapper);
      inputs.set(field.key, input);
      fieldErrors.set(field.key, error);
    }
    fieldset.append(grid);
    if (group.advanced) {
      const details = document.createElement("details");
      details.className = "resource-advanced";
      const summary = document.createElement("summary");
      summary.textContent = `${group.title} limits`;
      details.append(summary, fieldset);
      container.append(details);
    } else {
      container.append(fieldset);
    }
  }
  fillInputs();
}

function fillInputs(): void {
  for (const [key, input] of inputs) {
    const field = DISPLAY_FIELDS.get(key);
    if (field && key in customValues) {
      input.value = trimNumber(customValues[key] / field.scale);
    }
  }
}

function renderFieldStates(): void {
  const serverProblems = new Map<string, string>();
  for (const problem of validation?.problems ?? []) {
    if (problem.field && inputs.has(problem.field)) {
      serverProblems.set(problem.field, problem.message);
    }
  }
  for (const [key, input] of inputs) {
    const message = clientErrors.get(key) ?? serverProblems.get(key) ?? "";
    input.setAttribute("aria-invalid", String(Boolean(message)));
    const error = fieldErrors.get(key);
    if (error) {
      error.textContent = message;
    }
  }
  const changed = document.getElementById("resource-changed");
  if (changed) {
    const count = Object.keys(changedFromBase()).length;
    changed.textContent = count
      ? `${count} setting${count === 1 ? "" : "s"} changed from ${presetTitle(customBase)}`
      : `Same as ${presetTitle(customBase)}`;
  }
}

function renderSummary(): void {
  const summary = element<HTMLParagraphElement>("resource-summary");
  const values = currentValues();
  summary.textContent = values ? describeValues(values) : "";

  const capacity = element<HTMLSpanElement>("resource-capacity");
  const docker = options?.capacity;
  capacity.textContent = docker
    ? `Docker: ${plural(docker.cpus, "CPU")} · `
      + `${trimNumber(docker.memory_bytes / 1024 ** 3)} GiB`
    : options
      ? "Docker capacity unknown"
      : "";
}

function renderMessages(): void {
  const list = element<HTMLUListElement>("resource-messages");
  list.replaceChildren();
  renderFieldStates();
  const shownInline = (problem: ResourceProblem): boolean => (
    mode === CUSTOM && problem.field !== null && inputs.has(problem.field)
  );
  for (const problem of validation?.problems ?? []) {
    if (shownInline(problem)) {
      continue;
    }
    const item = document.createElement("li");
    item.className = "resource-problem";
    item.textContent = problem.message;
    list.append(item);
  }
  if (mode === CUSTOM && clientErrors.size > 0) {
    const item = document.createElement("li");
    item.className = "resource-problem";
    item.textContent = "Fix the highlighted settings before starting a scan.";
    list.append(item);
  }
  for (const warning of validation?.warnings ?? []) {
    const item = document.createElement("li");
    item.className = "resource-warning";
    item.textContent = warning;
    list.append(item);
  }
}

function resetCustom(base: string): void {
  if (!options || !(base in options.catalog.presets)) {
    return;
  }
  customBase = base;
  customValues = { ...options.catalog.presets[base] };
  clientErrors.clear();
  fillInputs();
  save();
  renderFieldStates();
  renderSummary();
  scheduleValidation();
}

function selectMode(name: string): void {
  mode = name;
  for (const button of element<HTMLDivElement>("resource-presets").children) {
    const preset = button as HTMLButtonElement;
    preset.setAttribute("aria-checked", String(preset.dataset.mode === name));
  }
  element<HTMLDivElement>("resource-custom").classList.toggle(
    "d-none",
    name !== CUSTOM,
  );
  validation = null;
  save();
  renderSummary();
  renderMessages();
  scheduleValidation();
}

/** Build the picker once the server's options have loaded. */
export function configureResourcePanel(loaded: ResourceOptions): void {
  options = loaded;
  const presets = loaded.catalog.presets;
  const fallback = loaded.catalog.default in presets
    ? loaded.catalog.default
    : Object.keys(presets)[0];
  mode = fallback;
  customBase = fallback;
  customValues = { ...presets[fallback] };
  loadSaved();
  renderPresets();
  renderCustomForm();
  // Re-check restored custom values against the current bounds.
  for (const field of DISPLAY_FIELDS.values()) {
    const spec = loaded.catalog.fields[field.key];
    if (spec && inputs.has(field.key)) {
      checkInput(field, spec);
    }
  }
  element<HTMLElement>("resource-profile-panel").classList.remove("d-none");
  selectMode(mode);
}
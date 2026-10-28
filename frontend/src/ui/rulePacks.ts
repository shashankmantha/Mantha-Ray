// The "YARA rules" panel: the signed bundle in use and your own rule files.

import { api } from "../api";
import { element } from "./elements";

interface LocalPack {
  name: string;
  rules?: number;
  severity?: string;
  rule_names?: string[];
  error?: string;
}

interface RulePacks {
  bundle: {
    version: string;
    verified: boolean;
    stale: boolean;
    rules: number;
  } | null;
  local: LocalPack[];
  max_local: number;
  error: string | null;
}

const MAX_FILE_BYTES = 8 * 1024 * 1024;

const severityText: Record<string, string> = {
  threat: "High Concern",
  suspicious: "Needs Review",
  info: "listed only",
  mixed: "mixed",
};

const bundleLabel = element<HTMLSpanElement>("rule-bundle");
const localList = element<HTMLUListElement>("local-rules");
const fileInput = element<HTMLInputElement>("local-rule-file");
const severityInput = element<HTMLSelectElement>("local-rule-severity");
const addButton = element<HTMLButtonElement>("local-rule-add");
const updateButton = element<HTMLButtonElement>("rule-update");
const message = element<HTMLParagraphElement>("local-rule-message");

function setMessage(text: string, kind: "info" | "error" | "ok" = "info"): void {
  message.textContent = text;
  message.dataset.kind = kind;
}

function render(packs: RulePacks): void {
  if (packs.bundle) {
    const signed = packs.bundle.verified ? "signed" : "unsigned, testing only";
    const stale = packs.bundle.stale ? " · over 30 days old" : "";
    bundleLabel.textContent =
      `Bundle ${packs.bundle.version} (${signed}) · ${packs.bundle.rules.toLocaleString()} rules${stale}`;
  } else {
    bundleLabel.textContent = "No signed rule packs installed";
  }
  localList.replaceChildren();
  for (const pack of packs.local) {
    const item = document.createElement("li");
    const label = document.createElement("span");
    if (pack.error) {
      label.textContent = `local:${pack.name} · not usable`;
      label.title = pack.error;
    } else {
      const count = pack.rules ?? 0;
      label.textContent =
        `local:${pack.name} · ${count.toLocaleString()} rule${count === 1 ? "" : "s"}`
        + ` · match = ${severityText[pack.severity ?? ""] ?? pack.severity}`;
      label.title = (pack.rule_names ?? []).join(", ");
    }
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "btn btn-link btn-sm local-rule-remove";
    remove.textContent = "Remove";
    remove.setAttribute("aria-label", `Remove local:${pack.name}`);
    remove.addEventListener("click", () => void removePack(pack.name));
    item.append(label, remove);
    localList.append(item);
  }
  addButton.disabled = packs.local.length >= packs.max_local;
}

export async function loadRulePacks(): Promise<void> {
  try {
    render(await api<RulePacks>("/api/packs"));
  } catch (error) {
    bundleLabel.textContent = "Rule packs couldn't be read";
    setMessage(error instanceof Error ? error.message : String(error), "error");
  }
}

async function removePack(name: string): Promise<void> {
  try {
    render(await api<RulePacks>(`/api/packs/local/${encodeURIComponent(name)}`, {
      method: "DELETE",
    }));
    setMessage(`Removed local:${name}.`, "ok");
  } catch (error) {
    setMessage(error instanceof Error ? error.message : String(error), "error");
  }
}

async function addRules(): Promise<void> {
  const file = fileInput.files?.[0];
  if (!file) {
    setMessage("Choose a .yar file first.", "error");
    return;
  }
  if (file.size > MAX_FILE_BYTES) {
    setMessage("That file is larger than 8 MiB.", "error");
    return;
  }
  addButton.disabled = true;
  setMessage(`Checking ${file.name} in the scan container...`);
  try {
    const content = await file.text();
    const result = await api<RulePacks & { added: LocalPack }>("/api/packs/local", {
      method: "POST",
      body: JSON.stringify({
        filename: file.name,
        content,
        severity: severityInput.value,
      }),
    });
    render(result);
    const count = result.added.rules ?? 0;
    setMessage(
      `Added ${count.toLocaleString()} rule${count === 1 ? "" : "s"} as local:${result.added.name}. `
      + "They run in every scan from now on.",
      "ok",
    );
    fileInput.value = "";
  } catch (error) {
    setMessage(error instanceof Error ? error.message : String(error), "error");
  } finally {
    addButton.disabled = false;
  }
}

async function updatePacks(): Promise<void> {
  updateButton.disabled = true;
  setMessage("Checking Mantha Hermit's releases for a newer signed bundle...");
  try {
    const result = await api<RulePacks & { message: string; updated: boolean }>(
      "/api/packs/update",
      { method: "POST" },
    );
    render(result);
    setMessage(result.message, result.updated ? "ok" : "info");
  } catch (error) {
    setMessage(error instanceof Error ? error.message : String(error), "error");
  } finally {
    updateButton.disabled = false;
  }
}

export function configureRulePacks(): void {
  addButton.addEventListener("click", () => void addRules());
  updateButton.addEventListener("click", () => void updatePacks());
}

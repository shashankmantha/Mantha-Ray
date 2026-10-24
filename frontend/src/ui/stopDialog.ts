// "Stop scan" confirmation. Stopping can't be undone, so the dialog opens
// with "Keep scanning" focused, and both destructive actions only fire
// after their button is held down for HOLD_MS.

import { element } from "./elements";

export const HOLD_MS = 2000;

const dialog = element<HTMLDialogElement>("stop-dialog");
const keepButton = element<HTMLButtonElement>("stop-keep");
const confirmButton = element<HTMLButtonElement>("stop-confirm");
const discardButton = element<HTMLButtonElement>("stop-discard");
const discardFold = dialog.querySelector<HTMLDetailsElement>(".stop-discard");

export interface StopDialogActions {
  stopAndSave(): void;
  discard(): void;
}

/** Fire `action` only after the button has been held for `ms`. */
export function holdToConfirm(
  button: HTMLButtonElement,
  action: () => void,
  ms: number = HOLD_MS,
): () => void {
  let timer: number | null = null;

  const reset = (): void => {
    if (timer !== null) {
      window.clearTimeout(timer);
      timer = null;
    }
    button.classList.remove("holding");
  };

  const start = (): void => {
    if (timer !== null || button.disabled) {
      return;
    }
    button.style.setProperty("--hold-ms", `${ms}ms`);
    button.classList.add("holding");
    timer = window.setTimeout(() => {
      timer = null;
      button.classList.remove("holding");
      action();
    }, ms);
  };

  button.addEventListener("pointerdown", (event) => {
    if (event.button === 0) {
      button.setPointerCapture(event.pointerId);
      start();
    }
  });
  for (const name of ["pointerup", "pointercancel", "lostpointercapture"]) {
    button.addEventListener(name, reset);
  }
  button.addEventListener("keydown", (event) => {
    if ((event.key === " " || event.key === "Enter") && !event.repeat) {
      event.preventDefault();
      start();
    }
  });
  button.addEventListener("keyup", (event) => {
    if (event.key === " " || event.key === "Enter") {
      reset();
    }
  });
  button.addEventListener("blur", reset);
  // A plain click (or a click synthesised by assistive tech) never acts.
  button.addEventListener("click", (event) => event.preventDefault());
  return reset;
}

let resets: Array<() => void> = [];

export function configureStopDialog(actions: StopDialogActions): void {
  keepButton.addEventListener("click", () => dialog.close());
  resets = [
    holdToConfirm(confirmButton, () => {
      dialog.close();
      actions.stopAndSave();
    }),
    holdToConfirm(discardButton, () => {
      dialog.close();
      actions.discard();
    }),
  ];
  dialog.addEventListener("close", () => {
    for (const reset of resets) {
      reset();
    }
    if (discardFold) {
      discardFold.open = false;
    }
  });
}

export function openStopDialog(): void {
  if (dialog.open) {
    return;
  }
  dialog.showModal();
  keepButton.focus();
}

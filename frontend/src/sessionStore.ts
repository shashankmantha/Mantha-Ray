// In-memory scan session state for the web UI.
// This module must not render the DOM or perform fetches.

import type { ScanSession } from "./types";

const sessions = new Map<string, ScanSession>();

const sessionOrder: string[] = [];

let activeScanId: string | null = null;

let selectedScanId: string | null = null;

export function getSession(id: string): ScanSession | undefined {
  return sessions.get(id);
}

export function hasSession(id: string): boolean {
  return sessions.has(id);
}

export function allSessions(): IterableIterator<ScanSession> {
  return sessions.values();
}

export function orderedSessionIds(): readonly string[] {
  return sessionOrder;
}

/** Add a new live scan at the top of the sidebar. */
export function prependSession(session: ScanSession): void {
  sessions.set(session.id, session);
  sessionOrder.unshift(session.id);
}

/** Add a saved case at the bottom of the sidebar. */
export function appendSession(session: ScanSession): void {
  sessions.set(session.id, session);
  sessionOrder.push(session.id);
}

/** Drop saved-case sessions before the history list is reloaded. */
export function removeHistoricalSessions(): void {
  for (const [id, session] of sessions) {
    if (session.historical) {
      sessions.delete(id);
      const index = sessionOrder.indexOf(id);
      if (index >= 0) {
        sessionOrder.splice(index, 1);
      }
    }
  }
}

export function getActiveScanId(): string | null {
  return activeScanId;
}

export function setActiveScanId(id: string | null): void {
  activeScanId = id;
}

export function getSelectedScanId(): string | null {
  return selectedScanId;
}

export function setSelectedScanId(id: string | null): void {
  selectedScanId = id;
}
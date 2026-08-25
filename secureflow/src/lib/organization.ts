/**
 * Small localStorage wrapper for "which organization is active in this
 * browser" — deliberately separate from React state/react-query so
 * dashboard.integrations.tsx's useOrganizationId() can read it
 * synchronously on first render (no flash of the empty state before a
 * previously-picked org loads).
 */

const ORG_STORAGE_KEY = "secureflow.organization_id";

/** Returns a valid positive integer org id, or null for anything else
 * (missing, empty, zero, negative, NaN, non-finite) — the single place
 * that decides what counts as "no organization selected". Accepts a
 * string too so it can validate a raw org-id text input directly,
 * without every caller having to parse first. */
export function normalizeOrgId(id: number | string | null | undefined): number | null {
  if (id === null || id === undefined || id === "") return null;
  const n = typeof id === "string" ? Number(id) : id;
  return Number.isFinite(n) && n > 0 ? Math.trunc(n) : null;
}

export function readStoredOrgId(): number | null {
  try {
    const raw = localStorage.getItem(ORG_STORAGE_KEY);
    return raw ? normalizeOrgId(Number(raw)) : null;
  } catch {
    // Private browsing / storage disabled — fall back to no persisted org;
    // the picker still works for the rest of the session via React state.
    return null;
  }
}

export function writeStoredOrgId(id: number | null): void {
  try {
    if (id) {
      localStorage.setItem(ORG_STORAGE_KEY, String(id));
    } else {
      localStorage.removeItem(ORG_STORAGE_KEY);
    }
  } catch {
    // Ignore — see readStoredOrgId.
  }
}

/** Clears the persisted org selection (e.g. after the active org is
 * deleted, or the user explicitly switches away). */
export function clearOrganizationState(): void {
  writeStoredOrgId(null);
}

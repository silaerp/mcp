import type { DokployIdentity } from "./oauth.js";

const SESSION_TIMEOUT_MS = 5_000;

export async function verifyDokploySession(
  sessionUrl: string,
  cookieHeader: string | undefined,
): Promise<DokployIdentity | null> {
  if (!cookieHeader) return null;

  const response = await fetch(sessionUrl, {
    method: "GET",
    headers: { Accept: "application/json", Cookie: cookieHeader },
    redirect: "manual",
    signal: AbortSignal.timeout(SESSION_TIMEOUT_MS),
  });
  if (response.status === 401 || response.status === 403 || isRedirect(response.status))
    return null;
  if (!response.ok)
    throw new Error(`Dokploy session verification failed with HTTP ${response.status}`);

  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().includes("application/json")) {
    throw new Error("Dokploy session verification returned a non-JSON response");
  }
  return extractIdentity(await response.json());
}

export function extractIdentity(payload: unknown): DokployIdentity | null {
  if (!isRecord(payload)) return null;
  const candidates = [
    payload.user,
    isRecord(payload.session) ? payload.session.user : undefined,
    isRecord(payload.data) ? payload.data.user : undefined,
    payload,
  ];
  for (const candidate of candidates) {
    if (!isRecord(candidate)) continue;
    const id = stringValue(candidate.id) ?? stringValue(candidate.userId);
    if (!id) continue;
    return {
      id,
      email: stringValue(candidate.email)?.toLowerCase(),
      name: stringValue(candidate.name),
    };
  }
  return null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function isRedirect(status: number): boolean {
  return status >= 300 && status < 400;
}

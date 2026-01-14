const DEFAULT_NEAR_EXPLORER_BASE_URL = "https://testnet.nearblocks.io";

export function getNearExplorerBaseUrl(configuredUrl?: string | null): string {
  return String(configuredUrl || DEFAULT_NEAR_EXPLORER_BASE_URL).replace(/\/$/, "");
}

export function getNearAccountExplorerUrl(baseUrl: string, accountId?: string | null): string {
  const id = (accountId || "").trim();
  if (!id) return "";
  return `${baseUrl}/address/${id}`;
}

export function getNearTransactionExplorerUrl(baseUrl: string, txHash?: string | null): string {
  const hash = (txHash || "").trim();
  if (!hash) return "";
  return `${baseUrl}/txns/${hash}`;
}

export function extractNearTransactionHash(message?: string | null): string {
  const text = (message || "").trim();
  if (!text) return "";
  const match = text.match(/\bTransaction\s+([1-9A-HJ-NP-Za-km-z]{32,})\b/i);
  return match?.[1] ?? "";
}

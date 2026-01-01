const DEFAULT_NEAR_EXPLORER_BASE_URL = "https://testnet.nearblocks.io";

export function getNearExplorerBaseUrl(configuredUrl?: string | null): string {
  return String(configuredUrl || DEFAULT_NEAR_EXPLORER_BASE_URL).replace(/\/$/, "");
}

export function getNearAccountExplorerUrl(baseUrl: string, accountId?: string | null): string {
  const id = (accountId || "").trim();
  if (!id) return "";
  return `${baseUrl}/address/${id}`;
}


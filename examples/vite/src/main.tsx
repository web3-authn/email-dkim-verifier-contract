import React from "react";
import ReactDOM from "react-dom/client";

import { TatchiPasskeyProvider, type TatchiConfigsInput } from "@tatchi-xyz/sdk/react";
import { Toaster } from "sonner";

import { HomePage } from "./pages/HomePage";
import "./index.css";

// Note: Vite requires using `import.meta.env` exactly; optional chaining breaks env injection.
const env = import.meta.env;

const relayerUrl = env.VITE_RELAYER_URL || "https://relay-server.localhost";
const emailRecovererContractId = env.VITE_EMAIL_RECOVERER_CONTRACT_ID;
const dkimVerifierContractId = env.VITE_DKIM_VERIFIER_CONTRACT_ID;
const zkEmailVerifierContractId = env.VITE_ZK_EMAIL_VERIFIER_CONTRACT_ID;

const config: TatchiConfigsInput = {
  relayer: { url: relayerUrl },
};

if (env.VITE_WEBAUTHN_CONTRACT_ID) config.contractId = env.VITE_WEBAUTHN_CONTRACT_ID;
if (env.VITE_NEAR_NETWORK) config.nearNetwork = env.VITE_NEAR_NETWORK;
if (env.VITE_NEAR_RPC_URL) config.nearRpcUrl = env.VITE_NEAR_RPC_URL;

if (emailRecovererContractId || dkimVerifierContractId || zkEmailVerifierContractId) {
  const emailRecoveryContracts: NonNullable<TatchiConfigsInput["emailRecoveryContracts"]> = {};
  if (emailRecovererContractId) emailRecoveryContracts.emailRecovererGlobalContract = emailRecovererContractId;
  if (zkEmailVerifierContractId) emailRecoveryContracts.zkEmailVerifierContract = zkEmailVerifierContractId;
  if (dkimVerifierContractId) emailRecoveryContracts.emailDkimVerifierContract = dkimVerifierContractId;
  config.emailRecoveryContracts = emailRecoveryContracts;
}

if (env.VITE_WALLET_ORIGIN) {
  config.iframeWallet = {
    walletOrigin: env.VITE_WALLET_ORIGIN,
    walletServicePath: env.VITE_WALLET_SERVICE_PATH || "/wallet-service",
    sdkBasePath: env.VITE_SDK_BASE_PATH || "/sdk",
    rpIdOverride: env.VITE_RP_ID_BASE,
  };
}

const appRoot = document.getElementById("app-root");

if (appRoot) {
  ReactDOM.createRoot(appRoot).render(
    <React.StrictMode>
      <TatchiPasskeyProvider config={config}>
        <Toaster richColors closeButton />
        <HomePage />
      </TatchiPasskeyProvider>
    </React.StrictMode>,
  );
}

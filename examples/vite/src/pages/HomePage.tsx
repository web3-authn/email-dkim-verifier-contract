import { useEffect, useState } from "react";
import { useAccountInput, useTatchi } from "@tatchi-xyz/sdk/react";
import { ContractsCard } from "../components/ContractsCard";
import { Step1RegisterOrLogin } from "../components/Step1RegisterOrLogin";
import { Step2SetRecoveryEmails } from "../components/Step2SetRecoveryEmails";
import { Step3Logout } from "../components/Step3Logout";
import { Step4RecoverWithEmail } from "../components/Step4RecoverWithEmail";

const env = import.meta.env;

const DEFAULT_ACCOUNT_ID = env.VITE_EXAMPLE_ACCOUNT_ID || "";
const EMAIL_RECOVERER_CONTRACT_ID =
  env.VITE_EMAIL_RECOVERER_CONTRACT_ID || "w3a-email-recoverer-v1.testnet";
const DKIM_VERIFIER_CONTRACT_ID =
  env.VITE_DKIM_VERIFIER_CONTRACT_ID || "email-dkim-verifier-v1.testnet";
const WEBAUTHN_CONTRACT_ID = env.VITE_WEBAUTHN_CONTRACT_ID || "w3a-v1.testnet";

export function HomePage() {
  const { loginState, tatchi } = useTatchi();

  const {
    inputUsername,
    displayPostfix,
    targetAccountId,
    setInputUsername,
    lastLoggedInUsername,
    lastLoggedInDomain,
    isUsingExistingAccount,
    accountExists,
  } = useAccountInput({
    tatchi,
    contractId: tatchi.configs.contractId,
    currentNearAccountId: loginState.nearAccountId,
    isLoggedIn: loginState.isLoggedIn,
  });

  const [recoveryEmail, setRecoveryEmail] = useState("");

  useEffect(() => {
    if (!DEFAULT_ACCOUNT_ID || inputUsername) return;
    setInputUsername(DEFAULT_ACCOUNT_ID.split(".")[0] ?? "");
  }, [DEFAULT_ACCOUNT_ID, inputUsername, setInputUsername]);

  const postfix = displayPostfix || `.${tatchi.configs.contractId}`;
  const shouldLogin = isUsingExistingAccount || accountExists;
  const lastAccountId =
    lastLoggedInUsername && lastLoggedInDomain ? `${lastLoggedInUsername}${lastLoggedInDomain}` : "";
  const explorerBaseUrl = String(tatchi?.configs?.nearExplorerUrl || "https://testnet.nearblocks.io").replace(/\/$/, "");
  const loggedInExplorerUrl = loginState.nearAccountId ? `${explorerBaseUrl}/address/${loginState.nearAccountId}` : "";

  return (
    <div className="page">
      <header className="hero">
        <div>
          <p className="eyebrow">DKIM outlayer example</p>
          <h1>Passkey registration + email recovery on NEAR.</h1>
          <p className="lede">
            This page wires the Tatchi SDK to the EmailRecoverer and DKIM verifier contracts.
            Run each section in order to see the on-chain calls.
          </p>
          {loginState.isLoggedIn && loginState.nearAccountId && loggedInExplorerUrl ? (
            <p className="status">
              Wallet status: logged in as{" "}
              <a className="mailto" href={loggedInExplorerUrl} target="_blank" rel="noopener noreferrer">
                {loginState.nearAccountId}
              </a>
            </p>
          ) : (
            loginState.isLoggedIn && <p className="status">Wallet status: logged in</p>
          )}
        </div>
        <ContractsCard
          webAuthnContractId={WEBAUTHN_CONTRACT_ID}
          emailRecovererContractId={EMAIL_RECOVERER_CONTRACT_ID}
          dkimVerifierContractId={DKIM_VERIFIER_CONTRACT_ID}
        />
      </header>

      <div className="rows">
        <Step1RegisterOrLogin
          mode={shouldLogin ? "login" : "register"}
          inputUsername={inputUsername}
          postfix={postfix}
          targetAccountId={targetAccountId}
          onChangeUsername={setInputUsername}
        />

        <Step2SetRecoveryEmails
          targetAccountId={targetAccountId}
          recoveryEmail={recoveryEmail}
          onChangeRecoveryEmail={setRecoveryEmail}
        />

        <Step3Logout />

        <Step4RecoverWithEmail
          targetAccountId={targetAccountId}
          lastAccountId={lastAccountId}
          recoveryEmail={recoveryEmail}
          onChangeRecoveryEmail={setRecoveryEmail}
        />
      </div>
    </div>
  );
}

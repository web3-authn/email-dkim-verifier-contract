import { useEffect } from "react";
import { useAccountInput, useTatchi } from "@tatchi-xyz/sdk/react";
import { Layout } from "../components/Layout";
import { Step1RegisterOrLogin } from "../components/Step1RegisterOrLogin";
import { Step2SetRecoveryEmails } from "../components/Step2SetRecoveryEmails";
import { Step3Logout } from "../components/Step3Logout";
import { Step4RecoverWithEmail } from "../components/Step4RecoverWithEmail";
import { Step5TestTransfer } from "../components/Step5TestTransfer";

const env = import.meta.env;

const DEFAULT_ACCOUNT_ID = env.VITE_EXAMPLE_ACCOUNT_ID || "";
const WEBAUTHN_CONTRACT_ID = env.VITE_WEBAUTHN_CONTRACT_ID || "w3a-v1.testnet";
const EMAIL_RECOVERER_CONTRACT_ID = env.VITE_EMAIL_RECOVERER_CONTRACT_ID || "";
const DKIM_VERIFIER_CONTRACT_ID = env.VITE_DKIM_VERIFIER_CONTRACT_ID || "";

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
  const emailRecovererExplorerUrl = EMAIL_RECOVERER_CONTRACT_ID
    ? `${explorerBaseUrl}/address/${EMAIL_RECOVERER_CONTRACT_ID}`
    : "";
  const dkimVerifierExplorerUrl = DKIM_VERIFIER_CONTRACT_ID ? `${explorerBaseUrl}/address/${DKIM_VERIFIER_CONTRACT_ID}` : "";

  return (
    <Layout>
      <header className="hero">
        <div>
          <p className="eyebrow">Passkey Accounts + Outlayer example</p>
          <h1>Recovering Accounts with Emails on NEAR</h1>
          <p className="lede">
            Create a NEAR account using a Passkey with {" "}
            <a className="link" href="https://tatchi.xyz" target="_blank">Tatchi Passkey SDK</a>
            <br/>
            Use <a className="link" href="https://outlayer.fastnear.com/" target="_blank">Outlayer</a> {" "} to recover accounts with an email
          </p>
          {loginState.isLoggedIn && loginState.nearAccountId && loggedInExplorerUrl ? (
            <p className="wallet-status-fixed chip">
              Logged in as: &nbsp;
              <a className="mailto" href={loggedInExplorerUrl} target="_blank" rel="noopener noreferrer">
                {loginState.nearAccountId}
              </a>
            </p>
          ) : (
            loginState.isLoggedIn && <p className="wallet-status-fixed chip">Wallet status: logged in</p>
          )}
        </div>
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
        />

        <Step3Logout />

        <Step4RecoverWithEmail
          targetAccountId={targetAccountId}
          lastAccountId={lastAccountId}
        />

        <Step5TestTransfer receiverId={WEBAUTHN_CONTRACT_ID} />

        <div className="row row-wide">
          <section className="panel flow-explainer span-columns">
            <div className="panel-header">
              <h2>What’s happening under the hood</h2>
            </div>
            <div className="stack">
              <ol className="helper">
                <li>
                  You send a recovery email to a Cloudflare Worker (the relayer).
                </li>
                <li>
                  The Worker encrypts the raw email using an encryption public key published by the Email DKIM Verifier
                  contract (derived inside Outlayer), then submits the encrypted email to the{" "}
                  <span className="inline-highlight">EmailRecoverer</span> contract on your{" "}
                  <span className="inline-highlight">near.near</span> smart account.
                </li>
                <li>
                  The EmailRecoverer contract calls into the global{" "}
                  <span className="inline-highlight">Email DKIM Verifier</span> contract, which asks Outlayer to run a
                  WASI worker inside a TEE.
                </li>
                <li>
                  Outlayer decrypts the email in the TEE, verifies DKIM signatures (using DNS TXT records), and returns a
                  compact verification result.
                </li>
                <li>
                  If verification passes, EmailRecoverer adds the new public key to your account (recovery complete).
                </li>
              </ol>

              <p className="helper">
                Passkey accounts are NEAR accounts deterministically derived from Passkeys. They use a local signer (your
                device’s Passkey/WebAuthn) plus a threshold signer, so no server is required. Your Passkey is your wallet.
              </p>

              <div className="chip-row">
                <a
                  className="link"
                  href="https://github.com/web3-authn/email-dkim-verifier-contract"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  GitHub: email-dkim-verifier-contract
                </a>
                <a
                  className="link"
                  href="https://github.com/web3-authn/email-recoverer-contract"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  GitHub: email-recoverer-contract
                </a>
              </div>

              {(emailRecovererExplorerUrl || dkimVerifierExplorerUrl) && (
                <div className="stack">
                  <p className="helper">Block explorer</p>
                  {emailRecovererExplorerUrl && (
                    <p className="helper">
                      EmailRecoverer:{" "}
                      <a className="mailto" href={emailRecovererExplorerUrl} target="_blank" rel="noopener noreferrer">
                        {EMAIL_RECOVERER_CONTRACT_ID}
                      </a>
                    </p>
                  )}
                  {dkimVerifierExplorerUrl && (
                    <p className="helper">
                      Email DKIM Verifier:{" "}
                      <a className="mailto" href={dkimVerifierExplorerUrl} target="_blank" rel="noopener noreferrer">
                        {DKIM_VERIFIER_CONTRACT_ID}
                      </a>
                    </p>
                  )}
                </div>
              )}
              {!emailRecovererExplorerUrl && !dkimVerifierExplorerUrl && (
                <p className="helper">
                  Set <span className="inline-highlight">VITE_EMAIL_RECOVERER_CONTRACT_ID</span> and{" "}
                  <span className="inline-highlight">VITE_DKIM_VERIFIER_CONTRACT_ID</span> to show block explorer links.
                </p>
              )}
            </div>
          </section>
        </div>
      </div>
    </Layout>
  );
}

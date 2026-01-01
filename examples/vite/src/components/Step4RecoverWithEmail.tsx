import { useState } from "react";
import {
  EmailRecoveryPhase,
  EmailRecoveryStatus,
  type EmailRecoverySSEEvent,
  useTatchi,
} from "@tatchi-xyz/sdk/react";
import { toast } from "sonner";
import { useOutputLog } from "../hooks/useOutputLog";
import { Output } from "./Output";
import { getErrorMessage } from "../utils/errors";
import { getNearAccountExplorerUrl, getNearExplorerBaseUrl } from "../utils/nearExplorer";

type Step4RecoverWithEmailProps = {
  targetAccountId: string;
  lastAccountId: string;
};

function getRequestIdFromMailtoUrl(mailtoUrl: string) {
  if (!mailtoUrl) return "";
  try {
    const subject = new URL(mailtoUrl).searchParams.get("subject") || "";
    return subject.match(/recover-([A-Z0-9]{6})\b/i)?.[1] ?? "";
  } catch {
    return mailtoUrl.match(/recover-([A-Z0-9]{6})\b/i)?.[1] ?? "";
  }
}

export function Step4RecoverWithEmail({
  targetAccountId,
  lastAccountId,
}: Step4RecoverWithEmailProps) {
  const { tatchi, loginState, getLoginSession, loginAndCreateSession, refreshLoginState } = useTatchi();
  const [isLoading, setIsLoading] = useState(false);
  const [mailtoUrl, setMailtoUrl] = useState("");
  const [pendingNearPublicKey, setPendingNearPublicKey] = useState("");
  const [requestId, setRequestId] = useState("");
  const log = useOutputLog();

  const toastId = "email-recovery";

  const onEmailRecoveryEvent = (event: EmailRecoverySSEEvent) => {
    if (event.message) log.appendOutput("idle", event.message);

    const data = (
      event as { data?: { requestId?: string; mailtoUrl?: string; nearPublicKey?: string } }
    ).data;
    if (data?.requestId) setRequestId(data.requestId);
    if (data?.mailtoUrl) setMailtoUrl(data.mailtoUrl);
    if (data?.nearPublicKey) setPendingNearPublicKey(data.nearPublicKey);

    if (event.phase === EmailRecoveryPhase.STEP_6_COMPLETE && event.status === EmailRecoveryStatus.SUCCESS) {
      toast.success(event.message || "Email recovery complete", { id: toastId });
      return;
    }
    if (event.phase === EmailRecoveryPhase.ERROR || event.status === EmailRecoveryStatus.ERROR) {
      toast.error(getErrorMessage((event as { error?: unknown }).error ?? event.message ?? "Email recovery failed"), {
        id: toastId,
      });
      return;
    }

    switch (event.phase) {
      case EmailRecoveryPhase.RESUMED_FROM_PENDING:
        toast.loading(event.message || "Resuming pending email recovery…", { id: toastId });
        return;
      case EmailRecoveryPhase.STEP_1_PREPARATION:
        toast.loading(event.message || "Preparing email recovery…", { id: toastId });
        return;
      case EmailRecoveryPhase.STEP_2_TOUCH_ID_REGISTRATION:
        toast.loading(event.message || "Registering this device (Touch ID / Passkey)…", { id: toastId });
        return;
      case EmailRecoveryPhase.STEP_3_AWAIT_EMAIL:
        toast.loading(event.message || "Waiting for the recovery email to be sent and verified…", { id: toastId });
        return;
      case EmailRecoveryPhase.STEP_4_POLLING_ADD_KEY:
      case EmailRecoveryPhase.STEP_4_POLLING_VERIFICATION_RESULT:
        toast.loading(event.message || "Polling for recovery verification…", { id: toastId });
        return;
      case EmailRecoveryPhase.STEP_5_FINALIZING_REGISTRATION:
        toast.loading(event.message || "Finalizing recovery registration…", { id: toastId });
        return;
      default:
        return;
    }
  };

  const accountIdToRecover = targetAccountId || lastAccountId;
  const canRecover = !loginState.isLoggedIn && Boolean(lastAccountId);
  const isBlocked = !canRecover;
  const isDisabled = isBlocked || isLoading;

  const explorerBaseUrl = getNearExplorerBaseUrl(tatchi?.configs?.nearExplorerUrl);
  const lastAccountExplorerUrl = getNearAccountExplorerUrl(explorerBaseUrl, lastAccountId);
  const recoverAccountExplorerUrl = getNearAccountExplorerUrl(explorerBaseUrl, accountIdToRecover);

  const recoverWithEmail = async () => {
    if (loginState.isLoggedIn) {
      log.setOutputText("error", "Logout before starting recovery.");
      return;
    }
    if (!lastAccountId) {
      log.setOutputText("error", "Recovery is available only after a prior login is stored locally.");
      return;
    }
    if (!accountIdToRecover) {
      log.setOutputText("error", "Missing account id.");
      return;
    }
    if (isLoading) return;

    setIsLoading(true);
    log.clearOutput();
    setMailtoUrl("");
    setPendingNearPublicKey("");
    setRequestId("");
    toast.loading("Preparing email recovery…", { id: toastId });

    try {
      const startResult = await tatchi.startEmailRecovery({
        accountId: accountIdToRecover,
        options: {
          onEvent: onEmailRecoveryEvent,
          confirmerText: {
            title: "Recover Account With Email",
            body: "Create a new passkey for this account and send a recovery email.",
          },
        },
      });

      setMailtoUrl(startResult.mailtoUrl);
      setPendingNearPublicKey(startResult.nearPublicKey);
      const extractedRequestId = getRequestIdFromMailtoUrl(startResult.mailtoUrl);
      if (extractedRequestId) setRequestId(extractedRequestId);

      if (extractedRequestId) log.appendOutput("ok", `Request ID: ${extractedRequestId}`);
      log.appendOutput("ok", `New public key (new_public_key): ${startResult.nearPublicKey}`);

      try {
        window.open(startResult.mailtoUrl, "_blank", "noopener,noreferrer");
      } catch {}

      await tatchi.finalizeEmailRecovery({
        accountId: accountIdToRecover,
        nearPublicKey: startResult.nearPublicKey,
        options: { onEvent: onEmailRecoveryEvent },
      });

      const session = await getLoginSession(accountIdToRecover).catch(() => null);
      const loginOk =
        Boolean(session?.login?.isLoggedIn) ||
        (await loginAndCreateSession(accountIdToRecover).then(
          () => true,
          () => false,
        ));

      await refreshLoginState(accountIdToRecover).catch(() => {});
      log.appendOutput(
        "ok",
        loginOk
          ? "Email recovery completed on this device."
          : "Email recovery completed. Please log in on this device.",
      );
    } catch (error) {
      const message = getErrorMessage(error);
      log.setOutputText("error", message);
      toast.error(message || "Email recovery failed", { id: toastId });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="row">
      <aside className={`panel note ${isBlocked ? "is-disabled" : ""}`}>
        <h3>04 Recover with email</h3>
        <p className="helper">
          Send an encrypted transactional email to an Outlayer worker, which verifies the email DKIM signature and
          recovers your account.
        </p>
        <p className="helper">
          Last known account:{" "}
          {lastAccountExplorerUrl ? (
            <a className="mailto" href={lastAccountExplorerUrl} target="_blank" rel="noopener noreferrer">
              {lastAccountId}
            </a>
          ) : (
            lastAccountId
          )}
          .
        </p>
      </aside>
      <section className={`panel ${isBlocked ? "is-disabled" : ""}`}>
        <div className="panel-header">
          <h2>Recover with email</h2>
          <span className="pill">04</span>
        </div>
        <div className="stack">
          <p className="helper">
            Recovering:{" "}
            {recoverAccountExplorerUrl ? (
              <a className="mailto" href={recoverAccountExplorerUrl} target="_blank" rel="noopener noreferrer">
                {accountIdToRecover || lastAccountId}
              </a>
            ) : (
              accountIdToRecover || lastAccountId
            )}
          </p>
          <p className="helper">
            Make sure you send the recovery email from your designated recovery address (set in Step 02). This page will
            keep polling until the on-chain recovery finishes.
          </p>
          {(requestId || pendingNearPublicKey) && (
            <div className="chip-row">
              {requestId && <span className="chip">request_id: {requestId}</span>}
              {pendingNearPublicKey && <span className="chip">{pendingNearPublicKey}</span>}
            </div>
          )}
          <button type="button" onClick={recoverWithEmail} disabled={isDisabled} aria-busy={isLoading}>
            {isLoading && <span className="spinner" aria-hidden="true" />}
            {isLoading ? "Recovering..." : "Recover account with email"}
          </button>
          {mailtoUrl && (
            <a className="mailto" href={mailtoUrl} target="_blank" rel="noopener noreferrer">
              Open recovery email draft
            </a>
          )}
          <Output state={log.output} />
        </div>
        {!canRecover && (
          <p className="helper">
            Recovery is available only after a prior login is stored locally, and you are logged out.
          </p>
        )}
      </section>
    </div>
  );
}

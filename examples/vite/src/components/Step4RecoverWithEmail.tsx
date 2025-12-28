import { useCallback, useState, type FormEvent } from "react";
import {
  EmailRecoveryPhase,
  EmailRecoveryStatus,
  type EmailRecoverySSEEvent,
  useTatchi,
} from "@tatchi-xyz/sdk/react";
import { toast } from "sonner";
import { useOutputLog } from "../hooks/useOutputLog";
import { Output } from "./Output";

type Step4RecoverWithEmailProps = {
  targetAccountId: string;
  lastAccountId: string;
  recoveryEmail: string;
  onChangeRecoveryEmail: (value: string) => void;
};

export function Step4RecoverWithEmail({
  targetAccountId,
  lastAccountId,
  recoveryEmail,
  onChangeRecoveryEmail,
}: Step4RecoverWithEmailProps) {
  const { tatchi, loginState, getLoginSession, loginAndCreateSession, refreshLoginState } = useTatchi();
  const [isLoading, setIsLoading] = useState(false);
  const [mailtoUrl, setMailtoUrl] = useState("");
  const {
    output: outputStart,
    clearOutput: clearOutputStart,
    appendOutput: appendOutputStart,
    setOutputText: setOutputTextStart,
  } = useOutputLog();
  const {
    output: outputFinalize,
    clearOutput: clearOutputFinalize,
    appendOutput: appendOutputFinalize,
    setOutputText: setOutputTextFinalize,
  } = useOutputLog();

  const onEmailRecoveryEvents = useCallback((event: EmailRecoverySSEEvent) => {
    const toastId = "email-recovery";
    if (event.phase === EmailRecoveryPhase.STEP_6_COMPLETE && event.status === EmailRecoveryStatus.SUCCESS) {
      toast.success(event.message || "Email recovery complete", { id: toastId });
      return;
    }
    if (event.phase === EmailRecoveryPhase.ERROR || event.status === EmailRecoveryStatus.ERROR) {
      toast.error((event as any)?.error || event.message || "Email recovery failed", { id: toastId });
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
  }, []);

  const onEmailRecoveryStartEvents = useCallback(
    (event: EmailRecoverySSEEvent) => {
      appendOutputStart("idle", `[${event.phase}] ${event.message ?? ""}`);
      onEmailRecoveryEvents(event);
    },
    [appendOutputStart, onEmailRecoveryEvents],
  );

  const onEmailRecoveryFinalizeEvents = useCallback(
    (event: EmailRecoverySSEEvent) => {
      appendOutputFinalize("idle", `[${event.phase}] ${event.message ?? ""}`);
      onEmailRecoveryEvents(event);
    },
    [appendOutputFinalize, onEmailRecoveryEvents],
  );

  const accountIdToRecover = targetAccountId || lastAccountId;
  const canRecover = !loginState.isLoggedIn && Boolean(lastAccountId);
  const isBlocked = !canRecover;
  const isDisabled = isBlocked || isLoading;

  const lastAccountLabel = lastAccountId || "nerp8.w3a-v1.testnet";
  const explorerBaseUrl = String(tatchi?.configs?.nearExplorerUrl || "https://testnet.nearblocks.io").replace(/\/$/, "");
  const lastAccountExplorerUrl = lastAccountId ? `${explorerBaseUrl}/address/${lastAccountId}` : "";
  const recoverAccountExplorerUrl = accountIdToRecover ? `${explorerBaseUrl}/address/${accountIdToRecover}` : "";

  const handleSubmit = useCallback(
    async (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();

      if (loginState.isLoggedIn) {
        setOutputTextStart("error", "Logout before starting recovery.");
        return;
      }
      if (!accountIdToRecover) {
        setOutputTextStart("error", "Missing account id.");
        return;
      }
      if (!recoveryEmail) {
        setOutputTextStart("error", "Recovery email is required.");
        return;
      }
      if (!lastAccountId) {
        setOutputTextStart("error", "Recovery is available only after a prior login is stored locally.");
        return;
      }
      if (isLoading) return;

      setIsLoading(true);
      clearOutputStart();
      clearOutputFinalize();
      setMailtoUrl("");
      toast.loading("Preparing email recovery…", { id: "email-recovery" });

      let stage: "start" | "finalize" = "start";
      try {
        const startResult = await tatchi.startEmailRecovery({
          accountId: accountIdToRecover,
          recoveryEmail,
          options: {
            onEvent: onEmailRecoveryStartEvents,
            confirmerText: {
              title: "Create New Recovery Account",
              body: "Send a recovery email to add a new passkey to your account",
            },
          },
        });

        setMailtoUrl(startResult.mailtoUrl);
        try {
          window.open(startResult.mailtoUrl, "_blank", "noopener,noreferrer");
        } catch {}

        stage = "finalize";
        await tatchi.finalizeEmailRecovery({
          accountId: accountIdToRecover,
          nearPublicKey: startResult.nearPublicKey,
          options: { onEvent: onEmailRecoveryFinalizeEvents },
        });

        let loginOk = false;
        const session = await getLoginSession(accountIdToRecover).catch(() => null);
        if (session?.login?.isLoggedIn) {
          loginOk = true;
        } else {
          loginOk = await loginAndCreateSession(accountIdToRecover).then(
            () => true,
            () => false,
          );
        }

        await refreshLoginState(accountIdToRecover).catch(() => {});
        appendOutputFinalize(
          "ok",
          loginOk
            ? "Email recovery completed on this device."
            : "Email recovery completed. Please log in on this device.",
        );
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (stage === "start") setOutputTextStart("error", message);
        else setOutputTextFinalize("error", message);
        toast.error(message || "Email recovery failed", { id: "email-recovery" });
      } finally {
        setIsLoading(false);
      }
    },
    [
      accountIdToRecover,
      appendOutputFinalize,
      clearOutputFinalize,
      clearOutputStart,
      getLoginSession,
      isLoading,
      lastAccountId,
      loginAndCreateSession,
      loginState.isLoggedIn,
      onEmailRecoveryFinalizeEvents,
      onEmailRecoveryStartEvents,
      recoveryEmail,
      refreshLoginState,
      setOutputTextFinalize,
      setOutputTextStart,
      tatchi,
    ],
  );

  return (
    <div className="row">
      <aside className={`panel note ${isBlocked ? "is-disabled" : ""}`}>
        <h3>04 Recover email</h3>
        <p className="helper">
          Send a encrypted transactional email to an Outlayer worker which verifies the email DKIM signature and
          recovers your account.
        </p>
        <p className="helper">
          Last known account:{" "}
          {lastAccountExplorerUrl ? (
            <a className="mailto" href={lastAccountExplorerUrl} target="_blank" rel="noopener noreferrer">
              {lastAccountLabel}
            </a>
          ) : (
            lastAccountLabel
          )}
          .
        </p>
      </aside>
      <section className={`panel ${isBlocked ? "is-disabled" : ""}`}>
        <div className="panel-header">
          <h2>Recover email</h2>
          <span className="pill">04</span>
        </div>
        <form onSubmit={handleSubmit} className="stack">
          <h3>Step 1: Start + finalize recovery</h3>
          <p className="helper">
            Recovering:{" "}
            {recoverAccountExplorerUrl ? (
              <a className="mailto" href={recoverAccountExplorerUrl} target="_blank" rel="noopener noreferrer">
                {accountIdToRecover || lastAccountLabel}
              </a>
            ) : (
              accountIdToRecover || lastAccountLabel
            )}
          </p>
          <label>
            Recovery email
            <input
              value={recoveryEmail}
              onChange={(event) => onChangeRecoveryEmail(event.target.value)}
              placeholder="you@example.com"
              disabled={isDisabled}
            />
          </label>
          <button type="submit" disabled={isDisabled} aria-busy={isLoading}>
            {isLoading && <span className="spinner" aria-hidden="true" />}
            {isLoading ? "Recovering..." : "Start email recovery"}
          </button>
          {mailtoUrl && (
            <a className="mailto" href={mailtoUrl}>
              Open recovery email
            </a>
          )}
          <Output state={outputStart} />
          <h3>Step 2: Finalize (automatic)</h3>
          <Output state={outputFinalize} />
        </form>
        {!canRecover && (
          <p className="helper">
            Recovery is available only after a prior login is stored locally, and you are logged out.
          </p>
        )}
      </section>
    </div>
  );
}

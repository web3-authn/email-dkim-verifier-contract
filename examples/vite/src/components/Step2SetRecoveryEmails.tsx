import { useCallback, useState, type FormEvent } from "react";
import {
  ActionPhase,
  ActionStatus,
  type ActionSSEEvent,
  useTatchi,
} from "@tatchi-xyz/sdk/react";
import { toast } from "sonner";
import { useOutputLog } from "../hooks/useOutputLog";
import { Output } from "./Output";

type Step2SetRecoveryEmailsProps = {
  targetAccountId: string;
  recoveryEmail: string;
  onChangeRecoveryEmail: (value: string) => void;
};

export function Step2SetRecoveryEmails({
  targetAccountId,
  recoveryEmail,
  onChangeRecoveryEmail,
}: Step2SetRecoveryEmailsProps) {
  const { tatchi, loginState } = useTatchi();
  const [isLoading, setIsLoading] = useState(false);
  const {
    output: log,
    clearOutput: clearLog,
    appendOutput: appendLog,
    setOutputText: setLogText,
  } = useOutputLog();

  const onSetRecoveryEmailEvents = useCallback(
    (event: ActionSSEEvent) => {
      appendLog("idle", `[${event.phase}] ${event.message ?? ""}`);

      const toastId = "set-recovery-email";
      if (
        event.phase === ActionPhase.ACTION_ERROR ||
        event.phase === ActionPhase.WASM_ERROR ||
        event.status === ActionStatus.ERROR
      ) {
        toast.error((event as any)?.error || event.message || "Failed to set recovery email", { id: toastId });
        return;
      }

      switch (event.phase) {
        case ActionPhase.STEP_1_PREPARATION:
          toast.loading(event.message || "Preparing transaction...", { id: toastId });
          return;
        case ActionPhase.STEP_2_USER_CONFIRMATION:
          toast.loading(event.message || "Awaiting confirmation...", { id: toastId });
          return;
        case ActionPhase.STEP_3_WEBAUTHN_AUTHENTICATION:
          toast.loading(event.message || "Authenticating...", { id: toastId });
          return;
        case ActionPhase.STEP_5_TRANSACTION_SIGNING_PROGRESS:
          toast.loading(event.message || "Signing transaction...", { id: toastId });
          return;
        case ActionPhase.STEP_7_BROADCASTING:
          toast.loading(event.message || "Broadcasting transaction...", { id: toastId });
          return;
        case ActionPhase.STEP_8_ACTION_COMPLETE:
          toast.success(event.message || "Recovery email saved.", { id: toastId });
          return;
        default:
          toast.loading(event.message || "Processing...", { id: toastId });
      }
    },
    [appendLog],
  );

  const isBlocked = !loginState.isLoggedIn;
  const isDisabled = isBlocked || isLoading;

  const handleSubmit = useCallback(
    async (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!loginState.isLoggedIn) {
        setLogText("error", "Login required to set recovery email.");
        return;
      }
      if (!targetAccountId) {
        setLogText("error", "Missing account id.");
        return;
      }
      if (!recoveryEmail) {
        setLogText("error", "Missing recovery email.");
        return;
      }
      if (isLoading) return;

      setIsLoading(true);
      clearLog();
      toast.loading("Saving recovery email…", { id: "set-recovery-email" });

      try {
        const result = await tatchi.setRecoveryEmails(targetAccountId, [recoveryEmail], {
          onEvent: onSetRecoveryEmailEvents,
          confirmerText: {
            title: "Set Recovery Email",
            body: "Add a recovery email address for account recovery",
          },
        });
        appendLog("ok", result);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        setLogText("error", message);
        toast.error(message || "Failed to set recovery email", { id: "set-recovery-email" });
      } finally {
        setIsLoading(false);
      }
    },
    [
      appendLog,
      isLoading,
      loginState.isLoggedIn,
      onSetRecoveryEmailEvents,
      recoveryEmail,
      setLogText,
      tatchi,
      targetAccountId,
    ],
  );

  return (
    <div className="row">
      <aside className={`panel note ${isBlocked ? "is-disabled" : ""}`}>
        <h3>02 Set recovery email</h3>
        <p className="helper">
          Add email recovery functionality to your NEAR account and add a recovery email.
        </p>
      </aside>
      <section className={`panel ${isBlocked ? "is-disabled" : ""}`}>
        <div className="panel-header">
          <h2>Set recovery email</h2>
          <span className="pill">02</span>
        </div>
        <form onSubmit={handleSubmit} className="stack">
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
            {isLoading ? "Submitting..." : "Save recovery email"}
          </button>
        </form>
        {loginState.nearAccountId && <p className="helper">Logged in as {loginState.nearAccountId}.</p>}
        {isBlocked && <p className="helper">Login required to set recovery email.</p>}
        <Output state={log} />
      </section>
    </div>
  );
}

import { useCallback, useState, type FormEvent } from "react";
import {
  LoginPhase,
  LoginStatus,
  RegistrationPhase,
  RegistrationStatus,
  type LoginSSEvent,
  type RegistrationSSEEvent,
  useTatchi,
} from "@tatchi-xyz/sdk/react";
import { toast } from "sonner";
import { useOutputLog } from "../hooks/useOutputLog";
import { Output } from "./Output";

type Step1RegisterOrLoginProps = {
  mode: "register" | "login";
  inputUsername: string;
  postfix: string;
  targetAccountId: string;
  onChangeUsername: (value: string) => void;
};

export function Step1RegisterOrLogin({
  mode,
  inputUsername,
  postfix,
  targetAccountId,
  onChangeUsername,
}: Step1RegisterOrLoginProps) {
  const { registerPasskey, loginAndCreateSession, loginState, tatchi } = useTatchi();
  const [isLoading, setIsLoading] = useState(false);
  const {
    output: log,
    clearOutput: clearLog,
    appendOutput: appendLog,
    setOutputText: setLogText,
  } = useOutputLog();

  const onRegisterEvents = useCallback(
    (event: RegistrationSSEEvent) => {
      appendLog("idle", `[${event.phase}] ${event.message ?? ""}`);

      const toastId = "registration";
      if (event.phase === RegistrationPhase.REGISTRATION_ERROR || event.status === RegistrationStatus.ERROR) {
        toast.error((event as any)?.error || event.message || "Registration failed", { id: toastId });
        return;
      }

      switch (event.phase) {
        case RegistrationPhase.STEP_1_WEBAUTHN_VERIFICATION:
          toast.loading("Starting registration...", { id: toastId });
          return;
        case RegistrationPhase.STEP_2_KEY_GENERATION:
          if (event.status === RegistrationStatus.SUCCESS) {
            toast.success("Keys generated...", { id: toastId });
          } else {
            toast.loading(event.message || "Generating keys...", { id: toastId });
          }
          return;
        case RegistrationPhase.STEP_3_CONTRACT_PRE_CHECK:
          toast.loading("Pre-checking contract and account state...", { id: toastId });
          return;
        case RegistrationPhase.STEP_4_ACCESS_KEY_ADDITION:
          toast.loading("Creating account...", { id: toastId });
          return;
        case RegistrationPhase.STEP_5_CONTRACT_REGISTRATION:
          toast.loading("Registering with Web3Authn contract...", { id: toastId });
          return;
        case RegistrationPhase.STEP_6_ACCOUNT_VERIFICATION:
          toast.loading(event.message || "Verifying account...", { id: toastId });
          return;
        case RegistrationPhase.STEP_7_DATABASE_STORAGE:
          toast.loading(event.message || "Saving credentials...", { id: toastId });
          return;
        case RegistrationPhase.STEP_8_REGISTRATION_COMPLETE:
          toast.success("Registration completed successfully!", { id: toastId });
          return;
        default:
          toast.loading("Processing...", { id: toastId });
      }
    },
    [appendLog],
  );

  const onLoginEvents = useCallback(
    (event: LoginSSEvent) => {
      appendLog("idle", `[${event.phase}] ${event.message ?? ""}`);

      const toastId = "login";
      if (event.phase === LoginPhase.LOGIN_ERROR || event.status === LoginStatus.ERROR) {
        toast.error((event as any)?.error || event.message || "Login failed", { id: toastId });
        return;
      }

      switch (event.phase) {
        case LoginPhase.STEP_1_PREPARATION:
          toast.loading(event.message || "Starting login...", { id: toastId });
          return;
        case LoginPhase.STEP_2_WEBAUTHN_ASSERTION:
          toast.loading(event.message || "Confirm with your passkey...", { id: toastId });
          return;
        case LoginPhase.STEP_3_VRF_UNLOCK:
          toast.loading(event.message || "Unlocking signing session...", { id: toastId });
          return;
        case LoginPhase.STEP_4_LOGIN_COMPLETE:
          toast.success(event.message || "Logged in.", { id: toastId });
          return;
        default:
          toast.loading("Logging in...", { id: toastId });
      }
    },
    [appendLog],
  );

  const title = mode === "login" ? "Login" : "Register";
  const loadingLabel = mode === "login" ? "Logging in..." : "Registering...";
  const buttonLabel = mode === "login" ? "Login with passkey" : "Register passkey";
  const explorerBaseUrl = String(tatchi?.configs?.nearExplorerUrl || "https://testnet.nearblocks.io").replace(/\/$/, "");
  const accountExplorerUrl = targetAccountId ? `${explorerBaseUrl}/address/${targetAccountId}` : "";

  const isBlocked = loginState.isLoggedIn;
  const isDisabled = isBlocked || isLoading;

  const handleSubmit = useCallback(
    async (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!targetAccountId) {
        setLogText("error", "Missing account id.");
        return;
      }
      if (loginState.isLoggedIn) {
        setLogText("error", "Already logged in. Logout to register/login again.");
        return;
      }
      if (isLoading) return;

      setIsLoading(true);
      clearLog();
      toast.loading(mode === "login" ? "Starting login..." : "Starting registration...", {
        id: mode === "login" ? "login" : "registration",
      });

      try {
        const result =
          mode === "login"
            ? await loginAndCreateSession(targetAccountId, { onEvent: onLoginEvents })
            : await registerPasskey(targetAccountId, { onEvent: onRegisterEvents });
        appendLog("ok", result);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        setLogText("error", message);
        toast.error(message || "Authentication failed", { id: mode === "login" ? "login" : "registration" });
      } finally {
        setIsLoading(false);
      }
    },
    [
      appendLog,
      isLoading,
      loginAndCreateSession,
      loginState.isLoggedIn,
      mode,
      onLoginEvents,
      onRegisterEvents,
      registerPasskey,
      setLogText,
      targetAccountId,
    ],
  );

  return (
    <div className="row">
      <aside className={`panel note ${isBlocked ? "is-disabled" : ""}`}>
        <h3>01 {title}</h3>
        <p className="helper">
          {mode === "login"
            ? "Login to your existing testnet NEAR account with a passkey."
            : "Create a testnet NEAR account with a passkey."}
        </p>
      </aside>
      <section className={`panel ${isBlocked ? "is-disabled" : ""}`}>
        <div className="panel-header">
          <h2>{title}</h2>
          <span className="pill">01</span>
        </div>
        <form onSubmit={handleSubmit} className="stack">
          <label>
            NEAR account id
            <div className="input-row">
              <input
                value={inputUsername}
                onChange={(event) => onChangeUsername(event.target.value)}
                placeholder="your-account"
                disabled={isDisabled}
              />
              <span className="postfix">{postfix}</span>
            </div>
          </label>
          <p className="helper">
            Target account:{" "}
            {accountExplorerUrl ? (
              <a className="mailto" href={accountExplorerUrl} target="_blank" rel="noopener noreferrer">
                {targetAccountId}
              </a>
            ) : (
              targetAccountId || "Enter a username to build the full account id."
            )}
          </p>
          <button type="submit" disabled={isDisabled} aria-busy={isLoading}>
            {isLoading && <span className="spinner" aria-hidden="true" />}
            {isLoading ? loadingLabel : buttonLabel}
          </button>
        </form>
        <Output state={log} />
      </section>
    </div>
  );
}

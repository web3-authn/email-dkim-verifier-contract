import { useState } from "react";
import {
  ActionPhase,
  ActionStatus,
  ActionType,
  type ActionSSEEvent,
  useTatchi,
} from "@tatchi-xyz/sdk/react";
import { toast } from "sonner";
import { useOutputLog } from "../hooks/useOutputLog";
import { Output } from "./Output";
import { getErrorMessage } from "../utils/errors";
import {
  extractNearTransactionHash,
  getNearAccountExplorerUrl,
  getNearExplorerBaseUrl,
  getNearTransactionExplorerUrl,
} from "../utils/nearExplorer";

const TRANSFER_NEAR = "0.000123";
const TRANSFER_AMOUNT_YOCTO = "123000000000000000000"; // 0.000123 NEAR

type Step5TestTransferProps = {
  receiverId: string;
};

export function Step5TestTransfer({ receiverId }: Step5TestTransferProps) {
  const { tatchi, loginState } = useTatchi();
  const [isLoading, setIsLoading] = useState(false);
  const log = useOutputLog();

  const onTransferEvents = (event: ActionSSEEvent) => {
    const logLine = event.message || String(event.phase);
    log.appendOutput("idle", logLine);

    const toastId = "test-transfer";
    if (
      event.phase === ActionPhase.ACTION_ERROR ||
      event.phase === ActionPhase.WASM_ERROR ||
      event.status === ActionStatus.ERROR
    ) {
      toast.error(getErrorMessage((event as { error?: unknown }).error ?? event.message ?? "Transfer failed"), {
        id: toastId,
      });
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
        {
          const message = event.message || "Transfer submitted.";
          const txHash = extractNearTransactionHash(message);
          const explorerBaseUrl = getNearExplorerBaseUrl(tatchi?.configs?.nearExplorerUrl);
          const txUrl = getNearTransactionExplorerUrl(explorerBaseUrl, txHash);
          toast.success(
            txUrl ? (
              <a className="mailto" href={txUrl} target="_blank" rel="noopener noreferrer">
                {message}
              </a>
            ) : (
              message
            ),
            { id: toastId },
          );
        }
        return;
      default:
        toast.loading(event.message || "Processing...", { id: toastId });
    }
  };

  const isBlocked = !loginState.isLoggedIn || !loginState.nearAccountId;
  const isDisabled = isBlocked || isLoading;

  const explorerBaseUrl = getNearExplorerBaseUrl(tatchi?.configs?.nearExplorerUrl);
  const senderExplorerUrl = getNearAccountExplorerUrl(explorerBaseUrl, loginState.nearAccountId);
  const receiverExplorerUrl = getNearAccountExplorerUrl(explorerBaseUrl, receiverId);

  const handleTransfer = async () => {
    if (!loginState.isLoggedIn || !loginState.nearAccountId) {
      log.setOutputText("error", "Login required to send a transfer.");
      return;
    }
    if (!receiverId) {
      log.setOutputText("error", "Missing receiver id.");
      return;
    }
    if (isLoading) return;

    const toastId = "test-transfer";

    setIsLoading(true);
    log.clearOutput();
    toast.loading("Preparing transfer…", { id: toastId });

    try {
      const result = await tatchi.executeAction({
        nearAccountId: loginState.nearAccountId,
        receiverId,
        actionArgs: {
          type: ActionType.Transfer,
          amount: TRANSFER_AMOUNT_YOCTO,
        },
        options: {
          onEvent: onTransferEvents,
          confirmerText: {
            title: "Test Transfer",
            body: `Send ${TRANSFER_NEAR} NEAR to ${receiverId}`,
          },
        },
      });
      log.appendOutput("ok", result);
    } catch (error) {
      const message = getErrorMessage(error);
      log.setOutputText("error", message);
      toast.error(message || "Transfer failed", { id: toastId });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="row">
      <aside className={`panel note ${isBlocked ? "is-disabled" : ""} pad-left-05`}>
        <h3>05 Test Transfer</h3>
        <p className="helper">
          Send a small NEAR transfer to confirm passkey transaction signing works after email recovery.
        </p>
      </aside>
      <section className={`panel ${isBlocked ? "is-disabled" : ""}`}>
        <div className="panel-header">
          <h2>Test transfer</h2>
        </div>
        <div className="stack">
          <p className="helper">
            From:{" "}
            {senderExplorerUrl ? (
              <a className="mailto" href={senderExplorerUrl} target="_blank" rel="noopener noreferrer">
                {loginState.nearAccountId}
              </a>
            ) : (
              loginState.nearAccountId || "—"
            )}
          </p>
          <p className="helper">
            To:{" "}
            {receiverExplorerUrl ? (
              <a className="mailto" href={receiverExplorerUrl} target="_blank" rel="noopener noreferrer">
                {receiverId}
              </a>
            ) : (
              receiverId
            )}
          </p>
          <p className="helper">Amount: {TRANSFER_NEAR} NEAR</p>
          <button type="button" onClick={handleTransfer} disabled={isDisabled} aria-busy={isLoading}>
            {isLoading && <span className="spinner" aria-hidden="true" />}
            {isLoading ? "Sending..." : "Send test transfer"}
          </button>
          {isBlocked && <p className="helper">Login required to send a transfer.</p>}
        </div>
        <Output state={log.output} />
      </section>
    </div>
  );
}

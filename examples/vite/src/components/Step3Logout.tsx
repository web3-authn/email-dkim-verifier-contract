import { useState } from "react";
import { toast } from "sonner";
import { useTatchi } from "@tatchi-xyz/sdk/react";
import { useOutputLog } from "../hooks/useOutputLog";
import { Output } from "./Output";
import { getErrorMessage } from "../utils/errors";

export function Step3Logout() {
  const { loginState, logout } = useTatchi();
  const [isLoading, setIsLoading] = useState(false);
  const log = useOutputLog();

  const isBlocked = !loginState.isLoggedIn;
  const isDisabled = isBlocked || isLoading;

  const handleLogout = async () => {
    if (!loginState.isLoggedIn) {
      log.setOutputText("error", "Not logged in.");
      return;
    }
    if (isLoading) return;

    setIsLoading(true);
    log.clearOutput();
    toast.loading("Logging out…", { id: "logout" });
    try {
      await logout();
      log.appendOutput("ok", "Logged out.");
      toast.success("Logged out.", { id: "logout" });
    } catch (error) {
      const message = getErrorMessage(error);
      log.setOutputText("error", message);
      toast.error(message || "Logout failed", { id: "logout" });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="row">
      <aside className={`panel note ${isBlocked ? "is-disabled" : ""}`}>
        <h3>03 Logout</h3>
        <p className="helper">Logout: simulate the user losing access to their account.</p>
      </aside>
      <section className={`panel ${isBlocked ? "is-disabled" : ""}`}>
        <div className="panel-header">
          <h2>Logout</h2>
        </div>
        <div className="stack">
          <p className="helper">Account recovery should be performed while logged out. Logout and clear the session.</p>
          <button type="button" onClick={handleLogout} disabled={isDisabled} aria-busy={isLoading}>
            {isLoading && <span className="spinner" aria-hidden="true" />}
            {isLoading ? "Logging out..." : "Logout"}
          </button>
        </div>
        <Output state={log.output} />
      </section>
    </div>
  );
}

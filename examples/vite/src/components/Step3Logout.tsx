import { useCallback, useState } from "react";
import { toast } from "sonner";
import { useTatchi } from "@tatchi-xyz/sdk/react";
import { useOutputLog } from "../hooks/useOutputLog";
import { Output } from "./Output";

export function Step3Logout() {
  const { loginState, logout } = useTatchi();
  const [isLoading, setIsLoading] = useState(false);
  const {
    output: log,
    clearOutput: clearLog,
    appendOutput: appendLog,
    setOutputText: setLogText,
  } = useOutputLog();

  const isBlocked = !loginState.isLoggedIn;
  const isDisabled = isBlocked || isLoading;

  const handleLogout = useCallback(async () => {
    if (!loginState.isLoggedIn) {
      setLogText("error", "Not logged in.");
      return;
    }
    if (isLoading) return;

    setIsLoading(true);
    clearLog();
    toast.loading("Logging out…", { id: "logout" });
    try {
      await Promise.resolve(logout());
      appendLog("ok", "Logged out.");
      toast.success("Logged out.", { id: "logout" });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setLogText("error", message);
      toast.error(message || "Logout failed", { id: "logout" });
    } finally {
      setIsLoading(false);
    }
  }, [appendLog, isLoading, loginState.isLoggedIn, logout, setLogText]);

  return (
    <div className="row">
      <aside className={`panel note ${isBlocked ? "is-disabled" : ""}`}>
        <h3>03 Logout</h3>
        <p className="helper">Logout: simulate the user losing access to their account.</p>
      </aside>
      <section className={`panel ${isBlocked ? "is-disabled" : ""}`}>
        <div className="panel-header">
          <h2>Logout</h2>
          <span className="pill">03</span>
        </div>
        <div className="stack">
          <p className="helper">Account recovery should be performed while logged out. Logout and clear the session.</p>
          <button type="button" onClick={handleLogout} disabled={isDisabled} aria-busy={isLoading}>
            {isLoading && <span className="spinner" aria-hidden="true" />}
            {isLoading ? "Logging out..." : "Logout"}
          </button>
        </div>
        <Output state={log} />
      </section>
    </div>
  );
}

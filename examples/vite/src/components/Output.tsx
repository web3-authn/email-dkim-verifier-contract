export type OutputState = { status: "idle" | "ok" | "error"; text: string };

export const emptyOutput: OutputState = { status: "idle", text: "" };

type OutputProps = {
  state: OutputState;
};

export function Output({ state }: OutputProps) {
  if (!state.text) {
    return <div className="output muted">No logs yet.</div>;
  }
  return (
    <pre className="output" data-status={state.status}>
      {state.text}
    </pre>
  );
}

import { useCallback, useState } from "react";
import { emptyOutput, type OutputState } from "../components/Output";
import { safeJson } from "./safeJson";

export function useOutputLog() {
  const [output, setOutput] = useState<OutputState>(emptyOutput);

  const clearOutput = useCallback(() => {
    setOutput(emptyOutput);
  }, []);

  const setOutputText = useCallback((status: OutputState["status"], value: unknown) => {
    setOutput({ status, text: safeJson(value) });
  }, []);

  const appendOutput = useCallback((status: OutputState["status"], value: unknown) => {
    const line = safeJson(value);
    setOutput((prev) => {
      const nextText = prev.text ? `${prev.text}\n${line}` : line;
      const nextStatus = prev.status === "error" ? "error" : status;
      return { status: nextStatus, text: nextText };
    });
  }, []);

  return { output, clearOutput, setOutputText, appendOutput };
}


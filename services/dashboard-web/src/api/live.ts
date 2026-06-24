import { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";

// Opens the backend WebSocket (/api/ws). On every server "tick" (the DB changed)
// it invalidates the data queries so they refetch — push-driven live updates,
// replacing per-client polling. Auto-reconnects; returns the connection state.
export function useLive(): boolean {
  const qc = useQueryClient();
  const [connected, setConnected] = useState(false);
  const retry = useRef<ReturnType<typeof setTimeout>>();

  useEffect(() => {
    let stopped = false;
    let ws: WebSocket | null = null;

    const invalidateAll = () =>
      ["summary", "alerts", "approvals", "attack", "metrics", "endpoints", "mapping"].forEach(
        (k) => qc.invalidateQueries({ queryKey: [k] }),
      );

    const connect = () => {
      if (stopped) return;
      const proto = window.location.protocol === "https:" ? "wss" : "ws";
      ws = new WebSocket(`${proto}://${window.location.host}/api/ws`);
      ws.onopen = () => setConnected(true);
      ws.onmessage = (e) => {
        try {
          const m = JSON.parse(e.data);
          if (m.type === "tick") invalidateAll();
        } catch {
          invalidateAll();
        }
      };
      ws.onclose = () => {
        setConnected(false);
        if (!stopped) retry.current = setTimeout(connect, 3000);
      };
      ws.onerror = () => ws?.close();
    };

    connect();
    return () => {
      stopped = true;
      if (retry.current) clearTimeout(retry.current);
      ws?.close();
    };
  }, [qc]);

  return connected;
}

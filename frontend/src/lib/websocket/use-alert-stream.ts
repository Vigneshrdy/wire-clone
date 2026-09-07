"use client";

import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useEffectEvent, useState } from "react";
import { AlertsResponseSchema, WsMessageSchema, type Alert } from "@/lib/api/schemas";

export type StreamState = "live" | "reconnecting" | "offline";

export function useAlertStream(onAlert?: (alert: Alert) => void) {
  const [state, setState] = useState<StreamState>("reconnecting");
  const queryClient = useQueryClient();
  const emitAlert = useEffectEvent((alert: Alert) => onAlert?.(alert));

  useEffect(() => {
    let socket: WebSocket | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let stopped = false;
    let attempt = 0;

    const connect = () => {
      if (stopped) return;
      setState(attempt ? "reconnecting" : "offline");
      const fallback = `${location.protocol === "https:" ? "wss" : "ws"}://${location.hostname}:8000/ws/alerts`;
      socket = new WebSocket(process.env.NEXT_PUBLIC_WS_URL || fallback);
      socket.onopen = () => { attempt = 0; };
      socket.onmessage = (event) => {
        try {
          const message = WsMessageSchema.parse(JSON.parse(String(event.data)));
          if (message.type === "connected" || message.type === "keepalive") setState("live");
          if (message.type === "alert") {
            setState("live");
            emitAlert(message.alert);
            queryClient.setQueriesData({ queryKey: ["alerts"] }, (current: unknown) => {
              const parsed = AlertsResponseSchema.safeParse(current);
              if (!parsed.success) return current;
              const alerts = [message.alert, ...parsed.data.alerts.filter((item) => item.alert_id !== message.alert.alert_id)].slice(0, parsed.data.limit);
              return { ...parsed.data, alerts, count: alerts.length, total: Math.max(parsed.data.total, alerts.length) };
            });
          }
        } catch { /* Invalid messages are isolated from the rest of the console. */ }
      };
      socket.onclose = () => {
        if (stopped) return;
        setState("reconnecting");
        const delay = Math.min(30_000, 1_000 * 2 ** attempt) + Math.random() * 500;
        attempt += 1;
        timer = setTimeout(connect, delay);
      };
      socket.onerror = () => socket?.close();
    };
    connect();
    return () => { stopped = true; if (timer) clearTimeout(timer); socket?.close(); };
  }, [queryClient]);

  return state;
}

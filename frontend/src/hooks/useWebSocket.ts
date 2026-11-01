import { useEffect, useRef } from "react";
import { getAccessToken } from "../lib/api";

export interface LiveEvent {
  topic: string;
  data: Record<string, unknown>;
}

const TOPICS = [
  "alerts.stream",
  "alerts.new",
  "indicators.high_severity",
  "incidents.updated",
  "system.ready",
  "system.health",
];

const extraTopics = new Set<string>();
let activeSocket: WebSocket | null = null;

function subscribeAll() {
  if (activeSocket?.readyState !== WebSocket.OPEN) return;
  activeSocket.send(JSON.stringify({ action: "subscribe", topics: [...new Set([...TOPICS, ...extraTopics])] }));
}

export function subscribeTopic(topic: string) {
  extraTopics.add(topic);
  subscribeAll();
}

export function unsubscribeTopic(topic: string) {
  extraTopics.delete(topic);
  subscribeAll();
}

export function useWebSocket(onEvent: (event: LiveEvent) => void, enabled = true) {
  const handlerRef = useRef(onEvent);

  useEffect(() => {
    handlerRef.current = onEvent;
  }, [onEvent]);

  useEffect(() => {
    if (!enabled) return;
    let socket: WebSocket | null = null;
    let reconnectTimer: number | undefined;
    let heartbeat: number | undefined;
    let attempts = 0;
    let closedByUs = false;

    const connect = () => {
      const token = getAccessToken();
      if (!token) return;
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      socket = new WebSocket(`${protocol}//${window.location.host}/api/v1/ws?token=${encodeURIComponent(token)}`);
      socket.onopen = () => {
        attempts = 0;
        activeSocket = socket;
        subscribeAll();
        heartbeat = window.setInterval(() => {
          if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ action: "ping" }));
        }, 25_000);
      };
      socket.onmessage = (message) => {
        try {
          const parsed = JSON.parse(message.data) as LiveEvent;
          if (parsed.topic === "pong") return;
          handlerRef.current(parsed);
        } catch {
          // Ignore non-JSON frames.
        }
      };
      socket.onclose = () => {
        if (activeSocket === socket) activeSocket = null;
        if (heartbeat) window.clearInterval(heartbeat);
        if (closedByUs) return;
        attempts += 1;
        const delay = Math.min(30_000, 1000 * 2 ** Math.min(attempts, 5));
        reconnectTimer = window.setTimeout(connect, delay);
      };
      socket.onerror = () => socket?.close();
    };

    connect();
    return () => {
      closedByUs = true;
      if (activeSocket === socket) activeSocket = null;
      if (reconnectTimer) window.clearTimeout(reconnectTimer);
      if (heartbeat) window.clearInterval(heartbeat);
      socket?.close();
    };
  }, [enabled]);
}

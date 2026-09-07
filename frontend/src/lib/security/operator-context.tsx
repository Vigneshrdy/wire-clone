"use client";

import { createContext, useContext, useSyncExternalStore, type ReactNode } from "react";

type OperatorContextValue = {
  token: string | null;
  unlocked: boolean;
  unlock: (token: string) => void;
  lock: () => void;
};

const OperatorContext = createContext<OperatorContextValue | null>(null);
const STORAGE_KEY = "sih-operator-token";
const CHANGE_EVENT = "sih-operator-change";

function subscribe(listener: () => void) { window.addEventListener(CHANGE_EVENT, listener); return () => window.removeEventListener(CHANGE_EVENT, listener); }
function snapshot() { return sessionStorage.getItem(STORAGE_KEY); }
function serverSnapshot() { return null; }

export function OperatorProvider({ children }: { children: ReactNode }) {
  const token = useSyncExternalStore(subscribe, snapshot, serverSnapshot);

  const unlock = (value: string) => {
    const clean = value.trim();
    if (!clean) return;
    sessionStorage.setItem(STORAGE_KEY, clean);
    window.dispatchEvent(new Event(CHANGE_EVENT));
  };
  const lock = () => {
    sessionStorage.removeItem(STORAGE_KEY);
    window.dispatchEvent(new Event(CHANGE_EVENT));
  };

  return <OperatorContext.Provider value={{ token, unlocked: Boolean(token), unlock, lock }}>{children}</OperatorContext.Provider>;
}

export function useOperator() {
  const value = useContext(OperatorContext);
  if (!value) throw new Error("useOperator must be used within OperatorProvider");
  return value;
}

"use client";

import * as Dialog from "@radix-ui/react-dialog";
import { KeyRound, Lock, Unlock, X } from "lucide-react";
import { useState } from "react";
import { useOperator } from "@/lib/security/operator-context";

export function OperatorAccess() {
  const { unlocked, unlock, lock } = useOperator();
  const [open, setOpen] = useState(false);
  const [value, setValue] = useState("");
  return <><div className="operator-access-row"><span className="operator-icon">{unlocked ? <Unlock size={17} /> : <Lock size={17} />}</span><div><strong>Operator mode: {unlocked ? "Unlocked" : "Locked"}</strong><p>Management credentials remain in this browser tab session only.</p></div>{unlocked ? <button onClick={lock}>Lock session</button> : <button onClick={() => setOpen(true)}><KeyRound size={14} />Unlock operator mode</button>}</div><Dialog.Root open={open} onOpenChange={setOpen}><Dialog.Portal><Dialog.Overlay className="dialog-overlay" /><Dialog.Content className="dialog-content"><div className="dialog-heading"><div><Dialog.Title>Operator access</Dialog.Title><Dialog.Description>Enter the management token configured by the FastAPI operator. It is stored only in sessionStorage and forwarded only to whitelisted management operations.</Dialog.Description></div><Dialog.Close aria-label="Close"><X size={16} /></Dialog.Close></div><label className="dialog-field">Management token<input type="password" autoComplete="off" value={value} onChange={(event) => setValue(event.target.value)} /></label><div className="dialog-actions"><Dialog.Close>Cancel</Dialog.Close><button className="primary-button" disabled={!value.trim()} onClick={() => { unlock(value); setValue(""); setOpen(false); }}>Unlock session</button></div></Dialog.Content></Dialog.Portal></Dialog.Root></>;
}

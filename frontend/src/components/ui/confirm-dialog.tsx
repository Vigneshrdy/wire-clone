"use client";

import * as Dialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import type { ReactNode } from "react";

export function ConfirmDialog({ open, onOpenChange, title, description, children, confirmLabel, onConfirm, dangerous = false, disabled = false }: { open: boolean; onOpenChange: (open: boolean) => void; title: string; description: string; children?: ReactNode; confirmLabel: string; onConfirm: () => void; dangerous?: boolean; disabled?: boolean }) {
  return <Dialog.Root open={open} onOpenChange={onOpenChange}><Dialog.Portal><Dialog.Overlay className="dialog-overlay" /><Dialog.Content className="dialog-content"><div className="dialog-heading"><div><Dialog.Title>{title}</Dialog.Title><Dialog.Description>{description}</Dialog.Description></div><Dialog.Close aria-label="Close"><X size={16} /></Dialog.Close></div>{children}<div className="dialog-actions"><Dialog.Close>Cancel</Dialog.Close><button className={dangerous ? "danger-button" : "primary-button"} disabled={disabled} onClick={onConfirm}>{confirmLabel}</button></div></Dialog.Content></Dialog.Portal></Dialog.Root>;
}

import { Suspense } from "react";
import { AlertsClient } from "@/features/alerts/alerts-client";

export default async function AlertDetailPage({ params }: PageProps<"/alerts/[alertId]">) { const { alertId } = await params; return <Suspense><AlertsClient initialAlertId={alertId} /></Suspense>; }

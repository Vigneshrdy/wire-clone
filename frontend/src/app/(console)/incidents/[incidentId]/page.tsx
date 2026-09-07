import { IncidentsClient } from "@/features/incidents/incidents-client";
export default async function IncidentPage({ params }: PageProps<"/incidents/[incidentId]">) { const { incidentId } = await params; return <IncidentsClient incidentId={incidentId} />; }

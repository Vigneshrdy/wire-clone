import type { z } from "zod";

export class ApiError extends Error {
  constructor(public status: number, message: string, public detail?: unknown) { super(message); }
}

export async function apiGet<T>(path: string, schema: z.ZodType<T>, signal?: AbortSignal): Promise<T> {
  const response = await fetch(`/api/backend/${path}`, { signal, cache: "no-store" });
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) throw new ApiError(response.status, `Request failed (${response.status})`, body);
  return schema.parse(body);
}

export async function apiText(path: string): Promise<string> {
  const response = await fetch(`/api/backend/${path}`, { cache: "no-store" });
  if (!response.ok) throw new ApiError(response.status, `Request failed (${response.status})`);
  return response.text();
}

export async function apiPost<T = unknown>(path: string, body: unknown, token?: string | null): Promise<T> {
  const response = await fetch(`/api/backend/${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(token ? { "x-operator-token": token } : {}) },
    body: JSON.stringify(body),
  });
  const data: unknown = await response.json().catch(() => null);
  if (!response.ok) throw new ApiError(response.status, `Action failed (${response.status})`, data);
  return data as T;
}

export function queryString(values: Record<string, string | number | undefined | null>) {
  const params = new URLSearchParams();
  Object.entries(values).forEach(([key, value]) => { if (value !== undefined && value !== null && value !== "") params.set(key, String(value)); });
  const value = params.toString();
  return value ? `?${value}` : "";
}

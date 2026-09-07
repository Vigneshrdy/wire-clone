import { NextRequest } from "next/server";

export const dynamic = "force-dynamic";

const READ_ROUTES = [
  /^health$/, /^ready$/, /^metrics$/, /^alerts(?:\/summary)?$/, /^alerts\/[A-Za-z0-9_-]+$/,
  /^incidents$/, /^incidents\/[A-Za-z0-9_-]+$/, /^flows$/, /^detectors$/, /^model-health$/,
  /^models$/, /^models\/[A-Za-z0-9_.-]+$/, /^drift$/, /^feedback$/, /^benchmarks$/, /^replay\/status$/,
];
const WRITE_ROUTES = [
  /^alerts\/[A-Za-z0-9_-]+\/status$/, /^feedback$/, /^replay\/start$/,
  /^models\/[A-Za-z0-9_.-]+\/(?:evaluate|promote|rollback)$/,
];

function backendPath(parts: string[], method: string) {
  const path = parts.join("/");
  const allowed = method === "GET" ? READ_ROUTES : method === "POST" ? WRITE_ROUTES : [];
  if (!allowed.some((pattern) => pattern.test(path))) return null;
  return path === "health" || path === "ready" || path === "metrics" ? `/${path}` : `/api/v1/${path}`;
}

async function proxy(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  const { path } = await context.params;
  const targetPath = backendPath(path, request.method);
  if (!targetPath) return Response.json({ detail: "Unsupported backend operation" }, { status: 404 });

  const base = process.env.FASTAPI_BASE_URL ?? "http://127.0.0.1:8000";
  const target = new URL(targetPath, base);
  request.nextUrl.searchParams.forEach((value, key) => target.searchParams.append(key, value));
  const headers = new Headers({ accept: request.headers.get("accept") ?? "application/json" });
  const operatorToken = request.headers.get("x-operator-token");
  if (operatorToken && request.method === "POST") headers.set("authorization", `Bearer ${operatorToken}`);
  if (request.method === "POST") headers.set("content-type", "application/json");

  try {
    const upstream = await fetch(target, { method: request.method, headers, body: request.method === "POST" ? await request.text() : undefined, cache: "no-store" });
    return new Response(upstream.body, { status: upstream.status, headers: { "content-type": upstream.headers.get("content-type") ?? "application/json" } });
  } catch {
    return Response.json({ detail: "Backend service is unreachable" }, { status: 502 });
  }
}

export const GET = proxy;
export const POST = proxy;

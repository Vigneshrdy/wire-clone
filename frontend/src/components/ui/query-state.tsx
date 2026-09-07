export function QueryError({ title = "Data unavailable" }: { title?: string }) {
  return <div className="inline-error" role="alert"><strong>{title}</strong><span>Check the backend connection and retry.</span></div>;
}

export function LoadingLine() { return <div className="loading-line" aria-label="Loading" />; }

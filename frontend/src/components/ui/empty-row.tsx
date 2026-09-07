export function EmptyRow({ columns, title, detail }: { columns: number; title: string; detail?: string }) {
  return <tr><td colSpan={columns} className="empty-row"><strong>{title}</strong>{detail ? <span>{detail}</span> : null}</td></tr>;
}

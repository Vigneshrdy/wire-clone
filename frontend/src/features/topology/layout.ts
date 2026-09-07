export type Position = [number, number, number];

export function stableHash(value: string) {
  let hash = 2166136261;
  for (const character of value) { hash ^= character.charCodeAt(0); hash = Math.imul(hash, 16777619); }
  return hash >>> 0;
}

export function isPrivateAddress(address: string) {
  return address.startsWith("10.") || address.startsWith("192.168.") || /^172\.(1[6-9]|2\d|3[01])\./.test(address);
}

export function logicalPosition(id: string, internal: boolean, index: number, total: number): Position {
  const hash = stableHash(id);
  const lane = internal ? -3.8 : 3.8;
  const spread = Math.max(1, total - 1);
  const y = ((index / spread) - 0.5) * 7.2;
  const z = ((hash % 1000) / 1000 - 0.5) * 2.2;
  return [lane + ((hash >> 8) % 7) * (internal ? 0.08 : -0.08), y, z];
}

# SIH 26145 Design System

## Visual principles

- Operations canvas, not a card dashboard. Dense ledgers, split investigations, rails, and timelines carry the interface.
- Evidence before decoration. Visual treatments must encode state, severity, direction, or comparison.
- Quiet chrome, high-signal content. One restrained security blue plus semantic status colors.
- Honest absence. Empty datasets remain compact and never create synthetic activity.

## Signature

The signal spine is a continuous operational rail joining throughput, alerts, incidents, detector readiness, stream state, and recency. It reads as one instrument rather than unrelated KPI cards.

## Themes

Light uses a blue-gray canvas (`#F5F7FA`), white working surfaces, graphite text, and security blue (`#1769AA`). Dark uses a near-black blue canvas (`#090D12`), layered slate surfaces, cool text, and blue (`#4C9BE8`). Semantic red, amber, and green are reserved for risk and health.

All runtime colors are CSS custom properties in `src/styles/tokens.css`. TSX and chart code consume computed tokens.

## Typography

- Inter: navigation, headings, prose, controls.
- IBM Plex Mono: IP addresses, timestamps, rates, versions, and evidence values.
- Page title: 20px/600. Section title: 14px/600. Body: 13px. Utility labels: 10–11px uppercase with tracking.
- Numeric data uses tabular figures.

## Spacing and shape

- Base spacing: 4px. Main content padding: 24–32px desktop, 16px tablet/mobile.
- Radius: 6px controls, 9px surfaces, 12px overlays. Status labels alone may be pill-shaped.
- Borders divide tables and structural regions; spacing and surface tone do most grouping.
- Shadows appear on overlays in light mode and are minimal elsewhere.

## Tables

- Operational rows are 42px high with sticky headers.
- Primary entity columns are strongest; metadata is muted; numeric columns align and use monospace.
- Empty states render as one table row plus at most one explanatory sentence.

## Status representation

- Status always includes text or an icon, never color alone.
- Critical: red. High: orange-red. Medium: amber. Low: blue. Informational: neutral.
- Unavailable is muted neutral, degraded is amber, ready is green.

## Charts

- Transparent backgrounds, subtle token-driven grids, muted axes, theme-aware tooltips.
- Blue is the primary series. Red and amber appear only for thresholds or adverse states.
- No chart renders without real backend data.

## Three.js

- Internal hosts are spheres; external destinations are octahedrons. Alerted relationships gain red or amber emphasis and a ring.
- Positions are deterministic logical lanes, never geography.
- Node, edge, and background colors come from design tokens. Motion is bounded and disabled for reduced-motion users.

## Motion and accessibility

- Interaction transitions are 120–180ms. No page entrance sequences or decorative loops.
- Keyboard navigation, visible focus, semantic HTML, accessible dialogs, and reduced motion are required.
- The network graph always has a tabular equivalent.

## Empty states

- Preserve surrounding operational context.
- Use a compact row or inline statement.
- Offer an action only when the backend supports it and operator access permits it.

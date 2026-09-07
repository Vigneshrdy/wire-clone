"use client";

import { Canvas } from "@react-three/fiber";
import { useLayoutEffect, useMemo, useRef } from "react";
import * as THREE from "three";
import type { GraphNode, TopologyGraph } from "./topology-data";

export function TopologyCanvas({ graph, selected, onSelect }: { graph: TopologyGraph; selected?: string; onSelect: (id: string) => void }) {
  return <div className="topology-canvas"><Canvas dpr={[1, 1.5]} camera={{ position: [0, 0, 12], fov: 48 }} frameloop="demand" gl={{ antialias: true, alpha: true, powerPreference: "high-performance" }} fallback={<div className="webgl-fallback">WebGL is unavailable. Use the endpoint inspector and flow table below.</div>}><ambientLight intensity={1.6} /><directionalLight position={[2, 4, 8]} intensity={1.2} /><GraphScene graph={graph} selected={selected} onSelect={onSelect} /></Canvas><div className="topology-lane topology-lane-internal">Internal network</div><div className="topology-lane topology-lane-external">External destinations</div></div>;
}

function GraphScene({ graph, selected, onSelect }: { graph: TopologyGraph; selected?: string; onSelect: (id: string) => void }) {
  const internals = graph.nodes.filter((node) => node.kind === "internal");
  const externals = graph.nodes.filter((node) => node.kind === "external");
  return <group><Edges graph={graph} /><NodeInstances nodes={internals} geometry="sphere" selected={selected} onSelect={onSelect} /><NodeInstances nodes={externals} geometry="octahedron" selected={selected} onSelect={onSelect} /></group>;
}

function NodeInstances({ nodes, geometry, selected, onSelect }: { nodes: GraphNode[]; geometry: "sphere" | "octahedron"; selected?: string; onSelect: (id: string) => void }) {
  const mesh = useRef<THREE.InstancedMesh>(null);
  const matrix = useMemo(() => new THREE.Matrix4(), []);
  const nodeColor = tokenColor("--topology-node", "#356f9f");
  const externalColor = tokenColor("--topology-external", "#526575");
  const dangerColor = tokenColor("--danger", "#b42318");
  useLayoutEffect(() => {
    nodes.forEach((node, index) => {
      const scale = Math.min(1.15, .38 + Math.log2(node.connections + 1) * .08);
      matrix.compose(new THREE.Vector3(...node.position), new THREE.Quaternion(), new THREE.Vector3(scale, scale, scale));
      mesh.current?.setMatrixAt(index, matrix);
      mesh.current?.setColorAt(index, new THREE.Color(node.alerts ? dangerColor : geometry === "sphere" ? nodeColor : externalColor));
    });
    if (mesh.current) { mesh.current.instanceMatrix.needsUpdate = true; if (mesh.current.instanceColor) mesh.current.instanceColor.needsUpdate = true; }
  }, [nodes, geometry, matrix, nodeColor, externalColor, dangerColor]);
  return <instancedMesh ref={mesh} args={[undefined, undefined, nodes.length]} onClick={(event) => { event.stopPropagation(); const node = event.instanceId == null ? undefined : nodes[event.instanceId]; if (node) onSelect(node.id); }}>{geometry === "sphere" ? <sphereGeometry args={[1, 16, 12]} /> : <octahedronGeometry args={[1, 0]} />}<meshStandardMaterial roughness={.72} metalness={.08} emissive={selected ? tokenColor("--accent", "#1769aa") : "#000000"} emissiveIntensity={.08} /></instancedMesh>;
}

function Edges({ graph }: { graph: TopologyGraph }) {
  const positions = useMemo(() => {
    const lookup = new Map(graph.nodes.map((node) => [node.id, node.position]));
    return new Float32Array(graph.edges.flatMap((edge) => [...(lookup.get(edge.source) ?? [0, 0, 0]), ...(lookup.get(edge.target) ?? [0, 0, 0])]));
  }, [graph]);
  return <lineSegments><bufferGeometry><bufferAttribute attach="attributes-position" args={[positions, 3]} /></bufferGeometry><lineBasicMaterial color={tokenColor("--topology-edge", "#8ca0b2")} transparent opacity={.5} /></lineSegments>;
}

function tokenColor(name: string, fallback: string) { if (typeof document === "undefined") return fallback; return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback; }

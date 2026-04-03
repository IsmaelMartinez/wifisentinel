"use client";

import { useEffect, useRef } from "react";
import {
  forceSimulation,
  forceLink,
  forceManyBody,
  forceCenter,
  forceCollide,
  type SimulationNodeDatum,
  type SimulationLinkDatum,
} from "d3-force";
import { select } from "d3-selection";

interface TopologyNode extends SimulationNodeDatum {
  id: string;
  label: string;
  vendor?: string;
  isGateway?: boolean;
  isCamera?: boolean;
  ports: Array<{ port: number; service: string }>;
}

interface TopologyLink extends SimulationLinkDatum<TopologyNode> {
  source: string;
  target: string;
}

interface Props {
  gateway: string;
  hosts: Array<{
    ip: string;
    mac: string;
    vendor?: string;
    isCamera?: boolean;
    ports: Array<{ port: number; service: string }>;
  }>;
  width?: number;
  height?: number;
}

function nodeColor(node: TopologyNode): string {
  if (node.isGateway) return "#cca700";
  if (node.isCamera) return "#f44747";
  if (node.ports.length > 0) return "#cca700";
  return "#4ec9b0";
}

export function NetworkTopology({ gateway, hosts, width = 500, height = 350 }: Props) {
  const svgRef = useRef<SVGSVGElement>(null);
  const simulationRef = useRef<ReturnType<typeof forceSimulation<TopologyNode>> | null>(null);

  useEffect(() => {
    if (!svgRef.current) return;

    const nodes: TopologyNode[] = [
      { id: gateway, label: gateway, isGateway: true, ports: [] },
      ...hosts.map((h) => ({
        id: h.ip,
        label: h.ip.split(".").pop() ?? h.ip,
        vendor: h.vendor,
        isCamera: h.isCamera,
        ports: h.ports,
      })),
    ];

    const links: TopologyLink[] = hosts.map((h) => ({
      source: gateway,
      target: h.ip,
    }));

    simulationRef.current?.stop();

    const svg = select(svgRef.current);

    // Create persistent layer groups once; select them if they already exist
    let linkGroup = svg.select<SVGGElement>("g.links");
    if (linkGroup.empty()) {
      linkGroup = svg.append("g").attr("class", "links");
    }

    let nodeGroup = svg.select<SVGGElement>("g.nodes");
    if (nodeGroup.empty()) {
      nodeGroup = svg.append("g").attr("class", "nodes");
    }

    // Data-join for links
    const linkSel = linkGroup
      .selectAll<SVGLineElement, TopologyLink>("line")
      .data(links, (d) => `${(d.source as unknown as TopologyNode).id ?? d.source}-${(d.target as unknown as TopologyNode).id ?? d.target}`)
      .join(
        (enter) => enter.append("line"),
        (update) => update,
        (exit) => exit.remove(),
      )
      .attr("stroke", "#555")
      .attr("stroke-width", "1");

    // Data-join for node groups
    const nodeSel = nodeGroup
      .selectAll<SVGGElement, TopologyNode>("g.node")
      .data(nodes, (d) => d.id)
      .join(
        (enter) => {
          const g = enter.append("g").attr("class", "node");
          g.append("circle").attr("fill", "#1e1e2e");
          g.append("text").attr("class", "label").attr("text-anchor", "middle").attr("font-family", "monospace");
          g.append("text").attr("class", "vendor").attr("text-anchor", "middle").attr("font-family", "monospace");
          return g;
        },
        (update) => update,
        (exit) => exit.remove(),
      );

    // Bind visual properties on the merged selection so both entering and updating nodes stay current
    nodeSel.select<SVGCircleElement>("circle")
      .attr("r", (d) => (d.isGateway ? 20 : 14))
      .attr("stroke", nodeColor)
      .attr("stroke-width", (d) => (d.isGateway ? "3" : "2"));

    nodeSel.select<SVGTextElement>("text.label")
      .attr("fill", (d) => (d.isGateway ? "#cca700" : "#ccc"))
      .attr("font-size", "9")
      .text((d) => (d.isGateway ? d.id : `.${d.label}`));

    nodeSel.select<SVGTextElement>("text.vendor")
      .attr("fill", "#888")
      .attr("font-size", "8")
      .text((d) => d.vendor ?? "");

    const simulation = forceSimulation<TopologyNode>(nodes)
      .force("link", forceLink<TopologyNode, TopologyLink>(links).id((d) => d.id).distance(100))
      .force("charge", forceManyBody().strength(-200))
      .force("center", forceCenter(width / 2, height / 2))
      .force("collide", forceCollide(30));

    simulationRef.current = simulation;

    simulation.on("tick", () => {
      linkSel
        .attr("x1", (d) => String((d.source as unknown as TopologyNode).x ?? 0))
        .attr("y1", (d) => String((d.source as unknown as TopologyNode).y ?? 0))
        .attr("x2", (d) => String((d.target as unknown as TopologyNode).x ?? 0))
        .attr("y2", (d) => String((d.target as unknown as TopologyNode).y ?? 0));

      nodeSel.select<SVGCircleElement>("circle")
        .attr("cx", (d) => String(d.x ?? 0))
        .attr("cy", (d) => String(d.y ?? 0));

      nodeSel.select<SVGTextElement>("text.label")
        .attr("x", (d) => String(d.x ?? 0))
        .attr("y", (d) => String((d.y ?? 0) + 4));

      nodeSel.select<SVGTextElement>("text.vendor")
        .attr("x", (d) => String(d.x ?? 0))
        .attr("y", (d) => String((d.y ?? 0) + 28));
    });

    return () => { simulation.stop(); };
  }, [gateway, hosts, width, height]);

  const hostSummary = hosts.length === 0
    ? "No hosts"
    : `${hosts.length} host${hosts.length !== 1 ? "s" : ""} connected to gateway ${gateway}`;

  return (
    <svg
      ref={svgRef}
      viewBox={`0 0 ${width} ${height}`}
      className="w-full h-auto"
      style={{ maxHeight: height }}
      role="img"
      aria-label={`Network topology map: ${hostSummary}`}
    >
      <title>Network topology map: {hostSummary}</title>
    </svg>
  );
}

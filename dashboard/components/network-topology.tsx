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

    const simulation = forceSimulation<TopologyNode>(nodes)
      .force("link", forceLink<TopologyNode, TopologyLink>(links).id((d) => d.id).distance(100))
      .force("charge", forceManyBody().strength(-200))
      .force("center", forceCenter(width / 2, height / 2))
      .force("collide", forceCollide(30));

    simulationRef.current = simulation;

    const svg = svgRef.current;

    simulation.on("tick", () => {
      while (svg.firstChild) svg.removeChild(svg.firstChild);

      for (const link of links) {
        const source = link.source as unknown as TopologyNode;
        const target = link.target as unknown as TopologyNode;
        const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
        line.setAttribute("x1", String(source.x ?? 0));
        line.setAttribute("y1", String(source.y ?? 0));
        line.setAttribute("x2", String(target.x ?? 0));
        line.setAttribute("y2", String(target.y ?? 0));
        line.setAttribute("stroke", "#333");
        line.setAttribute("stroke-width", "1");
        svg.appendChild(line);
      }

      for (const node of nodes) {
        const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
        const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
        circle.setAttribute("cx", String(node.x ?? 0));
        circle.setAttribute("cy", String(node.y ?? 0));
        circle.setAttribute("r", node.isGateway ? "20" : "14");
        circle.setAttribute("fill", "#1a1a2a");
        circle.setAttribute("stroke", nodeColor(node));
        circle.setAttribute("stroke-width", node.isGateway ? "2.5" : "1.5");
        g.appendChild(circle);

        const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
        text.setAttribute("x", String(node.x ?? 0));
        text.setAttribute("y", String((node.y ?? 0) + 4));
        text.setAttribute("text-anchor", "middle");
        text.setAttribute("fill", node.isGateway ? "#cca700" : "#ccc");
        text.setAttribute("font-size", "9");
        text.setAttribute("font-family", "monospace");
        text.textContent = node.isGateway ? node.id : `.${node.label}`;
        g.appendChild(text);

        if (node.vendor) {
          const vendor = document.createElementNS("http://www.w3.org/2000/svg", "text");
          vendor.setAttribute("x", String(node.x ?? 0));
          vendor.setAttribute("y", String((node.y ?? 0) + 28));
          vendor.setAttribute("text-anchor", "middle");
          vendor.setAttribute("fill", "#555");
          vendor.setAttribute("font-size", "8");
          vendor.setAttribute("font-family", "monospace");
          vendor.textContent = node.vendor;
          g.appendChild(vendor);
        }

        svg.appendChild(g);
      }
    });

    return () => { simulation.stop(); };
  }, [gateway, hosts, width, height]);

  return (
    <svg ref={svgRef} viewBox={`0 0 ${width} ${height}`} className="w-full h-auto" style={{ maxHeight: height }} />
  );
}

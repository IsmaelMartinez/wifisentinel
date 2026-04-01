"use client";

import { BarChart, Bar, XAxis, YAxis, Tooltip, Cell, ResponsiveContainer } from "recharts";

interface ChannelInfo {
  channel: number;
  saturationScore: number;
  networkCount: number;
  overlapCount: number;
}

function barColor(score: number, isCurrent: boolean): string {
  if (isCurrent) return "#3b82f6"; // blue for current
  if (score <= 30) return "#22c55e";
  if (score <= 60) return "#eab308";
  return "#ef4444";
}

export function ChannelChart({
  channels,
  currentChannel,
}: {
  channels: ChannelInfo[];
  currentChannel: number;
}) {
  const data = channels.map((ch) => ({
    name: `Ch ${ch.channel}`,
    saturation: ch.saturationScore,
    networks: ch.networkCount,
    overlap: ch.overlapCount,
    isCurrent: ch.channel === currentChannel,
  }));

  return (
    <ResponsiveContainer width="100%" height={250}>
      <BarChart data={data}>
        <XAxis dataKey="name" tick={{ fontSize: 11, fill: "#a1a1aa" }} />
        <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: "#a1a1aa" }} />
        <Tooltip
          contentStyle={{ backgroundColor: "#18181b", border: "1px solid #27272a", borderRadius: "8px" }}
          labelStyle={{ color: "#fafafa" }}
          formatter={(value: number | undefined, _name: string, props: any) => {
            const item = props.payload;
            return [`${value ?? 0}% (${item.networks} direct, ${item.overlap} overlap)`, "Saturation"];
          }}
        />
        <Bar dataKey="saturation" radius={[4, 4, 0, 0]}>
          {data.map((entry, index) => (
            <Cell key={index} fill={barColor(entry.saturation, entry.isCurrent)} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

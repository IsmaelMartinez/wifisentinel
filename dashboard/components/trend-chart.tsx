// dashboard/components/trend-chart.tsx
"use client";

import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";

interface DataPoint {
  date: string;
  value: number;
}

export function TrendChart({
  data,
  color = "#3b82f6",
  yDomain,
  unit = "",
}: {
  data: DataPoint[];
  color?: string;
  yDomain?: [number, number];
  unit?: string;
}) {
  return (
    <ResponsiveContainer width="100%" height={200}>
      <LineChart data={data}>
        <XAxis
          dataKey="date"
          tick={{ fontSize: 11, fill: "#a1a1aa" }}
          tickFormatter={(v) => {
            const d = new Date(v);
            return `${d.getDate()}/${d.getMonth() + 1}`;
          }}
        />
        <YAxis
          domain={yDomain ?? ["auto", "auto"]}
          tick={{ fontSize: 11, fill: "#a1a1aa" }}
        />
        <Tooltip
          contentStyle={{ backgroundColor: "#18181b", border: "1px solid #27272a", borderRadius: "8px" }}
          labelStyle={{ color: "#fafafa" }}
          labelFormatter={(v) => new Date(v).toLocaleString()}
          formatter={(value) => [`${value}${unit}`, ""]}
        />
        <Line type="monotone" dataKey="value" stroke={color} strokeWidth={2} dot={{ r: 3 }} />
      </LineChart>
    </ResponsiveContainer>
  );
}

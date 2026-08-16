import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

const traffic = [
  { name: "Mon", requests: 18200, blocked: 920 },
  { name: "Tue", requests: 22400, blocked: 1100 },
  { name: "Wed", requests: 19800, blocked: 870 },
  { name: "Thu", requests: 26400, blocked: 1420 },
  { name: "Fri", requests: 31200, blocked: 1640 },
  { name: "Sat", requests: 27600, blocked: 1180 },
  { name: "Sun", requests: 35400, blocked: 1910 },
];

export function TrafficChart() {
  return (
    <ResponsiveContainer width="100%" height={300}>
      <AreaChart data={traffic} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
        <defs>
          <linearGradient id="requests-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="var(--primary)" stopOpacity={0.28} />
            <stop offset="95%" stopColor="var(--primary)" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="blocked-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#ef4444" stopOpacity={0.18} />
            <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
        <XAxis dataKey="name" stroke="var(--muted-foreground)" fontSize={12} tickLine={false} axisLine={false} />
        <YAxis stroke="var(--muted-foreground)" fontSize={12} tickLine={false} axisLine={false} tickFormatter={(value) => `${Math.round(value / 1000)}k`} />
        <Tooltip
          contentStyle={{ background: "var(--popover)", border: "1px solid var(--border)", borderRadius: "8px", color: "var(--popover-foreground)" }}
          labelStyle={{ color: "var(--muted-foreground)" }}
          formatter={(value, name) => [Number(value).toLocaleString(), name === "requests" ? "Requests" : "Blocked"]}
        />
        <Area type="monotone" dataKey="requests" stroke="var(--primary)" fill="url(#requests-fill)" strokeWidth={2} />
        <Area type="monotone" dataKey="blocked" stroke="#ef4444" fill="url(#blocked-fill)" strokeWidth={2} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

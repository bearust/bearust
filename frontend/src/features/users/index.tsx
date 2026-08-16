import { useState } from "react";
import { toast } from "sonner";
import { Ellipsis, MailPlus, Search, ShieldCheck, UserRound, Users as UsersIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Main } from "@/components/layout/main";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";

type Member = { id: number; name: string; email: string; role: string; lastActive: string; status: "healthy" | "warning" };
const initialMembers: Member[] = [
  { id: 1, name: "Rizalord", email: "admin@bearust.local", role: "Administrator", lastActive: "Just now", status: "healthy" },
  { id: 2, name: "Maya Chen", email: "maya@bearust.local", role: "Operator", lastActive: "12 min ago", status: "healthy" },
  { id: 3, name: "Dimas Pratama", email: "dimas@bearust.local", role: "Viewer", lastActive: "2 hours ago", status: "healthy" },
  { id: 4, name: "Staging bot", email: "staging@bearust.local", role: "Operator", lastActive: "Yesterday", status: "warning" },
];

export function Users() {
  const [members, setMembers] = useState(initialMembers);
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState("");
  const visible = members.filter((member) => `${member.name} ${member.email} ${member.role}`.toLowerCase().includes(query.toLowerCase()));
  const invite = (event: React.FormEvent) => {
    event.preventDefault();
    if (!email) return;
    const name = email.split("@")[0].replace(/[._-]/g, " ");
    setMembers((current) => [...current, { id: Date.now(), name, email, role: "Viewer", lastActive: "Invitation pending", status: "warning" }]);
    setEmail("");
    setOpen(false);
    toast.success("Invitation created", { description: `${email} will receive a dummy invite.` });
  };
  return <Main><PageHeader title="Users & Roles" description="Manage who can operate your BeaRust control plane." action={<Button onClick={() => setOpen(true)}><MailPlus />Invite user</Button>} /><div className="mb-6 grid gap-4 sm:grid-cols-3"><Summary icon={UsersIcon} label="Team members" value={String(members.length)} detail="Across 3 roles" /><Summary icon={ShieldCheck} label="Administrators" value="1" detail="Full control" /><Summary icon={UserRound} label="Pending invites" value={String(members.filter((member) => member.status === "warning").length)} detail="Awaiting acceptance" /></div><Card><CardHeader className="gap-4 sm:flex-row sm:items-center sm:justify-between"><div><CardTitle>Team members</CardTitle><CardDescription>Role changes are frontend-only for now.</CardDescription></div><div className="relative w-full sm:w-64"><Search className="absolute left-2.5 top-2.5 size-4 text-muted-foreground" /><Input aria-label="Search users" placeholder="Search members..." value={query} onChange={(event) => setQuery(event.target.value)} className="h-9 pl-8" /></div></CardHeader><CardContent><Table><TableHeader><TableRow><TableHead>Member</TableHead><TableHead>Role</TableHead><TableHead>Last active</TableHead><TableHead>Status</TableHead><TableHead className="w-10"><span className="sr-only">Actions</span></TableHead></TableRow></TableHeader><TableBody>{visible.map((member) => <TableRow key={member.id}><TableCell><div className="font-medium">{member.name}</div><div className="text-xs text-muted-foreground">{member.email}</div></TableCell><TableCell><Badge variant="secondary">{member.role}</Badge></TableCell><TableCell className="text-sm text-muted-foreground">{member.lastActive}</TableCell><TableCell><StatusBadge status={member.status}>{member.status === "healthy" ? "Active" : "Pending"}</StatusBadge></TableCell><TableCell><DropdownMenu><DropdownMenuTrigger asChild><Button variant="ghost" size="icon" aria-label={`Actions for ${member.name}`}><Ellipsis /></Button></DropdownMenuTrigger><DropdownMenuContent align="end"><DropdownMenuItem onClick={() => toast.info("Role editor opened")}>Edit role</DropdownMenuItem><DropdownMenuItem onClick={() => toast.info("Session revocation queued")}>Revoke sessions</DropdownMenuItem></DropdownMenuContent></DropdownMenu></TableCell></TableRow>)}</TableBody></Table></CardContent></Card><Dialog open={open} onOpenChange={setOpen}><DialogContent><DialogHeader><DialogTitle>Invite a team member</DialogTitle><DialogDescription>Invite a teammate to this dummy control plane.</DialogDescription></DialogHeader><form id="invite-user-form" className="space-y-4" onSubmit={invite}><div className="space-y-2"><Label htmlFor="invite-email">Email address</Label><Input id="invite-email" type="email" placeholder="operator@example.com" value={email} onChange={(event) => setEmail(event.target.value)} required /></div><div className="space-y-2"><Label htmlFor="invite-role">Initial role</Label><select id="invite-role" className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"><option>Viewer</option><option>Operator</option><option>Administrator</option></select></div></form><DialogFooter><Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" form="invite-user-form">Send invite</Button></DialogFooter></DialogContent></Dialog></Main>;
}

function Summary({ icon: Icon, label, value, detail }: { icon: typeof UsersIcon; label: string; value: string; detail: string }) {
  return <Card><CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2"><CardTitle className="text-sm font-medium text-muted-foreground">{label}</CardTitle><Icon className="size-4 text-muted-foreground" /></CardHeader><CardContent><div className="text-2xl font-bold tabular-nums">{value}</div><p className="text-xs text-muted-foreground">{detail}</p></CardContent></Card>;
}

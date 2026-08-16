import { toast } from "sonner";
import { Bell, LockKeyhole, Palette, Save, UserRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Main } from "@/components/layout/main";
import { PageHeader } from "@/components/page-header";

export function Settings() {
  return <Main><PageHeader title="Settings" description="Configure your local BeaRust workspace." /><Tabs defaultValue="profile" className="space-y-6"><TabsList><TabsTrigger value="profile"><UserRound />Profile</TabsTrigger><TabsTrigger value="appearance"><Palette />Appearance</TabsTrigger><TabsTrigger value="notifications"><Bell />Notifications</TabsTrigger><TabsTrigger value="security"><LockKeyhole />Security</TabsTrigger></TabsList><TabsContent value="profile"><Card><CardHeader><CardTitle>Profile</CardTitle><CardDescription>Update the identity shown in this prototype.</CardDescription></CardHeader><CardContent className="max-w-xl space-y-4"><div className="space-y-2"><Label htmlFor="profile-name">Display name</Label><Input id="profile-name" defaultValue="Rizalord" /></div><div className="space-y-2"><Label htmlFor="profile-email">Email</Label><Input id="profile-email" type="email" defaultValue="admin@bearust.local" /></div><Button onClick={() => toast.success("Profile saved locally")}><Save />Save changes</Button></CardContent></Card></TabsContent><TabsContent value="appearance"><Card><CardHeader><CardTitle>Appearance</CardTitle><CardDescription>Use the account menu or toolbar control to switch theme and language.</CardDescription></CardHeader><CardContent><div className="rounded-lg border bg-muted/30 p-6 text-sm text-muted-foreground">Theme preferences are stored locally in this browser.</div></CardContent></Card></TabsContent><TabsContent value="notifications"><Card><CardHeader><CardTitle>Notifications</CardTitle><CardDescription>Choose which operational events appear in your workspace.</CardDescription></CardHeader><CardContent className="space-y-3"><Preference label="Security events" /><Preference label="Certificate renewals" /><Preference label="Cluster health" /></CardContent></Card></TabsContent><TabsContent value="security"><Card><CardHeader><CardTitle>Security preferences</CardTitle><CardDescription>Dummy controls for the frontend-first phase.</CardDescription></CardHeader><CardContent><Button variant="outline" onClick={() => toast.info("Passkey enrollment is not connected yet")}><LockKeyhole />Enroll a passkey</Button></CardContent></Card></TabsContent></Tabs></Main>;
}

function Preference({ label }: { label: string }) {
  return <label className="flex items-center justify-between rounded-lg border p-4 text-sm"><span>{label}</span><input type="checkbox" defaultChecked className="size-4 accent-primary" /></label>;
}

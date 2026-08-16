import { useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { Bell, LogOut, Settings, UserRound } from "lucide-react";
import { api } from "@/api";
import { DEMO_MODE } from "@/lib/demo";
import { useAuthStore } from "@/stores/auth-store";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

export function ProfileDropdown() {
  const user = useAuthStore((state) => state.user);
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  if (!user) return null;
  const initials = user.email.slice(0, 2).toUpperCase();

  const signOut = () => {
    const finish = () => {
      useAuthStore.getState().reset();
      queryClient.removeQueries({ queryKey: ["me"] });
      void navigate({ to: "/login" });
    };
    if (DEMO_MODE) return finish();
    void api.logout().catch(() => undefined).finally(finish);
  };

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" className="relative h-8 w-8 rounded-full p-0" aria-label="Open account menu">
          <Avatar className="h-8 w-8">
            <AvatarFallback className="bg-primary text-primary-foreground">{initials}</AvatarFallback>
          </Avatar>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent className="w-60" align="end" forceMount>
        <DropdownMenuLabel className="font-normal">
          <div className="flex flex-col gap-1.5">
            <p className="text-sm leading-none font-medium">{user.email.split("@")[0]}</p>
            <p className="text-xs leading-none text-muted-foreground">{user.email}</p>
          </div>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem onClick={() => void navigate({ to: "/users" })}>
          <UserRound />
          Account
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => void navigate({ to: "/audit-log" })}>
          <Bell />
          Activity log
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => void navigate({ to: "/settings" })}>
          <Settings />
          Settings
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem variant="destructive" onClick={signOut}>
          <LogOut />
          Sign out
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

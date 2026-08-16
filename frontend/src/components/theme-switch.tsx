import { Check, Moon, Sun } from "lucide-react";
import { cn } from "@/lib/utils";
import { useTheme, type ThemeMode } from "@/theme";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

export function ThemeSwitch() {
  const { mode, resolved, setMode } = useTheme();
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" className="relative rounded-full" aria-label="Change theme">
          <Sun className={cn("size-[1.15rem] transition-all", resolved === "dark" && "scale-0 rotate-90")} />
          <Moon className={cn("absolute size-[1.15rem] transition-all", resolved !== "dark" && "scale-0 -rotate-90")} />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        {(["light", "dark", "system"] as ThemeMode[]).map((value) => (
          <DropdownMenuItem key={value} onClick={() => setMode(value)}>
            {value[0].toUpperCase() + value.slice(1)}
            <Check size={14} className={cn("ms-auto", mode !== value && "invisible")} />
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

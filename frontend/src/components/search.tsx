import { SearchIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";

export function Search({ className = "", placeholder = "Search anything" }: { className?: string; placeholder?: string }) {
  const openCommand = () => window.dispatchEvent(new Event("bearust:open-command"));
  return (
    <Button
      type="button"
      variant="outline"
      className={cn(
        "group relative h-8 w-full flex-1 justify-start rounded-md bg-muted/25 text-sm font-normal text-muted-foreground shadow-none hover:bg-accent sm:w-40 sm:pe-12 md:flex-none lg:w-52 xl:w-64",
        className,
      )}
      aria-keyshortcuts="Meta+K Control+K"
      onClick={openCommand}
    >
      <SearchIcon aria-hidden="true" className="absolute inset-s-1.5 top-1/2 -translate-y-1/2" size={16} />
      <span className="ms-4">{placeholder}</span>
      <kbd className="pointer-events-none absolute inset-e-[0.3rem] top-[0.3rem] hidden h-5 items-center gap-1 rounded border bg-muted px-1.5 font-mono text-[10px] font-medium sm:flex">
        <span className="text-xs">⌘</span>K
      </kbd>
    </Button>
  );
}

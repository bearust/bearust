import { useEffect, useState } from "react";
import { cn } from "@/lib/utils";
import { Separator } from "@/components/ui/separator";
import { SidebarTrigger } from "@/components/ui/sidebar";

type HeaderProps = React.HTMLAttributes<HTMLElement> & {
  fixed?: boolean;
};

export function Header({ className, fixed, children, ...props }: HeaderProps) {
  const [offset, setOffset] = useState(0);

  useEffect(() => {
    const onScroll = () => setOffset(document.documentElement.scrollTop);
    document.addEventListener("scroll", onScroll, { passive: true });
    return () => document.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <header
      className={cn(
        "z-50 h-16",
        fixed && "sticky top-0 w-full",
        fixed && offset > 10 && "border-b bg-background/95 shadow-sm backdrop-blur supports-[backdrop-filter]:bg-background/70",
        className,
      )}
      {...props}
    >
      <div className="relative flex h-full items-center gap-3 px-4 sm:gap-4">
        <SidebarTrigger variant="outline" className="max-md:scale-110" />
        <Separator orientation="vertical" className="h-6" />
        {children}
      </div>
    </header>
  );
}

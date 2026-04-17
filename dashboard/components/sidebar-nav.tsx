// dashboard/components/sidebar-nav.tsx
"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { LayoutDashboard, History, TrendingUp, Shield, Menu, X } from "lucide-react";
import { cn } from "@/lib/utils";

const navItems = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/scans", label: "History", icon: History },
  { href: "/trends", label: "Trends", icon: TrendingUp },
];

export function SidebarNav() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);

  // Close sidebar on route change (mobile)
  useEffect(() => {
    setOpen(false);
  }, [pathname]);

  // Close on escape key
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, []);

  return (
    <>
      {/* Mobile top bar */}
      <div className="fixed top-0 left-0 right-0 z-20 flex h-14 items-center gap-2 border-b border-border bg-card px-4 md:hidden">
        <button
          onClick={() => setOpen(!open)}
          className="rounded-md p-1.5 text-muted-foreground hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          aria-label={open ? "Close menu" : "Open menu"}
        >
          {open ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </button>
        <Shield className="h-5 w-5 text-primary" aria-hidden="true" />
        <span className="font-semibold">WiFi Sentinel</span>
      </div>

      {/* Backdrop overlay for mobile */}
      {open && (
        <div
          className="fixed inset-0 z-20 bg-black/50 md:hidden"
          onClick={() => setOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Sidebar */}
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-30 flex w-56 flex-col border-r border-border bg-card transition-transform duration-200 ease-in-out",
          "md:translate-x-0",
          open ? "translate-x-0" : "-translate-x-full",
        )}
        role="complementary"
      >
        <div className="flex h-14 items-center gap-2 border-b border-border px-4">
          <Shield className="h-5 w-5 text-primary" aria-hidden="true" />
          <span className="font-semibold">WiFi Sentinel</span>
          <button
            onClick={() => setOpen(false)}
            className="ml-auto rounded-md p-1 text-muted-foreground hover:bg-accent md:hidden"
            aria-label="Close menu"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <nav className="flex-1 space-y-1 p-2" aria-label="Main navigation">
          {navItems.map((item) => {
            const isActive = item.href === "/"
              ? pathname === "/"
              : pathname.startsWith(item.href);
            return (
              <Link
                key={item.href}
                href={item.href}
                aria-current={isActive ? "page" : undefined}
                className={cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
                  isActive
                    ? "bg-accent text-accent-foreground"
                    : "text-muted-foreground hover:bg-accent hover:text-accent-foreground",
                )}
              >
                <item.icon className="h-4 w-4" aria-hidden="true" />
                {item.label}
              </Link>
            );
          })}
        </nav>
      </aside>
    </>
  );
}

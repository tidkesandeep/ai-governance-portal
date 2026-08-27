"use client";

import type { ReactNode } from "react";
import Link from "next/link";
import { useEffect, useState } from "react";
import { api, getToken, setToken } from "@/lib/api";
import type { Principal } from "@/lib/types";

export function Shell({ children }: { children: ReactNode }) {
  const [token, setTokenState] = useState("demo");
  const [me, setMe] = useState<Principal | null>(null);

  useEffect(() => {
    setTokenState(getToken());
  }, []);

  useEffect(() => {
    api
      .me()
      .then(setMe)
      .catch(() => setMe(null));
  }, [token]);

  return (
    <div className="min-h-screen">
      <div className="mx-auto grid min-h-screen max-w-7xl grid-cols-1 lg:grid-cols-[240px_1fr]">
        <aside className="border-b border-rule bg-navy text-paper lg:border-b-0 lg:border-r">
          <div className="px-6 py-8">
            <p className="font-mono text-[11px] uppercase tracking-[0.22em] text-brass">Control plane</p>
            <Link href="/" className="mt-2 block font-serif text-3xl leading-none">
              Aigov
            </Link>
            <p className="mt-3 max-w-[16rem] text-sm text-paper/70">
              Canonical estate, explainable risk, fail-closed deployment gates.
            </p>
          </div>
          <nav className="space-y-1 px-3 pb-8 font-mono text-sm">
            <Link className="block rounded-sm px-3 py-2 text-paper/90 hover:bg-white/5" href="/">
              Inventory
            </Link>
            <Link className="block rounded-sm px-3 py-2 text-paper/90 hover:bg-white/5" href="/systems/new">
              Register system
            </Link>
          </nav>
        </aside>
        <div className="flex min-h-screen flex-col">
          <header className="flex items-center justify-between border-b border-rule px-6 py-4">
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-navy/60">
              Slice 8 · OIDC identity
            </p>
            <div className="flex items-center gap-4">
              {me ? (
                <p className="hidden font-mono text-[11px] text-navy/60 sm:block">
                  {me.displayName} · {me.tenantId} · {me.authMethod}
                </p>
              ) : null}
              <label className="flex items-center gap-2 font-mono text-xs">
                Acting as
                <select
                  className="border border-rule bg-panel px-2 py-1"
                  value={token}
                  onChange={(event) => {
                    setToken(event.target.value);
                    setTokenState(event.target.value);
                  }}
                >
                  <option value="demo">Engineer (demo)</option>
                  <option value="demo-reviewer">Reviewer (privacy/security/risk)</option>
                </select>
              </label>
            </div>
          </header>
          <main className="flex-1 px-6 py-8">{children}</main>
        </div>
      </div>
    </div>
  );
}

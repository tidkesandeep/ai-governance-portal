"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { bandClass } from "@/lib/style";
import type { AISystem } from "@/lib/types";

export default function InventoryPage() {
  const [items, setItems] = useState<AISystem[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .list()
      .then((payload) => setItems(payload.items))
      .catch((err) => setError(err.message));
  }, []);

  return (
    <div>
      <div className="flex items-end justify-between gap-4">
        <div>
          <h1 className="font-serif text-4xl">AI estate</h1>
          <p className="mt-2 max-w-2xl text-navy/70">
            Systems of record for predictive models, GenAI apps, and agents. Risk and
            authorization live behind this inventory, not inside it.
          </p>
        </div>
        <Link
          href="/systems/new"
          className="border border-ink bg-ink px-4 py-2 font-mono text-xs uppercase tracking-wider text-paper"
        >
          Register system
        </Link>
      </div>
      {error ? <p className="mt-6 text-carmine">{error}</p> : null}
      <div className="mt-8 overflow-hidden border border-rule bg-panel">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-rule font-mono text-[11px] uppercase tracking-wider text-navy/60">
            <tr>
              <th className="px-4 py-3">System</th>
              <th className="px-4 py-3">Type</th>
              <th className="px-4 py-3">Lifecycle</th>
              <th className="px-4 py-3">Risk</th>
              <th className="px-4 py-3">Environment</th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 ? (
              <tr>
                <td className="px-4 py-8 text-navy/60" colSpan={5}>
                  No governed assets yet. Register the fraud-risk sample to exercise the gate.
                </td>
              </tr>
            ) : (
              items.map((item) => (
                <tr key={item.id} className="border-t border-rule/80 hover:bg-paper/80">
                  <td className="px-4 py-3">
                    <Link href={`/systems/${item.id}`} className="font-medium underline-offset-2 hover:underline">
                      {item.name}
                    </Link>
                    <div className="font-mono text-[11px] text-navy/50">{item.urn}</div>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs">{item.systemType}</td>
                  <td className="px-4 py-3 font-mono text-xs">{item.status}</td>
                  <td className="px-4 py-3">
                    <span className={`border px-2 py-0.5 font-mono text-[11px] ${bandClass(item.riskBand)}`}>
                      {item.riskBand ?? "—"}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs">{item.environment}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

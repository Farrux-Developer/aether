"use client";

// app/aether/page.tsx
//
// Live demo of the auth vertical. The SRP math runs IN THE BROWSER (lib/auth/srp.ts is
// isomorphic Web Crypto), so the password never leaves this tab — only {salt, verifier} at
// registration and {A, M1} at login ever hit the network. Watch the log: no password, no
// hash of the password, is ever transmitted.

import { useState } from "react";
import { register, SrpClient } from "@/lib/auth/srp";

export default function AetherDemo() {
  const [I, setI] = useState("alice@aether.app");
  const [P, setP] = useState("correct horse battery staple");
  const [log, setLog] = useState<string[]>([]);
  const add = (line: string) => setLog((l) => [...l, line]);

  async function doRegister() {
    add(`▶ register(${I}) — computing verifier locally…`);
    const cred = await register(I, P);
    add(`  client computed salt=${cred.salt.slice(0, 12)}… verifier=${cred.verifier.slice(0, 16)}…`);
    const res = await fetch("/api/auth/srp/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(cred), // note: NO password in this body
    });
    add(res.ok ? "  ✓ server stored verifier (never saw the password)" : `  ✗ ${res.status}`);
  }

  async function doLogin() {
    add(`▶ login(${I}) — SRP-6a handshake`);
    const client = new SrpClient();
    const A = await client.start();
    add(`  → sending A=${A.slice(0, 16)}…`);
    const ch = await fetch("/api/auth/srp/challenge", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ I, A }),
    });
    if (!ch.ok) return add(`  ✗ challenge ${ch.status}`);
    const { handshakeId, salt, B } = await ch.json();
    add(`  ← got B=${B.slice(0, 16)}… salt=${salt.slice(0, 12)}…`);
    const { M1, K } = await client.process(I, P, salt, B);
    add(`  → sending proof M1=${M1.slice(0, 16)}… (derived session key K locally)`);
    const vr = await fetch("/api/auth/srp/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ handshakeId, M1 }),
    });
    if (!vr.ok) return add(`  ✗ verify ${vr.status} — authentication failed`);
    const { M2 } = await vr.json();
    const serverProven = await client.verifyServer(M2, M1, K);
    add(serverProven ? "  ✓ mutual auth OK — server proved it knows the verifier (M2 verified)" : "  ✗ server proof M2 invalid — possible MITM");
    add("  ✓ HttpOnly Ed25519 session cookie set; edge proxy will validate it");
  }

  async function callSecure() {
    add("▶ GET /api/secure/whoami (validated at edge by proxy.ts)");
    const res = await fetch("/api/secure/whoami");
    const body = await res.json();
    add(`  ${res.ok ? "✓" : "✗"} ${res.status} — ${JSON.stringify(body)}`);
  }

  async function runSelftest() {
    add("▶ GET /api/selftest — running all algorithm cores…");
    const res = await fetch("/api/selftest");
    const r = await res.json();
    add(`  ${r.ok ? "✓" : "✗"} ${r.passed}/${r.total} checks passed in ${r.elapsedMs}ms`);
    for (const c of r.checks) add(`    ${c.pass ? "✓" : "✗"} ${c.name} — ${c.detail}`);
  }

  return (
    <main className="mx-auto max-w-3xl p-8 font-mono text-sm">
      <h1 className="mb-1 text-2xl font-semibold">Aether — Auth Vertical</h1>
      <p className="mb-6 text-zinc-500">
        SRP-6a zero-knowledge login · Ed25519 sessions · JA3-bound · edge-validated
      </p>

      <div className="mb-4 flex flex-col gap-2">
        <input className="rounded border border-zinc-300 px-3 py-2 dark:border-zinc-700 dark:bg-zinc-900" value={I} onChange={(e) => setI(e.target.value)} placeholder="identity" />
        <input className="rounded border border-zinc-300 px-3 py-2 dark:border-zinc-700 dark:bg-zinc-900" value={P} onChange={(e) => setP(e.target.value)} placeholder="password" type="password" />
      </div>

      <div className="mb-6 flex flex-wrap gap-2">
        <button onClick={doRegister} className="rounded-full bg-black px-4 py-2 text-white dark:bg-white dark:text-black">1 · Register</button>
        <button onClick={doLogin} className="rounded-full bg-black px-4 py-2 text-white dark:bg-white dark:text-black">2 · Login (SRP)</button>
        <button onClick={callSecure} className="rounded-full border border-black px-4 py-2 dark:border-white">3 · Call protected</button>
        <button onClick={runSelftest} className="rounded-full border border-black px-4 py-2 dark:border-white">Run self-test</button>
        <button onClick={() => setLog([])} className="rounded-full px-4 py-2 text-zinc-500">clear</button>
      </div>

      <pre className="min-h-64 overflow-auto rounded-lg bg-zinc-950 p-4 text-xs leading-5 text-green-400">
        {log.length ? log.join("\n") : "// log output appears here"}
      </pre>
    </main>
  );
}

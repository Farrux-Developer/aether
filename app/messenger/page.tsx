"use client";

// app/messenger/page.tsx
//
// Aether messenger — SRP login, global presence, GLOBAL + PRIVATE (DM) chat, and
// browser-to-browser WebRTC audio/video calls with a proper ringing / accept-decline flow.
// Open in two browsers, log in as different users, and call/DM between them. Media is P2P;
// only signaling passes through the server (SSE down / POST up), authed by the session cookie.

import { useCallback, useEffect, useRef, useState } from "react";
import { CallManager, type SignalType } from "@/lib/rtc/call";

interface ChatMsg {
  from: string;
  text: string;
  ts: number;
}
interface DMEvent extends ChatMsg {
  to: string;
}
interface RemoteTile {
  peer: string;
  stream: MediaStream;
}

const GLOBAL = "\u{1F310} Global";

export default function Messenger() {
  const [me, setMe] = useState("");
  const [password, setPassword] = useState("");
  const [phase, setPhase] = useState<"auth" | "connecting" | "online">("auth");
  const [error, setError] = useState("");
  const [online, setOnline] = useState<string[]>([]);

  const [selected, setSelected] = useState<string>(GLOBAL); // GLOBAL or a peer id
  const [globalMsgs, setGlobalMsgs] = useState<ChatMsg[]>([]);
  const [dmMsgs, setDmMsgs] = useState<Record<string, ChatMsg[]>>({});
  const [unread, setUnread] = useState<Record<string, number>>({});
  const [draft, setDraft] = useState("");

  const [remotes, setRemotes] = useState<RemoteTile[]>([]);
  const [localStream, setLocalStream] = useState<MediaStream | null>(null);
  const [muted, setMuted] = useState(false);
  const [incoming, setIncoming] = useState<string | null>(null); // peer ringing us
  const [outgoing, setOutgoing] = useState<string | null>(null); // peer we're calling

  const callRef = useRef<CallManager | null>(null);
  const esRef = useRef<EventSource | null>(null);
  const meRef = useRef("");
  const selectedRef = useRef(GLOBAL); // mirror of `selected` for use inside SSE listeners
  const scrollRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    selectedRef.current = selected;
  }, [selected]);

  // Switch conversation and clear its unread badge.
  function openConversation(key: string) {
    setSelected(key);
    setUnread((u) => (u[key] ? { ...u, [key]: 0 } : u));
  }

  const postSend = useCallback((body: unknown) => {
    void fetch("/api/rtc/send", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  }, []);

  // --- open sign-in: any username, any (or no) password gets in ---
  async function join() {
    setError("");
    setPhase("connecting");
    try {
      const res = await fetch("/api/auth/open", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: me }),
      });
      if (!res.ok) {
        setPhase("auth");
        return setError("could not sign in");
      }
      const { sub } = await res.json();
      meRef.current = sub; // server may assign a guest name if left blank
      if (sub !== me) setMe(sub);
      await startRealtime();
    } catch (e) {
      setPhase("auth");
      setError(`error: ${(e as Error).message}`);
    }
  }

  async function startRealtime() {
    const mgr = new CallManager(
      (s) => postSend({ kind: "signal", ...s }),
      (peer, stream) => {
        setRemotes((r) => [...r.filter((t) => t.peer !== peer), { peer, stream }]);
        setOutgoing((o) => (o === peer ? null : o)); // connected → stop "ringing"
      },
      (peer) => {
        setRemotes((r) => r.filter((t) => t.peer !== peer));
        setOutgoing((o) => (o === peer ? null : o));
        setIncoming((i) => (i === peer ? null : i));
      },
      (stream) => setLocalStream(stream),
      (peer) => setIncoming(peer), // ring
    );
    callRef.current = mgr;

    // Ephemeral TURN from our own coturn, if configured; else OpenRelay fallback is used.
    try {
      const t = await fetch("/api/rtc/turn").then((r) => r.json());
      if (t.enabled) mgr.setIceServers([{ urls: t.urls, username: t.username, credential: t.credential }]);
    } catch {
      /* fallback ICE already baked in */
    }

    const es = new EventSource("/api/rtc/stream");
    esRef.current = es;
    es.addEventListener("presence", (e) => {
      setOnline(JSON.parse((e as MessageEvent).data).users as string[]);
      setPhase("online");
    });
    es.addEventListener("history", (e) => {
      // Backlog replay on (re)connect so reloads and late joiners see past messages.
      const { global, dms } = JSON.parse((e as MessageEvent).data) as {
        global: ChatMsg[];
        dms: Record<string, ChatMsg[]>;
      };
      setGlobalMsgs(global);
      setDmMsgs(dms);
    });
    es.addEventListener("chat", (e) => {
      setGlobalMsgs((m) => [...m, JSON.parse((e as MessageEvent).data) as ChatMsg]);
      if (selectedRef.current !== GLOBAL) setUnread((u) => ({ ...u, [GLOBAL]: (u[GLOBAL] ?? 0) + 1 }));
    });
    es.addEventListener("dm", (e) => {
      const msg = JSON.parse((e as MessageEvent).data) as DMEvent;
      const peer = msg.from === meRef.current ? msg.to : msg.from; // conversation key = other party
      setDmMsgs((prev) => ({ ...prev, [peer]: [...(prev[peer] ?? []), msg] }));
      // Badge only for messages we received (not our own echo) in a non-active thread.
      if (msg.from !== meRef.current && selectedRef.current !== peer) {
        setUnread((u) => ({ ...u, [peer]: (u[peer] ?? 0) + 1 }));
      }
    });
    es.addEventListener("signal", (e) => {
      const { from, type, data } = JSON.parse((e as MessageEvent).data) as {
        from: string;
        type: SignalType;
        data: unknown;
      };
      void mgr.onSignal(from, type, data);
    });
    es.onerror = () => setError("realtime connection dropped — are you still logged in?");
  }

  function sendMessage() {
    if (!draft.trim()) return;
    if (selected === GLOBAL) postSend({ kind: "chat", text: draft });
    else postSend({ kind: "dm", to: selected, text: draft });
    setDraft("");
  }

  async function startCall(peer: string, video: boolean) {
    setError("");
    setOutgoing(peer);
    try {
      await callRef.current?.call(peer, video);
    } catch (e) {
      setOutgoing(null);
      setError(`could not start call: ${(e as Error).message} (mic/cam permission?)`);
    }
  }

  async function acceptCall(video: boolean) {
    if (!incoming) return;
    const peer = incoming;
    setIncoming(null);
    try {
      await callRef.current?.accept(peer, video);
    } catch (e) {
      setError(`could not accept: ${(e as Error).message}`);
    }
  }

  function declineCall() {
    if (incoming) callRef.current?.decline(incoming);
    setIncoming(null);
  }

  useEffect(() => {
    return () => {
      esRef.current?.close();
      callRef.current?.destroy();
    };
  }, []);

  const shownMsgs = selected === GLOBAL ? globalMsgs : dmMsgs[selected] ?? [];

  // Auto-scroll to the newest message whenever the active thread updates.
  useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [globalMsgs, dmMsgs, selected]);

  // --- auth screen ---
  if (phase !== "online") {
    return (
      <main className="mx-auto flex min-h-full max-w-sm flex-col justify-center gap-3 p-8">
        <h1 className="text-2xl font-semibold">Aether</h1>
        <p className="text-sm text-zinc-500">presence · DM · P2P audio/video · open sign-in</p>
        <input className="rounded border border-zinc-300 px-3 py-2 dark:border-zinc-700 dark:bg-zinc-900" placeholder="username (any name)" value={me} onChange={(e) => setMe(e.target.value)} onKeyDown={(e) => e.key === "Enter" && join()} />
        <input className="rounded border border-zinc-300 px-3 py-2 dark:border-zinc-700 dark:bg-zinc-900" placeholder="password (optional)" type="password" value={password} onChange={(e) => setPassword(e.target.value)} onKeyDown={(e) => e.key === "Enter" && join()} />
        <button onClick={join} disabled={phase === "connecting"} className="rounded-full bg-black px-4 py-2 text-white disabled:opacity-50 dark:bg-white dark:text-black">
          {phase === "connecting" ? "connecting…" : "Join"}
        </button>
        {error && <p className="text-sm text-red-500">{error}</p>}
        <p className="text-xs text-zinc-400">Any name gets you in (blank = guest). Open a second browser to call/DM.</p>
      </main>
    );
  }

  // --- app ---
  return (
    <main className="relative mx-auto grid max-w-5xl grid-cols-1 gap-4 p-4 md:grid-cols-[240px_1fr]">
      {/* Incoming-call modal */}
      {incoming && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="w-72 rounded-xl bg-white p-6 text-center shadow-xl dark:bg-zinc-900">
            <div className="mb-1 text-lg font-semibold">Incoming call</div>
            <div className="mb-4 text-zinc-500">{incoming} is calling…</div>
            <div className="flex justify-center gap-2">
              <button onClick={() => acceptCall(false)} className="rounded-full bg-green-600 px-4 py-2 text-sm text-white">Accept 📞</button>
              <button onClick={() => acceptCall(true)} className="rounded-full bg-green-700 px-4 py-2 text-sm text-white">Video 🎥</button>
              <button onClick={declineCall} className="rounded-full bg-red-600 px-4 py-2 text-sm text-white">Decline</button>
            </div>
          </div>
        </div>
      )}

      {/* Sidebar: conversations + presence */}
      <aside className="rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
        <div className="mb-2 text-xs uppercase tracking-wide text-zinc-500">Online · {online.length}</div>
        <button
          onClick={() => openConversation(GLOBAL)}
          className={`mb-1 flex w-full items-center justify-between rounded px-2 py-1 text-left text-sm ${selected === GLOBAL ? "bg-blue-100 dark:bg-blue-950" : "hover:bg-zinc-100 dark:hover:bg-zinc-900"}`}
        >
          <span>{GLOBAL}</span>
          {unread[GLOBAL] ? <span className="rounded-full bg-red-500 px-1.5 text-xs text-white">{unread[GLOBAL]}</span> : null}
        </button>
        <ul className="flex flex-col gap-1">
          {online.map((u) => {
            const isMe = u === meRef.current;
            return (
              <li key={u} className={`flex items-center justify-between gap-1 rounded px-2 py-1 text-sm ${selected === u ? "bg-blue-100 dark:bg-blue-950" : "hover:bg-zinc-100 dark:hover:bg-zinc-900"}`}>
                <button className="flex min-w-0 flex-1 items-center gap-1 truncate text-left" onClick={() => !isMe && openConversation(u)} title={isMe ? "you" : `message ${u}`}>
                  <span className="inline-block h-2 w-2 shrink-0 rounded-full bg-green-500" />
                  <span className="truncate">{isMe ? `${u} (you)` : u}</span>
                  {!isMe && unread[u] ? <span className="rounded-full bg-red-500 px-1.5 text-xs text-white">{unread[u]}</span> : null}
                </button>
                {!isMe && (
                  <span className="flex shrink-0 gap-1">
                    <button title="audio call" onClick={() => startCall(u, false)} className="rounded px-1 hover:bg-zinc-200 dark:hover:bg-zinc-800">📞</button>
                    <button title="video call" onClick={() => startCall(u, true)} className="rounded px-1 hover:bg-zinc-200 dark:hover:bg-zinc-800">🎥</button>
                  </span>
                )}
              </li>
            );
          })}
        </ul>
      </aside>

      {/* Main: calls + chat */}
      <section className="flex flex-col gap-4">
        {outgoing && (
          <div className="flex items-center justify-between rounded-lg border border-amber-300 bg-amber-50 px-3 py-2 text-sm dark:border-amber-800 dark:bg-amber-950">
            <span>Calling {outgoing}… ringing</span>
            <button onClick={() => { callRef.current?.hangup(outgoing); setOutgoing(null); }} className="rounded-full border border-red-400 px-2 py-0.5 text-xs text-red-500">cancel</button>
          </div>
        )}

        {(remotes.length > 0 || localStream) && (
          <div className="rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
            <div className="mb-2 flex items-center gap-2 text-sm">
              <span className="font-medium">Call</span>
              <button onClick={() => setMuted(callRef.current?.toggleMute() ?? false)} className="rounded-full border px-2 py-0.5 text-xs dark:border-zinc-700">{muted ? "unmute" : "mute"}</button>
              <button onClick={() => { callRef.current?.activePeers().forEach((p) => callRef.current?.hangup(p)); setRemotes([]); }} className="rounded-full border border-red-400 px-2 py-0.5 text-xs text-red-500">hang up all</button>
            </div>
            <div className="flex flex-wrap gap-3">
              {localStream && <VideoTile stream={localStream} label="you" muted />}
              {remotes.map((t) => <VideoTile key={t.peer} stream={t.stream} label={t.peer} />)}
            </div>
          </div>
        )}

        <div className="flex min-h-[320px] flex-1 flex-col rounded-lg border border-zinc-200 dark:border-zinc-800">
          <div className="border-b border-zinc-200 px-3 py-2 text-sm font-medium dark:border-zinc-800">
            {selected === GLOBAL ? GLOBAL : `Direct message · ${selected}`}
          </div>
          <div ref={scrollRef} className="flex-1 space-y-1 overflow-auto p-3 text-sm">
            {shownMsgs.length === 0 && <p className="text-zinc-400">{selected === GLOBAL ? "Global chat — say hi 👋" : `No messages with ${selected} yet.`}</p>}
            {shownMsgs.map((m, i) => (
              <div key={i}>
                <span className={m.from === meRef.current ? "font-semibold text-blue-500" : "font-semibold"}>{m.from}</span>
                <span className="text-zinc-400">: </span>
                <span>{m.text}</span>
                <span className="ml-1 text-[10px] text-zinc-400">{fmt(m.ts)}</span>
              </div>
            ))}
          </div>
          <div className="flex gap-2 border-t border-zinc-200 p-2 dark:border-zinc-800">
            <input className="flex-1 rounded border border-zinc-300 px-3 py-2 text-sm dark:border-zinc-700 dark:bg-zinc-900" placeholder={selected === GLOBAL ? "message everyone…" : `message ${selected}…`} value={draft} onChange={(e) => setDraft(e.target.value)} onKeyDown={(e) => e.key === "Enter" && sendMessage()} />
            <button onClick={sendMessage} className="rounded-full bg-black px-4 text-sm text-white dark:bg-white dark:text-black">Send</button>
          </div>
        </div>
        {error && <p className="text-sm text-red-500">{error}</p>}
      </section>
    </main>
  );
}

function fmt(ts: number): string {
  return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function VideoTile({ stream, label, muted }: { stream: MediaStream; label: string; muted?: boolean }) {
  const ref = useRef<HTMLVideoElement | null>(null);
  useEffect(() => {
    if (ref.current) ref.current.srcObject = stream;
  }, [stream]);
  return (
    <div className="flex flex-col items-center">
      <video ref={ref} autoPlay playsInline muted={muted} className="h-40 w-56 rounded-lg bg-zinc-900 object-cover" />
      <span className="mt-1 text-xs text-zinc-500">{label}</span>
    </div>
  );
}

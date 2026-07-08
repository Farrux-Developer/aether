// lib/signaling/relay.ts
//
// Signaling relay core: routes SDP offers/answers and trickled ICE candidates between
// peers that may be connected to DIFFERENT edge PoPs, via a pub/sub bus (Redis Pub/Sub in
// prod). Transport-agnostic: the bus is injected, so this is unit-testable with an
// in-memory bus and driven by Redis in services/signaling-node.ts.
//
// SDP/ICE are tiny control-plane metadata (codecs, DTLS fingerprints, candidate tuples) —
// they never carry media. Media rides the separate SRTP/UDP plane through the SFU/TURN.

export type SignalType = "offer" | "answer" | "candidate" | "bye";

export interface SignalMessage {
  from: string;
  to: string;
  type: SignalType;
  data: unknown; // SDP string, or an ICE candidate init
  seq: number; // per-sender monotonic; lets the peer order trickled candidates
}

// The pub/sub abstraction. In prod: `publish` -> Redis PUBLISH, `subscribe` -> a dedicated
// Redis SUBSCRIBE connection (Redis requires a separate conn for subscriber mode).
export interface Bus {
  publish(channel: string, payload: string): Promise<void>;
  subscribe(channel: string, handler: (payload: string) => void): Promise<void>;
  unsubscribe(channel: string): Promise<void>;
}

const channelFor = (userId: string) => `sig:${userId}`;

export class SignalingRelay {
  // Local sockets attached to THIS edge node: userId -> send fn.
  private local = new Map<string, (msg: SignalMessage) => void>();

  constructor(private readonly bus: Bus) {}

  // A client connects to this PoP. We subscribe to its channel so a message published by a
  // peer on another continent is delivered here (via Redis geo-replication) and forwarded
  // down the local socket. O(1) per delivered message.
  async attach(userId: string, send: (msg: SignalMessage) => void): Promise<void> {
    this.local.set(userId, send);
    await this.bus.subscribe(channelFor(userId), (payload) => {
      const msg = JSON.parse(payload) as SignalMessage;
      this.local.get(msg.to)?.(msg);
    });
  }

  async detach(userId: string): Promise<void> {
    this.local.delete(userId);
    await this.bus.unsubscribe(channelFor(userId));
  }

  // Relay a message toward its recipient. Fast path: recipient is on this same node → hand
  // off locally with zero bus hop. Otherwise publish to the recipient's channel.
  async relay(msg: SignalMessage): Promise<void> {
    const localSend = this.local.get(msg.to);
    if (localSend) {
      localSend(msg);
      return;
    }
    await this.bus.publish(channelFor(msg.to), JSON.stringify(msg));
  }
}

// --- Trickle ICE helpers ---
// TTFF budget is dominated by ICE. Vanilla ICE waits to gather ALL candidates before
// sending the offer (+1–3 s). Trickle ICE (RFC 8838) sends the offer immediately with zero
// candidates and streams each candidate as it's found, so connectivity checks run in
// parallel with gathering. Below: candidate priority so we attempt DIRECT paths first and
// fall back to a TURN relay only for symmetric NAT (where STUN cannot predict the port).

export type CandidateType = "host" | "srflx" | "prflx" | "relay";

// RFC 8445 §5.1.2 priority = (2^24)*typePref + (2^8)*localPref + (2^0)*(256 - component).
// host(126) > srflx(100) > relay(0): try LAN, then STUN-reflexive, then TURN last.
export function candidatePriority(
  type: CandidateType,
  localPref = 65535,
  component = 1,
): number {
  const typePref: Record<CandidateType, number> = {
    host: 126,
    prflx: 110,
    srflx: 100,
    relay: 0,
  };
  return (typePref[type] << 24) + (localPref << 8) + (256 - component);
}

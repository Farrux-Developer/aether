// lib/rtc/call.ts
//
// Browser-side WebRTC call manager (imported only by the client page). One
// RTCPeerConnection per remote peer, Trickle ICE, signaling forwarded through the injected
// `send` (POSTs to /api/rtc/send). Media is true peer-to-peer; the server only ferries
// SDP/ICE.
//
// Incoming calls are NOT auto-answered: an inbound offer raises onIncomingCall(peer); the
// UI shows a ringing prompt and only accept() sends an answer. ICE candidates that arrive
// before the user accepts are buffered per-peer and drained once the remote description is
// set (otherwise they'd be dropped and the call could fail to connect).

export type SignalType = "offer" | "answer" | "candidate" | "bye";
export interface OutSignal {
  to: string;
  type: SignalType;
  data: unknown;
}

// STUN + public TURN fallback (OpenRelay) so calls connect even behind symmetric NAT /
// UDP-blocking firewalls out of the box. Production TURN (your coturn) is appended at
// runtime from /api/rtc/turn via setIceServers().
const BASE_ICE: RTCIceServer[] = [
  { urls: "stun:stun.l.google.com:19302" },
  { urls: "stun:global.stun.twilio.com:3478" },
  { urls: "turn:openrelay.metered.ca:80", username: "openrelayproject", credential: "openrelayproject" },
  { urls: "turn:openrelay.metered.ca:443", username: "openrelayproject", credential: "openrelayproject" },
  { urls: "turn:openrelay.metered.ca:443?transport=tcp", username: "openrelayproject", credential: "openrelayproject" },
];

export class CallManager {
  private pcs = new Map<string, RTCPeerConnection>();
  private pendingOffers = new Map<string, RTCSessionDescriptionInit>();
  private pendingCandidates = new Map<string, RTCIceCandidateInit[]>();
  private extraIce: RTCIceServer[] = [];
  localStream: MediaStream | null = null;

  constructor(
    private readonly send: (s: OutSignal) => void,
    private readonly onRemoteStream: (peer: string, stream: MediaStream) => void,
    private readonly onCallEnd: (peer: string) => void,
    private readonly onLocalStream: (stream: MediaStream) => void,
    private readonly onIncomingCall: (peer: string) => void,
  ) {}

  // Append TURN creds fetched from the server (ephemeral, from lib/signaling/turn.ts).
  setIceServers(extra: RTCIceServer[]): void {
    this.extraIce = extra;
  }

  async ensureMedia(video: boolean): Promise<MediaStream> {
    if (this.localStream) {
      if (video && this.localStream.getVideoTracks().length === 0) {
        const cam = await navigator.mediaDevices.getUserMedia({ video: true });
        for (const t of cam.getVideoTracks()) {
          this.localStream.addTrack(t);
          for (const pc of this.pcs.values()) pc.addTrack(t, this.localStream);
        }
        this.onLocalStream(this.localStream);
      }
      return this.localStream;
    }
    this.localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video });
    this.onLocalStream(this.localStream);
    return this.localStream;
  }

  private getPC(peer: string): RTCPeerConnection {
    const existing = this.pcs.get(peer);
    if (existing) return existing;

    const pc = new RTCPeerConnection({ iceServers: [...BASE_ICE, ...this.extraIce] });
    this.pcs.set(peer, pc);

    for (const track of this.localStream?.getTracks() ?? []) {
      pc.addTrack(track, this.localStream!);
    }
    // Trickle ICE: emit each candidate as found; checks run in parallel with gathering.
    pc.onicecandidate = (e) => {
      if (e.candidate) this.send({ to: peer, type: "candidate", data: e.candidate.toJSON() });
    };
    pc.ontrack = (e) => {
      const stream = e.streams[0] ?? new MediaStream([e.track]);
      this.onRemoteStream(peer, stream);
    };
    pc.onconnectionstatechange = () => {
      if (["failed", "closed", "disconnected"].includes(pc.connectionState)) this.cleanup(peer);
    };
    return pc;
  }

  // Caller: capture media, create + send the offer.
  async call(peer: string, video: boolean): Promise<void> {
    await this.ensureMedia(video);
    const pc = this.getPC(peer);
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    this.send({ to: peer, type: "offer", data: pc.localDescription });
  }

  // Callee accepts a ringing call: build the answer now.
  async accept(peer: string, video = false): Promise<void> {
    const offer = this.pendingOffers.get(peer);
    if (!offer) return;
    await this.ensureMedia(video); // audio at minimum; caller's video still arrives via ontrack
    const pc = this.getPC(peer);
    await pc.setRemoteDescription(offer);
    // Drain ICE candidates that arrived while the call was ringing.
    for (const c of this.pendingCandidates.get(peer) ?? []) {
      try {
        await pc.addIceCandidate(c);
      } catch {
        /* ignore late/duplicate candidate */
      }
    }
    this.pendingCandidates.delete(peer);
    this.pendingOffers.delete(peer);
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    this.send({ to: peer, type: "answer", data: pc.localDescription });
  }

  // Callee rejects a ringing call.
  decline(peer: string): void {
    this.pendingOffers.delete(peer);
    this.pendingCandidates.delete(peer);
    this.send({ to: peer, type: "bye", data: null });
    this.onCallEnd(peer);
  }

  async onSignal(from: string, type: SignalType, data: unknown): Promise<void> {
    switch (type) {
      case "bye":
        this.cleanup(from);
        return;
      case "offer":
        // Ring — do NOT answer automatically.
        this.pendingOffers.set(from, data as RTCSessionDescriptionInit);
        this.onIncomingCall(from);
        return;
      case "answer": {
        const pc = this.pcs.get(from);
        if (pc) await pc.setRemoteDescription(data as RTCSessionDescriptionInit);
        return;
      }
      case "candidate": {
        const pc = this.pcs.get(from);
        if (pc) {
          try {
            await pc.addIceCandidate(data as RTCIceCandidateInit);
          } catch {
            /* candidate before remote desc; browser retries */
          }
        } else {
          // Ringing but not yet accepted → buffer until accept() sets the remote description.
          const buf = this.pendingCandidates.get(from) ?? [];
          buf.push(data as RTCIceCandidateInit);
          this.pendingCandidates.set(from, buf);
        }
        return;
      }
    }
  }

  hangup(peer: string): void {
    this.send({ to: peer, type: "bye", data: null });
    this.cleanup(peer);
  }

  private cleanup(peer: string): void {
    const pc = this.pcs.get(peer);
    if (pc) {
      pc.onicecandidate = null;
      pc.ontrack = null;
      pc.onconnectionstatechange = null;
      try {
        pc.close();
      } catch {
        /* ignore */
      }
      this.pcs.delete(peer);
    }
    this.pendingOffers.delete(peer);
    this.pendingCandidates.delete(peer);
    this.onCallEnd(peer);
  }

  toggleMute(): boolean {
    const track = this.localStream?.getAudioTracks()[0];
    if (!track) return false;
    track.enabled = !track.enabled;
    return !track.enabled; // true when now muted
  }

  activePeers(): string[] {
    return [...this.pcs.keys()];
  }

  destroy(): void {
    for (const peer of this.activePeers()) this.cleanup(peer);
    for (const t of this.localStream?.getTracks() ?? []) t.stop();
    this.localStream = null;
  }
}

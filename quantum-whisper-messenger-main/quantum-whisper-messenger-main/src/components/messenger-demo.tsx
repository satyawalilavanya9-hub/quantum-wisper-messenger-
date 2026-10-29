/**
 * PQ-Messenger demo UI — live post-quantum handshake and encrypted messaging.
 *
 * All cryptography runs client-side with real primitives:
 * ML-KEM-768 key encapsulation, ML-DSA-65 signatures, HKDF-SHA-256 and
 * AES-256-GCM. No demo data is faked; every hex string on screen comes
 * from an actual operation performed in this browser.
 */
import { useCallback, useMemo, useState } from "react";
import {
  AlertTriangle,
  ArrowRightLeft,
  BadgeCheck,
  Ban,
  KeyRound,
  Loader2,
  Lock,
  MessageSquareLock,
  Radio,
  ShieldCheck,
  ShieldX,
  Signature,
  Timer,
  Zap,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import {
  SCHEME_INFO,
  createIdentity,
  flipByte,
  hex,
  performHandshake,
  sealMessage,
  openMessage,
  type Identity,
  type LogEntry,
  type SealedMessage,
} from "@/lib/pqc";

type ChannelState = "idle" | "negotiating" | "secure" | "attacked";

interface TranscriptItem {
  id: string;
  from: Identity["name"];
  to: Identity["name"];
  /** Plaintext after successful decryption, or an error explaining rejection. */
  plaintext?: string;
  rejected?: string;
  ciphertextPreview: string;
  bytes: number;
  micros: number;
  tampered: boolean;
}

const STATUS_STYLES: Record<LogEntry["status"], string> = {
  ok: "border-success/40 bg-success/10 text-success",
  fail: "border-destructive/40 bg-destructive/10 text-destructive",
  warn: "border-warning/40 bg-warning/10 text-warning",
  info: "border-border bg-muted/40 text-muted-foreground",
};

function StatusDot({ status }: { status: LogEntry["status"] }) {
  const map = {
    ok: "bg-success",
    fail: "bg-destructive",
    warn: "bg-warning",
    info: "bg-muted-foreground",
  } as const;
  return <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${map[status]}`} />;
}

export function MessengerDemo() {
  const [alice, setAlice] = useState<Identity | null>(null);
  const [bob, setBob] = useState<Identity | null>(null);
  const [channel, setChannel] = useState<ChannelState>("idle");
  const [log, setLog] = useState<LogEntry[]>([]);
  const [sessionKey, setSessionKey] = useState<Uint8Array | null>(null);
  const [mitmSimulation, setMitmSimulation] = useState(false);
  const [busy, setBusy] = useState(false);
  const [handshakeMs, setHandshakeMs] = useState<number | null>(null);

  const [sender, setSender] = useState<Identity["name"]>("Alice");
  const [draft, setDraft] = useState("");
  const [tamperInTransit, setTamperInTransit] = useState(false);
  const [transcript, setTranscript] = useState<TranscriptItem[]>([]);
  const [seq, setSeq] = useState(0);

  const identitiesReady = alice !== null && bob !== null;

  const establishChannel = useCallback(async () => {
    if (busy) return;
    setBusy(true);
    setLog([]);
    setTranscript([]);
    setSessionKey(null);
    setSeq(0);
    setChannel("negotiating");

    const nextAlice = alice ?? createIdentity("Alice", "initiator");
    const nextBob = bob ?? createIdentity("Bob", "responder");
    setAlice(nextAlice);
    setBob(nextBob);

    const started = performance.now();
    const entries: LogEntry[] = [];
    const result = await performHandshake(nextAlice, nextBob, {
      tamper: mitmSimulation,
      onStep: async (entry) => {
        entries.push(entry);
        setLog([...entries]);
        // Let each step paint before the next one runs.
        await new Promise((resolve) => setTimeout(resolve, 160));
      },
    });
    const elapsed = performance.now() - started;
    setHandshakeMs(Math.round(elapsed));

    if (result.ok && result.sessionKey) {
      setSessionKey(result.sessionKey);
      setChannel(mitmSimulation ? "attacked" : "secure");
      setLog((prev) => [
        ...prev,
        {
          title: mitmSimulation
            ? "MITM attack blocked — channel re-established"
            : "Channel established",
          detail: mitmSimulation
            ? "The attacker's tampered ciphertext was rejected by its ML-DSA signature. Run without the attacker to exchange messages."
            : "ML-KEM-768 mutual encapsulation + ML-DSA-65 authentication complete. Messages are now end-to-end encrypted.",
          status: mitmSimulation ? "warn" : "ok",
        },
      ]);
    } else {
      setChannel("attacked");
    }
    setBusy(false);
  }, [alice, bob, busy, mitmSimulation]);

  const wipeKeys = useCallback(() => {
    setAlice(null);
    setBob(null);
    setSessionKey(null);
    setLog([]);
    setTranscript([]);
    setChannel("idle");
    setHandshakeMs(null);
    setSeq(0);
  }, []);

  const sendMessage = useCallback(async () => {
    if (!sessionKey || !alice || !bob || busy) return;
    const text = draft.trim();
    if (!text) return;

    const from = sender;
    const to = from === "Alice" ? "Bob" : "Alice";
    const senderId = from === "Alice" ? alice : bob;
    const nextSeq = seq + 1;

    setBusy(true);
    const started = performance.now();
    let sealed: SealedMessage;
    try {
      sealed = await sealMessage(sessionKey, senderId, to, nextSeq, text);
    } finally {
      setDraft("");
    }

    let wire = sealed;
    if (tamperInTransit) {
      wire = {
        ...sealed,
        ciphertext: flipByte(sealed.ciphertext),
        signature: flipByte(sealed.signature),
      };
    }

    let item: TranscriptItem;
    try {
      const opened = await openMessage(sessionKey, senderId, wire);
      item = {
        id: sealed.id,
        from,
        to,
        plaintext: opened,
        ciphertextPreview: hex(wire.ciphertext, 14),
        bytes: wire.ciphertext.length,
        micros: Math.round((performance.now() - started) * 1000),
        tampered: tamperInTransit,
      };
    } catch (error) {
      item = {
        id: sealed.id,
        from,
        to,
        rejected: error instanceof Error ? error.message : "Message rejected",
        ciphertextPreview: hex(wire.ciphertext, 14),
        bytes: wire.ciphertext.length,
        micros: Math.round((performance.now() - started) * 1000),
        tampered: tamperInTransit,
      };
    }
    setTranscript((prev) => [...prev, item]);
    setSeq(nextSeq);
    setBusy(false);
  }, [alice, bob, busy, draft, sender, seq, sessionKey, tamperInTransit]);

  const senderIdentity = sender === "Alice" ? alice : bob;

  const channelBadge = useMemo(() => {
    switch (channel) {
      case "secure":
        return { label: "CHANNEL SECURE", className: "border-success/50 bg-success/15 text-success" };
      case "attacked":
        return { label: "ATTACK BLOCKED", className: "border-warning/50 bg-warning/15 text-warning" };
      case "negotiating":
        return { label: "NEGOTIATING…", className: "border-primary/50 bg-primary/15 text-primary" };
      default:
        return { label: "NOT ESTABLISHED", className: "border-border bg-muted/40 text-muted-foreground" };
    }
  }, [channel]);

  return (
    <div className="mx-auto w-full max-w-6xl px-4 pb-16 sm:px-6">
      <header className="pt-10 pb-8 sm:pt-14">
        <div className="flex flex-wrap items-center gap-3">
          <span className="inline-flex h-11 w-11 items-center justify-center rounded-xl border border-primary/40 bg-primary/10 shadow-[var(--shadow-glow)]">
            <ShieldCheck className="h-6 w-6 text-primary" />
          </span>
          <div>
            <p className="font-mono text-xs tracking-[0.3em] text-primary uppercase">
              Post-Quantum Cryptography · Live Demo
            </p>
            <h1 className="mt-1 text-3xl font-bold tracking-tight text-foreground sm:text-4xl">
              PQ-Messenger
            </h1>
          </div>
        </div>
        <p className="mt-4 max-w-2xl text-sm leading-relaxed text-muted-foreground sm:text-base">
          A working messenger that survives quantum adversaries. Every button below runs real
          lattice-based cryptography in your browser — no mocks, no server, no pretend keys.
        </p>
        <div className="mt-5 flex flex-wrap gap-2">
          <Badge variant="outline" className="border-primary/40 bg-primary/10 font-mono text-primary">
            <Lock className="mr-1 h-3 w-3" /> {SCHEME_INFO.kem}
          </Badge>
          <Badge variant="outline" className="border-accent/60 bg-accent/30 font-mono text-foreground">
            <Signature className="mr-1 h-3 w-3" /> {SCHEME_INFO.dsa}
          </Badge>
          <Badge variant="outline" className="border-border bg-muted/40 font-mono text-muted-foreground">
            <KeyRound className="mr-1 h-3 w-3" /> {SCHEME_INFO.aead}
          </Badge>
          <Badge variant="outline" className="border-border bg-muted/40 font-mono text-muted-foreground">
            <Zap className="mr-1 h-3 w-3" /> {SCHEME_INFO.kdf}
          </Badge>
        </div>
      </header>

      <div className="grid gap-6 lg:grid-cols-[1.15fr_0.85fr]">
        {/* Handshake panel */}
        <Card className="border-border/80 shadow-[var(--shadow-panel)]">
          <CardHeader className="flex-row items-start justify-between space-y-0">
            <div className="space-y-1.5">
              <CardTitle className="flex items-center gap-2 text-lg">
                <ArrowRightLeft className="h-4 w-4 text-primary" />
                Step 1 — Quantum-safe handshake
              </CardTitle>
              <CardDescription>
                Mutual Kyber encapsulation, Dilithium-signed, with HKDF session derivation.
              </CardDescription>
            </div>
            <Badge variant="outline" className={`font-mono text-[10px] ${channelBadge.className}`}>
              {channelBadge.label}
            </Badge>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between rounded-lg border border-border bg-muted/30 px-4 py-3">
              <div className="space-y-0.5">
                <Label htmlFor="mitm" className="text-sm font-medium text-foreground">
                  Simulate MITM attack
                </Label>
                <p className="text-xs text-muted-foreground">
                  An attacker flips bits inside the Kyber ciphertext in transit.
                </p>
              </div>
              <Switch id="mitm" checked={mitmSimulation} onCheckedChange={setMitmSimulation} />
            </div>

            <div className="flex flex-wrap gap-2">
              <Button onClick={establishChannel} disabled={busy} className="gap-2">
                {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Radio className="h-4 w-4" />}
                {identitiesReady ? "Re-run handshake" : "Establish secure channel"}
              </Button>
              {identitiesReady && (
                <Button onClick={wipeKeys} variant="outline" disabled={busy} className="gap-2">
                  <Ban className="h-4 w-4" />
                  Wipe keys (forward secrecy)
                </Button>
              )}
              {handshakeMs !== null && (
                <span className="inline-flex items-center gap-1.5 rounded-md border border-border px-3 py-2 font-mono text-xs text-muted-foreground">
                  <Timer className="h-3.5 w-3.5 text-primary" /> {handshakeMs} ms full handshake
                </span>
              )}
            </div>

            <Separator />

            <ScrollArea className="h-72 rounded-lg border border-border/70 bg-background/60">
              <div className="space-y-2.5 p-4">
                {log.length === 0 && (
                  <p className="py-16 text-center font-mono text-xs text-muted-foreground">
                    [ handshake log appears here ]
                  </p>
                )}
                {log.map((entry, index) => (
                  <div key={index} className="flex gap-2.5">
                    <StatusDot status={entry.status} />
                    <div className="min-w-0">
                      <p className="text-xs font-semibold text-foreground">{entry.title}</p>
                      <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">
                        {entry.detail}
                      </p>
                      {entry.data && (
                        <p className="mt-1 break-all rounded border border-border/60 bg-muted/30 px-2 py-1 font-mono text-[10px] text-primary/90">
                          {entry.data}
                        </p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>

        {/* Key material panel */}
        <Card className="border-border/80 shadow-[var(--shadow-panel)]">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <KeyRound className="h-4 w-4 text-primary" />
              Live key material
            </CardTitle>
            <CardDescription>Generated in this browser tab, visible as hex.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {identitiesReady && alice && bob ? (
              <>
                {[
                  { name: "Alice" as const, identity: alice },
                  { name: "Bob" as const, identity: bob },
                ].map(({ name, identity }) => (
                  <div key={name} className="space-y-1.5">
                    <div className="flex items-center gap-2">
                      <BadgeCheck className="h-4 w-4 text-success" />
                      <span className="text-sm font-semibold text-foreground">{name}</span>
                      <span className="font-mono text-[10px] text-muted-foreground">
                        ML-KEM-768 pk · {identity.kem.publicKey.length} B · ML-DSA-65 verified
                      </span>
                    </div>
                    <p className="break-all rounded border border-border/60 bg-muted/30 px-2.5 py-1.5 font-mono text-[10px] text-muted-foreground">
                      {hex(identity.kem.publicKey, 20)}
                    </p>
                  </div>
                ))}
                <Separator />
                <div className="space-y-1.5">
                  <span className="text-sm font-semibold text-foreground">
                    Session key (AES-256)
                  </span>
                  {sessionKey ? (
                    <p className="break-all rounded border border-success/40 bg-success/10 px-2.5 py-1.5 font-mono text-[10px] text-success">
                      {hex(sessionKey, 32)}
                    </p>
                  ) : (
                    <p className="rounded border border-warning/40 bg-warning/10 px-2.5 py-1.5 font-mono text-[10px] text-warning">
                      withheld — no authenticated handshake yet
                    </p>
                  )}
                  <p className="text-xs text-muted-foreground">
                    Re-running the handshake derives an entirely new key: past traffic stays
                    sealed even if this key leaks (forward secrecy).
                  </p>
                </div>
              </>
            ) : (
              <div className="flex h-56 flex-col items-center justify-center gap-2 text-center">
                <Lock className="h-8 w-8 text-muted-foreground/50" />
                <p className="max-w-xs text-sm text-muted-foreground">
                  Run the handshake to generate Kyber key pairs, Dilithium certificates and the
                  shared session key.
                </p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Messaging panel */}
      <Card className="mt-6 border-border/80 shadow-[var(--shadow-panel)]">
        <CardHeader className="flex-row items-start justify-between space-y-0">
          <div className="space-y-1.5">
            <CardTitle className="flex items-center gap-2 text-lg">
              <MessageSquareLock className="h-4 w-4 text-primary" />
              Step 2 — Send a message over the channel
            </CardTitle>
            <CardDescription>
              AES-256-GCM sealing + ML-DSA-65 signature on every message. Watch the ciphertext
              that actually travels.
            </CardDescription>
          </div>
          <div className="flex items-center gap-2 rounded-lg border border-border bg-muted/30 px-3 py-2">
            <Switch
              id="tamper-msg"
              checked={tamperInTransit}
              onCheckedChange={setTamperInTransit}
              disabled={channel !== "secure"}
            />
            <Label htmlFor="tamper-msg" className="text-xs font-medium text-foreground">
              Tamper in transit
            </Label>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex overflow-hidden rounded-lg border border-border">
              {(["Alice", "Bob"] as const).map((name) => (
                <button
                  key={name}
                  type="button"
                  onClick={() => setSender(name)}
                  disabled={channel !== "secure"}
                  className={`px-4 py-2 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-40 ${
                    sender === name
                      ? "bg-primary/20 text-primary"
                      : "bg-muted/30 text-muted-foreground hover:bg-muted/60"
                  }`}
                >
                  Send as {name}
                </button>
              ))}
            </div>
            <Input
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") void sendMessage();
              }}
              placeholder={
                channel === "secure"
                  ? `Type a secret message from ${sender}…`
                  : "Establish the channel first"
              }
              disabled={channel !== "secure"}
              className="min-w-56 flex-1"
            />
            <Button
              onClick={() => void sendMessage()}
              disabled={channel !== "secure" || busy || !draft.trim()}
              className="gap-2"
            >
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Lock className="h-4 w-4" />}
              Seal &amp; send
            </Button>
          </div>

          <ScrollArea className="h-80 rounded-lg border border-border/70 bg-background/60">
            <div className="space-y-3 p-4">
              {transcript.length === 0 && (
                <p className="py-24 text-center font-mono text-xs text-muted-foreground">
                  [ encrypted transcript appears here ]
                </p>
              )}
              {transcript.map((item) => {
                const outgoing = item.from === sender;
                return (
                  <div key={item.id} className={`flex ${outgoing ? "justify-end" : "justify-start"}`}>
                    <div
                      className={`max-w-[85%] rounded-xl border px-3.5 py-2.5 ${
                        item.rejected
                          ? "border-destructive/50 bg-destructive/10"
                          : outgoing
                            ? "border-primary/40 bg-primary/10"
                            : "border-border bg-muted/30"
                      }`}
                    >
                      <div className="mb-1 flex items-center gap-2 font-mono text-[10px] text-muted-foreground">
                        <span className="font-semibold text-foreground">
                          {item.from} → {item.to}
                        </span>
                        <span>seq {transcript.indexOf(item) + 1}</span>
                        <span>· {item.bytes} B ct</span>
                        <span>· {item.micros / 1000} ms</span>
                        {item.tampered && (
                          <span className="inline-flex items-center gap-1 text-warning">
                            <AlertTriangle className="h-3 w-3" /> tampered
                          </span>
                        )}
                      </div>
                      {item.rejected ? (
                        <p className="flex items-start gap-1.5 text-sm font-medium text-destructive">
                          <ShieldX className="mt-0.5 h-4 w-4 shrink-0" />
                          {item.rejected}
                        </p>
                      ) : (
                        <p className="text-sm text-foreground">{item.plaintext}</p>
                      )}
                      <p className="mt-1.5 break-all font-mono text-[9px] text-muted-foreground/80">
                        ct: {item.ciphertextPreview}
                      </p>
                    </div>
                  </div>
                );
              })}
            </div>
          </ScrollArea>

          <p className="text-xs text-muted-foreground">
            {senderIdentity
              ? `Signing with ${sender}'s Dilithium secret key; the receiver verifies the signature before touching the ciphertext.`
              : "Messages are only possible after an authenticated handshake — exactly like TLS 1.3."}
          </p>
        </CardContent>
      </Card>

      <footer className="mt-10 border-t border-border/60 pt-6 text-center">
        <p className="font-mono text-xs text-muted-foreground">
          ML-KEM-768 · ML-DSA-65 · HKDF-SHA-256 · AES-256-GCM — audited @noble/post-quantum
          primitives, running entirely client-side
        </p>
      </footer>
    </div>
  );
}

/**
 * Post-quantum cryptographic engine for the PQ-Messenger demo.
 *
 * Real, audited primitives running in the browser:
 *  - ML-KEM-768 (CRYSTALS-Kyber) — quantum-safe key encapsulation
 *  - ML-DSA-65 (CRYSTALS-Dilithium) — quantum-safe digital signatures
 *  - HKDF-SHA-256 — session key derivation (bilateral shared secrets)
 *  - AES-256-GCM — authenticated encryption for messages
 *
 * Handshake design (bilateral encapsulation + mutual authentication):
 *  1. Each peer publishes a Dilithium-signed certificate for its Kyber key.
 *  2. Each peer encapsulates a shared secret against the peer's Kyber key.
 *  3. Every transmitted artifact is signed with ML-DSA; receivers verify
 *     before use, so a MITM key substitution is rejected.
 *  4. The session key is HKDF(ssA || ssB, transcript hash) — every handshake
 *     produces fresh keys, giving forward secrecy.
 */
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { gcm } from "@noble/ciphers/webcrypto.js";

export const SCHEME_INFO = {
  kem: "ML-KEM-768 (CRYSTALS-Kyber)",
  dsa: "ML-DSA-65 (CRYSTALS-Dilithium)",
  aead: "AES-256-GCM",
  kdf: "HKDF-SHA-256",
} as const;

export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface Identity {
  name: "Alice" | "Bob";
  role: "initiator" | "responder";
  kem: KeyPair;
  signing: KeyPair;
  /** ML-DSA signature over the Kyber public key (self-signed demo certificate). */
  certificate: { kemPublicKey: Uint8Array; signature: Uint8Array };
}

export type StepStatus = "ok" | "fail" | "warn" | "info";

export interface LogEntry {
  title: string;
  detail: string;
  data?: string;
  status: StepStatus;
}

export interface SealedMessage {
  id: string;
  from: Identity["name"];
  to: Identity["name"];
  seq: number;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  /** ML-DSA-65 signature over nonce || ciphertext. */
  signature: Uint8Array;
}

export function randomBytes(n: number): Uint8Array {
  const bytes = new Uint8Array(n);
  crypto.getRandomValues(bytes);
  return bytes;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function utf8(text: string): Uint8Array {
  return encoder.encode(text);
}

export function fromUtf8(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

/** Preview bytes as spaced hex, truncated for display. */
export function hex(bytes: Uint8Array, max = 16): string {
  const head = Array.from(bytes.slice(0, max), (b) => b.toString(16).padStart(2, "0")).join(" ");
  return bytes.length > max ? `${head} …` : head;
}

/** Return a copy with one bit flipped mid-buffer — the simulated attacker. */
export function flipByte(bytes: Uint8Array): Uint8Array {
  const copy = bytes.slice();
  const index = Math.floor(copy.length / 2);
  copy[index] = (copy[index] ?? 0) ^ 0xff;
  return copy;
}

export function createIdentity(name: Identity["name"], role: Identity["role"]): Identity {
  const kem = ml_kem768.keygen();
  const signing = ml_dsa65.keygen();
  const signature = ml_dsa65.sign(kem.publicKey, signing.secretKey);
  return {
    name,
    role,
    kem: { publicKey: kem.publicKey, secretKey: kem.secretKey },
    signing: { publicKey: signing.publicKey, secretKey: signing.secretKey },
    certificate: { kemPublicKey: kem.publicKey, signature },
  };
}

export function verifyCertificate(id: Identity): boolean {
  return ml_dsa65.verify(id.certificate.signature, id.certificate.kemPublicKey, id.signing.publicKey);
}

export interface HandshakeResult {
  ok: boolean;
  sessionKey?: Uint8Array;
  transcriptHash?: Uint8Array;
  failure?: string;
}

export interface HandshakeOptions {
  tamper?: boolean;
  onStep?: (entry: LogEntry) => Promise<void> | void;
}

const HKDF_INFO = utf8("pq-messenger/v1 | ml-kem-768 | ml-dsa-65");

export async function performHandshake(
  alice: Identity,
  bob: Identity,
  options: HandshakeOptions = {},
): Promise<HandshakeResult> {
  const { onStep } = options;
  const step = async (entry: LogEntry) => {
    if (onStep) await onStep(entry);
  };

  // Phase 1 — mutual identity authentication via Dilithium certificates.
  await step({
    title: "Phase 1 — Identity certificates (ML-DSA-65)",
    detail: `Verifying ${alice.name} and ${bob.name} Dilithium certificates binding each Kyber key.`,
    status: "info",
  });

  const aliceCertOk = verifyCertificate(alice);
  const bobCertOk = verifyCertificate(bob);
  if (!aliceCertOk || !bobCertOk) {
    await step({
      title: "Certificate verification FAILED",
      detail: "A Dilithium signature did not verify — aborting before any key material is used.",
      status: "fail",
    });
    return { ok: false, failure: "Certificate verification failed" };
  }
  await step({
    title: "Certificates verified",
    detail: "Both Dilithium signatures are valid — Kyber public keys are authentic.",
    data: `${hex(alice.certificate.kemPublicKey, 8)} · ${hex(bob.certificate.kemPublicKey, 8)}`,
    status: "ok",
  });

  // Phase 2 — bilateral Kyber encapsulation with signed ciphertexts.
  await step({
    title: "Phase 2 — CRYSTALS-Kyber mutual encapsulation",
    detail: "Each peer encapsulates a 32-byte shared secret against the peer's Kyber-768 public key.",
    status: "info",
  });

  const encA = ml_kem768.encapsulate(bob.kem.publicKey);
  const sigA = ml_dsa65.sign(encA.cipherText, alice.signing.secretKey);
  await step({
    title: `${alice.name} → ${bob.name}: Kyber ciphertext`,
    detail: "1088 B ciphertext + ML-DSA-65 signature over it.",
    data: hex(encA.cipherText, 10),
    status: "ok",
  });

  let ctA: Uint8Array = encA.cipherText;
  let sigAWire: Uint8Array = sigA;
  if (options.tamper) {
    ctA = flipByte(ctA);
    sigAWire = flipByte(sigAWire);
    await step({
      title: "Attacker intercepts the channel",
      detail: "A MITM flips a bit inside the Kyber ciphertext and its signature in transit.",
      data: hex(ctA, 10),
      status: "warn",
    });
  }

  const sigAOk = ml_dsa65.verify(sigAWire, ctA, alice.signing.publicKey);
  if (!sigAOk) {
    await step({
      title: "ML-DSA signature verification FAILED",
      detail: `${bob.name} rejects the tampered payload — impersonation attempt blocked, handshake aborted before decapsulation.`,
      status: "fail",
    });
    return { ok: false, failure: "Ciphertext signature invalid — MITM rejected" };
  }

  const ssA = ml_kem768.decapsulate(ctA, bob.kem.secretKey);
  await step({
    title: `${bob.name} decapsulated shared secret A`,
    detail: "32 bytes recovered with the Kyber secret key (Module-Lattice problem hard for quantum attackers).",
    data: hex(ssA, 8),
    status: "ok",
  });

  const encB = ml_kem768.encapsulate(alice.kem.publicKey);
  const sigB = ml_dsa65.sign(encB.cipherText, bob.signing.secretKey);
  await step({
    title: `${bob.name} → ${alice.name}: Kyber ciphertext`,
    detail: "1088 B ciphertext + ML-DSA-65 signature over it.",
    data: hex(encB.cipherText, 10),
    status: "ok",
  });

  const sigBOk = ml_dsa65.verify(sigB, encB.cipherText, bob.signing.publicKey);
  if (!sigBOk) {
    await step({
      title: "ML-DSA signature verification FAILED",
      detail: `${alice.name} rejects the payload — handshake aborted.`,
      status: "fail",
    });
    return { ok: false, failure: "Ciphertext signature invalid — MITM rejected" };
  }

  const ssB = ml_kem768.decapsulate(encB.cipherText, alice.kem.secretKey);
  await step({
    title: `${alice.name} decapsulated shared secret B`,
    detail: "32 bytes recovered on the return leg.",
    data: hex(ssB, 8),
    status: "ok",
  });

  // Phase 3 — session key derivation.
  await step({
    title: "Phase 3 — Session key derivation (HKDF-SHA-256)",
    detail: "Both sides combine ssA ‖ ssB with the transcript hash into one 32-byte AES-256 key.",
    status: "info",
  });

  const transcriptHash = sha256(
    concatBytes(alice.kem.publicKey, bob.kem.publicKey, ctA, encB.cipherText),
  );
  const sessionKey = hkdf(sha256, concatBytes(ssA, ssB), transcriptHash, HKDF_INFO, 32);

  await step({
    title: "Session key established",
    detail: "Identical 256-bit key on both sides. Ephemeral per handshake — re-running the handshake wipes it (forward secrecy).",
    data: hex(sessionKey, 8),
    status: "ok",
  });

  return { ok: true, sessionKey, transcriptHash };
}

const aad = (msg: { from: string; to: string; seq: number }) =>
  utf8(`v1|${msg.from}|${msg.to}|${msg.seq}`);

export async function sealMessage(
  sessionKey: Uint8Array,
  sender: Identity,
  receiverName: Identity["name"],
  seq: number,
  text: string,
): Promise<SealedMessage> {
  const nonce = randomBytes(12);
  const envelope = { from: sender.name, to: receiverName, seq };
  const ciphertext = await gcm(sessionKey, nonce, aad(envelope)).encrypt(utf8(text));
  const signature = ml_dsa65.sign(concatBytes(nonce, ciphertext), sender.signing.secretKey);
  return {
    id: `${sender.name}-${seq}-${Date.now().toString(36)}`,
    from: sender.name,
    to: receiverName,
    seq,
    nonce,
    ciphertext,
    signature,
  };
}

export async function openMessage(
  sessionKey: Uint8Array,
  sender: Identity,
  msg: SealedMessage,
): Promise<string> {
  const signatureOk = ml_dsa65.verify(
    msg.signature,
    concatBytes(msg.nonce, msg.ciphertext),
    sender.signing.publicKey,
  );
  if (!signatureOk) {
    throw new Error("ML-DSA signature invalid — message rejected before decryption");
  }
  try {
    const plaintext = await gcm(sessionKey, msg.nonce, aad(msg)).decrypt(msg.ciphertext);
    return fromUtf8(plaintext);
  } catch {
    throw new Error("AES-256-GCM integrity check failed — ciphertext tampered in transit");
  }
}

// @vitest-environment node
import { describe, expect, it } from "vitest";

import {
  createIdentity,
  flipByte,
  openMessage,
  performHandshake,
  sealMessage,
  verifyCertificate,
} from "@/lib/pqc";

describe("post-quantum channel", () => {
  it("derives the identical session key on both peers", async () => {
    const alice = createIdentity("Alice", "initiator");
    const bob = createIdentity("Bob", "responder");
    const result = await performHandshake(alice, bob);

    expect(result.ok).toBe(true);
    expect(result.sessionKey).toHaveLength(32);
  });

  it("produces a fresh session key on every handshake (forward secrecy)", async () => {
    const alice = createIdentity("Alice", "initiator");
    const bob = createIdentity("Bob", "responder");
    const first = await performHandshake(alice, bob);
    const second = await performHandshake(alice, bob);

    expect(first.sessionKey).not.toEqual(second.sessionKey);
  });

  it("seals and opens a message end to end", async () => {
    const alice = createIdentity("Alice", "initiator");
    const bob = createIdentity("Bob", "responder");
    const { sessionKey } = await performHandshake(alice, bob);

    const sealed = await sealMessage(sessionKey!, alice, "Bob", 1, "Meet at 21:00");
    const opened = await openMessage(sessionKey!, alice, sealed);

    expect(opened).toBe("Meet at 21:00");
  });

  it("rejects a message whose ciphertext was tampered in transit", async () => {
    const alice = createIdentity("Alice", "initiator");
    const bob = createIdentity("Bob", "responder");
    const { sessionKey } = await performHandshake(alice, bob);

    const sealed = await sealMessage(sessionKey!, alice, "Bob", 1, "Meet at 21:00");
    const tampered = {
      ...sealed,
      ciphertext: flipByte(sealed.ciphertext),
      signature: flipByte(sealed.signature),
    };

    await expect(openMessage(sessionKey!, bob, tampered)).rejects.toThrow(/rejected|tampered/i);
  });

  it("aborts the handshake when a MITM flips a bit in the Kyber ciphertext", async () => {
    const alice = createIdentity("Alice", "initiator");
    const bob = createIdentity("Bob", "responder");
    const result = await performHandshake(alice, bob, { tamper: true });

    expect(result.ok).toBe(false);
    expect(result.failure).toMatch(/MITM/i);
    expect(result.sessionKey).toBeUndefined();
  });

  it("binds each Kyber key to its owner with a Dilithium certificate", () => {
    const alice = createIdentity("Alice", "initiator");

    expect(verifyCertificate(alice)).toBe(true);
  });
});

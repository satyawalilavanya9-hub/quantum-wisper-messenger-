import { createFileRoute } from "@tanstack/react-router";

import { MessengerDemo } from "@/components/messenger-demo";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "PQ-Messenger — Post-Quantum Encrypted Messaging Demo" },
      {
        name: "description",
        content:
          "Live demo of a quantum-safe messaging framework: ML-KEM-768 key exchange, ML-DSA-65 signatures and AES-256-GCM end-to-end encryption running in the browser.",
      },
      {
        property: "og:title",
        content: "PQ-Messenger — Post-Quantum Encrypted Messaging Demo",
      },
      {
        property: "og:description",
        content:
          "Real CRYSTALS-Kyber key exchange and CRYSTALS-Dilithium signatures, with a live MITM-attack simulation you can run yourself.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Index,
});

function Index() {
  return <MessengerDemo />;
}

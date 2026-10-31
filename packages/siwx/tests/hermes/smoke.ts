import { hexToBytes } from "@noble/curves/utils.js";

import { evm } from "../../src/evm/index.ts";
/** Format→parse→authenticate smoke for the IIFE bundle Hermes runs. */
import { authenticate, generateNonce } from "../../src/index.ts";
import { svm } from "../../src/svm/index.ts";

export async function main(): Promise<void> {
  if (generateNonce().length < 8) {
    throw new Error("nonce too short");
  }

  const em = evm();
  const evmText = em.format(
    em.parse(
      new TextEncoder().encode(
        "siwe.xyz wants you to sign in with your Ethereum account:\n0xAE9aA90F1a627c7a20783AF9e8747fCFEDEFAd03\n\nSign In with Ethereum Example Statement\n\nURI: https://siwe.xyz\nVersion: 1\nChain ID: 1\nNonce: bTyXgcQxn2htgkjJn\nIssued At: 2022-01-27T17:09:38.578Z\nExpiration Time: 2100-01-07T14:31:43.952Z",
      ),
    ),
  );
  await authenticate(em, {
    message: evmText,
    signature: hexToBytes(
      "7fcf011b4dff0a6024ce6cea93dcd0ebc4592f43e7685e174d4d3d4a1f942ed75bbf5358841924dc8e1b261f750dfec5dbcc0aad9a3d9439f1e5c4d59d7d98a81c",
    ),
    expect: {
      domain: "siwe.xyz",
      nonce: "bTyXgcQxn2htgkjJn",
      time: new Date("2022-02-01T00:00:00Z"),
    },
  });

  const sm = svm();
  const siwsText = sm.format(
    sm.parse(
      new TextEncoder().encode(
        "service.org wants you to sign in with your Solana account:\n9C6hybhQ6Aycep9jaUnP6uL9ZYvDjUp1aSkFWPUFJtpj\n\nURI: https://service.org/login\nVersion: 1\nChain ID: mainnet\nNonce: 12341234\nIssued At: 2022-03-17T12:45:13.610Z",
      ),
    ),
  );
  await authenticate(sm, {
    message: siwsText,
    signature: hexToBytes(
      "bd85b34f8391470472fb15c2e77cb91970093fb9abf9bd9c66eabf1bd56910784eb6f90cec67ce1300ccf13624c7c4d70d49878dcb29ab795dcb81604e49cf04",
    ),
    expect: {
      domain: "service.org",
      nonce: "12341234",
      time: new Date("2022-03-18T00:00:00Z"),
    },
  });
}

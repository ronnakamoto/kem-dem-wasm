import fs from 'fs';
import init, { ZkEncryptor } from '../../pkg/kem_dem_wasm.js';

async function run() {
  console.log("Initializing WASM...");
  // Initialize the WebAssembly binary
  const wasmBuffer = fs.readFileSync('../../pkg/kem_dem_wasm_bg.wasm');
  await init(wasmBuffer);
  console.log("WASM initialized successfully!");

  console.log("\n--- Testing ZK standard methods ---");
  // 1. Generate keypair
  const kp = ZkEncryptor.generateKeypair();
  console.log("Keypair generated:");
  console.log("  secretKey  :", kp.secretKey);
  console.log("  publicKey.x:", kp.publicKey.x);
  console.log("  publicKey.y:", kp.publicKey.y);

  // 2. Encrypt
  const payload = [
    "0x000000000000000000000000000000000000000000000000000000000000cafe",
    "0x000000000000000000000000000000000000000000000000000000000000beef"
  ];
  console.log("Payload:", payload);

  const ct = ZkEncryptor.encrypt(kp.publicKey.x, kp.publicKey.y, payload);
  console.log("Ciphertext (unauthenticated):", ct.slice(0, 64) + "...");

  // 3. Decrypt
  const decrypted = ZkEncryptor.decrypt(kp.secretKey, ct);
  console.log("Decrypted payload (unauthenticated):", decrypted);

  if (JSON.stringify(decrypted) === JSON.stringify(payload)) {
    console.log("✅ Standard Roundtrip Passed!");
  } else {
    throw new Error("Standard Roundtrip Failed!");
  }

  console.log("\n--- Testing ZK authenticated methods ---");
  const ctAuth = ZkEncryptor.encryptAuthenticated(kp.publicKey.x, kp.publicKey.y, payload);
  console.log("Ciphertext (authenticated):", ctAuth.slice(0, 64) + "...");

  const decryptedAuth = ZkEncryptor.decryptAuthenticated(kp.secretKey, ctAuth);
  console.log("Decrypted payload (authenticated):", decryptedAuth);

  if (JSON.stringify(decryptedAuth) === JSON.stringify(payload)) {
    console.log("✅ Authenticated Roundtrip Passed!");
  } else {
    throw new Error("Authenticated Roundtrip Failed!");
  }

  console.log("\n--- Testing ZK domains methods ---");
  const kemDomain = "0x0000000000000000000000000000000000000000000000000000000000001111";
  const demDomain = "0x0000000000000000000000000000000000000000000000000000000000002222";

  // Test both uncompressed and compressed EPK
  for (const compressEpk of [false, true]) {
    console.log(`\nTesting domains with compress_epk = ${compressEpk}:`);
    const ctDomains = ZkEncryptor.encryptWithDomains(
      kp.publicKey.x,
      kp.publicKey.y,
      payload,
      kemDomain,
      demDomain,
      compressEpk
    );
    console.log("  Ciphertext:", ctDomains.slice(0, 64) + "...");

    const decryptedDomains = ZkEncryptor.decryptWithDomains(
      kp.secretKey,
      ctDomains,
      kemDomain,
      demDomain,
      compressEpk
    );
    console.log("  Decrypted:", decryptedDomains);

    if (JSON.stringify(decryptedDomains) === JSON.stringify(payload)) {
      console.log(`  ✅ Domains Roundtrip Passed (compress_epk = ${compressEpk})!`);
    } else {
      throw new Error(`Domains Roundtrip Failed (compress_epk = ${compressEpk})!`);
    }

    console.log(`Testing authenticated domains with compress_epk = ${compressEpk}:`);
    const ctAuthDomains = ZkEncryptor.encryptAuthenticatedWithDomains(
      kp.publicKey.x,
      kp.publicKey.y,
      payload,
      kemDomain,
      demDomain,
      compressEpk
    );
    console.log("  Ciphertext (auth):", ctAuthDomains.slice(0, 64) + "...");

    const decryptedAuthDomains = ZkEncryptor.decryptAuthenticatedWithDomains(
      kp.secretKey,
      ctAuthDomains,
      kemDomain,
      demDomain,
      compressEpk
    );
    console.log("  Decrypted (auth):", decryptedAuthDomains);

    if (JSON.stringify(decryptedAuthDomains) === JSON.stringify(payload)) {
      console.log(`  ✅ Authenticated Domains Roundtrip Passed (compress_epk = ${compressEpk})!`);
    } else {
      throw new Error(`Authenticated Domains Roundtrip Failed (compress_epk = ${compressEpk})!`);
    }
  }

  console.log("\n🎉 ALL ZK INTEGRATION TESTS PASSED!");
}

run().catch(err => {
  console.error("❌ Test failed:", err);
  process.exit(1);
});

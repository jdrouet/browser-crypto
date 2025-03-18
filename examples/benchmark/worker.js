import wasmInit, {
  createPayload,
  PureCipher,
  setPanicHook,
  WebCipher,
} from "./pkg/benchmark.js";

const MAX_SIZE = 17 * 1024 * 1024;
const LOOP = 100;

async function run(profile) {
  if (profile === "small") {
    const pure = runPure(16, 32 * 1024);
    const web = await runWeb(16, 32 * 1024);
    return [...pure, ...web];
  }
  if (profile === "medium") {
    const pure = runPure(16 * 1024, 1024 * 1024);
    const web = await runWeb(16 * 1024, 1024 * 1024);
    return [...pure, ...web];
  }
  const pure = runPure(512 * 1024, MAX_SIZE);
  const web = await runWeb(512 * 1024, MAX_SIZE);
  return [...pure, ...web];
}

function runPure(min, max) {
  const result = [];
  const cipher = PureCipher.fromKey(new Uint8Array(32));
  for (let size = min; size < max; size *= 2) {
    console.log(`[WORKER] running pure with size=${size}`);
    const payload = createPayload(size);
    const enc_start = self.performance.now();
    for (let i = 0; i < LOOP; i++) {
      let _encrypted = cipher.encrypt(payload);
    }
    const encryption = self.performance.now() - enc_start;

    const encrypted = cipher.encrypt(payload);

    const dec_start = self.performance.now();
    for (let i = 0; i < LOOP; i++) {
      let _decrypted = cipher.decrypt(encrypted);
    }
    const decryption = self.performance.now() - dec_start;

    result.push({ type: "pure", size, encryption, decryption });
  }
  return result;
}

async function runWeb(min, max) {
  const result = [];
  const cipher = await WebCipher.fromKey(new Uint8Array(32));
  for (let size = min; size < max; size *= 2) {
    console.log(`[WORKER] running web with size=${size}`);
    const payload = createPayload(size);
    const enc_start = self.performance.now();
    for (let i = 0; i < LOOP; i++) {
      let _encrypted = await cipher.encrypt(payload);
    }
    const encryption = self.performance.now() - enc_start;

    const encrypted = await cipher.encrypt(payload);

    const dec_start = self.performance.now();
    for (let i = 0; i < LOOP; i++) {
      let _decrypted = await cipher.decrypt(encrypted);
    }
    const decryption = self.performance.now() - dec_start;

    result.push({ type: "web", size, encryption, decryption });
  }
  return result;
}

self.onmessage = (event) => {
  if (event.data.event === "init") {
    console.log("[WORKER] init wasm");
    wasmInit().then(() => {
      setPanicHook();
      postMessage({ event: "init-done" });
    });
  }
  if (event.data.event === "bench") {
    console.log("[WORKER] starting benchmark");
    run(event.data.profile).then((result) =>
      postMessage({ event: "bench-done", result }),
    );
  }
};

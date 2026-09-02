import fs from "node:fs";

const modulePath = process.argv[2];
if (!modulePath) {
  console.error("usage: node scripts/wasm_edge_bench.mjs path/to/blackhole.wasm");
  process.exit(2);
}

const bytes = fs.readFileSync(modulePath);
const { instance } = await WebAssembly.instantiate(bytes, {});
const { memory, blackhole_edge_probe, blackhole_edge_reset } = instance.exports;
if (
  !(memory instanceof WebAssembly.Memory) ||
  typeof blackhole_edge_probe !== "function" ||
  typeof blackhole_edge_reset !== "function"
) {
  throw new Error("module must export memory, blackhole_edge_probe, and blackhole_edge_reset");
}

const validPacket = Uint8Array.from([
  0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x03, 0x77, 0x77, 0x77, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
  0x00, 0x00, 0x01, 0x00, 0x01,
]);
const shortPacket = validPacket.slice(0, 11);
const longPacket = Uint8Array.from([
  0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x03, ...new TextEncoder().encode("www"), 0x0b, ...new TextEncoder().encode("longexample"),
  0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
]);
const adversarialPacket = Uint8Array.from([
  0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
]);
const pointer = 65536;
const maxPacketLength = Math.max(validPacket.length, longPacket.length, adversarialPacket.length);
const view = new Uint8Array(memory.buffer, pointer, maxPacketLength);

function measure(packet) {
  const packets = Array.isArray(packet) ? packet : [packet];
  const iterations = 10_000;
  for (let index = 0; index < 1_000; index += 1) {
    const current = packets[index % packets.length];
    view.fill(0);
    view.set(current);
    blackhole_edge_reset();
    blackhole_edge_probe(pointer, current.length);
  }
  const samples = [];
  let checksum = 0;
  for (let sample = 0; sample < 25; sample += 1) {
    const started = process.hrtime.bigint();
    for (let index = 0; index < iterations; index += 1) {
      const current = packets[index % packets.length];
      view.fill(0);
      view.set(current);
      blackhole_edge_reset();
      checksum += blackhole_edge_probe(pointer, current.length);
    }
    samples.push(Number(process.hrtime.bigint() - started) / iterations);
  }
  samples.sort((left, right) => left - right);
  const mean = samples.reduce((sum, value) => sum + value, 0) / samples.length;
  const variance = samples.reduce((sum, value) => sum + (value - mean) ** 2, 0) / samples.length;
  const percentile = (rank) => samples[Math.min(samples.length - 1, Math.ceil(rank * samples.length) - 1)];
  return {
    p50: percentile(0.5),
    p95: percentile(0.95),
    p99: percentile(0.99),
    cov: Math.sqrt(variance) / mean,
    checksum,
  };
}

const workloads = new Map([
  ["valid", validPacket],
  ["short", shortPacket],
  ["long", longPacket],
  ["adversarial", adversarialPacket],
]);
for (const [name, packet] of workloads) {
  const result = measure(packet);
  console.log(`${name}_result=${blackhole_edge_probe(pointer, packet.length)}`);
  console.log(`${name}_p50_ns=${result.p50} ${name}_p95_ns=${result.p95} ${name}_p99_ns=${result.p99} ${name}_cov=${result.cov} ${name}_checksum=${result.checksum}`);
}
const mixed = [validPacket, longPacket, adversarialPacket];
const mixedResult = measure(mixed);
console.log(`mixed_p50_ns=${mixedResult.p50} mixed_p95_ns=${mixedResult.p95} mixed_p99_ns=${mixedResult.p99} mixed_cov=${mixedResult.cov} mixed_checksum=${mixedResult.checksum}`);

blackhole_edge_reset();
console.log(`module_bytes=${bytes.length}`);
console.log(`memory_bytes=${memory.buffer.byteLength}`);
console.log(`valid_result=${blackhole_edge_probe(pointer, validPacket.length)}`);
blackhole_edge_reset();
console.log(`short_result=${blackhole_edge_probe(pointer, shortPacket.length)}`);
console.log(`null_result=${blackhole_edge_probe(0, validPacket.length)}`);
console.log(`oversized_result=${blackhole_edge_probe(pointer, 4097)}`);

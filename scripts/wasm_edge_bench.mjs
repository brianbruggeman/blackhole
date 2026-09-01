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

const packet = Uint8Array.from([
  0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x03, 0x77, 0x77, 0x77, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
  0x00, 0x00, 0x01, 0x00, 0x01,
]);
const pointer = 65536;
new Uint8Array(memory.buffer, pointer, packet.length).set(packet);

const iterations = 100_000;
for (let index = 0; index < 10_000; index += 1) {
  blackhole_edge_reset();
  blackhole_edge_probe(pointer, packet.length);
}
const started = process.hrtime.bigint();
let checksum = 0;
for (let index = 0; index < iterations; index += 1) {
  blackhole_edge_reset();
  checksum += blackhole_edge_probe(pointer, packet.length);
}
const elapsedNs = Number(process.hrtime.bigint() - started);

blackhole_edge_reset();
console.log(`module_bytes=${bytes.length}`);
console.log(`memory_bytes=${memory.buffer.byteLength}`);
console.log(`valid_result=${blackhole_edge_probe(pointer, packet.length)}`);
blackhole_edge_reset();
console.log(`short_result=${blackhole_edge_probe(pointer, 11)}`);
console.log(`iterations=${iterations}`);
console.log(`elapsed_ns=${elapsedNs}`);
console.log(`ns_per_call=${elapsedNs / iterations}`);
console.log(`checksum=${checksum}`);

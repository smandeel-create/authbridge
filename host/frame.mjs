// Chrome native messaging framing: 4-byte little-endian length + UTF-8 JSON.
export function encodeFrame(obj) {
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  const head = Buffer.alloc(4);
  head.writeUInt32LE(body.length, 0);
  return Buffer.concat([head, body]);
}

export class FrameDecoder {
  constructor(onMessage, maxLen = 64 * 1024 * 1024) { this.buf = Buffer.alloc(0); this.onMessage = onMessage; this.maxLen = maxLen; }
  push(chunk) {
    this.buf = Buffer.concat([this.buf, chunk]);
    for (;;) {
      if (this.buf.length < 4) return;
      const len = this.buf.readUInt32LE(0);
      if (len > this.maxLen) throw new Error('frame too large');
      if (this.buf.length < 4 + len) return;
      const body = this.buf.subarray(4, 4 + len);
      this.buf = this.buf.subarray(4 + len);
      this.onMessage(JSON.parse(body.toString('utf8')));
    }
  }
}

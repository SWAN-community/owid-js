/* ****************************************************************************
 * Copyright 2026 51 Degrees Mobile Experts Limited (51degrees.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 * ***************************************************************************/

// The payload length field of an OWID is whatever the sender declared, so
// parsing must check it against the bytes present before sizing anything by
// it. These tests prove that a declared length that does not leave exactly
// the signature after the payload is refused, that refusing it costs nothing
// sized by the declared number, and that a correctly sized envelope still
// parses. The 64 byte signature is the fixed tail every valid OWID ends with.
// The library never signs anything itself, so the one signed envelope here
// is produced with node's crypto module in the same way the crypto tests do.

const owid = require('./v1');
const nodeCrypto = require('crypto');

const signatureLength = 64;
const domain = "51d.es";
const dateInMinutes = 1000;

/**
 * A version 3 envelope, being the version byte, the domain with its
 * terminator, four minute bytes, the declared payload length, the payload
 * bytes given and the signature bytes given, so a test can make the declared
 * length and the bytes present disagree.
 * @param {number} declaredLength - the payload length written to the field.
 * @param {Buffer} payload - the payload bytes actually present.
 * @param {Buffer} signature - the signature bytes actually present.
 * @returns {string} the envelope as base 64.
 */
function envelope(declaredLength, payload, signature) {
    var date = Buffer.alloc(4);
    date.writeUInt32LE(dateInMinutes);
    var length = Buffer.alloc(4);
    length.writeUInt32LE(declaredLength);
    return Buffer.concat([
        Buffer.from([3]),
        Buffer.from(domain, 'ascii'),
        Buffer.from([0]),
        date,
        length,
        payload,
        signature
    ]).toString('base64');
}

const payload = Buffer.alloc(37, 0x5A);
const signature = Buffer.alloc(signatureLength, 0x99);

// The declared length matches the bytes present, the signature is the last
// 64 bytes, and the envelope parses to the same payload.
test('declared length matches parses', () => {
    var o = new owid(envelope(payload.length, payload, signature));

    expect(o.domain).toBe(domain);
    expect(o.date).toBe(dateInMinutes);
    expect(Buffer.from(o.owid.payload).equals(payload)).toBe(true);
    expect(Buffer.from(o.signature).equals(signature)).toBe(true);
    expect(o.owid.payload.buffer).toBe(o.signature.buffer);
});

// A matching payload materially larger than an ordinary identifier remains
// valid. Applications may impose a smaller policy before decoding it, but
// that policy is not part of format parsing.
test('matching one mebibyte payload parses', () => {
    var largePayload = Buffer.alloc(1024 * 1024, 0x5A);

    var o = new owid(envelope(
        largePayload.length, largePayload, signature));

    expect(Buffer.from(o.owid.payload).equals(largePayload)).toBe(true);
});

// An envelope with a real 64 byte ECDSA signature over its contents, built
// the way the server side libraries build one, parses. The library is
// verify only so this is the closest thing to its own serialised output.
test('signed envelope parses', () => {
    var keyPair = nodeCrypto.generateKeyPairSync('ec', {
        namedCurve: 'prime256v1'
    });
    var unsigned = Buffer.from(
        envelope(payload.length, payload, Buffer.alloc(0)), 'base64');
    var realSignature = nodeCrypto.sign('sha256', unsigned, {
        key: keyPair.privateKey,
        dsaEncoding: 'ieee-p1363'
    });
    expect(realSignature.length).toBe(signatureLength);

    var o = new owid(
        Buffer.concat([unsigned, realSignature]).toString('base64'));

    expect(o.domain).toBe(domain);
    expect(Buffer.from(o.owid.payload).equals(payload)).toBe(true);
    expect(Buffer.from(o.signature).equals(realSignature)).toBe(true);
});

// One more or one fewer than the bytes present is refused, because either
// leaves something other than exactly the signature at the end.
test.each([
    [payload.length - 1],
    [payload.length + 1],
])('declared length off by one to %p is refused', (declared) => {
    var data = envelope(declared, payload, signature);

    expect(() => new owid(data)).toThrow("OWID payload length '" + declared);
});

// A byte after the signature is refused, because the signature must be the
// end of the envelope.
test('trailing byte after signature is refused', () => {
    var data = Buffer.concat([
        Buffer.from(envelope(payload.length, payload, signature), 'base64'),
        Buffer.from([0])
    ]).toString('base64');

    expect(() => new owid(data)).toThrow("OWID payload length");
});

// A short signature is refused. The declared payload length is right for the
// payload, but the bytes after it are fewer than a signature.
test('signature of 63 bytes is refused', () => {
    var data = envelope(
        payload.length, payload, Buffer.alloc(signatureLength - 1, 0x99));

    expect(() => new owid(data)).toThrow("OWID payload length");
});

// A large declaration whose payload bytes are absent is refused without any
// work sized by the declared number. JavaScript cannot measure allocation,
// so the proof is time. Each envelope is a few dozen bytes while declaring
// 64 MiB, 2 GiB, or the largest unsigned value. The numeric values remain
// valid when the matching payload is present. One thousand refusals of each
// complete in well under a second, which would fail if the parse allocated
// or copied the declared size on each attempt. The third value also proves
// the count is read as unsigned, as a signed read would turn it into minus
// one.
test.each([
    [64 * 1024 * 1024],
    [0x7FFFFFFF],
    [0xFFFFFFFF],
])('mismatched large declaration %p is refused quickly', (declared) => {
    var data = envelope(declared, Buffer.alloc(0), Buffer.alloc(0));
    var attempts = 1000;

    var start = Date.now();
    for (var i = 0; i < attempts; i++) {
        expect(() => new owid(data))
            .toThrow("OWID payload length '" + declared + "'");
    }
    var elapsed = Date.now() - start;

    expect(elapsed).toBeLessThan(1000);
});

// An empty payload is a valid envelope. The declared length of zero leaves
// exactly the 64 byte signature, so the check accepts it and the payload
// parses as empty.
test('empty payload with a signature parses', () => {
    var o = new owid(envelope(0, Buffer.alloc(0), signature));

    expect(o.domain).toBe(domain);
    expect(o.owid.payload.length).toBe(0);
    expect(Buffer.from(o.signature).equals(signature)).toBe(true);
});

// The other reads in the parser are bounded by the bytes present as well.
// A domain with no zero terminator, an envelope that ends inside the date
// and one that ends inside the payload length field are each refused
// rather than the parser reading past the end of the buffer.
test('domain without a terminator is refused', () => {
    var data = Buffer.concat([
        Buffer.from([3]),
        Buffer.from(domain, 'ascii')
    ]).toString('base64');

    expect(() => new owid(data)).toThrow("string terminator");
});

test('envelope ending inside the date is refused', () => {
    var data = Buffer.concat([
        Buffer.from([3]),
        Buffer.from(domain, 'ascii'),
        Buffer.from([0]),
        Buffer.from([1, 2])
    ]).toString('base64');

    expect(() => new owid(data)).toThrow("32 bit integer");
});

test('envelope ending inside the payload length is refused', () => {
    var whole = Buffer.from(
        envelope(payload.length, payload, signature), 'base64');
    var cut = whole.subarray(0, 1 + domain.length + 1 + 4 + 2);

    expect(() => new owid(cut.toString('base64'))).toThrow("32 bit integer");
});

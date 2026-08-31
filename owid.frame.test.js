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

// owid.parseFrame reads one OWID out of a buffer that may hold several, one
// after another. It differs from owid.parseBytes in one place only, which is
// what it may say about the bytes after the envelope: parseBytes is given a
// buffer holding one OWID and nothing else, so anything after the signature
// is wrong, while parseFrame is given one of a sequence, so what follows may
// be the next envelope and is none of its business.
//
// These tests hold both halves of that: the sequence reads, and the same
// bytes handed to parseBytes are refused.

const owid = require('./v1');
const nodeCrypto = require('crypto');

Object.defineProperty(global.self, 'crypto', {
    value: {
        subtle: nodeCrypto.webcrypto.subtle
    },
    configurable: true
});

const signatureLength = 64;
const domain = "51d.es";
const dateInMinutes = 1000;

/**
 * A version 3 envelope carrying the payload given, signed with a key pair
 * made here, as the library never signs anything itself.
 * @param {string} payloadText - the payload.
 * @returns {Object} the envelope bytes and the signing key pair's public key
 * as an SPKI PEM.
 */
function envelope(payloadText) {
    var keyPair = nodeCrypto.generateKeyPairSync('ec', {
        namedCurve: 'prime256v1'
    });
    var payload = Buffer.from(payloadText, 'utf8');
    var date = Buffer.alloc(4);
    date.writeUInt32LE(dateInMinutes);
    var length = Buffer.alloc(4);
    length.writeUInt32LE(payload.length);
    var unsigned = Buffer.concat([
        Buffer.from([3]),
        Buffer.from(domain, 'ascii'),
        Buffer.from([0]),
        date,
        length,
        payload
    ]);
    var signature = nodeCrypto.sign('sha256', unsigned, {
        key: keyPair.privateKey,
        dsaEncoding: 'ieee-p1363'
    });
    return {
        payload: payloadText,
        bytes: Buffer.concat([unsigned, signature]),
        publicPem: keyPair.publicKey.export({ type: 'spki', format: 'pem' })
    };
}

/**
 * Asserts that a frame parse failed for the reason given, and that it took
 * nothing, so a caller's position does not move.
 * @param {Object} r - the result.
 * @param {string} status - the expected ParseStatus.
 */
function assertRefused(r, status) {
    expect(r.ok).toBe(false);
    expect(r.owid).toBeNull();
    expect(r.status).toBe(status);
    expect(r.bytesRead).toBe(0);
}

/**
 * Reads every OWID in the buffer by walking it a frame at a time, which is
 * the loop the surface exists for.
 * @param {Uint8Array} buffer - the buffer.
 * @returns {Object} the OWIDs found, the last status and where it stopped.
 */
function readAll(buffer) {
    var found = [];
    var at = 0;
    for (;;) {
        var r = owid.parseFrame(buffer, at);
        if (!r.ok) {
            return { found: found, status: r.status, at: at };
        }
        found.push(r.owid);
        at += r.bytesRead;
        // A frame that reported more bytes than the buffer holds, or one
        // that ignored the offset it was given and kept handing back the
        // first envelope, would run this loop forever. Neither can happen
        // while the offset is honoured, and the bound here is what turns
        // either into a failed assertion rather than a hung test.
        expect(at).toBeLessThanOrEqual(buffer.length);
    }
}

//#region a sequence of envelopes

// Two complete envelopes one after another. The first reads without the
// second being in its way, the second reads from where the first ended, and
// between them they account for every byte.
test('two envelopes are read one after the other', () => {
    var first = envelope("first");
    var second = envelope("second");
    var both = Buffer.concat([first.bytes, second.bytes]);

    var one = owid.parseFrame(both, 0);
    expect(one.ok).toBe(true);
    expect(one.status).toBe(owid.ParseStatus.PARSED);
    expect(one.owid.payloadAsString()).toBe("first");
    expect(one.bytesRead).toBe(first.bytes.length);

    var two = owid.parseFrame(both, one.bytesRead);
    expect(two.ok).toBe(true);
    expect(two.status).toBe(owid.ParseStatus.PARSED);
    expect(two.owid.payloadAsString()).toBe("second");
    expect(two.bytesRead).toBe(second.bytes.length);

    expect(one.bytesRead + two.bytesRead).toBe(both.length);
});

// The same two envelopes handed to parseBytes are refused. There the buffer
// holds one OWID and nothing else, so the second envelope is bytes that
// nothing could own, and the declared payload no longer leaves exactly the
// signature.
test('the same two envelopes are refused by parseBytes', () => {
    var first = envelope("first");
    var second = envelope("second");
    var both = Buffer.concat([first.bytes, second.bytes]);

    var r = owid.parseBytes(both);

    expect(r.ok).toBe(false);
    expect(r.owid).toBeNull();
    expect(r.status).toBe(owid.ParseStatus.BYTE_COUNT_MISMATCH);
    expect(r.declared).toBe(Buffer.from("first").length);
    expect(r.present).toBe(
        Buffer.from("first").length + second.bytes.length);
});

// One trailing byte is the smallest version of the same difference. A whole
// buffer refuses it and a frame does not care, because a frame is told
// nothing about what a following byte belongs to.
test('one trailing byte is refused whole and ignored framed', () => {
    var only = envelope("payload");
    var withTrailer = Buffer.concat([only.bytes, Buffer.from([0])]);

    expect(owid.parseBytes(withTrailer).status)
        .toBe(owid.ParseStatus.BYTE_COUNT_MISMATCH);

    var framed = owid.parseFrame(withTrailer);
    expect(framed.ok).toBe(true);
    expect(framed.bytesRead).toBe(only.bytes.length);
    expect(framed.owid.payloadAsString()).toBe("payload");
});

// The loop the surface exists for. Reaching the end of the buffer is
// missing input, which is what ends it, and the position it stops at is the
// length of everything it read.
test('a loop reads every envelope and stops at the end', () => {
    var texts = ["one", "two", "three", "four"];
    var parts = texts.map(t => envelope(t));
    var joined = Buffer.concat(parts.map(p => p.bytes));

    var walk = readAll(joined);

    expect(walk.found.map(o => o.payloadAsString())).toEqual(texts);
    expect(walk.status).toBe(owid.ParseStatus.MISSING_INPUT);
    expect(walk.at).toBe(joined.length);
});

// An empty payload occupies no payload bytes, so a sequence of them still
// advances by the header and the signature each time and does not stall.
test('a sequence of empty payloads still advances', () => {
    var parts = [envelope(""), envelope(""), envelope("")];
    var joined = Buffer.concat(parts.map(p => p.bytes));

    var walk = readAll(joined);

    expect(walk.found.length).toBe(3);
    walk.found.forEach(o => expect(o.payload.length).toBe(0));
    expect(walk.at).toBe(joined.length);
});

// The offset defaults to the start of the buffer, so reading the first of a
// sequence needs no arithmetic from the caller.
test('the offset defaults to the start of the buffer', () => {
    var only = envelope("payload");

    var withOffset = owid.parseFrame(only.bytes, 0);
    var without = owid.parseFrame(only.bytes);

    expect(without.ok).toBe(true);
    expect(without.bytesRead).toBe(withOffset.bytesRead);
    expect(without.owid.data).toBe(withOffset.owid.data);
});

//#endregion

//#region a failed frame takes nothing

// An envelope cut before its signature is data that stopped early rather
// than a declaration that disagrees with data all of which is present. On
// this contract the bytes after the envelope are not for the parse to judge,
// so all that is certain is that what was declared has not arrived. Nothing
// is read, so a caller reading from a source still arriving can keep the
// bytes and wait for more of them, which is the answer a byte count mismatch
// would have got wrong.
test('an envelope truncated before its signature is an unexpected end', () => {
    var only = envelope("payload");
    var cut = only.bytes.subarray(0, only.bytes.length - 1);

    var r = owid.parseFrame(cut);

    assertRefused(r, owid.ParseStatus.UNEXPECTED_END);
    expect(r.declared).toBe(Buffer.from("payload").length);
    expect(r.remaining).toBe(
        Buffer.from("payload").length + signatureLength - 1);
});

// An envelope with no signature bytes at all is the same answer, so a
// caller sees one status whether the signature is short by one byte or by
// all sixty four.
test('an envelope with no signature at all is an unexpected end', () => {
    var only = envelope("payload");
    var cut = only.bytes.subarray(0, only.bytes.length - signatureLength);

    var r = owid.parseFrame(cut);

    assertRefused(r, owid.ParseStatus.UNEXPECTED_END);
    expect(r.remaining).toBe(Buffer.from("payload").length);
});

// The count that disagrees belongs to the whole buffer contract, where every
// byte is present by definition. A frame never reports it, because a frame
// is never in a position to say that all the bytes are there.
test('a short frame is never a byte count mismatch', () => {
    var only = envelope("payload");

    for (var cut = 1; cut < only.bytes.length; cut++) {
        var r = owid.parseFrame(only.bytes.subarray(0, cut));
        expect(r.ok).toBe(false);
        expect(r.status).not.toBe(owid.ParseStatus.BYTE_COUNT_MISMATCH);
    }
});

// The second envelope of a pair, cut short, is refused at the offset the
// first one ended at, and the first is still readable. A caller holding a
// partial buffer therefore keeps what it has already read.
test('a short second envelope leaves the first one readable', () => {
    var first = envelope("first");
    var second = envelope("second");
    var truncated = Buffer.concat([
        first.bytes,
        second.bytes.subarray(0, second.bytes.length - 5)
    ]);

    var one = owid.parseFrame(truncated, 0);
    expect(one.ok).toBe(true);
    expect(one.owid.payloadAsString()).toBe("first");

    assertRefused(
        owid.parseFrame(truncated, one.bytesRead),
        owid.ParseStatus.UNEXPECTED_END);
});

// The failures a frame shares with a whole buffer report the same statuses,
// and every one of them takes nothing.
test('data that stops inside a field is an unexpected end', () => {
    var only = envelope("payload");

    assertRefused(
        owid.parseFrame(only.bytes.subarray(0, 1 + domain.length + 1 + 2)),
        owid.ParseStatus.UNEXPECTED_END);
    assertRefused(
        owid.parseFrame(only.bytes.subarray(0, 1 + domain.length + 1 + 4 + 2)),
        owid.ParseStatus.UNEXPECTED_END);
});

test('an unsupported version is refused and takes nothing', () => {
    var r = owid.parseFrame(new Uint8Array([9, 1, 2, 3]));

    assertRefused(r, owid.ParseStatus.UNSUPPORTED_VERSION);
    expect(r.version).toBe(9);
});

// The absent node marker is what framed reading exists to meet. It hands
// back no OWID, because it carries no signature, and it reports the one byte
// it occupied so a caller can step over it and read the next frame. Reading
// a run of frames is the only place the difference between a node that is
// deliberately absent and one that is malformed can be acted on.
test('the absent node marker hands back no OWID and reports one byte', () => {
    var r = owid.parseFrame(new Uint8Array([0]));

    expect(r.ok).toBe(false);
    expect(r.owid).toBeNull();
    expect(r.status).toBe(owid.ParseStatus.ABSENT_NODE);
    expect(r.bytesRead).toBe(1);
});

test('the absent node marker at the head of a sequence reports one byte',
    () => {
        var after = envelope("after");
        var sequence = Buffer.concat([Buffer.from([0]), after.bytes]);

        var marker = owid.parseFrame(sequence, 0);
        expect(marker.ok).toBe(false);
        expect(marker.owid).toBeNull();
        expect(marker.status).toBe(owid.ParseStatus.ABSENT_NODE);
        expect(marker.bytesRead).toBe(1);

        // The byte it reported is exactly enough to reach the next envelope.
        var next = owid.parseFrame(sequence, marker.bytesRead);
        expect(next.ok).toBe(true);
        expect(next.owid.payloadAsString()).toBe("after");
    });

// A run carrying an absent node in the middle of it. This is the case the
// status exists for: without it a caller walking the run could not tell a
// node that was deliberately left out from bytes that are simply wrong, and
// would have to stop at the marker rather than step over it.
test('a run with an absent node in the middle is walked through', () => {
    var first = envelope("first");
    var second = envelope("second");
    var run = Buffer.concat([
        first.bytes, Buffer.from([0]), second.bytes]);

    var seen = [];
    var at = 0;
    for (;;) {
        var r = owid.parseFrame(run, at);
        if (r.ok) {
            seen.push(r.owid.payloadAsString());
            at += r.bytesRead;
        } else if (r.status === owid.ParseStatus.ABSENT_NODE) {
            // A marker that reported no bytes would leave this loop where it
            // started, so a caller walking a run would never get past it.
            expect(r.bytesRead).toBe(1);
            seen.push(null);
            at += r.bytesRead;
        } else {
            expect(r.status).toBe(owid.ParseStatus.MISSING_INPUT);
            break;
        }
        expect(at).toBeLessThanOrEqual(run.length);
    }

    expect(seen).toEqual(["first", null, "second"]);
    expect(at).toBe(run.length);
});

// Two markers in a row are two absent nodes, not one, so a caller counting
// the nodes in a run gets the right number.
test('a run of markers is a run of absent nodes', () => {
    var run = Buffer.from([0, 0, 0]);

    var at = 0;
    var count = 0;
    while (at < run.length) {
        var r = owid.parseFrame(run, at);
        expect(r.status).toBe(owid.ParseStatus.ABSENT_NODE);
        expect(r.bytesRead).toBe(1);
        at += r.bytesRead;
        count++;
    }

    expect(count).toBe(3);
});

test('an unterminated domain is refused and takes nothing', () => {
    var never = new Uint8Array(1 + 300);
    never.fill(0x61);
    never[0] = 3;

    assertRefused(
        owid.parseFrame(never), owid.ParseStatus.INVALID_DOMAIN_ENCODING);
});

//#endregion

//#region what the offset may be

// Running off the end is missing input rather than a fault, because it is
// what a caller reaching the last envelope sees.
test.each([
    ['exactly at the end', 0],
    ['past the end', 100],
])('an offset %s is missing input', (where, beyond) => {
    var only = envelope("payload");

    assertRefused(
        owid.parseFrame(only.bytes, only.bytes.length + beyond),
        owid.ParseStatus.MISSING_INPUT);
});

test('an empty buffer is missing input', () => {
    assertRefused(
        owid.parseFrame(new Uint8Array(0)), owid.ParseStatus.MISSING_INPUT);
});

test.each([
    [undefined],
    [null],
])('an absent buffer %p is missing input', (value) => {
    assertRefused(owid.parseFrame(value), owid.ParseStatus.MISSING_INPUT);
});

// An offset that is not a place in a buffer is the caller's mistake rather
// than anything a sender chose, and it is still answered rather than thrown,
// because a surface that never throws is easier to use correctly than one
// that throws for one argument out of two.
test.each([
    [-1],
    [1.5],
    [NaN],
    [Infinity],
    ["0"],
    [null],
    [{}],
])('an offset of %p reports the input type', (at) => {
    var only = envelope("payload");

    assertRefused(
        owid.parseFrame(only.bytes, at),
        owid.ParseStatus.INVALID_INPUT_TYPE);
});

test.each([
    [42],
    [{}],
    [true],
    [[]],
    [new Uint32Array(4)],
])('a buffer of the wrong type %p reports the input type', (value) => {
    assertRefused(
        owid.parseFrame(value), owid.ParseStatus.INVALID_INPUT_TYPE);
});

//#endregion

//#region byte arrays a frame is handed

// A frame taking an offset is exactly where a Buffer bites, because the
// Buffer type in node is a Uint8Array of a different realm whose slice
// returns a view over the same memory rather than a copy, and because a
// Buffer from Buffer.concat normally starts part way into a pooled
// ArrayBuffer of its own.
test('a Buffer holding a sequence is read frame by frame', () => {
    var parts = [envelope("one"), envelope("two")];
    var joined = Buffer.concat(parts.map(p => p.bytes));
    expect(Buffer.isBuffer(joined)).toBe(true);

    var walk = readAll(joined);

    expect(walk.found.map(o => o.payloadAsString())).toEqual(["one", "two"]);
    expect(walk.at).toBe(joined.length);
});

// A view into a larger ArrayBuffer, with bytes on both sides of it, is read
// from where the view starts rather than from the start of the memory behind
// it, and the offset is counted from there as well.
test('a view into a larger buffer is read from where it starts', () => {
    var parts = [envelope("one"), envelope("two")];
    var joined = Buffer.concat(parts.map(p => p.bytes));
    var big = new Uint8Array(16 + joined.length + 16);
    big.fill(0xEE);
    big.set(new Uint8Array(joined), 16);
    var view = big.subarray(16, 16 + joined.length);

    var walk = readAll(view);

    expect(walk.found.map(o => o.payloadAsString())).toEqual(["one", "two"]);
    expect(walk.at).toBe(joined.length);
});

// A frame copies only its own window, so an OWID read out of the middle of a
// sequence does not hold on to the envelopes either side of it, and a caller
// changing the buffer afterwards cannot change what was read.
test('a frame keeps only its own bytes', () => {
    var first = envelope("first");
    var second = envelope("second");
    var both = Buffer.concat([first.bytes, second.bytes]);

    var two = owid.parseFrame(both, first.bytes.length);
    var before = two.owid.data;
    expect(Buffer.from(two.owid.data, 'base64').length)
        .toBe(second.bytes.length);

    both.fill(0x41);

    expect(two.owid.data).toBe(before);
    expect(two.owid.payloadAsString()).toBe("second");
    expect(two.owid.domain).toBe(domain);
});

//#endregion

//#region a framed OWID is a complete OWID

// The bytes a signature is checked over are the bytes that arrived, so an
// OWID read out of the middle of a sequence must verify against its own
// creator's key. This is what proves the window a frame copies is the right
// one, because a window off by a single byte in either direction would
// verify as false.
test('an OWID read from the middle of a sequence verifies', async () => {
    var first = envelope("first");
    var second = envelope("second");
    var both = Buffer.concat([first.bytes, second.bytes]);

    var one = owid.parseFrame(both, 0);
    var two = owid.parseFrame(both, one.bytesRead);

    await expect(one.owid.verifyWithPublicKey(first.publicPem))
        .resolves.toBe(true);
    await expect(two.owid.verifyWithPublicKey(second.publicPem))
        .resolves.toBe(true);
    // Each was signed by its own key pair, so the other key must not verify
    // it. Without that the test above would pass on any two envelopes.
    await expect(two.owid.verifyWithPublicKey(first.publicPem))
        .resolves.toBe(false);
});

// An OWID from a frame is the same kind of thing as one from anywhere else,
// so it is frozen, it is known to the library, and its fields are read only.
test('an OWID from a frame is a complete OWID', () => {
    var only = envelope("payload");

    var o = owid.parseFrame(only.bytes).owid;

    expect(owid.isOwid(o)).toBe(true);
    expect(Object.isFrozen(o)).toBe(true);
    expect(o.version).toBe(3);
    expect(o.domain).toBe(domain);
    expect(o.date).toBe(dateInMinutes);
    expect(o.signature.length).toBe(signatureLength);
    expect(o.data).toBe(only.bytes.toString('base64'));
});

// A result from a frame cannot be changed either, so code downstream cannot
// turn a failure into a success or move a caller's position.
test('a frame result is frozen', () => {
    var only = envelope("payload");

    expect(Object.isFrozen(owid.parseFrame(only.bytes))).toBe(true);
    expect(Object.isFrozen(owid.parseFrame(new Uint8Array(0)))).toBe(true);
});

//#endregion

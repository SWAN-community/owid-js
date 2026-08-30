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

// An OWID is read from whatever a caller was handed, which on a public end
// point means anything at all, so failing to be an OWID is an ordinary
// outcome rather than an error. These tests hold the reader to that: nothing
// is thrown, the failure is reported, no value is handed back and the status
// names the specific reason. They also hold the two halves of the boundary
// that matters most, which are that an OWID cannot be built from outside and
// that a caller cannot change one after it has been read.

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
const payload = Buffer.from("example");

/**
 * A version 3 envelope signed with a key pair made here, as the library
 * never signs anything itself.
 * @param {Buffer} [payloadBytes] - the payload, "example" by default.
 * @param {number} [version] - the version byte, 3 by default.
 * @returns {Object} the envelope as base 64, its bytes and the signing key
 * pair's public key as an SPKI PEM.
 */
function signedEnvelope(payloadBytes, version) {
    var bytes = payloadBytes === undefined ? payload : payloadBytes;
    var keyPair = nodeCrypto.generateKeyPairSync('ec', {
        namedCurve: 'prime256v1'
    });
    var date = Buffer.alloc(4);
    date.writeUInt32LE(dateInMinutes);
    var length = Buffer.alloc(4);
    length.writeUInt32LE(bytes.length);
    var unsigned = Buffer.concat([
        Buffer.from([version === undefined ? 3 : version]),
        Buffer.from(domain, 'ascii'),
        Buffer.from([0]),
        date,
        length,
        bytes
    ]);
    var signature = nodeCrypto.sign('sha256', unsigned, {
        key: keyPair.privateKey,
        dsaEncoding: 'ieee-p1363'
    });
    var whole = Buffer.concat([unsigned, signature]);
    return {
        bytes: whole,
        data: whole.toString('base64'),
        publicPem: keyPair.publicKey.export({ type: 'spki', format: 'pem' })
    };
}

/**
 * Asserts that a read failed for the reason given and reported all of it.
 * @param {Object} r - the result of the read.
 * @param {string} status - the expected ParseStatus.
 */
function assertRefused(r, status) {
    expect(r.ok).toBe(false);
    expect(r.owid).toBeNull();
    expect(r.status).toBe(status);
}

beforeEach(() => {
    fetchMock.resetMocks();
    fetchMock.mockResponse(() => Promise.resolve({
        status: 404,
        body: "Not Found"
    }));
});

//#region what a read reports

// Success reports all three facts, being that it worked, a value, and the
// reason Parsed.
test('a successful read reports all three facts', () => {
    var e = signedEnvelope();

    var r = owid.tryParse(e.data);

    expect(r.ok).toBe(true);
    expect(r.owid).not.toBeNull();
    expect(r.status).toBe(owid.ParseStatus.PARSED);
    expect(owid.isOwid(r.owid)).toBe(true);
});

// The result of a read cannot be changed either, so code downstream of a
// read cannot turn a failure into a success.
test('a read result is frozen', () => {
    var e = signedEnvelope();

    var r = owid.tryParse(e.data);

    expect(Object.isFrozen(r)).toBe(true);
    expect(Object.isFrozen(owid.tryParse(""))).toBe(true);
});

test.each([
    [undefined],
    [null],
    [""],
])('absent input %p is missing input', (value) => {
    assertRefused(owid.tryParse(value), owid.ParseStatus.MISSING_INPUT);
});

test.each([
    [undefined],
    [null],
])('an absent buffer %p is missing input', (value) => {
    assertRefused(owid.tryParseBytes(value), owid.ParseStatus.MISSING_INPUT);
});

test('an empty buffer is missing input', () => {
    assertRefused(
        owid.tryParseBytes(new Uint8Array(0)),
        owid.ParseStatus.MISSING_INPUT);
});

test.each([
    [42],
    [{}],
    [true],
])('a buffer of the wrong type %p reports the input type', (value) => {
    assertRefused(
        owid.tryParseBytes(value), owid.ParseStatus.INVALID_INPUT_TYPE);
});

test('invalid base 64 is reported rather than thrown', () => {
    var r;

    expect(() => { r = owid.tryParse("not base 64 !!!"); }).not.toThrow();

    assertRefused(r, owid.ParseStatus.INVALID_BASE64);
});

// An unknown version byte is refused rather than read as though it were a
// version this library understands. Until 30 August 2026 the date field was
// skipped for an unknown version and reading carried on.
test.each([
    [0],
    [4],
    [255],
])('version byte %p is unsupported', (version) => {
    var e = signedEnvelope(payload, version);

    var r = owid.tryParse(e.data);

    assertRefused(r, owid.ParseStatus.UNSUPPORTED_VERSION);
    expect(r.version).toBe(version);
});

// One trailing byte after a complete envelope means the declaration no
// longer leaves exactly the signature, which is what the reader can say for
// certain.
test('one trailing byte after a complete envelope is a count mismatch', () => {
    var e = signedEnvelope();
    var data = Buffer.concat([e.bytes, Buffer.from([0])]).toString('base64');

    var r = owid.tryParse(data);

    assertRefused(r, owid.ParseStatus.BYTE_COUNT_MISMATCH);
    expect(r.declared).toBe(payload.length);
    expect(r.present).toBe(payload.length + 1);
});

// Data that stops inside the envelope, before the payload length is even
// read, is an unexpected end.
test.each([
    ['inside the version', 0],
    ['inside the domain', 1],
    ['inside the date', 1 + domain.length + 1 + 2],
    ['inside the payload length', 1 + domain.length + 1 + 4 + 2],
])('data that stops %s is an unexpected end', (where, at) => {
    var e = signedEnvelope();
    var cut = e.bytes.subarray(0, at).toString('base64');

    assertRefused(
        owid.tryParse(cut),
        at === 0
            ? owid.ParseStatus.MISSING_INPUT
            : owid.ParseStatus.UNEXPECTED_END);
});

// Raw bytes are read on the same terms as base 64, and the envelope must be
// the whole buffer.
test('tryParseBytes reads a complete envelope', () => {
    var e = signedEnvelope();

    var r = owid.tryParseBytes(new Uint8Array(e.bytes));

    expect(r.ok).toBe(true);
    expect(r.status).toBe(owid.ParseStatus.PARSED);
    expect(r.owid.domain).toBe(domain);
    expect(r.owid.data).toBe(e.data);
});

// A caller's buffer is copied once the envelope is known to be valid, so a
// caller changing their array afterwards cannot change an OWID whose
// signature is checked over the bytes as they arrived.
test('changing the buffer afterwards does not change the OWID', () => {
    var e = signedEnvelope();
    var buffer = new Uint8Array(e.bytes);

    var o = owid.tryParseBytes(buffer).owid;
    var before = o.payloadAsString();
    buffer.fill(0x41);

    expect(o.payloadAsString()).toBe(before);
    expect(o.domain).toBe(domain);
});

// A view that starts part way into a larger buffer is read from where it
// starts, not from the start of the memory behind it. A node Buffer from
// Buffer.concat is normally exactly that.
test('a view into a larger buffer is read from where it starts', () => {
    var e = signedEnvelope();
    var big = new Uint8Array(16 + e.bytes.length + 16);
    big.fill(0xEE);
    big.set(new Uint8Array(e.bytes), 16);
    var view = big.subarray(16, 16 + e.bytes.length);

    var r = owid.tryParseBytes(view);

    expect(r.ok).toBe(true);
    expect(r.owid.domain).toBe(domain);
    expect(Buffer.from(r.owid.payload).equals(payload)).toBe(true);
});

// A signed byte array holds the same bytes, so it reads as the same OWID
// rather than as bytes that have gone negative.
test('a signed byte array reads as the unsigned bytes it holds', () => {
    var e = signedEnvelope();
    var signed = new Int8Array(new Uint8Array(e.bytes).buffer);

    var r = owid.tryParseBytes(signed);

    expect(r.ok).toBe(true);
    expect(r.owid.domain).toBe(domain);
    expect(r.owid.date).toBe(dateInMinutes);
});

// A view of something wider than a byte is not a byte array.
test('a view of wider elements is the wrong input type', () => {
    assertRefused(
        owid.tryParseBytes(new Uint32Array(4)),
        owid.ParseStatus.INVALID_INPUT_TYPE);
});

// A node Buffer is a Uint8Array whose slice returns a view over the same
// memory rather than a copy, so a caller passing one would otherwise keep a
// handle on the OWID's own bytes.
test('changing a Buffer afterwards does not change the OWID', () => {
    var e = signedEnvelope();
    var buffer = Buffer.from(e.bytes);

    var o = owid.tryParseBytes(buffer).owid;
    var before = o.payloadAsString();
    buffer.fill(0x41);

    expect(o.payloadAsString()).toBe(before);
    expect(o.domain).toBe(domain);
    expect(Buffer.from(o.payload).equals(payload)).toBe(true);
});

// Writing into the payload of an OWID read from a Buffer must not reach the
// OWID either, for the same reason.
test('writing into a payload read from a Buffer does not change the OWID',
    () => {
        var o = owid.tryParseBytes(Buffer.from(signedEnvelope().bytes)).owid;

        o.payload.fill(0x41);
        o.signature.fill(0x41);

        expect(Buffer.from(o.payload).equals(payload)).toBe(true);
        expect(o.signature[0]).not.toBe(0x41);
    });

// The base 64 decode running out of room is this runtime having nowhere to
// put the bytes, which is a different answer from the characters not being
// base 64, and the same bytes may be readable in a runtime with more room.
// No envelope can reach that condition in practice here, because a string
// long enough to decode past the largest typed array cannot itself be built,
// so the classification is exercised by making the decode fail the way it
// would.
test('a decode that runs out of room is a capacity failure', () => {
    var real = global.atob;
    try {
        global.atob = function () { throw new RangeError("too long"); };
        assertRefused(
            owid.tryParse("AAAA"),
            owid.ParseStatus.IMPLEMENTATION_CAPACITY_EXCEEDED);

        global.atob = function () { throw new Error("bad character"); };
        assertRefused(
            owid.tryParse("AAAA"), owid.ParseStatus.INVALID_BASE64);
    } finally {
        global.atob = real;
    }
});

// Reading answers whether the bytes are an OWID. Whether the signature is
// genuine is a second question, and asking the first must not touch a key or
// a cryptographic provider.
test('a failed read fetches no key and checks no signature', () => {
    var verifySpy = jest.spyOn(nodeCrypto.webcrypto.subtle, 'verify');
    var importSpy = jest.spyOn(nodeCrypto.webcrypto.subtle, 'importKey');
    try {
        owid.tryParse("not base 64 !!!");
        owid.tryParse("AAAA");
        owid.tryParse(signedEnvelope().data + "AA");
        owid.tryParseBytes(new Uint8Array([9, 9, 9]));

        expect(fetch.mock.calls.length).toBe(0);
        expect(verifySpy).not.toHaveBeenCalled();
        expect(importSpy).not.toHaveBeenCalled();
    } finally {
        verifySpy.mockRestore();
        importSpy.mockRestore();
    }
});

// A successful read fetches no key either. Reading and verifying are two
// questions with two answers.
test('a successful read fetches no key and checks no signature', () => {
    var verifySpy = jest.spyOn(nodeCrypto.webcrypto.subtle, 'verify');
    try {
        var r = owid.tryParse(signedEnvelope().data);

        expect(r.ok).toBe(true);
        expect(fetch.mock.calls.length).toBe(0);
        expect(verifySpy).not.toHaveBeenCalled();
    } finally {
        verifySpy.mockRestore();
    }
});

//#endregion

//#region reading and verifying are two questions

// A structurally valid identifier whose signature does not match is a valid
// OWID to read. It is only when the second question is asked that the
// signature is judged, and the two answers stay apart.
test('a structurally valid OWID with a wrong signature reads, then fails ' +
    'verification', async () => {
    var e = signedEnvelope();
    var tampered = Buffer.from(e.bytes);
    tampered[tampered.length - 1] = tampered[tampered.length - 1] ^ 0xFF;

    var r = owid.tryParse(tampered.toString('base64'));

    expect(r.ok).toBe(true);
    expect(r.status).toBe(owid.ParseStatus.PARSED);
    expect(r.owid.domain).toBe(domain);

    await expect(r.owid.verifyWithPublicKey(e.publicPem)).resolves.toBe(false);
    var detailed = await r.owid.verifyWithPublicKeyDetailed(e.publicPem);
    expect(detailed.ok).toBe(false);
    expect(detailed.status).toBe(owid.SignatureStatus.SIGNATURE_INVALID);
});

test('a genuine signature is reported valid', async () => {
    var e = signedEnvelope();
    var o = owid.tryParse(e.data).owid;

    await expect(o.verifyWithPublicKey(e.publicPem)).resolves.toBe(true);
    var detailed = await o.verifyWithPublicKeyDetailed(e.publicPem);
    expect(detailed.ok).toBe(true);
    expect(detailed.status).toBe(owid.SignatureStatus.SIGNATURE_VALID);
});

// A key that cannot be used leaves the signature unjudged, which must never
// be reported as a forgery. On 30 August 2026 the key endpoints served PEM a
// strict parser rejects and every offline verification failed while the keys
// and the identifiers were both fine.
test('a key that cannot be imported is not an invalid signature', async () => {
    var e = signedEnvelope();
    var o = owid.tryParse(e.data).owid;

    var detailed = await o.verifyWithPublicKeyDetailed(
        "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----");

    expect(detailed.ok).toBe(false);
    expect(detailed.status).toBe(owid.SignatureStatus.INVALID_KEY);
    expect(detailed.status).not.toBe(owid.SignatureStatus.SIGNATURE_INVALID);
});

// A key that is well formed PEM but not a P-256 public key is also the key's
// fault rather than the identifier's.
test('a key of the wrong type is not an invalid signature', async () => {
    var e = signedEnvelope();
    var o = owid.tryParse(e.data).owid;
    var rsa = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

    var detailed = await o.verifyWithPublicKeyDetailed(
        rsa.publicKey.export({ type: 'spki', format: 'pem' }));

    expect(detailed.ok).toBe(false);
    expect(detailed.status).toBe(owid.SignatureStatus.INVALID_KEY);
});

// A creator end point that cannot be reached leaves the signature unjudged.
test('a key that cannot be fetched is not an invalid signature', async () => {
    fetchMock.mockRejectOnce(new Error("Network failure"));
    var o = owid.tryParse(signedEnvelope().data).owid;

    var detailed = await o.verifyDetailed();

    expect(detailed.ok).toBe(false);
    expect(detailed.status).toBe(owid.SignatureStatus.KEY_UNAVAILABLE);
});

// A creator that answers with something that is not a key list is a client
// protocol failure rather than a missing key or a forgery.
test('a creator response with no key is a verification error', async () => {
    fetchMock.mockResponseOnce(JSON.stringify({ notAKey: true }));
    var o = owid.tryParse(signedEnvelope().data).owid;

    var detailed = await o.verifyDetailed();

    expect(detailed.ok).toBe(false);
    expect(detailed.status).toBe(owid.SignatureStatus.VERIFICATION_ERROR);
});

//#endregion

//#region an OWID cannot be built

// There is no constructor. The exported function refuses to be called at
// all, so code written against the constructor it replaces is told what to
// use instead rather than silently receiving an object with nothing in it.
test('calling the module with new is refused', () => {
    expect(() => new owid(signedEnvelope().data))
        .toThrow("an OWID cannot be constructed");
    expect(() => new owid()).toThrow("owid.tryParse");
});

test('calling the module without new is refused', () => {
    expect(() => owid(signedEnvelope().data))
        .toThrow("an OWID cannot be constructed");
});

// Reaching for the prototype gives an object with none of the OWID's methods
// and no membership of the set the module keeps, so it is not an OWID.
test('an object made from the prototype is not an OWID', () => {
    var fake = Object.create(owid.prototype);

    expect(owid.isOwid(fake)).toBe(false);
    expect(fake.verify).toBeUndefined();
    expect(fake.domain).toBeUndefined();
});

// An OWID's own prototype leads nowhere either, so there is no constructor
// to reach through an instance.
test('an OWID exposes no constructor that builds another', () => {
    var o = owid.tryParse(signedEnvelope().data).owid;

    expect(Object.getPrototypeOf(o)).toBe(Object.prototype);
    expect(o.constructor).toBe(Object);
    expect(owid.isOwid(new o.constructor())).toBe(false);
});

// An object carrying the same field names has never been read from
// anything, so it is not an OWID and the library will not treat it as one.
test('an object that looks like an OWID is not one', () => {
    var e = signedEnvelope();
    var real = owid.tryParse(e.data).owid;
    var fake = {
        data: real.data,
        version: real.version,
        domain: real.domain,
        date: real.date,
        payload: real.payload,
        signature: real.signature
    };

    expect(owid.isOwid(fake)).toBe(false);
    expect(owid.isOwid(real)).toBe(true);
});

// The same look alike is refused where it would otherwise be folded into the
// bytes a signature is checked over.
test('a look alike is refused as another OWID', async () => {
    var e = signedEnvelope();
    var o = owid.tryParse(e.data).owid;
    var fake = { version: 3, domain: domain, date: 1, payload: payload };

    var detailed = await o.verifyWithPublicKeyDetailed(e.publicPem, [fake]);

    expect(detailed.ok).toBe(false);
    expect(detailed.status).toBe(owid.SignatureStatus.VERIFICATION_ERROR);
    expect(detailed.message).toMatch("owid.tryParse");
});

// A failure message names the type that was supplied and never the value, so
// logging a refusal cannot log whatever an untrusted sender put in it.
test('a refusal names no part of the input', async () => {
    var e = signedEnvelope();
    var o = owid.tryParse(e.data).owid;
    var secret = "aSecretACallerShouldNotSeeLogged";

    var detailed = await o.verifyWithPublicKeyDetailed(
        e.publicPem, [{ secret: secret }]);

    expect(detailed.message).not.toMatch(secret);
});

//#endregion

//#region an OWID cannot be changed

// A parsed OWID's signature covers its fields as they arrived, so a caller
// able to change one would hold something whose signature no longer
// describes it.

/**
 * Assigns in strict mode, where a write to a property with no setter is a
 * fault rather than a silent no operation.
 * @param {Object} o - the OWID.
 * @param {string} name - the field.
 * @param {*} value - the value to try to write.
 */
function strictAssign(o, name, value) {
    "use strict";
    o[name] = value;
}

test('an OWID is frozen', () => {
    var o = owid.tryParse(signedEnvelope().data).owid;

    expect(Object.isFrozen(o)).toBe(true);
});

test.each([
    ['data'],
    ['version'],
    ['domain'],
    ['date'],
    ['payload'],
    ['signature'],
])('the field %s cannot be set from outside', (name) => {
    var o = owid.tryParse(signedEnvelope().data).owid;
    var before = o[name];

    expect(() => strictAssign(o, name, "changed")).toThrow();
    expect(o[name]).toEqual(before);
});

test.each([
    ['verify'],
    ['verifyDetailed'],
    ['verifyWithPublicKey'],
    ['verifyWithPublicKeyDetailed'],
    ['payloadAsString'],
    ['payloadAsBase64'],
])('the method %s cannot be rebound from outside', (name) => {
    var o = owid.tryParse(signedEnvelope().data).owid;
    var before = o[name];

    expect(() => strictAssign(o, name, function () { return "changed"; }))
        .toThrow();
    expect(o[name]).toBe(before);
});

test('a new field cannot be added to an OWID', () => {
    var o = owid.tryParse(signedEnvelope().data).owid;

    expect(() => strictAssign(o, "extra", true)).toThrow();
    expect(o.extra).toBeUndefined();
});

// Writing into a returned byte array does not alter the OWID, because the
// accessors hand out copies.
test.each([
    ['payload'],
    ['signature'],
])('writing into the returned %s does not change the OWID', (name) => {
    var o = owid.tryParse(signedEnvelope().data).owid;
    var first = o[name];

    first.fill(0x41);

    expect(Buffer.from(o[name]).equals(Buffer.from(first))).toBe(false);
});

test('each read of a byte field gives a separate array', () => {
    var o = owid.tryParse(signedEnvelope().data).owid;

    expect(o.payload).not.toBe(o.payload);
    expect(o.payload.buffer).not.toBe(o.signature.buffer);
});

// A caller who writes into the payload cannot make a bad signature verify.
test('writing into the returned payload cannot change a verification',
    async () => {
        var e = signedEnvelope();
        var o = owid.tryParse(e.data).owid;

        o.payload.fill(0x41);
        o.signature.fill(0x41);

        await expect(o.verifyWithPublicKey(e.publicPem)).resolves.toBe(true);
    });

// The status vocabularies are frozen, so a caller cannot redefine what a
// status means for everyone else holding the same module.
test.each([
    ['ParseStatus'],
    ['SignatureStatus'],
])('%s is frozen', (name) => {
    expect(Object.isFrozen(owid[name])).toBe(true);
});

//#endregion

//#region the documented example

// The README shows this. Running it here keeps the documentation honest,
// because an example that names a method that does not exist fails the build
// rather than misleading the next reader.
test('the documented example works', async () => {
    var e = signedEnvelope();

    var result = owid.tryParse(e.data);
    if (result.ok) {
        var o = result.owid;
        expect(typeof o.payloadAsString()).toBe("string");
        expect(typeof o.payloadAsPrintable()).toBe("string");
        expect(typeof o.payloadAsBase64()).toBe("string");
        expect(typeof o.domain).toBe("string");
        expect(typeof o.date).toBe("number");
        expect(o.signature.length).toBe(signatureLength);
        await expect(o.verifyWithPublicKey(e.publicPem)).resolves.toBe(true);
    } else {
        throw new Error("the documented example did not read: " +
            result.status);
    }
});

//#endregion

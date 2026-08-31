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
// reading must check it against the bytes present before sizing anything by
// it. These tests prove that a declared length that does not leave exactly
// the signature after the payload is refused, that refusing it costs nothing
// sized by the declared number, and that a correctly sized envelope still
// reads. The 64 byte signature is the fixed tail every valid OWID ends with.
// The library never signs anything itself, so the one signed envelope here
// is produced with node's crypto module in the same way the crypto tests do.

const owid = require('./v1');
const nodeCrypto = require('crypto');

const signatureLength = 64;
const domain = "51d.es";
const dateInMinutes = 1000;

/**
 * Reads an OWID that the test expects to be valid, asserting the three facts
 * a read always reports before handing back the OWID itself.
 * @param {string} data - the OWID as base 64.
 * @returns {Object} the OWID.
 */
function read(data) {
    var r = owid.parse(data);
    expect(r.ok).toBe(true);
    expect(r.status).toBe(owid.ParseStatus.PARSED);
    expect(r.owid).not.toBeNull();
    return r.owid;
}

/**
 * Asserts that a read failed for the reason given and that it reported all
 * of it, being nothing thrown, the failure reported, no value handed back
 * and the specific status.
 * @param {string} data - the OWID as base 64.
 * @param {string} status - the expected ParseStatus.
 * @returns {Object} the result, so a test can check the numbers it carries.
 */
function refused(data, status) {
    var r = owid.parse(data);
    expect(r.ok).toBe(false);
    expect(r.owid).toBeNull();
    expect(r.status).toBe(status);
    return r;
}

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
// 64 bytes, and the envelope reads back to the same payload.
test('declared length matches parses', () => {
    var o = read(envelope(payload.length, payload, signature));

    expect(o.domain).toBe(domain);
    expect(o.date).toBe(dateInMinutes);
    expect(Buffer.from(o.payload).equals(payload)).toBe(true);
    expect(Buffer.from(o.signature).equals(signature)).toBe(true);
    // The accessors hand out copies, so exposing the payload cannot expose
    // the rest of the OWID envelope.
    expect(o.payload.buffer).not.toBe(o.signature.buffer);
});

// A matching payload materially larger than an ordinary identifier remains
// valid. Applications may impose a smaller policy before decoding it, but
// that policy is not part of format reading.
test('matching one mebibyte payload parses', () => {
    var largePayload = Buffer.alloc(1024 * 1024, 0x5A);

    var o = read(envelope(largePayload.length, largePayload, signature));

    expect(Buffer.from(o.payload).equals(largePayload)).toBe(true);
});

// An envelope with a real 64 byte ECDSA signature over its contents, built
// the way the server side libraries build one, reads. The library is verify
// only so this is the closest thing to its own serialised output.
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

    var o = read(Buffer.concat([unsigned, realSignature]).toString('base64'));

    expect(o.domain).toBe(domain);
    expect(Buffer.from(o.payload).equals(payload)).toBe(true);
    expect(Buffer.from(o.signature).equals(realSignature)).toBe(true);
});

// One more or one fewer than the bytes present is refused, because either
// leaves something other than exactly the signature at the end. The result
// carries both numbers so that a caller can say what disagreed without the
// library putting the sender's own data in a message.
test.each([
    [payload.length - 1],
    [payload.length + 1],
])('declared length off by one to %p is refused', (declared) => {
    var r = refused(
        envelope(declared, payload, signature),
        owid.ParseStatus.BYTE_COUNT_MISMATCH);

    expect(r.declared).toBe(declared);
    expect(r.present).toBe(payload.length);
});

// A byte after the signature is refused, because the signature must be the
// end of the envelope.
test('trailing byte after signature is refused', () => {
    var data = Buffer.concat([
        Buffer.from(envelope(payload.length, payload, signature), 'base64'),
        Buffer.from([0])
    ]).toString('base64');

    var r = refused(data, owid.ParseStatus.BYTE_COUNT_MISMATCH);

    expect(r.declared).toBe(payload.length);
    expect(r.present).toBe(payload.length + 1);
});

// A short signature is refused. The declared payload length is right for the
// payload, but the bytes after it are fewer than a signature, so what is
// certain is that the declaration cannot leave exactly the signature the
// version requires.
test('signature of 63 bytes is refused', () => {
    var data = envelope(
        payload.length, payload, Buffer.alloc(signatureLength - 1, 0x99));

    var r = refused(data, owid.ParseStatus.BYTE_COUNT_MISMATCH);

    expect(r.declared).toBe(payload.length);
    expect(r.present).toBe(payload.length - 1);
});

// A buffer that stops before the signature can even start gives a negative
// count of the payload bytes present rather than a count that has wrapped,
// so it can never equal a declaration.
test('a buffer shorter than a signature reports a negative count', () => {
    var data = envelope(0, Buffer.alloc(0), Buffer.alloc(10, 0x99));

    var r = refused(data, owid.ParseStatus.BYTE_COUNT_MISMATCH);

    expect(r.declared).toBe(0);
    expect(r.present).toBe(10 - signatureLength);
});

// A large declaration whose payload bytes are absent is refused without any
// work sized by the declared number. JavaScript cannot measure allocation,
// so the proof is time. Each envelope is a few dozen bytes while declaring
// 64 MiB, 2 GiB, or the largest unsigned value. The numeric values remain
// valid when the matching payload is present. One thousand refusals of each
// complete in well under a second, which would fail if the read allocated
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
        var r = owid.parse(data);
        expect(r.ok).toBe(false);
        expect(r.status).toBe(owid.ParseStatus.BYTE_COUNT_MISMATCH);
        expect(r.declared).toBe(declared);
    }
    var elapsed = Date.now() - start;

    expect(elapsed).toBeLessThan(1000);
});

// An empty payload is a valid envelope. The declared length of zero leaves
// exactly the 64 byte signature, so the check accepts it and the payload
// reads as empty. Having nothing to say is allowed.
test('empty payload with a signature parses', () => {
    var o = read(envelope(0, Buffer.alloc(0), signature));

    expect(o.domain).toBe(domain);
    expect(o.payload.length).toBe(0);
    expect(Buffer.from(o.signature).equals(signature)).toBe(true);
});

// The other reads in the reader are bounded by the bytes present as well.
// A domain with no zero terminator, an envelope that ends inside the date
// and one that ends inside the payload length field are each refused
// rather than the reader running past the end of the buffer.
test('domain without a terminator is refused', () => {
    var data = Buffer.concat([
        Buffer.from([3]),
        Buffer.from(domain, 'ascii')
    ]).toString('base64');

    refused(data, owid.ParseStatus.UNEXPECTED_END);
});

test('envelope ending inside the date is refused', () => {
    var data = Buffer.concat([
        Buffer.from([3]),
        Buffer.from(domain, 'ascii'),
        Buffer.from([0]),
        Buffer.from([1, 2])
    ]).toString('base64');

    refused(data, owid.ParseStatus.UNEXPECTED_END);
});

test('envelope ending inside the payload length is refused', () => {
    var whole = Buffer.from(
        envelope(payload.length, payload, signature), 'base64');
    var cut = whole.subarray(0, 1 + domain.length + 1 + 4 + 2);

    refused(cut.toString('base64'), owid.ParseStatus.UNEXPECTED_END);
});

// The creator domain is stored as ASCII followed by a zero terminator, and
// the reader finds its end by walking forward to that terminator. RFC 1035
// section 2.3.4 restricts a domain name to 255 octets in the DNS wire
// format, which is 253 characters in the presentation form an OWID stores,
// so the walk is bounded there. These tests prove that a domain of the
// published maximum still reads, that a longer one is refused, and that a
// buffer whose domain field never terminates is refused for a cost fixed by
// the maximum rather than by the length of whatever was sent.

const maximumDomainLength = 253;

/**
 * A domain of the length given, built as dot separated labels of no more
 * than the 63 characters RFC 1035 allows a label, so the only thing under
 * test is the total length.
 * @param {number} length - the number of characters the domain must have.
 * @returns {string} the domain.
 */
function domainOfLength(length) {
    var labels = [];
    var left = length;
    while (left > 63) {
        labels.push('a'.repeat(63));
        left -= 64;
    }
    labels.push('a'.repeat(left));
    return labels.join('.');
}

/**
 * A version 3 envelope carrying the domain given, with a payload and a
 * signature whose sizes agree, so the domain is the only field a test can
 * make invalid.
 * @param {string} domainText - the domain written to the envelope.
 * @param {boolean} terminated - whether the zero terminator is written.
 * @returns {string} the envelope as base 64.
 */
function domainEnvelope(domainText, terminated) {
    var date = Buffer.alloc(4);
    date.writeUInt32LE(dateInMinutes);
    var length = Buffer.alloc(4);
    length.writeUInt32LE(payload.length);
    return Buffer.concat([
        Buffer.from([3]),
        Buffer.from(domainText, 'ascii'),
        terminated ? Buffer.from([0]) : Buffer.alloc(0),
        date,
        length,
        payload,
        signature
    ]).toString('base64');
}

// A domain of exactly the published maximum is a valid domain, so it reads
// and comes back as the same text.
test('domain of the maximum length parses', () => {
    var longDomain = domainOfLength(maximumDomainLength);
    expect(longDomain.length).toBe(maximumDomainLength);

    var o = read(domainEnvelope(longDomain, true));

    expect(o.domain).toBe(longDomain);
    expect(o.date).toBe(dateInMinutes);
    expect(Buffer.from(o.payload).equals(payload)).toBe(true);
});

// One character more than the published maximum is refused, even though the
// envelope is otherwise well formed and its terminator is present.
test('domain one over the maximum length is refused', () => {
    var tooLong = domainOfLength(maximumDomainLength + 1);
    expect(tooLong.length).toBe(maximumDomainLength + 1);

    refused(
        domainEnvelope(tooLong, true),
        owid.ParseStatus.INVALID_DOMAIN_ENCODING);
});

// A buffer whose domain field has no terminator anywhere is refused without
// the reader walking the whole buffer. JavaScript cannot measure allocation,
// and the wall clock here is dominated by the base 64 decode rather than by
// the walk, so the bound is measured by counting the walk itself. Building
// the domain is the only thing that calls String.fromCharCode while an OWID
// is being read, so the number of calls is the number of domain bytes
// touched. The buffer is one mebibyte of domain characters with no zero byte
// in it, and the reader must touch no more than one byte past the maximum
// before it refuses.
test('domain that never terminates is refused for a bounded cost', () => {
    var data = Buffer.concat([
        Buffer.from([3]),
        Buffer.alloc(1024 * 1024, 0x61)
    ]).toString('base64');
    var real = String.fromCharCode;
    var touched = 0;
    String.fromCharCode = function () {
        touched++;
        return real.apply(String, arguments);
    };

    try {
        // The base 64 decode itself builds no string through fromCharCode,
        // so every call counted below comes from the domain walk.
        var r = owid.parse(data);
        expect(r.ok).toBe(false);
        expect(r.owid).toBeNull();
        expect(r.status).toBe(owid.ParseStatus.INVALID_DOMAIN_ENCODING);
    } finally {
        String.fromCharCode = real;
    }

    expect(touched).toBeLessThanOrEqual(maximumDomainLength + 1);
});

/**
 * A version 3 envelope carrying the domain given, signed with a key pair
 * made here, as the library never signs anything itself.
 * @param {string} domainText - the creator domain of the envelope.
 * @returns {Object} the unsigned bytes, the signature, the envelope as base
 * 64 and the signing key pair's public key as an SPKI PEM.
 */
function signedEnvelope(domainText) {
    var keyPair = nodeCrypto.generateKeyPairSync('ec', {
        namedCurve: 'prime256v1'
    });
    var date = Buffer.alloc(4);
    date.writeUInt32LE(dateInMinutes);
    var length = Buffer.alloc(4);
    length.writeUInt32LE(payload.length);
    var unsigned = Buffer.concat([
        Buffer.from([3]),
        Buffer.from(domainText, 'ascii'),
        Buffer.from([0]),
        date,
        length,
        payload
    ]);
    var signed = nodeCrypto.sign('sha256', unsigned, {
        key: keyPair.privateKey,
        dsaEncoding: 'ieee-p1363'
    });
    return {
        unsigned: unsigned,
        signature: signed,
        data: Buffer.concat([unsigned, signed]).toString('base64'),
        publicPem: keyPair.publicKey.export({ type: 'spki', format: 'pem' })
    };
}

// A real signed envelope carrying a domain of the published maximum reads
// and verifies as the same bytes, so the bound is not retrospective on
// anything a server side library would produce.
test('signed envelope with a maximum length domain parses', () => {
    var longDomain = domainOfLength(maximumDomainLength);
    var e = signedEnvelope(longDomain);
    expect(e.signature.length).toBe(signatureLength);

    var o = read(e.data);

    expect(o.domain).toBe(longDomain);
    expect(Buffer.from(o.payload).equals(payload)).toBe(true);
    expect(Buffer.from(o.signature).equals(e.signature)).toBe(true);
});

// The library serializes nothing for verification any more: the bytes a
// signature is checked over are the bytes that arrived, less the signature
// on the end. A Web Crypto implementation has to be present for the offline
// check below. Node provides one and it is exposed here the same way a
// browser would, as the crypto tests do.
Object.defineProperty(global.self, 'crypto', {
    value: {
        subtle: nodeCrypto.webcrypto.subtle
    },
    configurable: true
});

// A signed envelope with a domain of the maximum reads and verifies, so the
// domain bound leaves a domain the library accepts today untouched.
test('domain of the maximum length verifies', async () => {
    var longDomain = domainOfLength(maximumDomainLength);
    var e = signedEnvelope(longDomain);

    var o = read(e.data);

    expect(o.domain).toBe(longDomain);
    await expect(o.verifyWithPublicKey(e.publicPem)).resolves.toBe(true);
});

// A domain longer than the maximum can no longer reach a signature check at
// all. The read refuses it, so there is no OWID to verify with, and an
// object that merely carries the same field names is not an OWID and is
// refused as another OWID as well. Both routes are closed here, and the
// second is checked with a spy so that the refusal is shown to happen before
// any signature work.
test('a domain over the maximum cannot reach a signature check',
    async () => {
        var e = signedEnvelope(domain);
        var o = read(e.data);
        var fabricated = {
            version: 3,
            domain: domainOfLength(maximumDomainLength + 1),
            date: dateInMinutes,
            payload: payload
        };
        var verifySpy = jest.spyOn(nodeCrypto.webcrypto.subtle, 'verify');

        try {
            refused(
                domainEnvelope(fabricated.domain, true),
                owid.ParseStatus.INVALID_DOMAIN_ENCODING);

            var r = await o.checkSignatureWithPublicKey(
                e.publicPem, [fabricated]);
            expect(r.ok).toBe(false);
            expect(r.status).toBe(
                owid.SignatureStatus.VERIFICATION_ERROR);
            expect(verifySpy).not.toHaveBeenCalled();
        } finally {
            verifySpy.mockRestore();
        }
    });

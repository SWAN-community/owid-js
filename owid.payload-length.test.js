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
    // Parsed fields keep their historical independent backing buffers, so
    // exposing payload.buffer cannot expose the rest of the OWID envelope.
    expect(o.owid.payload.buffer).not.toBe(o.signature.buffer);
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

// The creator domain is stored as ASCII followed by a zero terminator, and
// the parser finds its end by walking forward to that terminator. RFC 1035
// section 2.3.4 restricts a domain name to 255 octets in the DNS wire
// format, which is 253 characters in the presentation form an OWID stores,
// so the walk is bounded there. These tests prove that a domain of the
// published maximum still parses, that a longer one is refused, and that a
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

// A domain of exactly the published maximum is a valid domain, so it parses
// and comes back as the same text.
test('domain of the maximum length parses', () => {
    var longDomain = domainOfLength(maximumDomainLength);
    expect(longDomain.length).toBe(maximumDomainLength);

    var o = new owid(domainEnvelope(longDomain, true));

    expect(o.domain).toBe(longDomain);
    expect(o.date).toBe(dateInMinutes);
    expect(Buffer.from(o.owid.payload).equals(payload)).toBe(true);
});

// One character more than the published maximum is refused, even though the
// envelope is otherwise well formed and its terminator is present.
test('domain one over the maximum length is refused', () => {
    var tooLong = domainOfLength(maximumDomainLength + 1);
    expect(tooLong.length).toBe(maximumDomainLength + 1);

    var data = domainEnvelope(tooLong, true);

    expect(() => new owid(data)).toThrow("OWID domain is not terminated");
});

// A buffer whose domain field has no terminator anywhere is refused without
// the parser walking the whole buffer. JavaScript cannot measure allocation,
// and the wall clock here is dominated by the base 64 decode rather than by
// the walk, so the bound is measured by counting the walk itself. Building
// the domain is the only thing that calls String.fromCharCode while an OWID
// is being constructed, so the number of calls is the number of domain bytes
// touched. The buffer is one mebibyte of domain characters with no zero byte
// in it, and the parser must touch no more than one byte past the maximum
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
        expect(() => new owid(data))
            .toThrow("OWID domain is not terminated");
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

// A real signed envelope carrying a domain of the published maximum parses
// and verifies as the same bytes, so the bound is not retrospective on
// anything a server side library would produce.
test('signed envelope with a maximum length domain parses', () => {
    var longDomain = domainOfLength(maximumDomainLength);
    var e = signedEnvelope(longDomain);
    expect(e.signature.length).toBe(signatureLength);

    var o = new owid(e.data);

    expect(o.domain).toBe(longDomain);
    expect(Buffer.from(o.owid.payload).equals(payload)).toBe(true);
    expect(Buffer.from(o.signature).equals(e.signature)).toBe(true);
});

// The same published maximum binds the write as well as the read. A domain
// reaches this library either inside an OWID that is parsed, which the tests
// above cover, or inside an OWID tree object handed to verify or to
// verifyWithPublicKey, which is serialized so the signature can be checked
// over the bytes the creator signed. Where Web Crypto is not available that
// serialized form is also the data posted to another implementation's verify
// end point, so a domain longer than the maximum would put on the wire bytes
// this same library refuses to read. These tests prove that a domain of the
// maximum still serializes and verifies, and that one character more is
// refused before any signature is checked.

// The library serializes for verification, so a Web Crypto implementation
// has to be present for the offline check below. Node provides one and it is
// exposed here the same way a browser would, as the crypto tests do.
Object.defineProperty(global.self, 'crypto', {
    value: {
        subtle: nodeCrypto.webcrypto.subtle
    },
    configurable: true
});

/**
 * An OWID tree object of the shape a caller can hand to verify, carrying the
 * domain given. Nothing here is signed, as the domain is refused, or not,
 * before the signature is reached.
 * @param {string} domainText - the creator domain of the tree.
 * @returns {Object} the OWID tree.
 */
function domainTree(domainText) {
    return {
        version: 3,
        domain: domainText,
        date: dateInMinutes,
        payload: payload
    };
}

// A signed envelope with a domain of the maximum is parsed, serialized again
// for verification and verifies, so the write bound leaves a domain the
// library accepts today untouched and the library still round trips its own
// serialized form back to the bytes that were signed.
test('domain of the maximum length serialises and verifies', async () => {
    var longDomain = domainOfLength(maximumDomainLength);
    var e = signedEnvelope(longDomain);

    var o = new owid(e.data);

    expect(o.domain).toBe(longDomain);
    await expect(o.verifyWithPublicKey(e.publicPem)).resolves.toBe(true);
});

// A tree carrying a domain of the maximum is serialized rather than refused.
// The serializer writes the unsigned bytes only, with no signature on the
// end, so verify goes on to complain that the bytes it was given stop where
// the signature should start. That complaint, rather than one about the
// domain, is what proves the domain of the maximum was written.
test('tree with a maximum length domain is serialised', () => {
    var tree = domainTree(domainOfLength(maximumDomainLength));

    expect(() => new owid().verify(tree)).toThrow("OWID payload length");
    expect(() => new owid().verify(tree)).not.toThrow(/domain/);
});

// One character more than the maximum is refused when the tree is
// serialized, with the maximum named in the message.
test('tree with a domain over the maximum is refused', () => {
    var tooLong = domainOfLength(maximumDomainLength + 1);
    expect(tooLong.length).toBe(maximumDomainLength + 1);
    var tree = domainTree(tooLong);

    expect(() => new owid().verify(tree))
        .toThrow("OWID domain of '254' characters is longer than the '" +
            maximumDomainLength + "' character maximum");
});

// Without the write bound an over long domain in an OWID tree handed to
// verifyWithPublicKey is serialized into the message and the signature is
// checked over it, as nothing on that route reads the bytes back. The bound
// refuses the domain before any signature work, so the check below is that
// the promise is rejected and that subtle.verify was never reached.
test('domain over the maximum is refused before any signature work',
    async () => {
        var e = signedEnvelope(domain);
        var o = new owid(e.data);
        var tree = domainTree(domainOfLength(maximumDomainLength + 1));
        var verifySpy = jest.spyOn(nodeCrypto.webcrypto.subtle, 'verify');

        try {
            await expect(o.verifyWithPublicKey(e.publicPem, [tree]))
                .rejects.toMatch("character maximum");
            expect(verifySpy).not.toHaveBeenCalled();
        } finally {
            verifySpy.mockRestore();
        }
    });

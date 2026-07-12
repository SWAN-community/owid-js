/* ****************************************************************************
 * Copyright 2021 51 Degrees Mobile Experts Limited (51degrees.com)
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

// These tests exercise the local public key verification path. When
// crypto.subtle is available the library fetches the creator's public key
// from the well known end point and verifies the ECDSA signature locally
// instead of calling the remote verify end point. Node 24 provides a web
// crypto implementation, so it is exposed here in the same way a browser
// would. The OWIDs used are test data constructed and signed with node's
// crypto module inside this file, the library itself never signs anything.

const owid = require('./v1');
const nodeCrypto = require('crypto');

Object.defineProperty(global.self, 'crypto', {
    value: {
        subtle: nodeCrypto.webcrypto.subtle
    }
});

// Key pair used to sign the test OWIDs.
const creatorKeyPair = nodeCrypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1'
});

// A second key pair that has not signed anything, used to prove that
// verification fails when the creator returns the wrong public key.
const otherKeyPair = nodeCrypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1'
});

// 2021-04-06 12:59 UTC expressed as minutes since 2020-01-01 00:00 UTC.
const testDateInMinutes = 664619;

const creatorDomain = "creator.swan-demo.uk";
const wrongKeyDomain = "wrong-key.swan-demo.uk";
const emptyKeyDomain = "empty-key.swan-demo.uk";

/**
 * Builds the unsigned portion of a version 3 OWID as a byte array in the
 * same form the library serializes for verification.
 * @param {string} domain - the creator domain.
 * @param {number} dateInMinutes - minutes since the OWID base date.
 * @param {Buffer} payload - the payload bytes.
 * @returns {Buffer} the unsigned OWID bytes.
 */
function buildUnsignedOWID(domain, dateInMinutes, payload) {
    var date = Buffer.alloc(4);
    date.writeUInt32LE(dateInMinutes);
    var length = Buffer.alloc(4);
    length.writeUInt32LE(payload.length);
    return Buffer.concat([
        Buffer.from([3]),
        Buffer.from(domain, 'ascii'),
        Buffer.from([0]),
        date,
        length,
        payload
    ]);
}

/**
 * Signs the unsigned OWID bytes, together with any additional data, and
 * returns the complete OWID as a base 64 string. The signature uses the raw
 * 64 byte r and s form that the OWID format requires.
 * @param {Buffer} unsigned - the unsigned OWID bytes.
 * @param {Object} privateKey - the signing key.
 * @param {Buffer} [extra] - additional data covered by the signature, used
 * when one OWID signs another.
 * @returns {string} the complete OWID as base 64.
 */
function signOWID(unsigned, privateKey, extra) {
    var message = extra ?
        Buffer.concat([unsigned, extra]) :
        unsigned;
    var signature = nodeCrypto.sign('sha256', message, {
        key: privateKey,
        dsaEncoding: 'ieee-p1363'
    });
    return Buffer.concat([unsigned, signature]).toString('base64');
}

/**
 * Returns the base 64 string with a single byte changed at the given offset
 * of the decoded byte array.
 * @param {string} encoded - the OWID as base 64.
 * @param {number} offset - byte offset to corrupt, negative counts from the
 * end.
 * @returns {string} the corrupted OWID as base 64.
 */
function corruptByte(encoded, offset) {
    var bytes = Buffer.from(encoded, 'base64');
    var index = offset < 0 ? bytes.length + offset : offset;
    bytes[index] = bytes[index] ^ 0xFF;
    return bytes.toString('base64');
}

beforeEach(() => {
    fetchMock.resetMocks();

    fetchMock.mockResponse(req => {
        var urlString = req.url;
        if (urlString.startsWith("//")) {
            urlString = "http:" + urlString;
        }
        var url = new URL(urlString);

        if (url.pathname.endsWith("/creator")) {
            // This domain returns a header only PEM with no key body, which
            // exercises the empty public key guard in the library.
            if (url.hostname == emptyKeyDomain) {
                return Promise.resolve(JSON.stringify({
                    publicKeySPKI:
                        "-----BEGIN PUBLIC KEY-----\n" +
                        "-----END PUBLIC KEY-----"
                }));
            }
            var keyPair = url.hostname == wrongKeyDomain ?
                otherKeyPair :
                creatorKeyPair;
            return Promise.resolve(JSON.stringify({
                publicKeySPKI: keyPair.publicKey.export({
                    type: 'spki',
                    format: 'pem'
                })
            }));
        }
        return Promise.resolve({
            status: 404,
            body: "Not Found"
        });
    });
});

test('crypto verify valid OWID passes', () => {
    var unsigned = buildUnsignedOWID(
        creatorDomain, testDateInMinutes, Buffer.from("example"));
    var o = new owid(signOWID(unsigned, creatorKeyPair.privateKey));

    return o.verify().then(valid => {
        expect(valid).toBe(true);
        // The library must have used the public key path, so the only
        // request is to the creator end point.
        expect(fetch.mock.calls.length).toBe(1);
        expect(fetch.mock.calls[0][0]).toBe(
            "//" + creatorDomain + "/owid/api/v1/creator?date=" + testDateInMinutes);
    });
});

test('crypto verify sends configured fetch headers', () => {
    var unsigned = buildUnsignedOWID(
        creatorDomain, testDateInMinutes, Buffer.from("example"));
    var o = new owid(signOWID(unsigned, creatorKeyPair.privateKey));

    owid.fetchHeaders = { "X-Api-Key": "test-key" };
    return o.verify().then(valid => {
        expect(valid).toBe(true);
        expect(fetch.mock.calls.length).toBe(1);
        expect(fetch.mock.calls[0][1].headers["X-Api-Key"])
            .toBe("test-key");
    }).finally(() => {
        owid.fetchHeaders = undefined;
    });
});

test('crypto verify tampered signature fails', () => {
    var unsigned = buildUnsignedOWID(
        creatorDomain, testDateInMinutes, Buffer.from("example"));
    var valid = signOWID(unsigned, creatorKeyPair.privateKey);
    // Corrupt the last byte, which is always within the 64 byte signature.
    var o = new owid(corruptByte(valid, -1));

    return o.verify().then(valid => {
        expect(valid).toBe(false);
    });
});

test('crypto verify tampered payload fails', () => {
    var unsigned = buildUnsignedOWID(
        creatorDomain, testDateInMinutes, Buffer.from("example"));
    var valid = signOWID(unsigned, creatorKeyPair.privateKey);
    // Corrupt the last payload byte, which is the last byte before the 64
    // byte signature.
    var o = new owid(corruptByte(valid, -65));

    return o.verify().then(valid => {
        expect(valid).toBe(false);
    });
});

test('crypto verify wrong public key fails', () => {
    var unsigned = buildUnsignedOWID(
        wrongKeyDomain, testDateInMinutes, Buffer.from("example"));
    // The OWID is signed correctly but the mocked creator end point for
    // this domain returns a different public key.
    var o = new owid(signOWID(unsigned, creatorKeyPair.privateKey));

    return o.verify().then(valid => {
        expect(valid).toBe(false);
    });
});

test('crypto verify party OWID signed with creator OWID passes', () => {
    var creatorUnsigned = buildUnsignedOWID(
        creatorDomain, testDateInMinutes, Buffer.from("example"));
    var creator = new owid(
        signOWID(creatorUnsigned, creatorKeyPair.privateKey));

    // The party signature covers the party bytes followed by the complete
    // creator OWID, matching how SWAN parties sign a transaction.
    var partyUnsigned = buildUnsignedOWID(
        creatorDomain, testDateInMinutes, Buffer.from([1, 3]));
    var party = new owid(signOWID(
        partyUnsigned,
        creatorKeyPair.privateKey,
        Buffer.from(creator.data, 'base64')));

    return party.verify(creator).then(valid => {
        expect(valid).toBe(true);
    });
});

test('crypto verify empty public key PEM rejects', () => {
    var unsigned = buildUnsignedOWID(
        emptyKeyDomain, testDateInMinutes, Buffer.from("example"));
    // The OWID is signed correctly but the mocked creator end point for this
    // domain returns a header only PEM with no key data, so the import must
    // reject with the clear message rather than an opaque DOMException.
    var o = new owid(signOWID(unsigned, creatorKeyPair.privateKey));

    return expect(o.verify()).rejects.toBe(
        "public key PEM contains no key data");
});

test('crypto verify party OWID with wrong creator OWID fails', () => {
    var creatorUnsigned = buildUnsignedOWID(
        creatorDomain, testDateInMinutes, Buffer.from("example"));
    var creator = new owid(
        signOWID(creatorUnsigned, creatorKeyPair.privateKey));

    // The party signature covers different additional data to the creator
    // OWID passed to verify, so verification must fail.
    var partyUnsigned = buildUnsignedOWID(
        creatorDomain, testDateInMinutes, Buffer.from([1, 3]));
    var party = new owid(signOWID(
        partyUnsigned,
        creatorKeyPair.privateKey,
        Buffer.from("different data")));

    return party.verify(creator).then(valid => {
        expect(valid).toBe(false);
    });
});

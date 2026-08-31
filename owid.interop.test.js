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

// These tests prove cross language compatibility. The OWID fixtures below
// were created and signed by the Rust, Go and .NET implementations on
// 2026-06-12 using throwaway P-256 keys generated only for the fixtures. At
// generation time the full matrix was verified, all four implementations
// verified all of the fixtures and rejected tampered copies. As in
// owid.crypto.test.js the tests exercise the local public key verification
// path. Node 24 provides a web crypto implementation, so it is exposed here
// in the same way a browser would, and the creator end point is mocked to
// return the public key matching each fixture's signing key.

const owid = require('./v1');
const nodeCrypto = require('crypto');

Object.defineProperty(global.self, 'crypto', {
    value: {
        subtle: nodeCrypto.webcrypto.subtle
    }
});

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

// The expected payload of the utf8 fixtures once decoded as UTF-8.
const utf8PayloadText = "Zürich ❤ OWID £€";

// One fixture set per implementation. The simple case carries the ASCII
// payload "example". The utf8 case carries the UTF-8 payload above. The
// chain case is a party OWID with payload "party" whose signature also
// covers the root OWID in chainRoot, both signed with the same key.
const fixtures = [
    {
        language: "rust",
        domain: "rust.swan-demo.uk",
        publicKeySPKI:
            "-----BEGIN PUBLIC KEY-----\n" +
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQcDroVnBAGAvy1SyUz4MyFxP16ki\n" +
            "aPLulPz92rmbDbFKB6p0xl3iatZQ0uADa+F9cZeemLKtlfPaaue/KvNQOw==\n" +
            "-----END PUBLIC KEY-----\n",
        simple:
            "A3J1c3Quc3dhbi1kZW1vLnVrAD69MwAHAAAAZXhhbXBsZQtzvD+xirWingyf" +
            "DxbykxurSxK4XdixdGR5lR0xnHmv2IFSsVCub2Jd1jRg/vQJ8XnXuNljRp/E" +
            "rjSOMMQo5CI=",
        utf8:
            "A3J1c3Quc3dhbi1kZW1vLnVrAD69MwAWAAAAWsO8cmljaCDinaQgT1dJRCDC" +
            "o+KCrDHenDds+W587AzXpBb94gmLOloeBJTlHnjCkez4Dz2yAPtjcoQ6M/ZU" +
            "WDIobtJHE5n9a81pTsn/Kvi74Azzx4s=",
        chainParty:
            "A3J1c3Quc3dhbi1kZW1vLnVrAD69MwAFAAAAcGFydHmJ7qaxWgIZUHmGOQb2" +
            "xC+RuZNwrkMmo1SA9/MfI4SoEpRYdnteXAKUQXxTOK3lmQ3Qz3UwBB6gBb3Q" +
            "8hi1Wx0R",
        chainRoot:
            "A3J1c3Quc3dhbi1kZW1vLnVrAD69MwAEAAAAcm9vdFd0+QLaBLGPyBrQO+VN" +
            "unBIQZzw8/lhEiDOKTx36Dc93A0n0fzPDMt/C+BdWMqhnL4nVvyurb3IHR7D" +
            "UAmgmO0="
    },
    {
        language: "go",
        domain: "go.swan-demo.uk",
        publicKeySPKI:
            "-----BEGIN PUBLIC KEY-----\n" +
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeO51FrQ8AmCFjLnePUH1qQ4GWGxj\n" +
            "1aL5ux6vNJFSRnGTVc5YC8kEwqfOaMEjVWqt4Gbq4+lEnIAgTl76YAGpcA==\n" +
            "-----END PUBLIC KEY-----\n",
        simple:
            "A2dvLnN3YW4tZGVtby51awA/vTMABwAAAGV4YW1wbGVPIQZ/uhIjVxrROjMD" +
            "fcAkRk8U4fYacm0Ck4aOxoRDJPK/QrKavqZqCf7cCKbNuJ0aA7GhVeuy4oje" +
            "SzNX56Qn",
        utf8:
            "A2dvLnN3YW4tZGVtby51awA/vTMAFgAAAFrDvHJpY2gg4p2kIE9XSUQgwqPi" +
            "gqzxY+4QgUGt84xC9HxHmHXDt+wcB0Y9a6E+Txm2F147Qacbp0CtrF8x7QCW" +
            "ZfkcKCKNGSM8hYZEfYjJtViG+tA+",
        chainParty:
            "A2dvLnN3YW4tZGVtby51awA/vTMABQAAAHBhcnR5l7NyNmFw2lxqc4DKJWoq" +
            "0UVd5ujGV/+fvVxqYTRlwCFxaSuwvnhLQQHjX5spxWb4O08IeuiuGCat1WFB" +
            "/Wqlyw==",
        chainRoot:
            "A2dvLnN3YW4tZGVtby51awA/vTMABAAAAHJvb3R/bEqzG8gAy9yTF1UMEtOl" +
            "YXBBmn3a20jxXq5NmxIC8iuZvduOXKMf+K8VoAapkWwfpoDKQHS09IhljasZ" +
            "qC0k"
    },
    {
        language: "dotnet",
        domain: "dotnet.swan-demo.uk",
        publicKeySPKI:
            "-----BEGIN PUBLIC KEY-----\n" +
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEec6dTi0JOYGP78lw7/zAjp3r73fZ\n" +
            "A7zSi4Ov90sVxgmqZ4cI1sbj7AbsnBhqJDe5Hu14gDBjZWErL7KpkjEl0A==\n" +
            "-----END PUBLIC KEY-----",
        simple:
            "A2RvdG5ldC5zd2FuLWRlbW8udWsAPb0zAAcAAABleGFtcGxlVegwXS00P/DU" +
            "2FJbLjof8qc/BwrffhbKJkV42pqFd7nUD+KR/DxxRSfLlm77/kAyR/dLOcwE" +
            "etjN1z9UWzyh0w==",
        utf8:
            "A2RvdG5ldC5zd2FuLWRlbW8udWsAPb0zABYAAABaw7xyaWNoIOKdpCBPV0lE" +
            "IMKj4oKsVuaeaDUej0sF+cHfYj/icDBmlBLOviC6ZE28am8EtY+IGuesFcg2" +
            "rKMybcsAxMmnrDtF2xsk1cJvHgoIYpSJJQ==",
        chainParty:
            "A2RvdG5ldC5zd2FuLWRlbW8udWsAPb0zAAUAAABwYXJ0eXtD6H4R7GbvRyFU" +
            "+bCKgjMAZFFm8KHln80XPwQOBb/Ub9EZfE4Ml3ueRkKX51+MD98RFgTSmjbq" +
            "rAnzFkLlilA=",
        chainRoot:
            "A2RvdG5ldC5zd2FuLWRlbW8udWsAPb0zAAQAAAByb290fErj2LccPYCduWUW" +
            "8vY2aBjrecDfnTpVpv3+SESJMFW5pcuPKEQik2rC0fWEoB5Vr6e0k5inrhUG" +
            "iF2c2Y2YDw=="
    }
];

// Public key PEM keyed on the creator domain so the mocked creator end
// point can return the right key for each implementation.
const publicKeys = {};
fixtures.forEach(f => {
    publicKeys[f.domain] = f.publicKeySPKI;
});

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

        if (url.pathname.endsWith("/creator") && publicKeys[url.hostname]) {
            return Promise.resolve(JSON.stringify({
                publicKeySPKI: publicKeys[url.hostname]
            }));
        }
        return Promise.resolve({
            status: 404,
            body: "Not Found"
        });
    });
});

fixtures.forEach(f => {

    test('interop verify ' + f.language + ' simple OWID passes', () => {
        var o = read(f.simple);

        return o.verify().then(valid => {
            expect(valid).toBe(true);
            // The library must have used the public key path, so the only
            // request is to the creator end point.
            expect(fetch.mock.calls.length).toBe(1);
            expect(fetch.mock.calls[0][0]).toBe(
                "//" + f.domain + "/owid/api/v1/creator?date=" + o.date);
        });
    });

    test('interop verify ' + f.language + ' utf8 OWID passes', () => {
        var o = read(f.utf8);

        return o.verify().then(valid => {
            expect(valid).toBe(true);
        });
    });

    test('interop ' + f.language + ' utf8 payload decodes to the ' +
        'expected text', () => {
        var o = read(f.utf8);

        // The parsed tree exposes the payload as a byte array. Decode the
        // bytes as UTF-8 rather than using payloadAsString, which maps each
        // byte to a character and would mangle multi byte sequences.
        var text = Buffer.from(o.payload).toString('utf8');
        expect(text).toBe(utf8PayloadText);
    });

    test('interop verify ' + f.language + ' party OWID with root OWID ' +
        'passes', () => {
        // The party signature covers the party bytes followed by the
        // complete root OWID, so the root must be supplied to verify.
        var party = read(f.chainParty);

        return party.verify([f.chainRoot]).then(valid => {
            expect(valid).toBe(true);
        });
    });

    test('interop verify ' + f.language + ' party OWID without root OWID ' +
        'fails', () => {
        // Without the root OWID the signed message cannot be rebuilt, so
        // verification must fail.
        var party = read(f.chainParty);

        return party.verify().then(valid => {
            expect(valid).toBe(false);
        });
    });

    test('interop verify ' + f.language + ' tampered OWID fails', () => {
        // Corrupt the last byte, which is always within the 64 byte
        // signature.
        var o = read(corruptByte(f.simple, -1));

        return o.verify().then(valid => {
            expect(valid).toBe(false);
        });
    });
});

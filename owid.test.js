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

const owid = require('./v1');

Object.defineProperty(global.self, 'crypto', {
  value: {
    // No subtle here, so these tests take the creator verify end point route.
  }
});

const testCreatorOWID =
    "AjUxZGIudWsAKyQKAFUBAAABAWhlYWRpbmcAcG9wLXVwLnN3YW4tZGVtby51awAQAAAA27eO" +
    "AAPSTXmKZT79iWgRagI1MWRhLnVrACskCgAQAAAAs1WelonmS0KoK6uiN3rz1rAxJHj2rNKv" +
    "V/9OMOyFlWHY/tbwpdVupNG62p3pCWCuzgV2YMEth3coZhFSZHXJ1mO/U/bkHhGCSG/BStI/" +
    "fJcCNTFkYi51awArJAoAFAAAAO/c7j2xwwF8GN4hOXBIb/auLhy7mftegVZqvbepqw8nVf8B" +
    "yI94w9I/XLNwf5kAFpFeSeo8kwRhXqUyUuWT7FYIi4DnOP9zyTaAY8xgMh77oUjL/QJjbXAu" +
    "c3dhbi1kZW1vLnVrACskCgACAAAAb25Lyrbl9PDGs6VAMqgozsfxCqsVWX6pf2JyFim3zg6l" +
    "LivRDqpCD921elvxdn85/vK0msyTOMjE8buKAza/H2zBAEqEMbMuIoZL8Ji4m4ScYkpQvD3K" +
    "jsLbqI5c7+Ra/Ju43vBMp2st7QLHD4sxwPugeSBEgQRkevAm0H1a3jekMEA";

const testSupplierOWID =
    "AnBvcC11cC5zd2FuLWRlbW8udWsAKyQKAAIAAAABA6Ljm9cxZfnmwRMjv4MQ0PrAjf8y29Ru" +
    "0sjZG5R+mkjBtQD9J02xZQIk5czsKJzOl6IkOPvbPSGakxyq0HPLX+w";

const testBadOWID =
    "AmJhZHNzcC5zd2FuLWRlbW8udWsAKyQKAAIAAAABAxu+OOtismihze3LlcNuvT2WXNTGSio" +
    "gw36t85HLwL6YdV4i9kYDCdsP54RS8on/roKKASyh19TpcUQxkIRALFk";

/**
 * Reads an OWID that the test expects to be valid, asserting the three facts
 * a read always reports before handing back the OWID itself.
 * @param {string} data - the OWID as base 64.
 * @returns {Object} the OWID.
 */
function read(data) {
    var r = owid.tryParse(data);
    expect(r.ok).toBe(true);
    expect(r.status).toBe(owid.ParseStatus.PARSED);
    expect(r.owid).not.toBeNull();
    return r.owid;
}

beforeEach(() => {
    fetchMock.resetMocks();

    fetchMock.mockResponse(async req => {
        var urlString = req.url;
        if (urlString.startsWith("//")) {
            urlString = "http:" + urlString;
        } else if (urlString.startsWith("/")) {
            urlString = "http://localhost" + urlString;
        }
        var url = new URL(urlString);

        if (url.pathname.endsWith("/verify")) {
            // The library sends the OWID being verified as form parameters
            // in the POST body, so read them from there.
            var body = new URLSearchParams(await req.text());
            var owidParam = body.get("owid");
            if (owidParam == testBadOWID) {
                return JSON.stringify({valid: false});
            } else if (owidParam == null || owidParam == "") {
                return {
                    status: 400,
                    body: "Not Found"
                };
            } else {
                return JSON.stringify({valid: true});
            }
        } else if (url.pathname.endsWith("/stop")) {
            // Respond with a fragment so that the redirect performed by the
            // stop method is a hash change that jsdom can complete.
            return "#stopped";
        } else {
            return {
                status: 404,
                body: "Not Found"
            };
        }
    });

});

test('verify OWID', () => {
    var o = read(testCreatorOWID);

    return o.verify().then(result => {
        expect(result).toBe(true);
    });
});

test('verify other OWIDs - string', () => {
    return owid.verify(testCreatorOWID).then(result => {
        expect(result).toBe(true);
    });
});

test.each([
    [",", true],
    ["@", true],
    ["#", true],
    ["$", true],
    ["*", true],
    ["^", true],
    ["|", true],
    [".", true],
])('verify other OWIDs - string separator %s', (separator, expected) => {
    var owids = [
        testCreatorOWID, testCreatorOWID, testCreatorOWID].join(separator);

    return owid.verify(owids).then(result => {
        expect(result).toBe(expected);
    });
});

test('verify other OWIDs - object', () => {
    var other = read(testCreatorOWID);

    return owid.verify(other).then(result => {
        expect(result).toBe(true);
    });
});

test('verify other OWIDs - array string', () => {
    return owid.verify([testCreatorOWID]).then(result => {
        expect(result).toBe(true);
    });
});

test('verify other OWIDs - array object', () => {
    var other = read(testCreatorOWID);

    return owid.verify([other]).then(result => {
        expect(result).toBe(true);
    });
});

test('verify other OWIDs - array mixed', () => {
    var other = read(testCreatorOWID);

    return owid.verify([other, testCreatorOWID]).then(result => {
        expect(result).toBe(true);
    });
});

test('test owid properties', () => {
    var o = read(testCreatorOWID);

    // Returns the payload as a string
    expect(o.payloadAsString()).toBeDefined();

    // Returns the payload in hexadecimal
    expect(o.payloadAsPrintable()).toBeDefined();

    // Returns the payload as a base 64 string
    expect(o.payloadAsBase64()).toBeDefined();

    // Returns the creator of the OWID
    expect(o.domain).toBeDefined();

    // Returns the date and time the OWID was created in UTC
    expect(o.date).toBeDefined();

    // Returns the signature as byte array
    expect(o.signature).toBeDefined();

    // Uses a promise to determine if the OWID is valid.
    return o.verify().then(valid => {
        expect(valid).toBe(true);
    });
});

// The verify method takes other OWIDs, or strings that can be read as OWIDs.
// They are used in the order they were received to form the byte array that
// is used to verify the OWID. For example;
test('verify party\'s OWID', () => {
    var id = read(testCreatorOWID);
    var party = read(testSupplierOWID);

    return party.verify(id).then(valid => {
        expect(valid).toBe(true);
    }); // Verifies the party's OWID that was created with the swan.ID.
});

test('verify bad actor\'s OWID', () => {
    var id = read(testCreatorOWID);
    var party = read(testBadOWID);

    return party.verify(id).then(valid => {
        expect(valid).toBe(false);
    }); // Verifies the party's OWID that was created with the swan.ID.
});

// Nothing to read is not an OWID, and the read says so rather than handing
// back an instance with no data in it.
test('reading an empty string reports missing input', () => {
    var r = owid.tryParse("");

    expect(r.ok).toBe(false);
    expect(r.owid).toBeNull();
    expect(r.status).toBe(owid.ParseStatus.MISSING_INPUT);
});

test('module level verify of an empty string rejects', () => {
    return expect(owid.verify("")).rejects.toBe(
        "OWID(s) must have a value and cannot be an empty string.");
});

test('verify with an empty string as another OWID rejects', () => {
    var o = read(testCreatorOWID);

    return expect(o.verify("")).rejects.toBe(
        "OWID(s) must have a value and cannot be an empty string.");
});

// The date field of the creator fixture decodes to 664619 minutes after the
// OWID base date of 2020-01-01 00:00, which is 2021-04-06 12:59. Note that
// the implementation reads the base date without an explicit UTC marker, so
// the result matches UTC only when the local time zone offset is zero on
// 2020-01-01, as it is for the UK where these tests are normally run.
test('dateAsJavaScriptDate returns the creation date to the minute', () => {
    var o = read(testCreatorOWID);

    expect(o.date).toBe(664619);
    var expected = new Date(Date.UTC(2020, 0, 1) + 664619 * 60 * 1000);
    expect(o.dateAsJavaScriptDate().getTime()).toBe(expected.getTime());
    expect(o.dateAsJavaScriptDate().toISOString())
        .toBe("2021-04-06T12:59:00.000Z");
});

test('reading invalid base 64 reports a status rather than throwing', () => {
    var r = owid.tryParse("not valid base64!!!");

    expect(r.ok).toBe(false);
    expect(r.owid).toBeNull();
    expect(r.status).toBe(owid.ParseStatus.INVALID_BASE64);
});

// Truncating the fixture to 20 characters leaves valid base 64 of 15 bytes,
// which stops two bytes into the four byte payload length field. Data that
// stops inside a field before the length is even read is an unexpected end
// rather than a count that disagrees.
test('reading truncated base 64 is refused', () => {
    var r = owid.tryParse(testCreatorOWID.substring(0, 20));

    expect(r.ok).toBe(false);
    expect(r.owid).toBeNull();
    expect(r.status).toBe(owid.ParseStatus.UNEXPECTED_END);
});

test.each([
    [42],
    [{}],
    [true],
    [[]],
])('reading non-string input %p reports the input type', (value) => {
    var r = owid.tryParse(value);

    expect(r.ok).toBe(false);
    expect(r.owid).toBeNull();
    expect(r.status).toBe(owid.ParseStatus.INVALID_INPUT_TYPE);
});

// The expected values below were derived by reading the fixture once and are
// locked in here as a regression test.
test('creator OWID fields decode to expected values', () => {
    var o = read(testCreatorOWID);

    expect(o.version).toBe(2);
    expect(o.domain).toBe("51db.uk");
    expect(o.date).toBe(664619);
    expect(o.payload.length).toBe(341);
    expect(o.signature.length).toBe(64);
    expect(o.signature[0]).toBe(74);
    expect(o.signature[63]).toBe(64);
});

// The expected values below were derived by reading the fixture once and are
// locked in here as a regression test. The party OWID has a two byte payload
// of 0x01 0x03 which makes the exact value assertions easy to read.
test('party OWID payload accessors return exact values', () => {
    var o = read(testSupplierOWID);

    expect(o.version).toBe(2);
    expect(o.domain).toBe("pop-up.swan-demo.uk");
    expect(o.date).toBe(664619);
    expect(o.payloadAsString()).toBe("\u0001\u0003");
    // payloadAsPrintable does not pad single digit hex values, so the two
    // payload bytes 0x01 and 0x03 print as "13".
    expect(o.payloadAsPrintable()).toBe("13");
    expect(o.payloadAsBase64()).toBe("AQM=");
    expect(o.signature.length).toBe(64);
});

test('verify rejects when the verify end point returns an error', () => {
    fetchMock.mockResponseOnce("Server Error", { status: 500 });
    var o = read(testCreatorOWID);

    return expect(o.verify())
        .rejects.toMatch("'Verify' request HTTP status code: 500");
});

// A verify end point that fails leaves the signature unjudged, which is a
// different answer from the signature not matching, so it must not be
// reported as an invalid signature.
test('a failing verify end point is not an invalid signature', () => {
    fetchMock.mockResponseOnce("Server Error", { status: 500 });
    var o = read(testCreatorOWID);

    return o.verifyDetailed().then(r => {
        expect(r.ok).toBe(false);
        expect(r.status).toBe(owid.SignatureStatus.VERIFICATION_ERROR);
    });
});

// A creator answering something other than the question leaves the
// signature unjudged, which is a different answer from the signature not
// matching. Reading a missing field as false would report an end point fault
// as a forgery.
test('a verify response with no judgement is not an invalid signature', () => {
    fetchMock.mockResponseOnce(JSON.stringify({ somethingElse: true }));
    var o = read(testCreatorOWID);

    return o.verifyDetailed().then(r => {
        expect(r.ok).toBe(false);
        expect(r.status).toBe(owid.SignatureStatus.VERIFICATION_ERROR);
        expect(r.status).not.toBe(owid.SignatureStatus.SIGNATURE_INVALID);
    });
});

// A string that is not base 64 cannot be read as an OWID, and the refusal
// reaches the caller as a message rather than as one of the library's own
// internal carriers.
test('module level verify of something that is not base 64 rejects', () => {
    return expect(owid.verify("....")).rejects.toEqual(expect.any(String));
});

test('verify rejects when the verify end point cannot be reached', () => {
    fetchMock.mockRejectOnce(new Error("Network failure"));
    var o = read(testCreatorOWID);

    return expect(o.verify()).rejects.toThrow("Network failure");
});

test('stop issues the expected POST to the stop end point', async () => {
    var logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    try {
        var stopping = owid.stop(
            "cmp.swan-demo.uk", "https://return.swan-demo.uk/");

        expect(fetch.mock.calls.length).toBe(1);
        var url = fetch.mock.calls[0][0];
        var init = fetch.mock.calls[0][1];
        expect(url).toBe("/stop");
        expect(init.method).toBe("POST");
        expect(init.body.get("host")).toBe("cmp.swan-demo.uk");
        expect(init.body.get("returnUrl")).toBe("https://return.swan-demo.uk/");

        // The mocked response is a fragment, so the redirect becomes a hash
        // change that jsdom supports.
        await stopping;
        expect(window.location.hash).toBe("#stopped");
    } finally {
        logSpy.mockRestore();
    }
});

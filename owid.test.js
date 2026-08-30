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
const { subtle } = require('crypto').webcrypto;

Object.defineProperty(global.self, 'crypto', {
  value: {
    //subtle: subtle
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
    var o = new owid(testCreatorOWID);

    return o.verify().then(result => {
        expect(result).toBe(true);
    });
});

test('verify other OWIDs - string', () => {
    var o = new owid();

    return o.verify(testCreatorOWID).then(result => {
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
    var o = new owid();

    var owids = [testCreatorOWID, testCreatorOWID, testCreatorOWID].join(separator);

    return o.verify(owids).then(result => {
        expect(result).toBe(expected);
    });
});

test('verify other OWIDs - object', () => {
    var o = new owid();
    var other = new owid(testCreatorOWID)

    return o.verify(other).then(result => {
        expect(result).toBe(true);
    });
});

test('verify other OWIDs - array string', () => {
    var o = new owid();

    return o.verify([testCreatorOWID]).then(result => {
        expect(result).toBe(true);
    });
});

test('verify other OWIDs - array object', () => {
    var o = new owid();
    var other = new owid(testCreatorOWID)

    return o.verify([other]).then(result => {
        expect(result).toBe(true);
    });
});

test('verify other OWIDs - array mixed', () => {
    var o = new owid();
    var other = new owid(testCreatorOWID);

    return o.verify([other, testCreatorOWID]).then(result => {
        expect(result).toBe(true);
    });
});

test('test owid properties', () => {
    var o = new owid(testCreatorOWID);

    // Returns the payload as a string
    console.log(o.payloadAsString()); 
    expect(o.payloadAsString()).toBeDefined();

    // Returns the payload as a string
    console.log(o.payloadAsPrintable()); 
    expect(o.payloadAsPrintable()).toBeDefined();

    // Returns the payload as a base 64 array
    console.log(o.payloadAsBase64()); 
    expect(o.payloadAsBase64()).toBeDefined();

    // Returns the creator of the OWID
    console.log(o.domain); 
    expect(o.domain).toBeDefined();

    // Returns the date and time the OWID was created in UTC
    console.log(o.date); 
    expect(o.date).toBeDefined();

    // Returns the signature as byte array
    console.log(o.signature); 
    expect(o.signature).toBeDefined();

    // Uses a promise to determine if the OWID is valid.
    return o.verify().then(valid => {
        console.log(valid);
        expect(valid).toBe(true);
    }); 
});

// The verify method takes an array of others OWID instances, strings that can 
// be turned into OWIDs. There are used in the order they were received to form 
// the byte array that is used to verify the OWID. For example;
test('verify party\'s OWID', () => {
    var id = new owid(testCreatorOWID);
    var party = new owid(testSupplierOWID);

    return party.verify(id).then(valid => {
        expect(valid).toBe(true);
    }); // Verifies the party’s OWID that was created with the swan.ID.
});

test('verify bad actor\'s OWID', () => {
    var id = new owid(testCreatorOWID);
    var party = new owid(testBadOWID);

    return party.verify(id).then(valid => {
        expect(valid).toBe(false);
    }); // Verifies the party’s OWID that was created with the swan.ID.
});

test ('verify empty string throws error', () => {
    var o = new owid("");

    expect(() => o.verify()).toThrow();
    expect(() => o.verify()).toThrow("OWID must have a value and cannot be an empty string.");
});

test ('verify empty string throws error', () => {
    var o = new owid();

    expect(() => o.verify("")).toThrow();
    expect(() => o.verify("")).toThrow("OWID(s) must have a value and cannot be an empty string.");
});

test ('verify empty string throws error', () => {
    var o = new owid(testCreatorOWID);

    expect(() => o.verify("")).toThrow();
    expect(() => o.verify("")).toThrow("OWID(s) must have a value and cannot be an empty string.");
});

// The date field of the creator fixture decodes to 664619 minutes after the
// OWID base date of 2020-01-01 00:00, which is 2021-04-06 12:59. Note that
// the implementation parses the base date without an explicit UTC marker, so
// the result matches UTC only when the local time zone offset is zero on
// 2020-01-01, as it is for the UK where these tests are normally run.
test('dateAsJavaScriptDate returns the creation date to the minute', () => {
    var o = new owid(testCreatorOWID);

    expect(o.date).toBe(664619);
    var expected = new Date(Date.UTC(2020, 0, 1) + 664619 * 60 * 1000);
    expect(o.dateAsJavaScriptDate().getTime()).toBe(expected.getTime());
    expect(o.dateAsJavaScriptDate().toISOString())
        .toBe("2021-04-06T12:59:00.000Z");
});

test('constructor with invalid base 64 throws', () => {
    expect(() => new owid("not valid base64!!!")).toThrow();
});

test('parse with invalid base 64 throws', () => {
    var o = new owid();

    expect(() => o.parse("not valid base64!!!")).toThrow();
});

// Truncating the fixture after the date field leaves valid base 64 that no
// longer contains a payload or signature. Every read is bounded by the bytes
// present, so the parser refuses the envelope rather than reading past the
// end and returning empty arrays for the missing fields.
test('constructor with truncated base 64 is refused', () => {
    expect(() => new owid(testCreatorOWID.substring(0, 20)))
        .toThrow("bytes but only");
});

test.each([
    [42],
    [{}],
    [null],
    [true],
])('constructor with non-string input %p throws', (value) => {
    expect(() => new owid(value))
        .toThrow("'data' parameter must be a string or undefined");
});

// The expected values below were derived by parsing the fixture once and are
// locked in here as a regression test.
test('creator OWID fields decode to expected values', () => {
    var o = new owid(testCreatorOWID);

    expect(o.owid.version).toBe(2);
    expect(o.domain).toBe("51db.uk");
    expect(o.date).toBe(664619);
    expect(o.owid.payload.length).toBe(341);
    expect(o.signature.length).toBe(64);
    expect(o.signature[0]).toBe(74);
    expect(o.signature[63]).toBe(64);
});

// The expected values below were derived by parsing the fixture once and are
// locked in here as a regression test. The party OWID has a two byte payload
// of 0x01 0x03 which makes the exact value assertions easy to read.
test('party OWID payload accessors return exact values', () => {
    var o = new owid(testSupplierOWID);

    expect(o.owid.version).toBe(2);
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
    var o = new owid(testCreatorOWID);

    return expect(o.verify())
        .rejects.toMatch("'Verify' request HTTP status code: 500");
});

test('verify rejects when the verify end point cannot be reached', () => {
    fetchMock.mockRejectOnce(new Error("Network failure"));
    var o = new owid(testCreatorOWID);

    return expect(o.verify()).rejects.toThrow("Network failure");
});

test('stop issues the expected POST to the stop end point', async () => {
    var logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    try {
        var o = new owid();

        o.stop(undefined, "cmp.swan-demo.uk", "https://return.swan-demo.uk/");

        expect(fetch.mock.calls.length).toBe(1);
        var url = fetch.mock.calls[0][0];
        var init = fetch.mock.calls[0][1];
        expect(url).toBe("/stop");
        expect(init.method).toBe("POST");
        expect(init.body.get("host")).toBe("cmp.swan-demo.uk");
        expect(init.body.get("returnUrl")).toBe("https://return.swan-demo.uk/");

        // Allow the response chain inside stop to settle before the test
        // ends. The mocked response is a fragment so the redirect becomes a
        // hash change that jsdom supports.
        await new Promise(resolve => setTimeout(resolve, 0));
        await new Promise(resolve => setTimeout(resolve, 0));
        expect(window.location.hash).toBe("#stopped");
    } finally {
        logSpy.mockRestore();
    }
});
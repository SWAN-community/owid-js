const owid = require('./owid');

const crypto = require('crypto');

Object.defineProperty(global.self, 'crypto', {
  value: {
    getRandomValues: arr => crypto.randomBytes(arr.length)
  }
});

global.fetch = jest.fn(() =>
  Promise.resolve({
    json: () => Promise.resolve({ valid: true }),
  })
);

const testOWID = "AjUxZGEudWsA2wIKAFMBAAABAWhlYWRpbmcAbmV3LXBvcmstbGltZXMudWs" +
            "AEAAAACdy1uYpIUDfig5Yf/qrTlACNTFkYS51awDs/AkAEAAAAGbRLWHGH07KoY4" +
            "R9rDekNZxOJK3rhBYW5SbGoxD3oGrrckBvqf2gJ9eAuc4egHGxGPqKrhl8mslf7X" +
            "TlkUhXDkIKj47WYaCIzN83PgrsroOAjUxZGEudWsA2wIKABQAAADv3O49scMBfBj" +
            "eITlwSG/2ri4cu0etpQdFNMgaEf1pVN2hOV6xER9k5TXGpOuBMViaRdUQcnQQK2N" +
            "6JFW2WV6JhT+mgIzVa7unKKpoLh+r/GSjgKkCY21wLnN3YW4tZGVtby51awDbAgo" +
            "AAgAAAG9uYb2MpYHagU7oE+zvLqBhyQTNVmZquLrT+ut2GBjqYWDjC7B8KZXSJy0" +
            "rM4qDs1vI1XXKEIn3SGgZUvpCy8nohADJxLC8vAN3MgbQ8rmI8Y7NF4y8DBcAW0m" +
            "9bO9bhiO+socLw/ylL9dRcvQVojB0UNtmpiRD7LgrahVbyhUE6rk5";

test('verify OWID', () => {
    var o = new owid(testOWID);

    return o.verify().then(result => {
        expect(result).toBe(true);
    });
});

test('verify other OWIDs - string', () => {
    var o = new owid();

    return o.verify(testOWID).then(result => {
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

    var owids = [testOWID, testOWID, testOWID].join(separator);

    return o.verify(owids).then(result => {
        expect(result).toBe(expected);
    });
});

test('verify other OWIDs - object', () => {
    var o = new owid();
    var other = new owid(testOWID)

    return o.verify(other).then(result => {
        expect(result).toBe(true);
    });
});

test('verify other OWIDs - array string', () => {
    var o = new owid();

    return o.verify([testOWID]).then(result => {
        expect(result).toBe(true);
    });
});

test('verify other OWIDs - array object', () => {
    var o = new owid();
    var other = new owid(testOWID)

    return o.verify([other]).then(result => {
        expect(result).toBe(true);
    });
});

test('verify other OWIDs - array mixed', () => {
    var o = new owid();
    var other = new owid(testOWID);

    return o.verify([other, testOWID]).then(result => {
        expect(result).toBe(true);
    });
});
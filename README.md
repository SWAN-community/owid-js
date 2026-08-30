![Open Web Id](https://github.com/SWAN-community/owid/raw/main/images/owl.128.pxls.100.dpi.png)

# Open Web Id (OWID) JavaScript

## Overview

Open Web Id (OWID) is an open source cryptographically secure shared web
identifier schema. This repository implements OWID in JavaScript.

Read the [OWID](https://github.com/SWAN-community/owid) project to learn more
about the concepts before looking into this implementation.

## Scope of this implementation

This library is verify only and is intended for use in the browser. It reads
OWIDs that were created elsewhere and verifies their signatures. It cannot
create or sign OWIDs. Creation and signing are performed by the server side
implementations.

When the browser provides `crypto.subtle` the library fetches the creator's
public key from their well known end point and verifies the ECDSA signature
locally. When `crypto.subtle` is not available it falls back to the creator's
remote verify end point.

The public key is requested for the OWID's own creation date
(`?date=<minutes>`), so OWIDs signed before a signing-key rotation still
verify. A creator that does not support the `date` parameter ignores it and
returns its current key.

Servers MAY require a credential on the creator end point. Supply the
required headers via `owid.fetchHeaders` before verifying:

```js
owid.fetchHeaders = { "X-Api-Key": "your key" };
```

The headers are sent to every creator domain that a verification touches,
so only set a credential that all the creators in the tree are meant to
see.

## Reading answers instead of throwing

An OWID is read from whatever a caller was handed, which on a public end
point means anything at all, so malformed data is an ordinary outcome rather
than an error. `owid.tryParse` and `owid.tryParseBytes` therefore never
throw. Each returns a frozen result reporting the same three facts:

|Field|Type|Description|
|-|-|-|
|ok|boolean|True when the bytes were a complete, structurally valid OWID.|
|owid|Object\|null|The OWID on success and null on failure.|
|status|string|`ParseStatus.PARSED` on success, otherwise the specific reason.|

A failure result also carries the numbers that disagreed where there are
any, being `declared` and `present` for a byte count mismatch and `version`
for an unsupported version. It never carries any part of the input, so
logging a failure cannot log whatever an untrusted sender chose to put in
it.

```js
var result = owid.tryParse(untrusted);
if (result.ok) {
    result.owid.verify().then(valid => console.log(valid));
} else {
    console.log("not an OWID: " + result.status);
}
```

### Read statuses

`owid.ParseStatus` is a frozen object of stable string values. Compare
against its members rather than against the text of any message.

|Status|Meaning|
|-|-|
|PARSED|The bytes form a structurally valid OWID. This says nothing about the signature.|
|MISSING_INPUT|Nothing was supplied to read, including an empty string or an empty buffer.|
|INVALID_INPUT_TYPE|The input was supplied in a form this surface cannot read.|
|INVALID_BASE64|The string is not valid base 64, so there are no bytes to read.|
|UNSUPPORTED_VERSION|The first byte names a version this implementation does not know.|
|UNEXPECTED_END|The data stopped in the middle of a field.|
|INVALID_DOMAIN_ENCODING|The creator domain is not terminated, or is longer than the published maximum.|
|BYTE_COUNT_MISMATCH|The declared payload byte count disagrees with the bytes actually present.|
|IMPLEMENTATION_CAPACITY_EXCEEDED|The envelope is structurally consistent but larger than this runtime can hold.|
|MALFORMED_ENVELOPE|Malformed in a way none of the above describes.|

Reading and verifying are two questions with two answers. A structurally
valid identifier whose signature does not match reads successfully and then
fails verification, and a read fetches no key and checks no signature.

### Signature statuses

`owid.SignatureStatus` is a frozen object of stable string values. Only
`SIGNATURE_VALID` and `SIGNATURE_INVALID` say anything about the signature
itself, and the rest say the question could not be answered. A network
failure, a missing key, a malformed key response or an invalid PEM must
never be read as a forgery.

|Status|Meaning|
|-|-|
|SIGNATURE_VALID|The signature is genuine for this data and this key.|
|SIGNATURE_INVALID|The signature is well formed and does not match. The only status that means the identifier should be distrusted.|
|INVALID_SIGNATURE_LENGTH|A signature field of the wrong length reached a verification surface directly. No surface in this library takes a signature on its own, so nothing reports this today.|
|KEY_UNAVAILABLE|No key could be obtained, or none covers the identifier's date.|
|INVALID_KEY|Key material arrived but cannot be decoded, imported or used as the required type.|
|IMPLEMENTATION_CAPACITY_EXCEEDED|The work required exceeds what this runtime can hold. Nothing reports this today.|
|VERIFICATION_ERROR|The check could not be completed for a reason that is not the identifier's fault.|

`verifyDetailed` and `verifyWithPublicKeyDetailed` report these statuses.
The plain `verify` and `verifyWithPublicKey` reduce them to a boolean,
resolving true or false only for the two statuses that judge the signature
and rejecting for the rest, because a caller told false would treat an
outage as a forgery.

## An OWID cannot be built

An OWID is only worth anything because it is signed, and an unsigned one is
indistinguishable from a signed one to the code downstream of it, with the
difference surfacing later where nobody is watching. This library therefore
has no constructor. An OWID reaches calling code by one route only, which is
a successful read of a complete serialized OWID. Because the library is
verify only there is no create operation either, so signing remains with the
server side implementations.

`new owid(...)` throws, naming what to use instead. An OWID that has been
read is frozen, its fields are read only, and `payload` and `signature` are
handed out as fresh copies, so writing into one cannot change the OWID whose
signature was checked over the bytes as they arrived.

Where the library is given other OWIDs that the same signature covered, it
accepts base 64 strings and OWIDs from `tryParse`, and refuses an object
that merely carries the same field names, because such an object has never
been read from anything.

## Payload size and application limits

The OWID wire format stores the payload length as an unsigned 32 bit value,
so a payload from zero through 4,294,967,295 bytes is structurally valid. The
format defines no smaller payload limit. The null-terminated domain is
bounded at the 253 characters RFC 1035 allows a domain name in its
presentation form, so the protocol alone is not an application input limit
for the complete envelope.

This library validates that the declared payload length agrees with the bytes
present before it takes a view of the payload. A large declaration without
the corresponding bytes is malformed and is reported as
`BYTE_COUNT_MISMATCH` without allocating the declared size. A matching large
payload is not malformed merely because it is large, and reading work and
memory use scale with the bytes actually present.

The in-memory APIs remain subject to the browser's typed-array, string,
address-space and available-memory limits. Applications accepting untrusted
OWIDs must choose limits suitable for their use case and enforce them before
buffering or base 64 decoding the input. An implementation capacity failure
or an application policy rejection is distinct from an invalid OWID.

For transport input, limit the complete HTTP body or encoded envelope; allow
for the domain and other OWID fields as well as the payload. After reading,
`instance.payload.length` reports the actual payload size and can be used for
downstream policy, noting that each read of `payload` is a fresh copy.

## Usage

To use OWID-js:

* Add the `owid.js` file to your CDN or web application.
* reference owid.js:
    ```html
    <script src="https://<host>/owid.js" type="text/javascript"></script>
    ```
* call the library:
    ```js
    var result = owid.tryParse("[owid base 64 string]");
    if (result.ok) {
        result.owid.verify().then(valid => console.log(valid));
    }
    ```

## Interface

### Module operations

|Operation|Params|Return Type|Description|
|-|-|-|-|
|tryParse|base 64 string|Object|Reads a complete OWID from its base 64 form. Never throws.|
|tryParseBytes|Uint8Array|Object|Reads a complete OWID from a buffer holding exactly one. Never throws.|
|isOwid|any|boolean|True when the value is an OWID this library read.|
|verify|owid\|owids[]|Promise(bool)|Verifies each of the OWIDs supplied in its own right. Resolves to true when every one of them is genuine.|
|stop|domain, return url|Promise|Posts the domain and return URL to the `/stop` end point and redirects the browser to the URL contained in the response.|
|ParseStatus|n/a|Object|Frozen read statuses.|
|SignatureStatus|n/a|Object|Frozen signature statuses.|
|fetchHeaders|n/a|Object|Optional HTTP headers sent with the creator request.|

### Methods

Methods available on an OWID returned by a successful read.

|Method|Params|Return Type|Description|
|-|-|-|-|
|dateAsJavaScriptDate|n/a|Date|Returns the OWID creation date as a JavaScript Date object.|
|payloadAsPrintable|n/a|string|Returns the payload in hexadecimal.|
|payloadAsString|n/a|string|Returns the payload as a string.|
|payloadAsBase64|n/a|string|Returns the payload as a base 64 string.|
|verify|owid\|owids[] (optional)|Promise(bool)|Determines whether this OWID is genuine, together with any other OWIDs the same signature covered. Rejects when the question could not be answered.|
|verifyDetailed|owid\|owids[] (optional)|Promise(Object)|As verify, reporting a `SignatureStatus` for every outcome.|
|verifyWithPublicKey|SPKI PEM, owids[] (optional)|Promise(bool)|Verifies offline against a caller supplied public key, contacting no network end point.|
|verifyWithPublicKeyDetailed|SPKI PEM, owids[] (optional)|Promise(Object)|As verifyWithPublicKey, reporting a `SignatureStatus`.|

### Fields

All fields are read only. `payload` and `signature` are fresh copies on each
read.

|Field|Type|Description|
|-|-|-|
|data|string|Returns the OWID as a base 64 string.|
|version|number|Returns the OWID version byte.|
|date|number|Returns the date and time the OWID was created in UTC as minutes since `2020-01-01 00:00`|
|domain|string|Returns the creator of the OWID.|
|payload|Uint8Array|Returns the payload as a byte array.|
|signature|Uint8Array|Returns the signature as byte array.|

## Examples

Every call below is exercised by the test suite, so an example naming
something that does not exist fails the build rather than misleading the next
reader. The first example is run as written in
`owid.parse-contract.test.js`.

Read and verify an OWID.

```js
var result = owid.tryParse("[signed OWID]");
if (!result.ok) {
    console.log("not an OWID: " + result.status);
    return;
}
var o = result.owid;

console.log(o.payloadAsString()); // Returns the payload as a string.
console.log(o.payloadAsPrintable()); // Returns the payload as a hexadecimal.
console.log(o.payloadAsBase64()); // Returns the payload as a base 64 string.
console.log(o.domain); // Returns the creator of the OWID.
console.log(o.date); // Minutes since 2020-01-01 00:00 UTC.
console.log(o.signature); // Returns the signature as byte array.

o.verify()
    .then(valid => console.log(valid)) // True when the signature is genuine.
    .catch(error => console.log(error)); // The question could not be answered.
```

Verify one OWID that was signed with another OWID.

```js
var o = owid.tryParse("[signed OWID]").owid;
var other = owid.tryParse("[other signed OWID]").owid;

o.verify(other)
    .then(valid => console.log(valid))
    .catch(error => console.log(error));
```

Verify one OWID with multiple OWID base 64 strings.

```js
var o = owid.tryParse("[signed OWID]").owid;

o.verify(["[signed OWID 1]", "[signed OWID 2]", "[signed OWID 3]"])
    .then(valid => console.log(valid))
    .catch(error => console.log(error));
```

Verify several OWIDs, each in its own right.

```js
owid.verify(["[signed OWID 1]", "[signed OWID 2]"])
    .then(valid => console.log(valid))
    .catch(error => console.log(error));
```

Tell an outage apart from a forgery.

```js
owid.tryParse("[signed OWID]").owid.verifyDetailed().then(r => {
    if (r.status === owid.SignatureStatus.SIGNATURE_INVALID) {
        // The identifier should be distrusted.
    } else if (!r.ok) {
        // The signature was never judged. Do not treat this as a forgery.
        console.log(r.status + ": " + r.message);
    }
});
```

## Migrating from the constructor

|Before|After|
|-|-|
|`var o = new owid(s);`|`var r = owid.tryParse(s); if (r.ok) { var o = r.owid; }`|
|`try { new owid(s) } catch (e) { }`|`if (!owid.tryParse(s).ok) { }`|
|`new owid().verify(others)`|`owid.verify(others)`|
|`new owid().parse(s)`|`owid.tryParse(s)`|
|`new owid().stop(undefined, d, r)`|`owid.stop(d, r)`|
|`o.owid.version`|`o.version`|
|`o.owid.payload`|`o.payload`|
|`o.owid.payloadAsString()`|`o.payloadAsString()`|
|a hand built `{version, domain, date, payload}` passed to `verify`|not supported, pass a base 64 string or an OWID from `tryParse`|

## Testing

Tests are performed using Jest. The fetch calls made by the library are
mocked with jest-fetch-mock. The tests in `owid.test.js` cover reading and
the remote verify end point. The tests in `owid.parse-contract.test.js` cover
what a read reports, that an OWID cannot be built or changed, and that
reading and verifying stay two separate questions. The tests in
`owid.payload-length.test.js` cover the declared payload length and the
creator domain bound. The tests in `owid.crypto.test.js` cover local ECDSA
signature verification using the web crypto implementation provided by Node.
The tests in `owid.interop.test.js` verify externally signed fixtures to
prove signature compatibility.

### Pre-requisites

* Node.js version 15 or above. The tests are routinely run with Node.js 24.
* Yarn or npm. The repository includes a `yarn.lock` file, so Yarn is
  preferred.

### Steps

Install yarn if it is not already available.

```bash
npm install --global yarn
```

Install the dependencies.

```bash
yarn install
```

Run the tests.

```bash
yarn test
```

Alternatively use npm.

```bash
npm install
npm test
```

## License

This project is licensed under the Apache License, Version 2.0. See the
[LICENSE](LICENSE) file for details.

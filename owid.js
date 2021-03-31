owid = function() {
    "use-strict";

    // Parses a base 64 byte array into an ascii string.
    function parseToString(v) {
    }

    // Parses a base 64 encoded byte array into a OWID tree.
    function parse(v) {

        function readByte(b) {
            return b.array[b.index++];
        }

        function readString(b) {
            var r = ""; 
            while (b.index < b.array.length && b.array[b.index] != 0) {
                r += String.fromCharCode(b.array[b.index++]);
            }
            b.index++;
            return r;
        }

        function readUint32(b) {
            return b.array[b.index++] | 
                b.array[b.index++]<<8 | 
                b.array[b.index++]<<16 |
                b.array[b.index++]<<24;
        }

        function readByteArray(b) {
            var c = readUint32(b);
            var r = b.array.slice(b.index, b.index + c)
            b.index += c;
            return r;
        }

        function readDate(b, v) {
            if (v == 1) {
                var h = readByte(b);
                var l = readByte(b);
                return (h>>8 | l) * 24 * 60;
            } 
            if (v == 2) {
                return readUint32(b);
            }
        }

        function readSignature(b) {
            var c = 64; // The OWID signature is always 64 bytes.
            var r = b.array.slice(b.index, b.index + c)
            b.index += c;
            return r;
        }

        function readOWID(b) {
            var o = Object();
            o.version = readByte(b);
            o.domain = readString(b);
            o.date = readDate(b, o.version);
            o.payload = readByteArray(b);
            o.signature = readSignature(b);
            o.payloadAsString = function() {
                var s = "";
                Uint8Array.from(this.payload, c => s+=String.fromCharCode(c));
                return s;
            };
            o.payloadAsPrintable = function() { 
                var s = "";
                Uint8Array.from(this.payload, c => s+=(c&0xFF).toString(16));
                return s;
            }
            return o
        }

        // Decode the base64 string into a byte array.
        var b = Object();
        b.index = 0;
        b.array = Uint8Array.from(atob(v), c => c.charCodeAt(0));

        // Unpack the byte array into the OWID tree.
        var q = [];
        var r = readOWID(b);
        q.push(r);
        while (q.length > 0) {
            var n = q.shift();
            for (var i = 0; i < n.count; i++) {
                var c = readOWID(b);
                n.children.push(c)
                c.parent = n
                q.push(c)
            }
        }

        return r;
    }

    function getByteArray(t) {

        function writeByte(b, v) {
            b.push(v);
        }

        function writeString(b, v) {
            for (var i = 0; i < v.length; i++) {
                b.push(v.charCodeAt(i));
            }
            b.push(0);
        }

        function writeUint32(b, v) {
            var a = new ArrayBuffer(4);
            var d = new DataView(a);
            d.setUint32(0, v, true);
            for (var i = 0; i < 4; i++) {
                b.push(d.getUint8(i));
            }
        }

        function writeByteArray(b, v) {
            writeUint32(b, v.length)
            v.forEach(e => b.push(e));
        }

        if (t.version && t.domain && t.date && t.payload) {
            var buf = [];
            writeByte(buf, t.version);
            writeString(buf, t.domain);
            writeUint32(buf, t.date);
            writeByteArray(buf, t.payload);
            return new Uint8Array(buf);
        }
    }

    this.parse = function(t) { return parse(t); }

    this.stop = function(s, d, r) {
        fetch("/stop?" +
            "host=" + encodeURIComponent(d) + "&" +
            "returnUrl=" + encodeURIComponent(r),
            { method: "GET", mode: "cors", cache: "no-cache" })
            .then(r => r.text() )
            .then(m => {
                console.log(m);
                window.location.href = m;
            })
            .catch(x => {
                console.log(x);
            });
    }

    this.appendComplaintEmail = function(e, d, o, s, g) {
        fetch((d ? "//" + d : "") + "/complain?" +
            "offerid=" + encodeURIComponent(o) + "&" +
            "swanowid=" + encodeURIComponent(s),
            { method: "GET", mode: "cors", cache: "no-cache" })
            .then(r => r.text() )
            .then(m => {
                var a = document.createElement("a");
                a.href = m;
                if (g) {
                    var i = document.createElement("img");
                    i.src = g;
                    i.style="width:32px"
                    a.appendChild(i);
                } else {
                    a.innerText = "?";
                }
                e.appendChild(a);
            }).catch(x => {
                console.log(x);
            });
    }

    this.appendName = function(e, s) {
        fetch("//" + parse(s).domain + "/owid/api/v1/creator", 
            { method: "GET", mode: "cors" })
            .then(r => r.json())
            .then(o => {
                var t = document.createTextNode(o.name);
                e.appendChild(t);
            }).catch(x => {
                console.log(x);
                var t = document.createTextNode(x);
                e.appendChild(t);
            });
    }

    this.appendAuditMark = function(e, r, t) {

        function importRsaKey(pem) {
            
            // Remove the header, footer and line breaks to get the PEM content.
            var lines = pem.split('\n');
            var pemContents = '';
            for (var i = 0; i < lines.length; i++) {
                if (lines[i].trim().length > 0 &&
                    lines[i].indexOf('-----BEGIN RSA PUBLIC KEY-----') < 0 &&
                    lines[i].indexOf('-----END RSA PUBLIC KEY-----') < 0) {
                    pemContents += lines[i].trim();
                }
            }

            // Import the public key with the SHA-256 hash algorithm.
            return window.crypto.subtle.importKey(
                "spki",
                Uint8Array.from(atob(pemContents), c => c.charCodeAt(0)),
                {
                name: "RSASSA-PKCS1-v1_5",
                hash: "SHA-256"
                },
                false,
                ["verify"]
            );
        }

        // Append a failure HTML element.
        function returnFailed(e) {
            var t = document.createTextNode("Failed");
            e.appendChild(t);
        }

        // Append an audit HTML element.
        function addAuditMark(e, r) {
            var t = document.createElement("img");
            if (r) {
                t.src = "/green.svg";
            } else {
                t.src = "/red.svg";
            }
            e.appendChild(t);
        }

        // Use the well known end point for the alleged OWID creator. 
        function verifyOWIDWithAPI(p, t) {
            var o = parse(t)
            return fetch("//" + o.domain +
                "/owid/api/v" + o.version + "/verify" +
                "?parent=" + encodeURIComponent(p) + 
                "&owid=" + encodeURIComponent(t),
                { method: "GET", mode: "cors", cache: "no-cache" })
                .then(r => r.json())
                .then(r => r.valid);
        }

        // Verify the payload of this OWID is the signature of the parent
        // OWID.
        function verifyOWIDWithPublicKey(r, t) {
            var o = parse(t)
            var a = getByteArray(o);
            var b = Uint8Array.from(atob(r), c => c.charCodeAt(0));
            var m = new Uint8Array(a.length + b.length);
            m.set(a);
            m.set(b, a.length);
            return fetch("//" + o.domain + "/owid/api/v1/creator",
                { mode: "cors", cache: "default" })
                .then(response => response.json())
                .then(c => importRsaKey(c.publicKeySPKI))
                .then(k => crypto.subtle.verify(
                    "RSASSA-PKCS1-v1_5",
                    k,
                    o.signature,
                    m));
        }

        // Valid the OWID against the creators public key OR if crypto not 
        // supported the well known end point for OWID creators. OWID providers
        // are not required to operate an end point for verifying OWIDs so these
        // calls might fail to return a result.
        if (window.crypto.subtle) {
            verifyOWIDWithPublicKey(r, t)
                .then(r => addAuditMark(e, r))
                .catch(x => {
                    console.log(x);
                    returnFailed(e);
                })
        } else {
            verifyOWIDWithAPI(r, t)
                .then(r => addAuditMark(e, r))
                .catch(x => {
                    console.log(x);
                    returnFailed(e);
                });
        }
    }
}
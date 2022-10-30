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

import * as crypto from 'crypto';

const { subtle } = crypto.webcrypto;

type PemType = Exclude<KeyType, 'secret'>;

export class Crypto {

    // The ECDSA settings to use with OWIDs.
    private static readonly ECDSA = {
        name: 'ECDSA',
        namedCurve: 'P-256',
        hash: { name: 'SHA-256' }
    };

    /**
     * Creates a public and private key pair for signing and verification. 
     * The keys can be exported for storage in PEM or other formats.
     * @returns a pair of private and public keys
     */
    public static async generateKeys(): Promise<CryptoKeyPair> {
        return subtle.generateKey(Crypto.ECDSA, true, ['sign', 'verify']);
    }

    /**
     * sign the data with the key provided.
     * @param key to sign the data with
     * @param data to be signed
     * @returns an array of bytes representing the signature
     */
    public static async sign(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
        if (key.usages.find((i) => 'sign' === i)) {
            return new Uint8Array(await subtle.sign(Crypto.ECDSA, key, data.buffer));
        }
        throw new Error('key does not support sign');
    }

    /**
     * verify confirms the signature matches the data.
     * @param key
     * @param signature
     * @param data
     * @returns true if the signature matches the data, otherwise false
     */
    public static async verify(
        key: CryptoKey, 
        signature: Uint8Array, 
        data: Uint8Array): Promise<boolean> {
        if (key.usages.find((i) => 'verify' === i)) {
            return subtle.verify(Crypto.ECDSA, key, signature, data);
        }
        throw new Error('key does not support verify');
    }

    /**
     * Turns the public or private key into a PEM format string.
     * @param key to be exported
     * @returns string containing the key in PEM format
     */
    public static async exportKey(key: CryptoKey): Promise<string> {
        const type = key.type.toUpperCase();
        const k = new Uint8Array(await subtle.exportKey('spki', key));
        let b = '';
        for (let i = 0; i < k.length; i++) {
            b += String.fromCharCode(k[i]);
        }
        const base64 = btoa(b);
        let pemContents = `-----BEGIN ${type} KEY-----\n`;
        let index = 0;
        while(index < base64.length) {
            pemContents += base64.substring(index, index + 64) + '\n';
            index += 64;
        }
        pemContents = pemContents + `-----END ${type} KEY-----`;
        return pemContents;
    }

    public static importKey(pem: string): Promise<CryptoKey> {
        if (pem.indexOf('PRIVATE') >= 0) {
            return Crypto.importPrivateKey(pem);
        }
        if (pem.indexOf('PUBLIC') >= 0) {
            return Crypto.importPublicKey(pem);
        }
        throw new Error('PEM key must contain PRIVATE or PUBLIC');
    }

    /**
     * Converts a PEM format public key into a crypto key that can be used to verify an OWID.
     * @param pem public key in PEM format
     * @returns 
     */
     public static importPublicKey(pem: string): Promise<CryptoKey> {
        return subtle.importKey(
            'spki',
            Crypto.getPemByteArray(pem, 'public'),
            Crypto.ECDSA,
            false,
            ['verify']);
    }

    /**
     * Converts a PEM format private key into a crypto key that can be used to sign an OWID.
     * @param crypto instance
     * @param pem private key in PEM format
     * @returns a new instance of a crypto key configured for signing OWIDs
     */
    public static importPrivateKey(pem: string): Promise<CryptoKey> {
        return subtle.importKey(
            'spki',
            Crypto.getPemByteArray(pem, 'private'),
            Crypto.ECDSA,
            false,
            ['sign']);
    }
    
    /**
     * Obtains the byte array for use with the crypto import key method.
     * @param pem format key
     * @param type private or public
     * @returns byte array containing the key
     */
    private static getPemByteArray(pem: string, type: PemType): Uint8Array {
        const content = Crypto.getPemContents(pem, type);
        if (content && content.length > 0) {
            return Uint8Array.from(atob(content), c => c.charCodeAt(0));
        }
        throw new Error(`pem '${pem}' invalid`);
    }

    /**
     * Obtains the base 64 format string ready to be converted to a byte array.
     * @param pem format key
     * @param type private or public
     * @returns base 64 string
     */
    private static getPemContents(pem: string, type: PemType): string {
        const begin = `-----BEGIN ${type.toUpperCase()} KEY-----`;
        const end = `-----END ${type.toUpperCase()} KEY-----`;
        const lines = pem.split('\n');
        let pemContents = '';
        for (let i = 0; i < lines.length; i++) {
            if (lines[i].trim().length > 0 &&
                lines[i].indexOf(begin) < 0 &&
                lines[i].indexOf(end) < 0) {
                pemContents += lines[i].trim();
            }
        }
        return pemContents;
    }
}
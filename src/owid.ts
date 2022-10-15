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

import { Signer } from './signer';
import { DateHelper } from './dateHelper';
import { Io, Reader } from './io';
import { Crypto } from './crypto';
import { PublicKey } from './publicKey';
import { SignerCache } from './signerCache';
import { PrivateKey } from './privateKey';

export interface OWIDTarget {

    /**
     * Adds to the buffer the bytes that form the target of the OWID.
     * @param buffer to add bytes to
     */
    addOwidData(buffer: number[]): void;
}

/**
 * Interface used for serialization.
 */
export interface IOWID {
    version: number; // The byte version of the OWID.
    domain: string; // Domain associated with the signer.
    // The date and time to the nearest minute in UTC that the OWID was signed.
    timestamp: number; 
    // Signature for this OWID and the data returned from the target.
    signature: string; 
}

/**
 * The OWID class and instance of which is contained in target data structures.
 */
export class OWID<T extends OWIDTarget> implements IOWID {
    
    public version: number; // The byte version of the OWID.
    public domain: string; // Domain associated with the signer.
    // The date and time to the nearest minute in UTC that the OWID was signed.
    public timestamp: number; 
    public signatureArray: Uint8Array; // The signature as a byte array.
    
    /**
     * Gets the time stamp as a date so that it can be compared to other dates.
     * Note: OWID's store the timestamp as the number of minutes since 1st 
     * January 2020.
     * @returns the time stamp as a Date instance
     */
    public get timeStampDate(): Date {
        return DateHelper.getDateFromMinutes(this.timestamp);
    }
    public set timeStampDate(value: Date) {
        this.timestamp = DateHelper.getDateInMinutes(value);
    }

    /**
     * Signature for this OWID and the data returned from the target.
     */
    public get signature(): string {
        return Io.byteArrayToBase64(this.signatureArray);
    }
    public set signature(value: string) {
        this.signatureArray = Uint8Array.from(atob(value), c => c.charCodeAt(0));
    }

    /**
     * True if the OWID is signed, otherwise false.
     */
    public get isSigned(): boolean {
        return this.signatureArray && this.signatureArray.length > 0;
    }

    /**
     * Constructs a new instance of an OWID from the source if provided.
     * @param source
     * @param target that the OWID relates to.
     */
    constructor(public target: T, source?: IOWID) {
        if (source) {
            Object.assign(this, source);
        }
    }

    /**
     * Set the members of this instance from the byte array reader provided.
     * @param array 
     */
    public fromByteArray(b: Reader) {
        this.version = Io.readByte(b);
        switch(this.version) {
            case 1: 
                this.fromByteArrayV1(b);
                break;
            default:
                throw new Error(`version ${this.version} not supported`);
        }
    }

    /**
     * Read the byte array as a version 1 OWID.
     * @param b 
     */
    private fromByteArrayV1(b: Reader) {
        this.domain = Io.readString(b);
        this.timestamp = Io.readDate(b);
        this.signatureArray = Io.readSignature(b);
    }   

    /**
     * Sign the data provided and update the signature of the OWID. The
     * timestamp is updated to the current time. The domain and timestamp are 
     * appended to the target data before signing.
     * @param cryptoKey the private key instance
     */
    public async signWithCryptoKey(cryptoKey: CryptoKey): Promise<void> {
        this.timestamp = DateHelper.getDateInMinutes(new Date());
        const data = Uint8Array.from(this.addTargetAndOwidData([]));
        const buffer = await Crypto.sign(cryptoKey, data);
        this.signatureArray = new Uint8Array(buffer);
    }

    /**
     * Sign the data provided and update the signature of the OWID. The 
     * timestamp is updated to the current time. The domain and timestamp are
     * appended to the target data before signing.
     * @param pemKey PEM format private key
     */
    public async signWithPemKey(pemKey: string): Promise<void> {
        this.signWithCryptoKey(await Crypto.importPrivateKey(pemKey));
    }
    
    /**
     * Sign the data provided and update the signature of the OWID. The 
     * timestamp is updated to the current time. The domain and timestamp are 
     * appended to the target data before signing.
     * @param signer instance where the most recent private key is used
     */
    public async signWithSigner(signer: Signer): Promise<void> {
        let newest: PrivateKey;
        for(let i = 0; i < signer.privateKeys.length; i++) {
            const key = signer.privateKeys[i];
            if (!newest || key.created > newest.created) {
                newest = key;
            }
        }
        if (newest) {
            this.signWithPemKey(newest.key);
        }
    }   

    /**
     * verifyWithCrypto the signature in the OWID and the data provided.
     * @param key public key for verification
     * @returns true if the signature matches the data, otherwise false
     */
    public async verifyWithCrypto(key: CryptoKey): Promise<boolean> {
        const data = Uint8Array.from(this.addTargetAndOwidData([]));
        return Crypto.verify(key, this.signatureArray, data);
    }

    /**
     * Verifies the signature in the OWID and the associated target using the 
     * PEM format public key.
     * @param key public key 
     * @returns true if the signature matches the data, otherwise false
     */
    public async verifyWithPublicKey(key: PublicKey): Promise<boolean> {
        if (!key.cryptoKey) {
            key.cryptoKey = await Crypto.importPublicKey(key.key);
        }
        return this.verifyWithCrypto(key.cryptoKey);
    }

    /**
     * Chooses public keys created on or before the timestamp in the OWID to 
     * determine if any of then can verify the signature. A one hour tolerance
     * is used for the time stamp check to handle clock differences between 
     * difference environments.
     * @param keys one or more public keys
     */
    public async verifyWithPublicKeys(keys: PublicKey[]): Promise<boolean> {
        const time = this.timeStampDate.getTime();
        for(let i = 0; i < keys.length; i++) {
            const key = keys[i];
            // Take 1 hour from the created time to handle any clock differences
            // between participants.
            const created = key.createdDate.getTime() - 60 * 60 * 1000;
            if (time >= created) {
                if (await this.verifyWithPublicKey(key)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Verify this OWID with the provided signer.
     * @param signer
     * @returns true if the signature matches the data, otherwise false
     */
    public async verifyWithSigner(signer: Signer): Promise<boolean> {
        return this.verifyWithPublicKeys(signer.publicKeys);
    }

    /**
     * Verify this OWID by fetching the public keys from the signer's domain 
     * using the cache.
     * @param cache
     * @returns true if the signature matches the data, otherwise false
     */
    public async verifyWithCache(cache: SignerCache): Promise<boolean> {
        const signer = await cache.get(this);
        if (signer) {
            return this.verifyWithSigner(signer);
        }
        return false;
    }

    /**
     * Adds the target data and then the OWID data to the byte array ready for
     * signing or verification. The domain and timestamp associated with the
     * OWID also need to be included in the data that is passed to signing or 
     * verification.
     * @param b byte array to append the target and OWID data to
     * @returns the updated byte array which was passed to the method
     */
    public addTargetAndOwidData(b: number[]): number[] {
        if (this.target) {
            this.target.addOwidData(b);
            Io.writeByte(b, this.version);
            Io.writeString(b, this.domain);
            Io.writeUint32(b, this.timestamp);
            return b;
        }
        throw new Error('target must be set');
    }

    /**
     * A fresh instance of the interface for serialization.
     * @returns 
     */
    public asInterface(): IOWID {
        return {
            version: this.version,
            domain: this.domain,
            signature: this.signature,
            timestamp: this.timestamp};
    }
}
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
import { Io } from './io';
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
 * The OWID class and instance of which is contained in target data structures.
 */
export class OWID<T extends OWIDTarget> {
    
    public version: number; // The byte version of the OWID.
    public domain: string; // Domain associated with the signer.
    public timeStamp: number; // The date and time to the nearest minute in UTC that the OWID was signed.
    public signature: Uint8Array; // Signature for this OWID and the data returned from the target.
    public target: T; // The target that the OWID relates to.
    private timeStampAsDate: Date; // The date and time that the OWID was signed. Populated by getTimeStamp().

    /**
     * Constructs a new instance of an OWID.
     * @param domain for the signer of the OWID
     */
    constructor(domain?: string) {
        this.domain = domain;
    }

    /**
     * Sign the data provided and update the signature of the OWID. The timestamp is updated to the current time. The
     * domain and timestamp are appended to the target data before signing.
     * @param cryptoKey the private key instance
     */
    public async signWithCryptoKey(cryptoKey: CryptoKey): Promise<void> {
        this.timeStamp = DateHelper.getDateInMinutes(new Date());
        const data = Uint8Array.from(this.addTargetAndOwidData([]));
        const buffer = await Crypto.sign(cryptoKey, data);
        this.signature = new Uint8Array(buffer);
    }

    /**
     * Sign the data provided and update the signature of the OWID. The timestamp is updated to the current time. The
     * domain and timestamp are appended to the target data before signing.
     * @param pemKey PEM format private key
     */
    public async signWithPemKey(pemKey: string): Promise<void> {
        this.signWithCryptoKey(await Crypto.importPrivateKey(pemKey));
    }
    
    /**
     * Sign the data provided and update the signature of the OWID. The timestamp is updated to the current time. The
     * domain and timestamp are appended to the target data before signing.
     * @param signer signer instance where the most recent private key is used for signing
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
        return Crypto.verify(key, this.signature, data);
    }

    /**
     * Verifies the signature in the OWID and the associated target using the PEM format public key.
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
     * Chooses public keys created on or after the timestamp in the OWID to determine if any of then can verify the 
     * signature. 
     * @param keys one or more public keys
     */
    public async verifyWithPublicKeys(keys: PublicKey[]): Promise<boolean> {
        for(let i = 0; i < keys.length; i++) {
            const key = keys[i];
            if (key.created >= this.getTimeStamp()) {
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
     * Verify this OWID by fetching the public keys from the signer's domain using the cache.
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
     * Adds the target data and then the OWID data to the byte array ready for signing or verification.
     * The domain and timestamp associated with the OWID also need to be included in the data that is passed to 
     * signing or verification.
     * @param b byte array to append the target and OWID data to
     * @returns the updated byte array which was passed to the method
     */
    public addTargetAndOwidData(b: number[]): number[] {
        if (this.target) {
            this.target.addOwidData(b);
            Io.writeString(b, this.domain);
            Io.writeUint32(b, this.timeStamp);
            return b;
        }
        throw new Error('target must be set');
    }

    /**
     * Gets the time stamp as a date so that it can be compared to other dates.
     * Note: OWID's store the timestamp as the number of minutes since 1st January 2020.
     * @returns the time stamp as a Date instance
     */
    public getTimeStamp(): Date {
        if (!this.timeStampAsDate) {
            this.timeStampAsDate = DateHelper.getDateFromMinutes(this.timeStamp);
        }
        return this.timeStampAsDate;
    }
}
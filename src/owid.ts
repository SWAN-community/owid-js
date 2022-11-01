/* ****************************************************************************
 * Copyright 2022 51 Degrees Mobile Experts Limited (51degrees.com)
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
import { Key } from './key';
import { SignerService } from './signerCache';
import { OWIDTarget } from './target';
import { VerifiedStatus } from './verifiedStatus';

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

  /**
   * The date and time to the nearest minute in UTC that the OWID was signed.
   */
  public timestamp: number;

  public signatureArray: Uint8Array; // The signature as a byte array.

  /**
   * Signer information available after signing or verifying the OWID.
   */
  public get signer() { return this._signer; }

  /**
   * The verified status of the field at the current point in time.
   */
  public get status() { return this._status; }

  /**
   * Internal status used to make the public status read only.
   */
  private _status = VerifiedStatus.NotStarted;

  /**
   * Internal signer used when the OWID was signed or verified.
   */
  private _signer: Signer;

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
      this.version = source.version;
      this.domain = source.domain;
      this.timestamp = source.timestamp;
      this.signature = source.signature;
    }
  }

  /**
   * See https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/stringify
   * @returns a fresh IOWID instance for serialization.
   */
  public toJSON(): IOWID {
    return {
      version: this.version,
      domain: this.domain,
      signature: this.signature,
      timestamp: this.timestamp
    };
  }

  /**
   * Adds the fields of the OWID to the provided byte array.
   * @param b byte array to add fields to
   */
  public addToByteArray(b: number[]): number[] {
    Io.writeByte(b, this.version);
    Io.writeString(b, this.domain);
    Io.writeDate(b, this.timestamp);
    Io.writeSignature(b, this.signatureArray);
    return b;
  }

  /**
   * Set the members of this instance from the byte array reader provided.
   * @param array 
   */
  public fromByteArray(b: Reader) {
    this.version = Io.readByte(b);
    switch (this.version) {
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
   * timestamp is updated to the current time. The version, domain, and 
   * timestamp are appended to the target data before signing.
   * @param cryptoKey the private key instance
   */
  public async signWithCryptoKey(cryptoKey: CryptoKey): Promise<void> {
    this.version = 1;
    this.timeStampDate = new Date();
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
    await this.signWithCryptoKey(await Crypto.importPrivateKey(pemKey));
  }

  /**
   * Sign the data provided and update the signature of the OWID. The 
   * timestamp is updated to the current time. The domain and timestamp are 
   * appended to the target data before signing.
   * Updates the domain of the OWID to match that of the signer and sets the
   * signer property to the signer used.
   * @param signer instance where the most recent private key is used for 
   * signing
   */
  public async signWithSigner(signer: Signer): Promise<void> {
    if (!signer.privateKeys || signer.privateKeys.length === 0) {
      throw 'signer missing private keys';
    }
    let newest = signer.privateKeys[0];
    for (let i = 1; i < signer.privateKeys.length; i++) {
      const key = signer.privateKeys[i];
      if (key.created > newest.created) {
        newest = key;
      }
    }
    this.domain = signer.domain;
    await this.signWithPemKey(newest.pem);
    this._signer = signer;
  }

  /**
   * Verifies the signature in the OWID and the associated target using the 
   * public crypto key. 
   * Sets the status property of the OWID to the result of verification.
   * Sets the signer property to undefined.
   * @param key public key to verify the OWID
   * @returns the VerifiedStatus following verification
   */
  public async verifyWithCrypto(key: CryptoKey): Promise<VerifiedStatus> {
    try {
      this.startVerify();
      this._signer = undefined;
      const data = Uint8Array.from(this.addTargetAndOwidData([]));
      this._status = await Crypto.verify(key, this.signatureArray, data) ?
        VerifiedStatus.Valid :
        VerifiedStatus.NotValid;
      return this._status;
    } catch (e) {
      this._status = VerifiedStatus.Exception;
      throw e;
    }
  }

  /**
   * Verifies the signature in the OWID and the associated target using the 
   * PEM format public key.
   * Sets the status property of the OWID to the result of verification.
   * Sets the signer property to undefined.
   * @param key public key to verify the OWID
   * @returns the VerifiedStatus following verification
   */
  public async verifyWithPublicKey(key: Key): Promise<VerifiedStatus> {
    try {
      this.startVerify();
      return this.verifyWithCrypto(await key.getCryptoKey());
    } catch (e) {
      this._status = VerifiedStatus.Exception;
      throw e;
    }
  }

  /**
   * Chooses public keys created on or before the timestamp in the OWID to 
   * determine if any of then can verify the signature. A one hour tolerance
   * is used for the time stamp check to handle clock differences between 
   * difference environments.
   * Sets the status property of the OWID to the result of verification.
   * Sets the signer property to undefined.
   * @param keys one or more public keys to verify the OWID
   * @returns the VerifiedStatus following verification
   */
  public async verifyWithPublicKeys(keys: Key[]): Promise<VerifiedStatus> {
    try {
      this.startVerify();
      const time = this.timeStampDate.getTime();
      for (let i = 0; i < keys.length; i++) {
        const key = keys[i];
        // Take 1 hour from the created time to handle any clock differences
        // between participants.
        const created = key.createdDate.getTime() - 60 * 60 * 1000;
        if (time >= created) {
          return this.verifyWithPublicKey(key);
        }
      }
      this._status = VerifiedStatus.KeyNotFound;
      return this._status;
    } catch (e) {
      this._status = VerifiedStatus.Exception;
      throw e;
    }
  }

  /**
   * Verify this OWID with the provided signer.
   * Sets the status property of the OWID to the result of verification.
   * Sets the signer property of the OWID to the signer provided if an error is
   * not thrown.
   * @param signer instance to use to verify the OWID
   * @returns the VerifiedStatus following verification
   */
  public async verifyWithSigner(signer: Signer): Promise<VerifiedStatus> {
    try {
      this.startVerify();
      if (signer.domain !== this.domain) {
        throw `signer domain '${signer.domain}' can't be used with OWID ` +
        `'${this.domain}'`;
      }
      const status = await this.verifyWithPublicKeys(signer.publicKeys);
      this._signer = signer;
      return status;
    } catch (e) {
      this._status = VerifiedStatus.Exception;
      throw e;
    }
  }

  /**
   * Verify this OWID by fetching the public keys from the signer's domain 
   * using the cache.
   * Sets the status property of the OWID to the result of verification.
   * @param service that returns public key signer information for domains
   * @returns the VerifiedStatus following verification
   */
  public async verifyWithService(service: SignerService)
    : Promise<VerifiedStatus> {
    try {
      this.startVerify();
      const signer = await service.get(this);
      if (signer) {
        return this.verifyWithSigner(signer);
      }
      this._status = VerifiedStatus.SignerNotFound;
      return this._status;
    } catch (e) {
      this._status = VerifiedStatus.Exception;
      throw e;
    }
  }

  /**
   * Adds the target data and then the OWID data to the byte array ready for
   * signing or verification. The domain and timestamp associated with the
   * OWID also need to be included in the data that is passed to signing or 
   * verification.
   * @param b byte array to append the target and OWID data to
   * @returns the updated byte array which was passed to the method
   */
  private addTargetAndOwidData(b: number[]): number[] {
    if (this.target) {
      this.target.addOwidData(b);
      if (!this.domain) {
        throw new Error('domain must be present');
      }
      Io.writeByte(b, this.version);
      Io.writeString(b, this.domain);
      Io.writeUint32(b, this.timestamp);
      return b;
    }
    throw new Error('target must be set');
  }

  private startVerify() {
    this._signer = undefined;
    this._status = VerifiedStatus.Processing;
  }
}
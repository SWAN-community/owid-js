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

/**
 * Used to read from a byte array.
 */
export class Reader {

  /**
   * Current index in the array of the byte to be read next.
   */
  index = 0;

  /**
   * New reader for the array
   * @param array 
   */
  constructor(public readonly array: Uint8Array) { }
}

export class Io {

  /**
   * The base year for all dates encoded with the io time methods.
   * Must be aligned across implementations.
   */
  public static readonly dateBase = new Date(2020, 0, 1, 0, 0, 0, 0);

  /**
   * Write a single byte.
   * @param b 
   * @param v 
   * @returns 
   */
  public static writeByte(b: number[], v: number): number {
    if (v < 0 || v > 255) {
      throw new Error('value must be a byte');
    }
    return b.push(v);
  }

  /**
   * Write a null terminated string.
   * @param b 
   * @param v 
   * @returns 
   */
  public static writeString(b: number[], v: string): number {
    if (v) {
      let c = 0;
      for (let i = 0; i < v.length; i++) {
        c += Io.writeByte(b, v.charCodeAt(i));
      }
      c += b.push(0);
      return c;
    }
    throw new Error('value must be a valid string');
  }

  /**
   * Write an array of strings where the first dimension can be upto an
   * unsigned 16 bit integer in length. If the value is empty then a zero length
   * entry is written which when read back will result in an empty array.
   * @param b 
   * @param v 
   * @returns 
   */
  public static writeStrings(b: number[], v: string[]): number {
    if (!v || v.length === 0) {
      return this.writeUint16(b, 0);
    }
    if (v.length > Math.pow(2, 16)) {
      throw new Error('array too long');
    }
    let c = this.writeUint16(b, v.length);
    for (let i = 0; i < v.length; i++) {
      c += this.writeString(b, v[i]);
    }
    return c;
  }

  public static writeDate(b: number[], v: number): number {
    return Io.writeUint32(b, v);
  }

  /**
   * Write a 32 bit unsigned integer.
   * @param b 
   * @param v 
   * @returns 
   */
  public static writeUint32(b: number[], v: number): number {
    let c = 0;
    const a = new ArrayBuffer(4);
    const d = new DataView(a);
    d.setUint32(0, v, true);
    for (let i = 0; i < 4; i++) {
      c += Io.writeByte(b, d.getUint8(i));
    }
    return c;
  }

  /**
   * Write a 16 bit unsigned integer.
   * @param b 
   * @param v 
   * @returns 
   */
  public static writeUint16(b: number[], v: number): number {
    let c = 0;
    const a = new ArrayBuffer(2);
    const d = new DataView(a);
    d.setUint16(0, v, true);
    for (let i = 0; i < 2; i++) {
      c += Io.writeByte(b, d.getUint8(i));
    }
    return c;
  }

  /**
   * Write a byte array without any length information.
   * @param b 
   * @param v 
   * @returns 
   */
  public static writeByteArrayNoLength(b: number[], v: Uint8Array): number {
    let c = 0;
    for (let i = 0; i < v.length; i++) {
      c += Io.writeByte(b, v[i]);
    }
    return c;
  }

  /**
   * Write a byte array with the initial 4 bytes representing the length.
   * @param b 
   * @param v 
   * @returns 
   */
  public static writeByteArray(b: number[], v: Uint8Array) {
    let c = Io.writeUint32(b, v.length);
    c += Io.writeByteArrayNoLength(b, v);
    return c;
  }

  /**
   * Write an array of arrays where the first dimension can be upto an
   * unsigned 16 bit integer in length.
   * @param b 
   * @param v 
   * @returns 
   */
  public static writeByteArrayArray(b: number[], v: Uint8Array[]) {
    if (b.length > Math.pow(2, 16)) {
      throw new Error('array too long');
    }
    let c = Io.writeUint16(b, v.length);
    for (let i = 0; i < v.length; i++) {
      c += Io.writeByteArray(b, v[i]);
    }
    return c;
  }

  /**
   * Read a single byte.
   * @param r
   * @returns 
   */
  public static readByte(r: Reader): number {
    return r.array[r.index++];
  }

  /**
   * Read a null terminated string.
   * @param b 
   * @returns 
   */
  public static readString(b: Reader): string {
    let r = '';
    while (b.index < b.array.length && b.array[b.index] !== 0) {
      r += String.fromCharCode(b.array[b.index++]);
    }
    b.index++;
    return r;
  }

  /**
   * Read an unsigned integer in big endian format.
   * @param b 
   * @returns 
   */
  public static readUint32(b: Reader): number {
    return Io.readByte(b) |
      Io.readByte(b) << 8 |
      Io.readByte(b) << 16 |
      Io.readByte(b) << 24;
  }

  /**
   * Read a byte array where the first 4 bytes are the length as an unsigned
   * integer.
   * @param b 
   * @returns 
   */
  public static readByteArray(b: Reader) {
    const c = Io.readUint32(b);
    const r = b.array.slice(b.index, b.index + c);
    b.index += c;
    return r;
  }

  /**
   * Read an OWID data in minutes from the epoch.
   * @param b 
   * @returns 
   */
  public static readDate(b: Reader): number {
    return Io.readUint32(b);
  }

  /**
   * Read the V1 signature.
   * @param b 
   * @returns 
   */
  public static readSignature(b: Reader) {
    const c = 64; // The OWID signature is always 64 bytes.
    const r = b.array.slice(b.index, b.index + c);
    b.index += c;
    return r;
  }

  public static writeSignature(b: number[], signature: Uint8Array): number {
    if (signature.length !== 64) {
      throw new Error('signature incorrect length');
    }
    return Io.writeByteArrayNoLength(b, signature);
  }

  /**
   * Converts byte array into a base64 string.
   * @param array of bytes
   * @returns base 64 representation
   */
  public static byteArrayToBase64(array: Uint8Array) {
    let b = '';
    for (let i = 0; i < array.byteLength; i++) {
      b += String.fromCharCode(array[i]);
    }
    return btoa(b);
  }

  /**
   * Converts a base 64 string into a byte array.
   * @param value base 64 representation of a byte array
   * @returns 
   */
  public static byteArrayFromBase64(value: string): Uint8Array {
    if (value) {
      return Uint8Array.from(atob(value), c => c.charCodeAt(0));
    }
    return undefined;
  }
}
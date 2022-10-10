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

export class Io {

    // The base year for all dates encoded with the io time methods.
    // Must be aligned across implementations.
    public static readonly dateBase = new Date(2020,0,1,0,0,0,0);

    public static writeByte(b: number[], v: number): number {
        if (v < 0 || v > 255) {
            throw new Error('value must be a byte');
        }
        return b.push(v);
    }

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

    public static writeStrings(b: number[], v: string[]): number {
        let c = this.writeUint16(b, v.length);
        for (let i = 0; i < v.length; i++) {
            c += this.writeString(b, v[i]);
        }
        return c;
    }

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

    public static writeByteArrayNoLength(b: number[], v: Uint8Array): number {
        let c = 0;
        for (let i = 0; i < v.length; i++) {
            c += Io.writeByte(b, v[i]);
        }
        return c;
    }

    public static writeByteArray(b: number[], v: Uint8Array) {
        let c = Io.writeUint32(b, v.length);
        c += Io.writeByteArrayNoLength(b, v);
        return c;
    }

    public static writeByteArrayArray(b: number[], v: Uint8Array[]) {
        let c = Io.writeUint16(b, v.length);
        for(let i = 0; i < v.length; i++) {
            c += Io.writeByteArray(b, v[i]);
        }
        return c;
    }
}
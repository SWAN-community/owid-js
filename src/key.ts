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

import { Crypto } from './crypto';

/**
 * Key (either public or private) associated with the signer at a given point in
 * time.
 */
export class Key {
	pem: string; // The key in PEM format
	created: string; // Date time and time the key was created as a string

	/**
	 * The crypto instance for the PEM key
	 */
	public async getCryptoKey(): Promise<CryptoKey> {
		// If the crypto key instance is not set for the public key then import
		// it from the PEM format version and record it to speed up future 
		// operations.
		let cryptoKey = this._cryptoKey;
		if (!cryptoKey) {
			cryptoKey = await Crypto.importKey(this.pem);
			this._cryptoKey = cryptoKey;
		}
		return this._cryptoKey;
	}

	/**
	 * Internal instance of the cryptokey.
	 */
	private _cryptoKey: CryptoKey;

	/**
	 * The date and time that the key was created as a Date.
	 */
	get createdDate(): Date {
		return new Date(Date.parse(this.created));
	}
	set createdDate(value: Date) {
		this.created = value.toString();
	}

	/**
	 * Parameters optional to enable JSON serialization.
	 * @param key public key in PEM format
	 * @param created date the key was created
	 */
	constructor(key?: string, created?: string | Date | number) {
		this.pem = key;
		if (created instanceof Date) {
			this.createdDate = created;
		} else if (typeof (created) === 'number') {
			this.createdDate = new Date(created);
		} else {
			this.created = created;
		}
	}
}
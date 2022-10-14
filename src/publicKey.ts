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

// PublicKey associated with the signer at a given point in time.
export class PublicKey {
	key: string; // The public key in PEM format
	created: string; // Date time instance of the created value
	cryptoKey?: CryptoKey; // The crypto version of the key

	// The date and time that the key was created as a string
	get createdDate(): Date {
		return new Date(Date.parse(this.created));
	}
	set createdDate(value: Date) {
		this.created = value.toString();
	}

	/**
	 * Parameters optional to enable JSON serialization.
	 * @param key public key in PEM format
	 * @param created date the key created
	 */
	constructor(key?: string, created?: string | Date | number) {
		this.key = key;
		if (created instanceof Date) {
			this.createdDate = created;
		} else if (typeof(created) === 'number') {
			this.createdDate = new Date(created);
		} else {
			this.created = created;
		}
	}
}
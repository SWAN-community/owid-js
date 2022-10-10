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
export interface PublicKey {
	key: string; // The public key in PEM format
	created: string; // The date and time that the key was created as a string
	createdDate: Date;// Date time instance of the created value
	cryptoKey?: CryptoKey; // The crypto version of the key
}

/**
 * Gets the created date of the public key as a date type.
 * @param publicKey 
 * @returns 
 */
export const getCreatedDate = (publicKey: PublicKey): Date => {
	if (!publicKey.createdDate) {
		publicKey.createdDate = new Date(Date.parse(publicKey.created));
	}
	return publicKey.createdDate;
};

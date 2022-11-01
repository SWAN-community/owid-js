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

import { Key } from './key';

/**
 * Signer of Open Web Ids.
 */
export interface Signer {
	version: number; // The version for the signer instance
	domain: string; // The registered domain name and key field
	name: string; // The common name of the signer
	email: string; // The email address to use to contact the signer
	termsURL: string; // URL returning the T&Cs associated with the signed data
	publicKeys: Key[]; // Public keys associated with the signer
	privateKeys?: Key[]; // Private keys associated with the signer if available
}

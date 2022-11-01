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
 * Different status associated with verified values.
 */
export enum VerifiedStatus {
  NotStarted = 'NotStarted', // a verify method has not yet been called
  SignerNotFound = 'SignerNotFound', // the signer data was not returned
  KeyNotFound = 'KeyNotFound', // a public key is not available for verification
  Valid = 'Valid', // the data is valid for the signature
  NotValid = 'NotValid', // the data is not valid for the signature
  Processing = 'Processing', // the process to verify the entity is not complete
  Exception = 'Exception' // an error was thrown during verification
}

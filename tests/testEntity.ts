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

import { OWIDEntity } from '../src/entity';
import { OWIDTarget } from '../src/target';
import { Io } from '../src/io';
import { OWID } from '../src/owid';

/**
 * Test entity class used with the OWID features.
 */
export class TestEntity implements OWIDTarget, OWIDEntity<TestEntity> {

  // Test value to be included in the data associated with the OWID.
  public value: Uint8Array;

  // Instance of the OWID related to the data.
  public source: OWID<TestEntity>;

  /**
   * Needed to get the data that is signed along with the OWID domain and 
   * timestamp.
   * @param buffer 
   */
  public addOwidData(buffer: number[]) {
    Io.writeByteArray(buffer, this.value);
  }
}
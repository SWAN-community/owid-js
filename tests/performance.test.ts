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

import { Artifact } from './artifact';
import { OWID } from '@owid/owid';
import { Signer } from '@owid/signer';
import { TestEntity } from './testEntity';

// testPerformanceVerifyRun reports the number of signings complete in the
// duration.
async function testPerformanceVerifyRun(seconds: number, length: number) {
  const a = await new Artifact().init();
  setByteArray(length, a);
  await a.target.source.signWithSigner(a.signer);
  const i = await testPerformanceVerifyLoop(seconds, a.signer, a.target.source);
  console.log(
    `completed '${i}' verifications in '${seconds}'s with length '${length}'`);
}

// testPerformanceSignRun reports the number of signings complete in the
// duration.
async function testPerformanceSignRun(seconds: number, length: number) {
  const a = await new Artifact().init();
  setByteArray(length, a);
  const i = await testPerformanceSignLoop(a, seconds);
  console.log(
    `completed '${i}' signings in '${seconds}'s with length '${length}'`);
}

// testPerformanceVerifyLoop verifies the provided OWID using the signer for the
// duration provided. Returns the number of verifications that were complete.
async function testPerformanceVerifyLoop(
  seconds: number,	
  s: Signer, 
  o: OWID<TestEntity>): Promise<number> {
  const e = new Date().getTime() + (seconds * 1000);
  let i = 0;
  while (new Date().getTime() < e) {
    await o.verifyWithSigner(s);
    i++;
  }
	return i;
}

// testPerformanceLoop creates a signer and then loops for the duration signing
// the test data returning the number of iterations that could be completed in
// the duration.
async function testPerformanceSignLoop(a: Artifact, seconds: number)
  : Promise<number> {
  const e = new Date().getTime() + (seconds * 1000);
  let i = 0;
  while (new Date().getTime() < e) {
    await a.target.source.signWithSigner(a.signer);
    i++;
  }
	return i;
}

function setByteArray(length: number, a: Artifact) {
  const b: number[] = [length];
  for (let i = 0; i < length; i++) {
    b[i] = '#'.charCodeAt(0);
  }
  a.target.value = new Uint8Array(b);
}

describe('performance verify', () => {
  const seconds = 1;
	for (let l = 0; l <= 2000; l += 1000) {
    test(`${seconds}s ${l}`, async () => {
      await testPerformanceVerifyRun(seconds, l);
		});
	}
});

describe('performance sign', () => {
  const seconds = 1;
	for (let l = 0; l <= 2000; l += 1000) {
    test(`${seconds}s ${l}`, async () => {
      await testPerformanceSignRun(seconds, l);
		});
	}
});
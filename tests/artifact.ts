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

import { OWID } from '../src/owid';
import { Key } from '../src/key';
import { Signer } from '../src/signer';
import { TestEntity } from './testEntity';
import { Crypto } from '../src/crypto';
import { VerifiedStatus } from '../src/verifiedStatus';
import { Io } from '../src/io';

export class Artifact {

  public static readonly testDomain = 'example.test';

  public static readonly testValue = 'example test';

  public static readonly testName = 'test';

  // Target data.
  public readonly target: TestEntity;

  // The test signer.
  public signer: Signer;

  constructor() {
    this.target = new TestEntity();
    const b: number[] = [];
    Io.writeString(b, Artifact.testValue);
    this.target.value = new Uint8Array(b);
    this.target.source = new OWID<TestEntity>(this.target);
    this.target.source.domain = Artifact.testDomain;
  }

  public async init(): Promise<Artifact> {
    const keys = await Crypto.generateKeys();
    const date = new Date();
    this.signer = {
      version: 1,
      domain: Artifact.testDomain,
      name: Artifact.testName,
      termsURL: `${Artifact.testDomain}/terms.html`,
      email: `${Artifact.testName}@${Artifact.testDomain}`,
      publicKeys: [new Key(await Crypto.exportKey(keys.publicKey), date)],
      privateKeys: [new Key(await Crypto.exportKey(keys.privateKey), date)]
    };
    await this.target.source.signWithSigner(this.signer);
    expect(this.target.source.signer).toBe(this.signer);
    return this;
  }
}

/**
 * Creates a test artifact checking that the OWID is verified.
 * @returns the test artifact
 */
export async function createArtifact() {
  const a = await new Artifact().init();
  const r1 = await a.target.source.verifyWithSigner(a.signer);
  expect(r1).toBe(VerifiedStatus.Valid);
  expect(a.target.source.signer).toBe(a.signer);
  expect(a.target.source.status).toBe(VerifiedStatus.Valid);
  return a;
}
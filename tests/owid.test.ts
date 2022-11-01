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

import { SignerCacheMap } from '../src/signerCache';
import { Key } from '../src/key';
import { Artifact, createArtifact } from './artifact';
import { VerifiedStatus } from '../src/verifiedStatus';

describe('verify service', () => {
  test('pass', async () => {
    const a = await new Artifact().init();
    const c = new SignerCacheMap(0);
    c.map.set(a.target.source, a.signer);
    const r = await a.target.source.verifyWithService(c);
    expect(r).toBe(VerifiedStatus.Valid);
    expect(a.target.source.signer).toBe(a.signer);
    expect(a.target.source.status).toBe(VerifiedStatus.Valid);
  });
  test('fail', async () => {
    const a = await new Artifact().init();
    const c = new SignerCacheMap(0);
    c.map.set(a.target.source, a.signer);
    a.target.source.signatureArray = a.target.source.signatureArray.slice(1);
    const r = await a.target.source.verifyWithService(c);
    expect(r).toBe(VerifiedStatus.NotValid);
    expect(a.target.source.signer).toBe(a.signer);
    expect(a.target.source.status).toBe(VerifiedStatus.NotValid);
  });
  test('signer not found', async () => {
    const a = await new Artifact().init();
    const c = new SignerCacheMap(0);
    c.map.set({
      domain: 'not.found',
      version: a.target.source.version
    },
      a.signer);
    const r = await a.target.source.verifyWithService(c);
    expect(r).toBe(VerifiedStatus.SignerNotFound);
    expect(a.target.source.signer).toBe(undefined);
    expect(a.target.source.status).toBe(VerifiedStatus.SignerNotFound);
  });
});

describe('verify public keys', () => {
  test('public key', async () => {
    const a = await createArtifact();
    const r2 = await a.target.source.verifyWithPublicKey(a.signer.publicKeys[0]);
    expect(r2).toBe(VerifiedStatus.Valid);
    expect(a.target.source.signer).toBe(undefined);
  });
  test('public keys single', async () => {
    const a = await createArtifact();
    const time = a.target.source.timeStampDate.getTime();
    const r2 = await a.target.source.verifyWithPublicKeys(
      [new Key(a.signer.publicKeys[0].pem, time)]);
    expect(r2).toBe(VerifiedStatus.Valid);
    expect(a.target.source.signer).toBe(undefined);
  });
  test('public keys multiple one valid', async () => {
    const a = await createArtifact();
    const other = await createArtifact();
    const time = a.target.source.timeStampDate.getTime();
    const r2 = await a.target.source.verifyWithPublicKeys(
      [
        new Key(a.signer.publicKeys[0].pem, time - 1),
        new Key(other.signer.publicKeys[0].pem, time + 1),
        new Key(a.signer.publicKeys[0].pem, time + 2)
      ]);
    expect(r2).toBe(VerifiedStatus.Valid);
    expect(a.target.source.signer).toBe(undefined);
  });
  test('public keys multiple past valid', async () => {
    const a = await createArtifact();
    const other = await createArtifact();
    const time = a.target.source.timeStampDate.getTime();
    const r2 = await a.target.source.verifyWithPublicKeys(
      [
        new Key(a.signer.publicKeys[0].pem, time - 1),
        new Key(other.signer.publicKeys[0].pem, time + 1),
        new Key(other.signer.publicKeys[0].pem, time + 2)
      ]);
    expect(r2).toBe(VerifiedStatus.Valid);
    expect(a.target.source.signer).toBe(undefined);
  });
  test('public keys multiple future valid', async () => {
    const a = await createArtifact();
    const other = await createArtifact();
    const time = a.target.source.timeStampDate.getTime();
    const r2 = await a.target.source.verifyWithPublicKeys(
      [
        new Key(other.signer.publicKeys[0].pem, time - 1),
        new Key(other.signer.publicKeys[0].pem, time + 1),
        // Add two hours in the future to ensure the clock different checks are
        // not applied to match the future key.
        new Key(a.signer.publicKeys[0].pem, time + 60 * 60 * 1000 * 2)
      ]);
    expect(r2).toBe(VerifiedStatus.NotValid);
    expect(a.target.source.signer).toBe(undefined);
  });
  test('public keys multiple all other', async () => {
    const a = await createArtifact();
    const other = await createArtifact();
    const time = a.target.source.timeStampDate.getTime();
    const r2 = await a.target.source.verifyWithPublicKeys(
      [
        new Key(other.signer.publicKeys[0].pem, time - 1),
        new Key(other.signer.publicKeys[0].pem, time + 1),
        new Key(other.signer.publicKeys[0].pem, time + 2)
      ]);
    expect(r2).toBe(VerifiedStatus.NotValid);
    expect(a.target.source.signer).toBe(undefined);
  });
});

describe('verify signer', () => {
  test('pass', async () => {
    const a = await new Artifact().init();
    const r = await a.target.source.verifyWithSigner(a.signer);
    expect(r).toBe(VerifiedStatus.Valid);
    expect(a.target.source.signer).toBe(a.signer);
  });
  test('corrupt domain', async () => {
    const a = await new Artifact().init();
    a.target.source.domain += ' ';
    try {
      await a.target.source.verifyWithSigner(a.signer);
      fail();
    } catch (e) {
      expect(a.target.source.status).toBe(VerifiedStatus.Exception);
      expect(a.target.source.signer).toBe(undefined);
    }
  });
  test('corrupt time', async () => {
    const a = await new Artifact().init();
    a.target.source.timestamp += 1;
    const r = await a.target.source.verifyWithSigner(a.signer);
    expect(r).toBe(VerifiedStatus.NotValid);
    expect(a.target.source.signer).toBe(a.signer);
  });
  test('corrupt data', async () => {
    const a = await new Artifact().init();
    a.target.source.target.value = a.target.source.target.value.slice(1);
    const r = await a.target.source.verifyWithSigner(a.signer);
    expect(r).toBe(VerifiedStatus.NotValid);
    expect(a.target.source.signer).toBe(a.signer);
  });
  test('wrong key', async () => {
    const a = await new Artifact().init();
    a.signer.publicKeys[0].pem = '';
    try {
      await a.target.source.verifyWithSigner(a.signer);
      fail();
    } catch (e) {
      expect(a.target.source.status).toBe(VerifiedStatus.Exception);
      expect(a.target.source.signer).toBe(undefined);
    }
  });
});

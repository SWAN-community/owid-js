import { OWID } from '../src/owid';
import { Crypto } from '../src/crypto';
import { SignerCacheMap } from '../src/signerCache';
import { Signer } from '../src/signer';
import { Data } from './data';
import { PublicKey } from '../src/publicKey';

export class Artifact {

  public static readonly testDomain = 'example.test';

  public static readonly testValue = 'example test';

  public static readonly testName = 'test';

  // Target data.
  public readonly target: Data;

  // Keys.
  public keys: CryptoKeyPair;

  // The test signer.
  public signer: Signer;

  constructor() {
    this.target = new Data();
    this.target.value = Artifact.testValue;
    this.target.owid = new OWID<Data>(this.target);
    this.target.owid.domain = Artifact.testDomain;
  }

  public async init(): Promise<Artifact> {
    this.keys = await Crypto.generateKeys();
    await this.target.owid.signWithCryptoKey(this.keys.privateKey);
    this.signer = {
      version: 1,
      domain: Artifact.testDomain,
      name: Artifact.testName,
      termsURL: `${Artifact.testDomain}/terms.html`,
      email: `${Artifact.testName}@${Artifact.testDomain}`,
      publicKeys: [new PublicKey(
        await Crypto.exportKey(this.keys.publicKey),
        this.target.owid.timeStampDate)],
      // Private keys can't be exported.
      privateKeys: [{
        created: this.target.owid.timeStampDate,
        key: '',
        cryptoKey: this.keys.privateKey
      }]
    };
    return this;
  }
}

/**
 * Creates a test artifact checking that the OWID is verified.
 * @returns the test artifact
 */
export async function createArtifactWithVerifiedOWID() {
  const a = await new Artifact().init();
  const r1 = await a.target.owid.verifyWithCrypto(a.keys.publicKey);
  expect(r1).toBe(true);
  return a;
}

describe('testing cache', () => {
  test('pass', async () => {
    const a = await new Artifact().init();
    const c = new SignerCacheMap(0);
    c.map.set(a.target.owid, a.signer);
    const r = await a.target.owid.verifyWithCache(c);
    expect(r).toBe(true);
  });
  test('fail', async () => {
    const a = await new Artifact().init();
    const c = new SignerCacheMap(0);
    c.map.set({ 
      domain: 'not.found', 
      version: a.target.owid.version }, 
      a.signer);
    const r = await a.target.owid.verifyWithCache(c);
    expect(r).toBe(false);
  });
});

describe('testing public keys', () => {
  test('public key', async () => {
    const a = await createArtifactWithVerifiedOWID();
    const r2 = await a.target.owid.verifyWithPublicKey(a.signer.publicKeys[0]);
    expect(r2).toBe(true);
  });
  test('public keys single', async () => {
    const a = await createArtifactWithVerifiedOWID();
    const time = a.target.owid.timeStampDate.getTime();
    const r2 = await a.target.owid.verifyWithPublicKeys(
      [new PublicKey(a.signer.publicKeys[0].key, time)]);
    expect(r2).toBe(true);
  });
  test('public keys multiple one valid', async () => {
    const a = await createArtifactWithVerifiedOWID();
    const other = await createArtifactWithVerifiedOWID();
    const time = a.target.owid.timeStampDate.getTime();
    const r2 = await a.target.owid.verifyWithPublicKeys(
      [
        new PublicKey(a.signer.publicKeys[0].key, time - 1),
        new PublicKey(other.signer.publicKeys[0].key, time + 1),
        new PublicKey(a.signer.publicKeys[0].key, time + 2)
      ]);
    expect(r2).toBe(true);
  });
  test('public keys multiple past valid', async () => {
    const a = await createArtifactWithVerifiedOWID();
    const other = await createArtifactWithVerifiedOWID();
    const time = a.target.owid.timeStampDate.getTime();
    const r2 = await a.target.owid.verifyWithPublicKeys(
      [
        new PublicKey(a.signer.publicKeys[0].key, time - 1),
        new PublicKey(other.signer.publicKeys[0].key, time + 1),
        new PublicKey(other.signer.publicKeys[0].key, time + 2)
      ]);
    expect(r2).toBe(true);
  });
  test('public keys multiple future valid', async () => {
    const a = await createArtifactWithVerifiedOWID();
    const other = await createArtifactWithVerifiedOWID();
    const time = a.target.owid.timeStampDate.getTime();
    const r2 = await a.target.owid.verifyWithPublicKeys(
      [
        new PublicKey(other.signer.publicKeys[0].key, time - 1),
        new PublicKey(other.signer.publicKeys[0].key, time + 1),
        // Add two hours in the future to ensure the clock different checks are
        // not applied to match the future key.
        new PublicKey(a.signer.publicKeys[0].key, time + 60 * 60 * 1000 * 2)
      ]);
    expect(r2).toBe(false);
  });
  test('public keys multiple all other', async () => {
    const a = await createArtifactWithVerifiedOWID();
    const other = await createArtifactWithVerifiedOWID();
    const time = a.target.owid.timeStampDate.getTime();
    const r2 = await a.target.owid.verifyWithPublicKeys(
      [
        new PublicKey(other.signer.publicKeys[0].key, time - 1),
        new PublicKey(other.signer.publicKeys[0].key, time + 1),
        new PublicKey(other.signer.publicKeys[0].key, time + 2)
      ]);
    expect(r2).toBe(false);
  });
});

describe('testing owid', () => {
  test('pass', async () => {
    const a = await new Artifact().init();
    const r = await a.target.owid.verifyWithCrypto(a.keys.publicKey);
    expect(r).toBe(true);
  });
  test('corrupt domain', async () => {
    const a = await new Artifact().init();
    a.target.owid.domain += ' ';
    const r = await a.target.owid.verifyWithCrypto(a.keys.publicKey);
    expect(r).toBe(false);
  });
  test('corrupt time', async () => {
    const a = await new Artifact().init();
    a.target.owid.timestamp += 1;
    const r = await a.target.owid.verifyWithCrypto(a.keys.publicKey);
    expect(r).toBe(false);
  });
  test('corrupt data', async () => {
    const a = await new Artifact().init();
    a.target.owid.target.value += '!';
    const r = await a.target.owid.verifyWithCrypto(a.keys.publicKey);
    expect(r).toBe(false);
  });
  test('wrong key', async () => {
    const a = await new Artifact().init();
    try {
      await a.target.owid.verifyWithCrypto(a.keys.privateKey);
      fail();
    } catch (e) {
      // Do nothing as exception should be throw.
    }
  });
});

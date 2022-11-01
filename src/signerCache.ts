import { OWID } from './owid';
import { Key } from './key';
import { Signer } from './signer';
import { OWIDTarget } from './target';

/**
 * Service interface used to get signer information for the domain.
 */
export interface SignerService {
  /**
   * Returns the signer for the OWID version and domain, or null if the OWID has 
   * no signer.
   * @param owid
   */
  get<T extends OWIDTarget>(owid: OWID<T>): Promise<Signer | null>;
}

/**
 * Interface that supports OWIDs to use to map version and domain.
 */
 export interface CacheKey {
  version: number; // The byte version of the OWID.
  domain: string; // Domain associated with the signer.
}

/**
 * Returns the signer using a map of host keys to signers.
 */
export class SignerCacheMap implements SignerService {
  public readonly map: Map<CacheKey, Signer>;

  /**
   * New instance of the signer Cache backed with a map.
   * @param msDelay length of time to wait in milliseconds before 
   * responding
   * @param map of prepared signers or empty of not available
   */
  constructor(private readonly msDelay: number, map?: Map<CacheKey, Signer>) {
    this.map = map ?? new Map<CacheKey, Signer>();
  }

  /**
   * Waits for the time to pass before responding. Simulates network latency.
   * @param milliseconds to wait before responding
   * @returns
   */
  private delay(milliseconds: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, milliseconds));
  }

  /**
   * Returns the signer for the OWID, or null if the host has no signer.
   * @param owid
   */
  public get<T extends OWIDTarget>(owid: OWID<T>): Promise<Signer> {
    if (this.msDelay > 0) {
      return this.delay(this.msDelay).then(() => this.map.get(owid));
    }
    return Promise.resolve(this.map.get(owid));
  }
}

/**
 * Returns the signer using an HTTP request to the host if the entry is not 
 * available in the cache.
 */
export class SignerCacheHttp implements SignerService {

  /**
   * Cache of responses found so far.
   */
  private readonly map = new Map<CacheKey, Signer>();

  /**
   * Protocol to use when fetching signer information.
   */
  private readonly protocol: string;

  /**
   * A new HTTP backed cache of signer information.
   * If there is a window object and it has a location then use the protocol
   * from there. Otherwise use https.
   */
  constructor() {
    this.protocol = window?.location?.protocol;
    if (!this.protocol) {
      this.protocol = 'https:';
    }
  }

  /**
   * Returns the signer for the OWID, or null if the OWID has no signer.
   * Uses a map to avoid requesting the same signer information from the 
   * network.
   * @param owid
   */
  public async get(owid: CacheKey): Promise<Signer> {
    let signer = this.map.get(owid);
    if (!signer) {
      const response = await fetch(
        `${this.protocol}//${owid.domain}/owid/api/v${owid.version}/signer`, {
        method: 'GET',
        mode: 'cors',
        cache: 'default',
      });
      if (response) {
        signer = await response.json();

        // Turn the anonymous interface into a concrete instance of the class.
        const k: Key[] = [];
        signer.publicKeys.forEach(i => {
          k.push(new Key(i.pem, i.created));
        });
        signer.publicKeys = k;

        this.map.set(owid, signer);
      } else {
        throw new Error(response.statusText);
      }
    }
    return signer;
  }
}

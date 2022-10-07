import { PrivateKey } from './privateKey';
import { PublicKey } from './publicKey';

/**
 * Signer of Open Web Ids.
 */
export interface Signer {
	version: number; // The version for the signer instance
	domain: string; // The registered domain name and key field
	name: string; // The common name of the signer
	email: string; // The email address to use to contact the signer
	termsURL: string; // URL returning the T&Cs associated with the signed data
    publicKeys: PublicKey[]; // The public keys associated with the signer
	privateKeys: PrivateKey[]; // The private keys associated with the signer
}

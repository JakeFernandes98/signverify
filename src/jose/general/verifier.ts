import type { Cache } from '../../utils/types.js';
import type { PublicJwk } from '../types.js';
import type { GeneralJws, SignatureEntry } from './types.js';

import lodash from 'lodash';
import { VerificationMethod } from 'did-resolver'
import { DidResolver } from '../../did/did-resolver.js';
import { Encoder } from '../../utils/encoder.js';
import { MemoryCache } from '../../utils/memory-cache.js';
// import { validateJsonSchema } from '../../../validator.js';
import { signers as verifiers } from '../algorithms/signers.js';

type VerificationResult = {
  /** DIDs of all signers */
  signers: string[];
};

export class GeneralJwsVerifier {
  jws: GeneralJws;
  cache: Cache;
  didResolver: DidResolver;

  constructor(jws: GeneralJws, cache?: Cache) {
    this.jws = jws;
    this.cache = cache || new MemoryCache(600);
    this.didResolver = new DidResolver()
  }

  async verify(): Promise<VerificationResult> {
    const signers: string[] = [];

    for (const signatureEntry of this.jws.signatures) {
      let isVerified: boolean;
      const cacheKey = `${signatureEntry.protected}.${this.jws.payload}.${signatureEntry.signature}`;
      const kid = GeneralJwsVerifier.getKid(signatureEntry);

      const publicJwk = await this.getPublicKey(kid);

      const cachedValue = await this.cache.get(cacheKey);

      if (cachedValue === undefined) {
        isVerified = await GeneralJwsVerifier.verifySignature(this.jws.payload, signatureEntry, publicJwk);
        await this.cache.set(cacheKey, isVerified);
      } else {
        isVerified = cachedValue;
      }

      const did = GeneralJwsVerifier.extractDid(kid);

      if (isVerified) {
        signers.push(did);
      } else {
        throw new Error(`signature verification failed for ${did}`);
      }
    }

    return { signers };
  }

  async verifyWithPublicKey(publicJwk: PublicJwk){
    const signers: string[] = [];

    for (const signatureEntry of this.jws.signatures) {
      let isVerified: boolean;
      const cacheKey = `${signatureEntry.protected}.${this.jws.payload}.${signatureEntry.signature}`;
      const kid = GeneralJwsVerifier.getKid(signatureEntry);


      const cachedValue = await this.cache.get(cacheKey);

      if (cachedValue === undefined) {
        isVerified = await GeneralJwsVerifier.verifySignature(this.jws.payload, signatureEntry, publicJwk);
        await this.cache.set(cacheKey, isVerified);
      } else {
        isVerified = cachedValue;
      }


      const did = GeneralJwsVerifier.extractDid(kid);

      if (isVerified) {
        signers.push(did);
      } else {
        throw new Error(`signature verification failed for ${did}`);
      }
    }

    return { signers };


  }

  /**
   * Gets the `kid` from a general JWS signature entry.
   */
  private static getKid(signatureEntry: SignatureEntry): string {
    const { kid } = Encoder.base64UrlToObject(signatureEntry.protected);
    return kid;
  }

  /**
   * Gets the DID from a general JWS signature entry.
   */
  public static getDid(signatureEntry: SignatureEntry): string {
    const kid = GeneralJwsVerifier.getKid(signatureEntry);
    const did = GeneralJwsVerifier.extractDid(kid);
    return did;
  }

  /**
   * Gets the public key given a fully qualified key ID (`kid`).
   */
  public async getPublicKey(kid: string): Promise<PublicJwk> {
    // `resolve` throws exception if DID is invalid, DID method is not supported,
    // or resolving DID fails

    const did = GeneralJwsVerifier.extractDid(kid);
    const doc = await this.didResolver.resolve(did);
    let verificationMethods: VerificationMethod[] = doc.didDocument?.verificationMethod || []

    let verificationMethod
    for (const vm of verificationMethods) {
      if (kid.endsWith(vm.id)) {
        verificationMethod = vm;
        break;
      }
    }

    if (!verificationMethod) {
      throw new Error('public key needed to verify signature not found in DID Document');
    }

    // if(verificationMethod.hasOwnProperty('publicKeyJwk')){
      const { publicKeyJwk: publicJwk } = verificationMethod;
      return publicJwk as PublicJwk;
    // } else if (verificationMethod.hasOwnProperty('publicKeyBase58')){
      // const publicKeyUint8Array = base58.decode(verificationMethod.publicKeyBase58);
      // const keyPair = new Ed25519KeyPair({ publicKeyUint8Array });
      // const publicJWK = keyPair.toJwk(true);
    // }
    
  }

  public static async verifySignature(base64UrlPayload: string, signatureEntry: SignatureEntry, jwkPublic: PublicJwk): Promise<boolean> {
    const verifier = verifiers[jwkPublic.crv];

    if (!verifier) {
      throw new Error(`unsupported crv. crv must be one of ${Object.keys(verifiers)}`);
    }

    const payload = Encoder.stringToBytes(`${signatureEntry.protected}.${base64UrlPayload}`);
    const signatureBytes = Encoder.base64UrlToBytes(signatureEntry.signature);

    return await verifier.verify(payload, signatureBytes, jwkPublic);
  }

  public static decodePlainObjectPayload(jws: GeneralJws): any {
    let payloadJson;
    try {
      payloadJson = Encoder.base64UrlToObject(jws.payload);
    } catch {
      throw new Error('authorization payload is not a JSON object');
    }

    if (!lodash.isPlainObject(payloadJson)) {
      throw new Error('auth payload must be a valid JSON object');
    }

    return payloadJson;
  }

  /**
   * Extracts the DID from the given `kid` string.
   */
  public static extractDid(kid: string): string {
    const [ did ] = kid.split('#');
    return did;
  }
}
import { Did } from './did.js';
import { ed25519 } from '../jose/algorithms/ed25519.js';
import { DidResolutionResult, DIDDocument, DidWithKeys } from './types.js';
import {  Resolver } from 'did-resolver';
import { getResolver } from 'web-did-resolver';
import { DidMethodResolver } from './did-resolver.js';
import { ALGS } from '../jose/types.js';
import { secp256k1 } from '../jose/algorithms/secp256k1.js';

export class DidWebResolver implements DidMethodResolver {
    method(): string {
      return 'web';
    }

    webResolver = getResolver()
    didWebResolver = new Resolver({
        ...this.webResolver,
        //...you can flatten multiple resolver methods into the Resolver
    })
  
  
    public async resolve(did: string): Promise<DidResolutionResult> {
        return this.didWebResolver.resolve(did) as Promise<DidResolutionResult>
    }
  
    /**
     * generates a new ed25519 public/private key pair. Creates a DID using the private key
     * @returns did, public key, private key
     */
    public static async generate(did:string, alg:ALGS){


        let keyId = did+"#key-1"
        let jwkPair: { publicJwk: any; privateJwk: any; }
        if (alg == ALGS.ED25519){
          jwkPair = await ed25519.generateKeyPair();
        }else if (alg == ALGS.SECP256K1){
          jwkPair = await secp256k1.generateKeyPair();
        }else{
          throw("Algorithm not supported")
        }

        const { publicJwk, privateJwk } = jwkPair
        

        const didDocument: DIDDocument = {
            '@context': [
                'https://www.w3.org/ns/did/v1',
                'https://w3id.org/security/suites/jws-2020/v1',
                'https://w3id.org/security/suites/ed25519-2020/v1'
            ],
            'id': did,
            'verificationMethod' : [{
                id           : keyId,
                type         : 'JsonWebKey2020',
                controller   : did,
                publicKeyJwk : publicJwk
            }],
            'authentication'       : [keyId],
            'assertionMethod'      : [keyId],
            'capabilityDelegation' : [keyId],
            'capabilityInvocation' : [keyId]
        };
  
      return { did, keyId, keyPair: { publicJwk, privateJwk }, didDocument };
    }
  
    /**
     * Gets the fully qualified key ID of a `did:key` DID. ie. '<did>#<method-specific-id>'
     */
    public static getKeyId(did: string): string {
      const methodSpecificId = Did.getMethodSpecificId(did);
      const keyId = `${did}#${methodSpecificId}`;
      return keyId;
    };
  }
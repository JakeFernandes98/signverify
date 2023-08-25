import { Resolver } from 'did-resolver'
import { getResolver } from 'web-did-resolver'
import { Did } from '../did/did.js';
import { DidResolutionResult } from './types.js'
import { DidKeyResolver } from './did-key-resolver.js';
import { DidWebResolver } from './did-web-resolver.js';

export class DidResolver {

    resolvers: {[index:string]: DidMethodResolver} = {
        'web': new DidWebResolver(),
        'key': new DidKeyResolver()
    }
  
    /**
     * attempt to resolve the DID provided using the available DidMethodResolvers
     * @throws {Error} if DID is invalid
     * @throws {Error} if DID method is not supported
     * @throws {Error} if resolving DID fails
     * @param did - the DID to resolve
     * @returns {DidResolutionResult}
     */
    public async resolve(did: string): Promise<DidResolutionResult> {
      // naively validate requester DID
      Did.validate(did);
      const splitDID = did.split(':', 3);
  
      const didMethod = splitDID[1];

      const didResolver = this.resolvers[didMethod]
  
      if (!didResolver) {
        throw new Error(`${didMethod} DID method not supported`);
      }
  
      const resolutionResult =await didResolver.resolve(did);
  
      const { didDocument, didResolutionMetadata } = resolutionResult;
  
      if (!didDocument || didResolutionMetadata?.error) {
        const { error } = didResolutionMetadata;
        let errMsg = `Failed to resolve DID ${did}.`;
        errMsg += error ? ` Error: ${error}` : '';
  
        throw new Error(errMsg);
      }
  
      return resolutionResult;
    }
  }


  /**
 * A generalized interface that can be implemented for individual
 * DID methods
 */
export interface DidMethodResolver {
  /**
   * @returns the DID method supported by {@link DidMethodResolver.resolve}
   */
  method(): string;

  /**
   * attempts to resolve the DID provided into its respective DID Document.
   * More info on resolving DIDs can be found
   * {@link https://www.w3.org/TR/did-core/#resolution here}
   * @param did - the DID to resolve
   * @throws {Error} if unable to resolve the DID
   */
  resolve(did: string): Promise<DidResolutionResult>;
}

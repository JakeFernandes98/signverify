
import { DidWithKeys } from "./did/types.js";
import { GeneralJws, SignatureInput } from "./jose/general/types.js";
import { GeneralJwsVerifier } from "./jose/general/verifier.js";
import { PublicJwk } from "./jose/types.js";
import { generateCid, parseCid } from "./utils/cid.js";

export type APIBody = {
    content: Object,
    authorisation : GeneralJws
}

//supports did:key and did:web
export async function verify(message: APIBody){
    let content = message.content
    // console.log('verify14,',message)
    let authorisation = message.authorisation

    const authorisationCid = GeneralJwsVerifier.decodePlainObjectPayload(authorisation);
    const { contentCID } = authorisationCid
    const providedDescriptorCid = parseCid(contentCID);
    const expectedDescriptorCid = await generateCid(content);
    if (!providedDescriptorCid.equals(expectedDescriptorCid)) {
        throw new Error(`provided descriptorCid ${providedDescriptorCid} does not match expected CID ${expectedDescriptorCid}`);
    }

    //CID matches

    const verifier = new GeneralJwsVerifier(authorisation);
    return await verifier.verify(); 
}


export async function verifyWithPublicKey(message: APIBody, publicJwk: PublicJwk){
  let content = message.content
  // console.log('verify14,',message)
  let authorisation = message.authorisation

  const authorisationCid = GeneralJwsVerifier.decodePlainObjectPayload(authorisation);
  const { contentCID } = authorisationCid
  const providedDescriptorCid = parseCid(contentCID);
  const expectedDescriptorCid = await generateCid(content);
  if (!providedDescriptorCid.equals(expectedDescriptorCid)) {
      throw new Error(`provided descriptorCid ${providedDescriptorCid} does not match expected CID ${expectedDescriptorCid}`);
  }

  //CID matches
  const verifier = new GeneralJwsVerifier(authorisation);
  return await verifier.verifyWithPublicKey(publicJwk); 


}

export function createSignatureInput(structuredDidKey: DidWithKeys) {
    const signatureInput: SignatureInput = {
      privateJwk: structuredDidKey.keyPair.privateJwk,
      protectedHeader: {
        alg: structuredDidKey.keyPair.privateJwk.crv,
        kid: structuredDidKey.keyId
      }
    };
    return signatureInput
  }
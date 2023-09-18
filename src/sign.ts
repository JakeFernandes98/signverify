import { DidWithKeys } from "./did/types.js";
import { GeneralJwsSigner } from "./jose/general/signer.js";
import { SignatureInput } from "./jose/general/types.js";
import { generateCid } from "./utils/cid.js";
import { createSignatureInput } from "./verify.js";

export async function sign(content: Object, did: DidWithKeys){

    let signatureInput: SignatureInput = createSignatureInput(did)

    const contentCID = await generateCid(content)
    const authPayload = { contentCID : contentCID.toString() }
    const authPayloadStr = JSON.stringify(authPayload);
    const authPayloadBytes = new TextEncoder().encode(authPayloadStr);

    const signer = await GeneralJwsSigner.create(authPayloadBytes, [signatureInput]);

    return signer.getJws();
}
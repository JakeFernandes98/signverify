Allows for signing and verifying of content using privateJWKs from keypairs generated using ed25519 curve.

Currently supports JsonWebKey2020 using ed25519. 

Supports creation and resolving of did:web and did:key based identifiers.

At the moment, this is limited to creating JSON Web Signatures in the following style

```
{
  content: {
      // This holds whatever body is required for the API
  },
  authorisation: {
      payload : this is the signed content
      signature : this is the signed header
  }
}
```

For example, you could use this to add did-based authorisation to API calls.
In order to achieve this, you will need to add functionality to your consumer app to sign messages using your private key and add functionality to your APIs to verify these signatures.

Below is a simple example of using the package

```
import {sign, verify, DidKeyResolver, DidResolver} from "signverify"


let didResolver = new DidResolver()
let did = await DidKeyResolver.generate()

let content = "My Name is Jake"

// as the message sender, I have access to my private key so can create the authorisation object
let authorisation = await sign(content, did)

let signed_message = {
    content: content,
    authorisation: authorisation
}


// as the message verifier, I do not have access to the public key directly, so I have to resolve the on the did
let didDoc = await didResolver.resolve(did.did)
let did1public = didDoc.didDocument.verificationMethod[0].publicKeyJwk

// DIDDoc resolving is handled directly by the verify method
let verified_message_did = await verify(signed_message)

```
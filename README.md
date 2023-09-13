# address-generator

Command

```sh
npm start
```
Output

```JSON
{
  "compressedPublicKey": "034505a233408038dcbccbc649cc9405e06b97fa04608ceece68f0770cc26f87a8",
  "privateKey": "0x5cf6a35fbef071b9c28703ef46ee1e1951653cf0ec8ab5f8e022632c2e760705",
  "publicKey": "4505a233408038dcbccbc649cc9405e06b97fa04608ceece68f0770cc26f87a899d9af4d8416150bbdd8d0852ae84a4d30eb5790e1760961602644a00409d7f1",
  "address": "0xd721C010fbEEdBC0829d996c79DB9a3B765062AF"
}
```


## Sign & Verify examples

### Java

[Java examples](https://github.com/wallet-manager/wallet-manager-client-java/blob/main/src/main/java/dev/m18/walletmanager/client/utils/WalletManagerUtils.java)

```java

public Header sign(String body) {

	Header header = new Header();
	header.setAddress(this.address);
	header.setTimestamp(System.currentTimeMillis());
	header.setSession(this.sessionId);
	header.setSequence(this.seq.getAndIncrement());

	String content = contentToBeSigned(header, body);

	byte[] messageHash = sha256(content);

	SignatureData signature = Sign.signMessage(messageHash, this.keyPair, false);

	log.debug("Sign message content {}", content);
	log.debug("Sign message hash {}", Hex.encodeHexString(messageHash));
	log.debug("Signagure V {}", Hex.encodeHexString(signature.getV()));
	log.debug("Signature R {}", Hex.encodeHexString(signature.getR()));
	log.debug("Signature S {}", Hex.encodeHexString(signature.getS()));

	header.setSignature(signature((signature)));

	return header;

}

public static VerifyResult verify(Set<String> whiteListedAddresses, Header header, String body, long expiredInMs) {
	
	if(!whiteListedAddresses.contains(header.getAddress())) {
		return VerifyResult.InvalidAddress;
	}
	
	long now = System.currentTimeMillis();
	if (header.getTimestamp() < now - expiredInMs) {
		return VerifyResult.Expired;
	}

	String content = contentToBeSigned(header, body);

	byte[] messageHash = sha256(content);
	
	String signature = header.getSignature();
	if(!signature.startsWith("0x")){
		signature = "0x" + signature;
	}
	
	try {
		log.debug("Sign message content {}", content);
		log.debug("Verfiy message hash {}", Hex.encodeHexString(messageHash));

		List<SignatureData> signatures = new ArrayList<>();
		if (signature.length() == 130) {
			SignatureData signatureData27 = signature(signature + "1b");  // v = 27
			SignatureData signatureData28 = signature(signature + "1c");  // v = 28
			signatures.add(signatureData27);
			signatures.add(signatureData28);
			log.debug("Signagure V {}", Hex.encodeHexString(signatureData27.getV()));
			log.debug("Signature R {}", Hex.encodeHexString(signatureData27.getR()));
		} else {
			SignatureData signatureData = signature(signature);
			signatures.add(signatureData);
			log.debug("Signagure V {}", Hex.encodeHexString(signatureData.getV()));
			log.debug("Signature R {}", Hex.encodeHexString(signatureData.getR()));
			log.debug("Signature S {}", Hex.encodeHexString(signatureData.getS()));
		}

		boolean match = false;
		for(SignatureData s : signatures) {
			BigInteger publicKey = Sign.signedMessageHashToKey(messageHash, s);
			String address = getAddressFromPublicKey(publicKey);
			if (address.equals(header.getAddress())) {
				match = true;
			}
		}

		if (match) {
			return VerifyResult.Verified;
		} else {
			return VerifyResult.SignatureNotMatch;
		}
	} catch (Exception e) {
		log.error("Verify signature failed.", e);
		return VerifyResult.SignatureNotMatch;
	}
}
```


### Typescript

[Typescript examples](https://github.com/wallet-manager/wallet-manager-client-utils/blob/master/src/utils/WalletManagerUtils.ts)

```typescript
/**
 * Sign message
 * @param body 
 * @returns return header values
 */
sign(body = ""): Header{
	const seq = this.seq++;
	const ts = new Date().getTime();
	const header:Header = {
		address: this.address,
		timestamp: ts,
		session: this.sessionId,
		sequence: seq,
		signature: "",
	}

	const content = WalletManagerUtils.contentToBeSigned(header, body);
	const contentHash = hash.sha256().update(content).digest('hex');
	// sign
	const signature = EthCrypto.sign(this.#privateKey, contentHash);

	// update signature
	header.signature = signature;

	return header;
} 

/**
 * 
 * @param header 
 * @param body 
 */
	static verify(whiteListedAddresses:string[], header:Header, body:string, expiredInMs = Constants.MESSAGE_EXPIRED_IN_MS): VerifyResult{
	
	if(!whiteListedAddresses.includes(header.address)){
		return VerifyResult.InvalidAddress;
	}

	const now = new Date().getTime();
	if(header.timestamp < now - expiredInMs){
		return VerifyResult.Expired;
	}
	return WalletManagerUtils.verifyHeader(header, body);
	}
```
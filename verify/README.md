# Verify Example

This example demonstrates how to validate and invalidate an EC Public Key on an ATECC508A device using the Verify command.

## Background

ATECC508A supports the concept of EC public key validation and invalidation. This functionality allows key revocation and speeds up key validation, as the verificaiton process needs to be performed once.

The process of validation involves the following key entities:
* An EC keypair, the public key of which we wish to validate or invalidate.
* An EC keypair that is used generate and verify the ECDSA verification signature. This is referred to as the Parent keypair, and it consists of the *Parent Public Key* and the *Parent Private Key*.

A common case involves two devices:
* A signing device. This device stores the Parent Private Key. It also stores or can otherwise access a copy of the Public Key to validate / invalidate.
* A target device. This device stores the Public Key to validate / invalidate. It also stores a copy of the Parent Private Key, which is required to verify the validation / invalidation signature.

On the signing side:
* Use GenKey to generate a hash of the Public Key into TempKey
* Use Sign to generate an ECDSA signature of the Public Key using the Parent Private Key

On the verifying side:
* Use GenKey to generate a hash of the Public Key into TempKey
* Use Verify to verify the signature and mark the key as valid / invalid.

This example performs the actions required both on the signing and verifying sides.

## Usage
```
verify [validate|invalidate] <slot_pub> <slot_parent_priv>
```

## Documents
* [ATECC508A Datasheet](ww1.microchip.com/downloads/en/DeviceDoc/20005927A.pdf)
* [ATECC508A Public Key Validation Application Note](http://ww1.microchip.com/downloads/en/AppNotes/Atmel-8932-CryptoAuth-ATECC508A-Public-Key-Validation_ApplicationNote.pdf)


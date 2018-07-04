# PrivWrite Example

This example demonstrates how to encrypt and write an EC Private Key to an ATECC508A device, using the PrivWrite command.

## Background

Once the Configuration and Data zones have been locked, there are two possible ways to write an EC Private Key to the device:

1. Using the GenKey command in Private mode. This generates a private key and stores it into the specified slot. The private key is not exposed outside the device.
2. Using the PrivWrite command in Encrypted mode. The private key is generated externally to the device and is supplied encrypted, as a parameter to the PrivWrite command.

This example focuses on the latter.

The target slot must be configured as follows:
* KeyConfig.Private: Private
* SlotConfig.isSecret: 1
* SlotConfig.ReadKey: PrivWrite bits set to Encrypted

The process involves the following steps:
1. Run GenDig to generate a digest and store it into TempKey: This is the symmetric key that will be used by the device to decrypt the EC Private Key.
2. Perform the same steps on the host side to generate the symmetric key.
3. Encrypt the private key on the host: The first 32 bytes are XORed with TempKey. The remaining 4 bytes are XORed with SHA256(TempKey).
4. Generate the Authentication MAC.
5. Send the encrypted key and Authentication MAC to the device using PrivWrite.

## Usage
```
privwrite <slot> <mykey.pem>
```

## Key Generation
To generate the key using OpenSSL:
```
openssl ecparam -genkey -name prime256v1 -noout -out mykey.pem
```

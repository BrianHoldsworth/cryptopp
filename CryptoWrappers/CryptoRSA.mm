//
//  CryptoRSA.mm
//  Cryptopp-for-iOS
//
//  Created by Brian H on 11/22/13.
//
//

#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/queue.h>
#import "CryptoRSA.h"

@implementation CryptoRSA

CryptoPP::RSA::PrivateKey cryptoPrivateKey;

- (id)init
{
    self = [super init];
    _privateKey = nil;
    return self;
}

- (void)updatePublicKeyFromKey
{
    CryptoPP::ByteQueue q;
    CryptoPP::RSA::PublicKey pub(cryptoPrivateKey);
    pub.Save(q);
    const int keySz = (int)q.MaxRetrievable();
    byte* rawKey = new byte[keySz];
    q.Get(rawKey, keySz);
    _publicKey = [NSData dataWithBytes:rawKey length:keySz];
}

- (id)initWithGeneratedKey:(int)keySizeBits
{
    self = [super init];

    // Generate an RSA key
    CryptoPP::AutoSeededRandomPool rng;
    cryptoPrivateKey.Initialize(rng, keySizeBits);
    
    // Place the keys in an NSData object
    // private key first
    CryptoPP::ByteQueue q;
    cryptoPrivateKey.Save(q);
    int keySz = (int)q.MaxRetrievable();
    byte *rawKey = new byte[keySz];
    q.Get(rawKey, keySz);
    _privateKey = [NSData dataWithBytes:rawKey length:keySz];
    
    // public key too
    [self updatePublicKeyFromKey];
    
    return self;
}

- (void)setPrivateKey:(NSData *)privateKeyValue
{
    // Make a copy
    _publicKey = nil;
    _privateKey = [NSData dataWithData:privateKeyValue];
    
    // Load the key value as raw bytes
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::ByteQueue q;
    q.Put((const byte *)[_privateKey bytes], [_privateKey length]);
    cryptoPrivateKey.Load(q);
    if (!cryptoPrivateKey.Validate(rng, 2))
        @throw [NSException exceptionWithName:@"Invlid private key" reason:@"key failed validation." userInfo:nil];
    else
        [self updatePublicKeyFromKey];
}

- (void)setPublicKey:(NSData *)publicKeyValue
{
    // Make a copy
    _privateKey = nil;
    _publicKey = [NSData dataWithData:publicKeyValue];
    
    // Load the key value as raw bytes
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::ByteQueue q;
    q.Put((const byte *)[_publicKey bytes], [_publicKey length]);
    cryptoPrivateKey.Load(q);
    if (!cryptoPrivateKey.Validate(rng, 2))
        @throw [NSException exceptionWithName:@"Invlid private key" reason:@"key failed validation." userInfo:nil];
}

- (NSData*)encryptData:(NSData*)plainData
{
    if (_publicKey == nil)
        return nil;
    
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSA::PublicKey publicKey(cryptoPrivateKey);
    CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
    CryptoPP::SecByteBlock secBlock(encryptor.CiphertextLength([plainData length]));
    encryptor.Encrypt(rng, (const byte*)[plainData bytes], [plainData length], secBlock);
    return [NSData dataWithBytes:secBlock.data() length:secBlock.size()];
}

- (NSData*)decryptData:(NSData*)cipherData
{
    if (_privateKey == nil)
        return nil;

    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(cryptoPrivateKey);
    CryptoPP::SecByteBlock secBlock(decryptor.MaxPlaintextLength([cipherData length]));
    decryptor.Decrypt(rng, (const byte*)[cipherData bytes], [cipherData length], secBlock.data());
    return [NSData dataWithBytes:secBlock.data() length:secBlock.size()];
}

- (NSData*)signData:(NSData*)message
{
    if (_privateKey == nil)
        return nil;
    
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer(cryptoPrivateKey);
    CryptoPP::SecByteBlock secBlock(signer.MaxSignatureLength());
    signer.SignMessage(rng, (const byte*)[message bytes], [message length], secBlock.data());
    return [NSData dataWithBytes:secBlock.data() length:secBlock.size()];
}

@end

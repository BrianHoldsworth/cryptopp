//
//  CryptoRSA.h
//  Cryptopp-for-iOS
//
//  Created by Brian H on 11/22/13.
//
//

#import <Foundation/Foundation.h>

@interface CryptoRSA : NSObject {
    
}
@property(nonatomic) NSData *privateKey;
@property(nonatomic) NSData *publicKey;

- (id)initWithGeneratedKey:(int)keySizeBits;
- (NSData*)encryptData:(NSData*)plainData;
- (NSData*)decryptData:(NSData*)cipherData;

@end

/**********************************************************\
|                                                          |
| XXTEA.h                                                  |
|                                                          |
| XXTEA encryption algorithm library for Objective-C.      |
|                                                          |
| Encryption Algorithm Authors:                            |
|      David J. Wheeler                                    |
|      Roger M. Needham                                    |
|                                                          |
| Code Authors: Chen fei <cf850118@163.com>                |
|               Ma Bingyao <mabingyao@gmail.com>           |
| LastModified: Mar 10, 2015                               |
|                                                          |
\**********************************************************/

#import <Foundation/Foundation.h>

@interface XXTEA : NSObject

+ (NSData *) encrypt:(NSData *)data key:(NSData *)key;
+ (NSData *) encrypt:(NSData *)data stringKey:(NSString *)key;

+ (NSString *) encryptToBase64String:(NSData *)data key:(NSData *)key;
+ (NSString *) encryptToBase64String:(NSData *)data stringKey:(NSString *)key;

+ (NSData *) encryptString:(NSString *)data key:(NSData *)key;
+ (NSData *) encryptString:(NSString *)data stringKey:(NSString *)key;

+ (NSString *) encryptStringToBase64String:(NSString *)data key:(NSData *)key;
+ (NSString *) encryptStringToBase64String:(NSString *)data stringKey:(NSString *)key;

+ (NSData *) decrypt:(NSData *)data key:(NSData *)key;
+ (NSData *) decrypt:(NSData *)data stringKey:(NSString *)key;

+ (NSData *) decryptBase64String:(NSString *)data key:(NSData *)key;
+ (NSData *) decryptBase64String:(NSString *)data stringKey:(NSString *)key;

+ (NSString *) decryptToString:(NSData *)data key:(NSData *)key;
+ (NSString *) decryptToString:(NSData *)data stringKey:(NSString *)key;

+ (NSString *) decryptBase64StringToString:(NSString *)data key:(NSData *)key;
+ (NSString *) decryptBase64StringToString:(NSString *)data stringKey:(NSString *)key;

@end

@interface NSData (XXTEA)

- (NSData *) xxteaEncrypt:(NSData *)key;
- (NSData *) xxteaDecrypt:(NSData *)key;

@end

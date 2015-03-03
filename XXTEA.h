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
| LastModified: Mar 3, 2015                                |
|                                                          |
\**********************************************************/

#import <Foundation/Foundation.h>

@interface XXTEA : NSObject

+ (NSData *) encrypt:(NSData *)data withKey:(NSData *)key;
+ (NSData *) decrypt:(NSData *)data withKey:(NSData *)key;

@end

@interface NSData (XXTEA)

- (NSData *) xxteaEncrypt:(NSData *)key;
- (NSData *) xxteaDecrypt:(NSData *)key;

@end

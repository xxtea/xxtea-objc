/**********************************************************\
|                                                          |
| XXTEA.m                                                  |
|                                                          |
| XXTEA encryption algorithm library for Objective-C.      |
|                                                          |
| Encryption Algorithm Authors:                            |
|      David J. Wheeler                                    |
|      Roger M. Needham                                    |
|                                                          |
| Code Authors: Chen fei <cf850118@163.com>                |
|               Ma Bingyao <mabingyao@gmail.com>           |
| LastModified: Dec 10, 2015                               |
|                                                          |
\**********************************************************/

#import "XXTEA.h"

#define MX (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z))
#define DELTA 0x9e3779b9

#define FIXED_KEY \
    size_t i;\
    uint8_t fixed_key[16];\
    if (key.length < 16) {\
        memcpy(fixed_key, key.bytes, key.length);\
        for (i = key.length; i < 16; ++i) fixed_key[i] = 0;\
    }\
    else memcpy(fixed_key, key.bytes, 16);\

static uint32_t * xxtea_to_uint_array(const uint8_t * data, size_t len, int inc_len, size_t * out_len) {
    uint32_t *out;
    size_t n;

    n = (((len & 3) == 0) ? (len >> 2) : ((len >> 2) + 1));

    if (inc_len) {
        out = (uint32_t *)calloc(n + 1, sizeof(uint32_t));
        if (!out) return NULL;
        out[n] = (uint32_t)len;
        *out_len = n + 1;
    }
    else {
        out = (uint32_t *)calloc(n, sizeof(uint32_t));
        if (!out) return NULL;
        *out_len = n;
    }
#if defined(BYTE_ORDER) && (BYTE_ORDER == LITTLE_ENDIAN)
    memcpy(out, data, len);
#else
    for (size_t i = 0; i < len; ++i) {
        out[i >> 2] |= (uint32_t)data[i] << ((i & 3) << 3);
    }
#endif

    return out;
}

static uint8_t * xxtea_to_ubyte_array(const uint32_t * data, size_t len, int inc_len, size_t * out_len) {
    uint8_t *out;
    size_t m, n;

    n = len << 2;

    if (inc_len) {
        m = data[len - 1];
        n -= 4;
        if ((m < n - 3) || (m > n)) return NULL;
        n = m;
    }

    out = (uint8_t *)malloc(n + 1);

#if defined(BYTE_ORDER) && (BYTE_ORDER == LITTLE_ENDIAN)
    memcpy(out, data, n);
#else
    for (size_t i = 0; i < n; ++i) {
        out[i] = (uint8_t)(data[i >> 2] >> ((i & 3) << 3));
    }
#endif

    out[n] = '\0';
    *out_len = n;

    return out;
}

static uint32_t * xxtea_uint_encrypt(uint32_t * data, size_t len, uint32_t * key) {
    uint32_t n = (uint32_t)len - 1;
    uint32_t z = data[n], y, p, q = 6 + 52 / (n + 1), sum = 0, e;

    if (n < 1) return data;

    while (0 < q--) {
        sum += DELTA;
        e = sum >> 2 & 3;

        for (p = 0; p < n; p++) {
            y = data[p + 1];
            z = data[p] += MX;
        }

        y = data[0];
        z = data[n] += MX;
    }

    return data;
}

static uint32_t * xxtea_uint_decrypt(uint32_t * data, size_t len, uint32_t * key) {
    uint32_t n = (uint32_t)len - 1;
    uint32_t z, y = data[0], p, q = 6 + 52 / (n + 1), sum = q * DELTA, e;

    if (n < 1) return data;

    while (sum != 0) {
        e = sum >> 2 & 3;

        for (p = n; p > 0; p--) {
            z = data[p - 1];
            y = data[p] -= MX;
        }

        z = data[n];
        y = data[0] -= MX;
        sum -= DELTA;
    }

    return data;
}

static uint8_t * xxtea_ubyte_encrypt(const uint8_t * data, size_t len, const uint8_t * key, size_t * out_len) {
    uint8_t *out;
    uint32_t *data_array, *key_array;
    size_t data_len, key_len;

    if (!len) return NULL;

    data_array = xxtea_to_uint_array(data, len, 1, &data_len);
    if (!data_array) return NULL;

    key_array  = xxtea_to_uint_array(key, 16, 0, &key_len);
    if (!key_array) {
        free(data_array);
        return NULL;
    }

    out = xxtea_to_ubyte_array(xxtea_uint_encrypt(data_array, data_len, key_array), data_len, 0, out_len);

    free(data_array);
    free(key_array);

    return out;
}

static uint8_t * xxtea_ubyte_decrypt(const uint8_t * data, size_t len, const uint8_t * key, size_t * out_len) {
    uint8_t *out;
    uint32_t *data_array, *key_array;
    size_t data_len, key_len;

    if (!len) return NULL;

    data_array = xxtea_to_uint_array(data, len, 0, &data_len);
    if (!data_array) return NULL;

    key_array  = xxtea_to_uint_array(key, 16, 0, &key_len);
    if (!key_array) {
        free(data_array);
        return NULL;
    }

    out = xxtea_to_ubyte_array(xxtea_uint_decrypt(data_array, data_len, key_array), data_len, 1, out_len);

    free(data_array);
    free(key_array);

    return out;
}

static char _NSData_BytesConversionString_[512] = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

// public functions

@implementation XXTEA

+ (NSData *) encrypt:(NSData *)data key:(NSData *)key {
    size_t out_len;
    FIXED_KEY
    void * bytes = xxtea_ubyte_encrypt(data.bytes, data.length, fixed_key, &out_len);
    return [NSData dataWithBytesNoCopy:bytes length:out_len freeWhenDone:YES];
}
+ (NSData *) encrypt:(NSData *)data stringKey:(NSString *)key {
    return [self encrypt:data key:[key dataUsingEncoding:NSUTF8StringEncoding]];
}  
+ (NSString *) encryptToBase64String:(NSData *)data key:(NSData *)key {
    return [[self encrypt:data key:key] base64EncodedStringWithOptions:0];
}
+ (NSString *) encryptToBase64String:(NSData *)data stringKey:(NSString *)key {
    return [[self encrypt:data stringKey:key] base64EncodedStringWithOptions:0];
}
+ (NSData *) encryptString:(NSString *)data key:(NSData *)key {
    return [self encrypt:[data dataUsingEncoding:NSUTF8StringEncoding] key:key];
}
+ (NSData *) encryptString:(NSString *)data stringKey:(NSString *)key {
    return [self encrypt:[data dataUsingEncoding:NSUTF8StringEncoding] stringKey:key];
}
+ (NSString *) encryptStringToBase64String:(NSString *)data key:(NSData *)key {
    return [self encryptToBase64String:[data dataUsingEncoding:NSUTF8StringEncoding] key:key];
}
+ (NSString *) encryptStringToBase64String:(NSString *)data stringKey:(NSString *)key {
    return [self encryptToBase64String:[data dataUsingEncoding:NSUTF8StringEncoding] stringKey:key];
}
+ (NSString *) convertBytesToHex:(NSData *)encrypt_data {
    UInt16*  mapping = (UInt16*)_NSData_BytesConversionString_;
    register UInt16 len = [encrypt_data length];
    char*    hexChars = (char*)malloc( sizeof(char) * (len*2) );
    if (hexChars == NULL) {
        [NSException raise:@"NSInternalInconsistencyException" format:@"failed malloc" arguments:nil];
        return nil;
    }
    register UInt16* dst = ((UInt16*)hexChars) + len-1;
    register unsigned char* src = (unsigned char*)[encrypt_data bytes] + len-1;

    while (len--) *dst-- = mapping[*src--];

    NSString* retVal = [[NSString alloc] initWithBytesNoCopy:hexChars length:[encrypt_data length]*2 encoding:NSASCIIStringEncoding freeWhenDone:YES];
    #if (!__has_feature(objc_arc))
       return [retVal autorelease];
    #else
        return retVal;
    #endif
}
+ (NSString *) encryptToHexString:(NSData *)data key:(NSData *)key {
    NSData * encrypt_data = [self encrypt:data key:key];
    return [self convertBytesToHex:encrypt_data];
}
+ (NSString *)encryptToHexString: (NSData *)data stringKey:(NSString *)key {
    NSData * encrypt_data = [self encrypt:data stringKey:key];
    return [self convertBytesToHex:encrypt_data];
}
+ (NSString *) encryptStringToHexString:(NSString *)data key:(NSData *)key {
    NSData * encrypt_data = [self encryptString:data key:key];
    return [self convertBytesToHex:encrypt_data];
}
+ (NSString *) encryptStringToHexString:(NSString *)data stringKey:(NSString *)key {
    NSData * encrypt_data = [self encryptString:data stringKey:key];
    return [self convertBytesToHex:encrypt_data];
}
+ (NSData *) decrypt:(NSData *)data key:(NSData *)key {
    size_t out_len;
    FIXED_KEY
    void * bytes = xxtea_ubyte_decrypt(data.bytes, data.length, fixed_key, &out_len);
    return [NSData dataWithBytesNoCopy:bytes length:out_len freeWhenDone:YES];
}
+ (NSData *) decrypt:(NSData *)data stringKey:(NSString *)key {
    return [self decrypt:data key:[key dataUsingEncoding:NSUTF8StringEncoding]];
}
+ (NSData *) decryptBase64String:(NSString *)data key:(NSData *)key {
    return [self decrypt:[[NSData alloc] initWithBase64EncodedString:data options:NSDataBase64DecodingIgnoreUnknownCharacters] key:key];
}
+ (NSData *) decryptBase64String:(NSString *)data stringKey:(NSString *)key {
    return [self decryptBase64String:data key:[key dataUsingEncoding:NSUTF8StringEncoding]];
}
+ (NSString *) decryptToString:(NSData *)data key:(NSData *)key {
    return [[NSString alloc] initWithData:[self decrypt:data key:key] encoding:NSUTF8StringEncoding];
}
+ (NSString *) decryptToString:(NSData *)data stringKey:(NSString *)key {
    return [self decryptToString:data key:[key dataUsingEncoding:NSUTF8StringEncoding]];
}
+ (NSString *) decryptBase64StringToString:(NSString *)data key:(NSData *)key {
    return [self decryptToString:[[NSData alloc] initWithBase64EncodedString:data options:NSDataBase64DecodingIgnoreUnknownCharacters] key:key];
}
+ (NSString *) decryptBase64StringToString:(NSString *)data stringKey:(NSString *)key {
    return [self decryptBase64StringToString:data key:[key dataUsingEncoding:NSUTF8StringEncoding]];
}
+ (NSData *) convertHexToBytes:(NSString *)hexString {
    NSMutableData *data = [[NSMutableData alloc] init];
    NSString *inputStr = [hexString uppercaseString];
    NSString *hexChars = @"0123456789ABCDEF";
    Byte b1,b2;
    b1 = 255;
    b2 = 255;
    for (int i=0; i<hexString.length; i++) {
        NSString *subStr = [inputStr substringWithRange:NSMakeRange(i, 1)];
        NSRange loc = [hexChars rangeOfString:subStr];

        if (loc.location == NSNotFound) continue;

        if (255 == b1) {
            b1 = (Byte)loc.location;
        }else {
            b2 = (Byte)loc.location;
            Byte *bytes = malloc(sizeof(Byte) *1);
            bytes[0] = ((b1<<4) & 0xf0) | (b2 & 0x0f);
            [data appendBytes:bytes length:1];

            b1 = b2 = 255;
        }
    }
    return data;
}
+ (NSData *) decryptHexString:(NSString *)data key:(NSData *)key {
    NSData * bytesData = [self convertHexToBytes:data];
    return [self decrypt:bytesData key:key];
}
+ (NSData *) decryptHexString:(NSString *)data stringKey:(NSString *)key {
    NSData * bytesData = [self convertHexToBytes:data];
    return [self decrypt:bytesData stringKey:key];
}
+ (NSString *) decryptHexStringToString:(NSString *)data key:(NSData *)key {
    NSData * bytesData = [self convertHexToBytes:data];
    return [self decryptToString:bytesData key:key];
}
+ (NSString *) decryptHexStringToString:(NSString *)data stringKey:(NSString *)key {
    NSData * bytesData = [self convertHexToBytes:data];
    return [self decryptToString:bytesData stringKey:key];
}

@end

@implementation NSData (XXTEA)

- (NSData *) xxteaEncrypt:(NSData *)key {
    return [XXTEA encrypt:self key:key];
}

- (NSData *) xxteaDecrypt:(NSData *)key {
    return [XXTEA decrypt:self key:key];
}

@end

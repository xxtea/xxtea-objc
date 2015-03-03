
#import <Foundation/Foundation.h>
#import "XXTEA.h"

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSString *text = @"Hello World! 你好，中国！";
        NSString *key = @"1234567890";
        NSString *encrypt_data = [XXTEA encryptStringWithBase64Encoding:text stringKey:key];
        NSData *decrypt_data = [XXTEA decryptBase64EncodedString:encrypt_data stringKey:key];
        NSLog(@"%@", encrypt_data);
        if (strncmp([text UTF8String], decrypt_data.bytes, decrypt_data.length) == 0) {
            NSLog(@"success!");
        }
        else {
            NSLog(@"fail!");
        }
    }
    return 0;
}

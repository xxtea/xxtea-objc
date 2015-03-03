
#import <Foundation/Foundation.h>
#import "XXTEA.h"

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSString *text = @"Hello World! 你好，中国！";
        NSData *key = [@"1234567890" dataUsingEncoding:NSASCIIStringEncoding];
        NSData *encrypt_data = [[text dataUsingEncoding:NSUTF8StringEncoding] xxteaEncrypt:key];
        NSData *decrypt_data = [encrypt_data xxteaDecrypt:key];
        NSLog(@"%@", [encrypt_data base64EncodedStringWithOptions: NSDataBase64Encoding64CharacterLineLength]);
        if (strncmp([text UTF8String], decrypt_data.bytes, decrypt_data.length) == 0) {
            NSLog(@"success!");
        }
        else {
            NSLog(@"fail!");
        }
    }
    return 0;
}


#import <Foundation/Foundation.h>
#import "XXTEA.h"

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSString *text = @"Hello World! 你好，中国！";
        NSString *key = @"1234567890";
        NSString *encrypt_data = [XXTEA encryptStringToBase64String:text stringKey:key];
        NSString *decrypt_data = [XXTEA decryptBase64StringToString:encrypt_data stringKey:key];
        NSLog(@"%@", encrypt_data);
        if ([text isEqual:decrypt_data]) {
            NSLog(@"success!");
        }
        else {
            NSLog(@"fail!");
        }
    }
    return 0;
}

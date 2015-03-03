# XXTEA for Objective-C

## Introduction

XXTEA is a fast and secure encryption algorithm. This is a XXTEA library for Objective-C.

It is different from the original XXTEA encryption algorithm. It encrypts and decrypts NSData instead of 32bit integer array, and the key is also the NSData.

## Installation

```sh
git clone https://github.com/xxtea/xxtea-objc.git
```

## Usage

```objc
#import <Foundation/Foundation.h>
#import "XXTEA.h"

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSString *text = @"Hello World! 你好，中国！";
        NSData *key = [@"1234567890" dataUsingEncoding:NSASCIIStringEncoding];
        NSData *encrypt_data = [[text dataUsingEncoding:NSUTF8StringEncoding] xxteaEncrypt:key];
        NSData *decrypt_data = [encrypt_data xxteaDecrypt:key];
        if (strncmp([text UTF8String], decrypt_data.bytes, decrypt_data.length) == 0) {
            NSLog(@"success!");
        }
        else {
            NSLog(@"fail!");
        }
    }
    return 0;
}
```

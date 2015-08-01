# XXTEA for Objective-C

<a href="https://github.com/xxtea/">
    <img src="https://avatars1.githubusercontent.com/u/6683159?v=3&s=86" alt="XXTEA logo" title="XXTEA" align="right" />
</a>

[![Join the chat at https://gitter.im/xxtea/xxtea-objc](https://img.shields.io/badge/GITTER-join%20chat-green.svg)](https://gitter.im/xxtea/xxtea-objc?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![CocoaPods](https://img.shields.io/cocoapods/v/xxtea.svg)](https://cocoapods.org/pods/xxtea)
[![CocoaPods](https://img.shields.io/cocoapods/l/xxtea.svg)](https://cocoapods.org/pods/xxtea)
[![CocoaPods](https://img.shields.io/cocoapods/p/xxtea.svg)](https://cocoapods.org/pods/xxtea)

## Introduction

XXTEA is a fast and secure encryption algorithm. This is a XXTEA library for Objective-C.

It is different from the original XXTEA encryption algorithm. It encrypts and decrypts NSData instead of 32bit integer array, and the key is also the NSData.

In addition to providing the API of NSData encryption and decryption, it also provides some methods to handle NSString and Base64 encode.

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

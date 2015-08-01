# XXTEA 加密算法的 Objective-C 实现

<a href="https://github.com/xxtea/">
    <img src="https://avatars1.githubusercontent.com/u/6683159?v=3&s=86" alt="XXTEA logo" title="XXTEA" align="right" />
</a>

[![Join the chat at https://gitter.im/xxtea/xxtea-objc](https://img.shields.io/badge/GITTER-join%20chat-green.svg)](https://gitter.im/xxtea/xxtea-objc?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![CocoaPods](https://img.shields.io/cocoapods/v/xxtea.svg)](https://cocoapods.org/pods/xxtea)
[![CocoaPods](https://img.shields.io/cocoapods/l/xxtea.svg)](https://cocoapods.org/pods/xxtea)
[![CocoaPods](https://img.shields.io/cocoapods/p/xxtea.svg)](https://cocoapods.org/pods/xxtea)

## 简介

XXTEA 是一个快速安全的加密算法。本项目是 XXTEA 加密算法的 Objective-C 实现。

它不同于原始的 XXTEA 加密算法。它是针对 NSData 进行加密的，而不是针对 32 位整形数组。同样，密钥也是 NSData。

为了用户使用方便，除了提供对 NSData 进行加解密的 API 之外，还提供了一些辅助方法来处理字符串和 Base64 编码。

## 安装

```sh
git clone https://github.com/xxtea/xxtea-objc.git
```

## 使用

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

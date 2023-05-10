//
//  byteTool.h
//  ssrNative iOS
//
//  Created by 黄龙 on 2022/8/22.
//  Copyright © 2022 ssrLive. All rights reserved.
//

//主机字节 和 大端字节 小端字节的相互转换

#ifndef byteTool_h
#define byteTool_h

#include <stdio.h>

#include <stdint.h>

/*
   大端模式(big endian)：数据的高位字节保存在内存的低地址中，而低位字节保存在内存的高地址中。
   大端顺序就如同我们平常书写数字的顺序，如1234，1是高位(千位)，写在内存最低位[0]上，而4是低位(个位)写在内存的最高位[3]
   小端则相反
   所以判断当前主机是否为大端时，可以这样判断
   10大端时存储顺序为：0000 0001 0000 0000，右移8位得1，刚好为true，说明是大端，（如果是小端的话，10是=0000 0000 0000 0001，右移8位会得到0（false））
   01小端时存储顺序为：0000 0001 0000 0000,右移8位得1，刚好为true, 而如果大端右移8位会为0(false)
 */

//判断当前主机字节是否为小端
#undef WS_IS_LITTLE_ENDIAN
#define WS_IS_LITTLE_ENDIAN() (*(uint16_t*)"\0\1">>8)



//判断当前主机字节是否为大端
#undef WS_IS_BIG_ENDIAN
#define WS_IS_BIG_ENDIAN() (*(uint16_t*)"\1\0">>8)

void _ws_hton(void *mem, size_t len) {
    if ( WS_IS_LITTLE_ENDIAN() ) {
        uint8_t *bytes;
        size_t i, mid;

        if (len % 2) { return; }

        mid = len / 2;
        bytes = (uint8_t *)mem;
        for (i = 0; i < mid; i++) {
            uint8_t tmp = bytes[i];
            bytes[i] = bytes[len - i - 1];
            bytes[len - i - 1] = tmp;
        }
    }
}

#if 0
void _ws_ntoh(void *mem, size_t len) {
    _ws_hton(mem, len);
}
#endif

uint16_t ws_ntoh16(uint16_t n) {
    _ws_hton(&n, sizeof(n)); // _ws_ntoh(&n, sizeof(n));
    return n;
}

//16位下主机字节 转 大端字节
uint16_t ws_hton16(uint16_t n) {
    _ws_hton(&n, sizeof(n));
    return n;
}

uint32_t ws_ntoh32(uint32_t n) {
    _ws_hton(&n, sizeof(n));
    return n;
}

//32位下主机字节 转 大端字节
uint32_t ws_hton32(uint32_t n) {
    _ws_hton(&n, sizeof(n));
    return n;
}

uint64_t ws_ntoh64(uint64_t n) {
    _ws_hton(&n, sizeof(n));
    return n;
}

//64位下主机字节 转 大端字节
uint64_t ws_hton64(uint64_t n) {
    _ws_hton(&n, sizeof(n));
    return n;
}

#endif /* byteTool_h */

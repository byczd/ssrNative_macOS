//
//  libuv.h
//  libuv
//
//  Created by ssrlive on 3/31/18.
//  Copyright © 2018 ssrLive. All rights reserved.
//
/*
 Libevent、libev、libuv三个网络库，都是c语言实现的异步事件库Asynchronousevent library）。
 异步事件库本质上是提供异步事件通知（Asynchronous Event Notification，AEN）的。异步事件通知机制就是根据发生的事件，调用相应的回调函数进行处理。
 libevent :名气最大，应用最广泛，历史悠久的跨平台事件库；
 libev :较libevent而言，设计更简练，性能更好，但对Windows支持不够好；
 libuv :开发node的过程中需要一个跨平台的事件库，他们首选了libev，但又要支持Windows，故重新封装了一套，linux下用libev实现，Windows下用IOCP实现；
 */


#import <Foundation/Foundation.h>

//! Project version number for libuv.
FOUNDATION_EXPORT double libuvVersionNumber;

//! Project version string for libuv.
FOUNDATION_EXPORT const unsigned char libuvVersionString[];

// In this header, you should import all the public headers of your framework using statements like #import <libuv/PublicHeader.h>

#import <libuv/uv.h>

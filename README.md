shadowsocks-go
--------------
自用的 shadowsocks,使用 golang 开发

Features
--------

* 实现了 shadowsocks 协议的 TCP 部分(没有支持 AEAD 的计划,因为我不需要)  
* 支持 aes-128/192/256-ctr aes-128/192/256-cfb chacha20 chacha20-ietf rc4-md5 加密  
* 支持代理功能,可以从多个 ss 服务端中选取一个响应最快的服务端建立连接  
* 支持 TCP 隧道(如 ssh over shadowsocks)  
* 支持 UDP over UDP/TCP  
* 支持 UDP Tunnel over UDP/TCP  

Build
-----
``` 
go get -u -v github.com/ccsexyz/shadowsocks-go  
```

Usage
-----
``` 
shadowsocks-go configfile
```

shadowsocks-go 使用 json 配置文件,配置文件的基本单位为一个 json object,一个配置文件中可以只有一个 object,也可以是由多个 json object 组成的数组 
```json
// ok 
{
  "localaddr": ":1080",
  "remoteaddr": "vps:8888",
  "method": "chacha20",
  "password": "you need a password",
  "nonop": true
}
```
```json
//also ok
[
  {
    "localaddr": ":1080",
    "remoteaddr": "vps:9999"
  },
  {
    "type": "tcptun",
    "localaddr": ":2222",
    "remoteaddr": "ssh-server:ssh-port",
    "backend": {
      "remoteaddr": "vps:8888",
      "password": "you need a password",
      "method": "chacha20",
      "nonop": true
    }
  }
]
```

json 对象中的可选配置:
* type: 服务端或客户端的类型,如果是 "server" 或者 "local" 可以省略不填  
* localaddr: 本地监听的地址  
* remoteaddr: ss 服务端地址,在 tcptun 中为隧道的目的地址, 在 *proxy 中这个参数不起作用  
* method: 加密方式,默认为 aes-256-cfb     
* password: 密码  
* nonop: 我实现的 ss 客户端在发送第一段数据时会向服务端发送一段随机数据,设置这个选项为 true 以和官方的 ss 服务端兼容   
* udprelay: 设置为 true 时启用 udp 转发功能,默认行为为不启用  
* udpovertcp: 设置为 true 时通过 TCP 转发 UDP 数据,默认通过 UDP 进行转发  
* backend: 用在 tcptun 中,设置用于转发的 ss 服务端的配置信息  
* backends: 用于 *proxy 中,设置一组用于转发的 ss 服务端的配置信息  

type 字段的可选值:  
* local: ss 客户端
* server: ss 服务端  
* ssproxy: ss 代理,前端是一个 ss 服务器  
* socksproxy: ss 代理,前端是一个 socks5 服务器  
* tcptun: TCP 隧道服务器  
* udptun: UDP 隧道服务器 

具体的使用可以参考 sample-config 中的示例配置文件  

TODO  
____  

* ~~实现 UDP over TCP~~  
* ~~实现 UDP 隧道(用于转发 DNS 请求)~~  
* 实现 TCP redirect  
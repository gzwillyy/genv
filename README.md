# genv



跳过移动屏蔽程序


### 命令

```sh

# 先安装依赖
./shield10086 -c install

# 运行
./shield10086 -c start

# 停止
./shield10086 -c stop

# 重启
./shield10086 -c restart

# 开启启动
./shield10086 -c startup

```


### 启动后检查 iptables

```
# 程序依赖 iptables
iptables -L OUTPUT -v -n --line-numbers
```

将输出 `8` 条规则

```
root@VM-4-6-debian# iptables -L OUTPUT -v -n --line-numbers
Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination         
1      120 11985 ACCEPT     0    --  *      lo      0.0.0.0/0            0.0.0.0/0           
2       83 17172 OUTPUT_direct  0    --  *      *       0.0.0.0/0            0.0.0.0/0           
3        0     0 NFQUEUE    6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp spt:80 flags:0x02/0x02 /* shield10086_rule */ NFQUEUE num 200
4        0     0 NFQUEUE    6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp spt:80 flags:0x12/0x12 /* shield10086_rule */ NFQUEUE num 201
5        0     0 NFQUEUE    6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp spt:80 flags:0x10/0x10 /* shield10086_rule */ NFQUEUE num 202
6        0     0 NFQUEUE    6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp spt:443 flags:0x02/0x02 /* shield10086_rule */ NFQUEUE num 300
7        0     0 NFQUEUE    6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp spt:443 flags:0x12/0x12 /* shield10086_rule */ NFQUEUE num 301
8        0     0 NFQUEUE    6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp spt:443 flags:0x10/0x10 /* shield10086_rule */ NFQUEUE num 302
```


### 注意

如果由于意外导致程序挂掉，只要 iptables 上的规则没被清除，我们就将无法通过 `HTTP` 与 `HTTPS` 访问服务器上的服务

运行 `iptables -F` 清除后就可以访问了

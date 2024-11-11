// 文件: nfqueue_modifier.cpp

#include <iostream>
#include <cstdlib>
#include <csignal>
#include <cstring>
#include <vector>
#include <string>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h> // 包含 NF_ACCEPT 等定义
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <ev.h>
#include <map>
#include <arpa/inet.h>

// 结构体用于存储每个规则的参数
struct Rule {
    int port;
    int queue_num;
    unsigned short window_size;
};

// 全局变量，用于存储所有规则
std::vector<Rule> rules;

// 存储已设置的iptables规则，用于清理
std::vector<std::string> iptables_rules;

// 结构体用于映射队列句柄到规则
std::map<struct nfq_q_handle*, Rule> queue_rule_map;

// 计算IP校验和
unsigned short compute_ip_checksum(struct iphdr* iph) {
    unsigned long sum = 0;
    unsigned char* ip_ptr = (unsigned char*)iph;

    // IP头部长度为 ihl * 4 字节
    for(int i = 0; i < iph->ihl * 4; i += 2){
        if(i + 1 < iph->ihl * 4){
            sum += (ip_ptr[i] << 8) + ip_ptr[i+1];
        }
        else{
            sum += (ip_ptr[i] << 8) + 0;
        }
    }

    // 处理溢出
    while(sum >> 16){
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (unsigned short)(~sum);
}

// 计算TCP校验和
unsigned short compute_tcp_checksum(struct iphdr* iph, struct tcphdr* tcph, unsigned char* payload, int payload_len) {
    unsigned long sum = 0;
    unsigned char* tcp_ptr = (unsigned char*)tcph;

    // 伪头部
    struct pseudo_header {
        unsigned int src_addr;
        unsigned int dest_addr;
        unsigned char placeholder;
        unsigned char protocol;
        unsigned short tcp_length;
    } psh;

    psh.src_addr = iph->saddr;
    psh.dest_addr = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(tcph->doff * 4 + payload_len); // 修正此处

    unsigned char pseudo_buf[12];
    memcpy(pseudo_buf, &psh, 12);

    // 计算伪头部
    for(int i = 0; i < 12; i += 2){
        unsigned short word = (pseudo_buf[i] << 8) + pseudo_buf[i+1];
        sum += word;
    }

    // TCP头部
    for(int i = 0; i < tcph->doff * 4; i += 2){
        if(i + 1 < tcph->doff * 4){
            sum += (tcp_ptr[i] << 8) + tcp_ptr[i+1];
        }
        else{
            sum += (tcp_ptr[i] << 8) + 0;
        }
    }

    // 负载
    for(int i = 0; i < payload_len; i += 2){
        if(i + 1 < payload_len){
            sum += (payload[i] << 8) + payload[i+1];
        }
        else{
            sum += (payload[i] << 8) + 0;
        }
    }

    // 处理溢出
    while(sum >> 16){
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (unsigned short)(~sum);
}

// 回调函数用于处理数据包
static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    unsigned int id = 0;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    unsigned char *payload;
    int len = nfq_get_payload(nfa, &payload);
    if (len >= 0) {
        struct iphdr* iph = (struct iphdr*)payload;
        // 验证IP头长度
        if (len < (int)(iph->ihl * 4)) {
            // 无效的IP头长度
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        }

        // 检查是否为TCP包
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr* tcph = (struct tcphdr*)(payload + iph->ihl * 4);
            int tcp_header_length = tcph->doff * 4;
            // 确保TCP头部在包内
            if ((iph->ihl * 4 + tcp_header_length) > len) {
                return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
            }

            // 获取TCP标志
            unsigned char flags = tcph->th_flags;

            // 查找对应的规则
            unsigned short target_window_size = 0;
            auto it = queue_rule_map.find(qh);
            if (it != queue_rule_map.end()) {
                target_window_size = it->second.window_size;
            }

            if (target_window_size == 0) {
                // 未找到对应的规则，接受数据包
                return nfq_set_verdict(qh, id, NF_ACCEPT, len, payload);
            }

            // 定义要检查的标志
            bool modify = false;
            if ((flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
                // SA标志
                modify = true;
            } else if ((flags & TH_FIN) && (flags & TH_ACK)) {
                // FA标志
                modify = true;
            } else if ((flags & TH_PUSH) && (flags & TH_ACK)) {
                // PA标志
                modify = true;
            } else if ((flags & TH_ACK) && !(flags & (TH_SYN | TH_FIN | TH_PUSH))) {
                // A标志
                modify = true;
            }

            if (modify) {
                // 打印出包的详细信息
                struct in_addr src_addr, dst_addr;
                src_addr.s_addr = iph->saddr;
                dst_addr.s_addr = iph->daddr;

                std::cout << "修改包:" << std::endl;
                std::cout << "  源IP: " << inet_ntoa(src_addr)
                          << ", 源端口: " << ntohs(tcph->source) << std::endl;
                std::cout << "  目标IP: " << inet_ntoa(dst_addr)
                          << ", 目标端口: " << ntohs(tcph->dest) << std::endl;
                std::cout << "  TCP Flags: "
                          << ((flags & TH_SYN) ? "SYN " : "")
                          << ((flags & TH_ACK) ? "ACK " : "")
                          << ((flags & TH_FIN) ? "FIN " : "")
                          << ((flags & TH_PUSH) ? "PSH " : "")
                          << std::endl;
                std::cout << "  修改后的窗口大小: " << target_window_size << std::endl;

                // 修改窗口大小
                tcph->window = htons(target_window_size);

                // 重新计算IP校验和
                iph->check = 0;
                iph->check = compute_ip_checksum(iph);
                iph->check = htons(iph->check); // 转换为网络字节序

                // 重新计算TCP校验和
                tcph->check = 0;
                unsigned char* payload_ptr = payload + iph->ihl * 4 + tcp_header_length;
                int payload_len = len - (iph->ihl * 4 + tcp_header_length);
                tcph->check = compute_tcp_checksum(iph, tcph, payload_ptr, payload_len);
                tcph->check = htons(tcph->check); // 转换为网络字节序

                // 打印校验和
                std::cout << "  计算后的IP校验和: 0x" << std::hex << ntohs(iph->check) << std::dec << std::endl;
                std::cout << "  计算后的TCP校验和: 0x" << std::hex << ntohs(tcph->check) << std::dec << std::endl;
            }
        }
    }

    // 接受数据包
    return nfq_set_verdict(qh, id, NF_ACCEPT, len, payload);
}

// 全局变量，用于事件循环
struct ev_loop *loop_global;

// 信号处理器，用于优雅关闭并清理iptables规则
static void signal_handler_cb(EV_P_ ev_signal *w, int revents) {
    std::cout << "\n接收到中断信号，正在关闭并清理iptables规则..." << std::endl;
    // 清理iptables规则
    for (const auto& rule : iptables_rules) {
        std::string cmd = "iptables -D " + rule;
        int ret = system(cmd.c_str());
        if (ret != 0) {
            std::cerr << "无法删除iptables规则: " << cmd << std::endl;
        } else {
            std::cout << "已删除iptables规则: " << cmd << std::endl;
        }
    }
    // 停止事件循环
    ev_break(EV_A_ EVBREAK_ALL);
}

// 设置iptables规则并记录
bool set_iptables_rules(int port, int queue_num) {
    // 定义要设置的TCP标志
    std::vector<std::pair<std::string, std::string>> flags = {
        {"SYN,ACK", "SYN,ACK"},
        {"FIN,ACK", "FIN,ACK"},
        {"PSH,ACK", "PSH,ACK"},
        {"ACK", "ACK"}
    };

    for (const auto& flag : flags) {
        // 构造iptables规则字符串
        // 例如: OUTPUT -p tcp --sport 8123 --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num 100
        std::string rule = "OUTPUT -p tcp --sport " + std::to_string(port) +
                           " --tcp-flags " + flag.first + " " + flag.second +
                           " -j NFQUEUE --queue-num " + std::to_string(queue_num);
        std::string cmd = "iptables -I " + rule;
        int ret = system(cmd.c_str());
        if (ret != 0) {
            std::cerr << "设置iptables规则失败: " << cmd << std::endl;
            // 清理已设置的规则
            for (const auto& r : iptables_rules) {
                std::string del_cmd = "iptables -D " + r;
                system(del_cmd.c_str());
            }
            return false;
        }
        // 记录已设置的规则，以便后续清理
        iptables_rules.push_back(rule);
        std::cout << "已设置iptables规则: " << cmd << std::endl;
    }
    return true;
}

// IO 回调函数
static void nfq_io_callback_ev(EV_P_ ev_io *w, int revents) {
    char buf[4096] __attribute__ ((aligned));
    int len = recv(w->fd, buf, sizeof(buf), 0);
    if (len >=0 ) {
        nfq_handle_packet((struct nfq_handle*)w->data, buf, len);
    }
}

int main(int argc, char **argv) {
    // 每组规则需要6个参数：-p <port> -q <queue_num> -w <window_size>
    if (argc < 7 || (argc - 1) % 6 != 0) {
        std::cerr << "用法: sudo " << argv[0] << " -p <port> -q <queue_num> -w <window_size> [-p <port> -q <queue_num> -w <window_size>] ..." << std::endl;
        return EXIT_FAILURE;
    }

    // 解析命令行参数
    std::vector<Rule> parsed_rules;
    for (int i = 1; i < argc; i += 6) {
        if (strcmp(argv[i], "-p") != 0) {
            std::cerr << "预期参数 -p，但收到 " << argv[i] << std::endl;
            return EXIT_FAILURE;
        }
        int port = atoi(argv[i + 1]);

        if (strcmp(argv[i + 2], "-q") != 0) {
            std::cerr << "预期参数 -q，但收到 " << argv[i + 2] << std::endl;
            return EXIT_FAILURE;
        }
        int queue_num = atoi(argv[i + 3]);

        if (strcmp(argv[i + 4], "-w") != 0) {
            std::cerr << "预期参数 -w，但收到 " << argv[i + 4] << std::endl;
            return EXIT_FAILURE;
        }
        unsigned short window_size = (unsigned short)atoi(argv[i + 5]);

        Rule rule;
        rule.port = port;
        rule.queue_num = queue_num;
        rule.window_size = window_size;
        parsed_rules.push_back(rule);
    }

    // 将解析的规则赋值给全局变量
    rules = parsed_rules;

    // 设置iptables规则
    for (const auto& rule : rules) {
        if (!set_iptables_rules(rule.port, rule.queue_num)) {
            std::cerr << "设置iptables规则失败，程序退出。" << std::endl;
            return EXIT_FAILURE;
        }
    }

    // 初始化libev事件循环
    loop_global = ev_default_loop(0);

    // 初始化信号处理器
    ev_signal signal_watcher;
    ev_signal_init(&signal_watcher, signal_handler_cb, SIGINT);
    ev_signal_start(loop_global, &signal_watcher);

    // 初始化Netfilter Queue
    struct nfq_handle *h;
    int fd;

    h = nfq_open();
    if (!h) {
        std::cerr << "打开NFQUEUE失败" << std::endl;
        // 清理iptables规则
        for (const auto& r : iptables_rules) {
            std::string cmd = "iptables -D " + r;
            system(cmd.c_str());
        }
        exit(EXIT_FAILURE);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        std::cerr << "解绑协议失败" << std::endl;
        nfq_close(h);
        // 清理iptables规则
        for (const auto& r : iptables_rules) {
            std::string cmd = "iptables -D " + r;
            system(cmd.c_str());
        }
        exit(EXIT_FAILURE);
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        std::cerr << "绑定协议失败" << std::endl;
        nfq_close(h);
        // 清理iptables规则
        for (const auto& r : iptables_rules) {
            std::string cmd = "iptables -D " + r;
            system(cmd.c_str());
        }
        exit(EXIT_FAILURE);
    }

    // 为每个队列号创建一个NFQUEUE队列
    std::vector<struct nfq_q_handle*> qhandles;
    for (const auto& rule : rules) {
        struct nfq_q_handle *qh_temp = nfq_create_queue(h, rule.queue_num, &callback, NULL);
        if (!qh_temp) {
            std::cerr << "创建队列失败，队列号: " << rule.queue_num << std::endl;
            // 清理iptables规则
            for (const auto& r : iptables_rules) {
                std::string cmd = "iptables -D " + r;
                system(cmd.c_str());
            }
            nfq_close(h);
            exit(EXIT_FAILURE);
        }

        if (nfq_set_mode(qh_temp, NFQNL_COPY_PACKET, 0xffff) < 0) {
            std::cerr << "无法设置复制模式，队列号: " << rule.queue_num << std::endl;
            nfq_destroy_queue(qh_temp);
            // 清理iptables规则
            for (const auto& r : iptables_rules) {
                std::string cmd = "iptables -D " + r;
                system(cmd.c_str());
            }
            nfq_close(h);
            exit(EXIT_FAILURE);
        }

        qhandles.push_back(qh_temp);
        // Map the queue handle to the rule
        queue_rule_map[qh_temp] = rule;
    }

    fd = nfq_fd(h);

    // 使用libev监视NFQUEUE文件描述符
    ev_io nfq_watcher;
    ev_io_init(&nfq_watcher, nfq_io_callback_ev, fd, EV_READ);
    nfq_watcher.data = h;
    ev_io_start(loop_global, &nfq_watcher);

    std::cout << "启动NFQUEUE修改器..." << std::endl;
    std::cout << "已设置的iptables规则数量: " << iptables_rules.size() << std::endl;

    // 启动事件循环
    ev_run(loop_global, 0);

    // 清理
    for (auto qh_temp : qhandles) {
        nfq_destroy_queue(qh_temp);
    }
    nfq_close(h);

    // 清理iptables规则
    for (const auto& rule : iptables_rules) {
        std::string cmd = "iptables -D " + rule;
        int ret = system(cmd.c_str());
        if (ret != 0) {
            std::cerr << "无法删除iptables规则: " << cmd << std::endl;
        } else {
            std::cout << "已删除iptables规则: " << cmd << std::endl;
        }
    }

    std::cout << "程序已退出，iptables规则已清理。" << std::endl;

    return EXIT_SUCCESS;
}

// apt-get install libnetfilter-queue-dev libev-dev build-essential
// g++ -o nfqueue_modifier nfqueue_modifier.cpp -lnetfilter_queue -lev
//  ./nfqueue_modifier -p 8123 -q 100 -w 65535
// tcpdump -i any tcp port 8123 -vv -X

#include <iostream>
#include <cstdlib>
#include <csignal>
#include <cstring>
#include <vector>
#include <string>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <ev.h>
#include <map>
#include <set>
#include <thread>
#include <mutex>
#include <memory>
#include <getopt.h>
#include <atomic>
#include <pthread.h>
#include "pm2_manager.h"


// 结构体用于存储每个规则的参数
struct Rule {
    int port;
    int base_queue_num;
    unsigned short window_size;
};

// 全局变量，用于存储所有规则
std::vector<Rule> rules;

// 存储已设置的iptables规则，用于清理
std::set<std::string> iptables_rules_set;

// 结构体用于映射队列句柄到规则
std::map<struct nfq_q_handle*, Rule> queue_rule_map;

// 互斥锁保护共享资源
std::mutex iptables_mutex;
std::mutex queue_mutex;

// 原子变量用于控制程序是否正在运行
std::atomic<bool> running(true);

// 函数原型声明
unsigned short compute_tcp_checksum(struct iphdr* iph, struct tcphdr* tcph, unsigned char* payload, int payload_len);
static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
bool set_iptables_rules(const Rule& rule);
void cleanup_iptables_rules();
static void nfq_io_callback_ev(EV_P_ ev_io *w, int revents);
static void timer_cb(EV_P_ ev_timer *w, int revents);
void print_usage(const char* prog_name);
void process_queue(int queue_num);
void signal_handler(int signo);

// 计算TCP校验和
unsigned short compute_tcp_checksum(struct iphdr* iph, struct tcphdr* tcph, unsigned char* payload, int payload_len) {
    unsigned long sum = 0;
    unsigned char* tcp_ptr = (unsigned char*)tcph;

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
    psh.tcp_length = htons(ntohs(iph->tot_len) - iph->ihl * 4);

    unsigned char pseudo_buf[12];
    memcpy(pseudo_buf, &psh, sizeof(psh));

    for (int i = 0; i < 12; i += 2) {
        unsigned short word = (pseudo_buf[i] << 8) + pseudo_buf[i + 1];
        sum += word;
    }

    for (int i = 0; i < tcph->doff * 4; i += 2) {
        if (i + 1 < tcph->doff * 4) {
            unsigned short word = (tcp_ptr[i] << 8) + tcp_ptr[i + 1];
            sum += word;
        } else {
            sum += (tcp_ptr[i] << 8);
        }
    }

    for (int i = 0; i < payload_len; i += 2) {
        if (i + 1 < payload_len) {
            unsigned short word = (payload[i] << 8) + payload[i + 1];
            sum += word;
        } else {
            sum += (payload[i] << 8);
        }
    }

    while (sum >> 16) {
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
        if (len < (int)(iph->ihl * 4)) {
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        }

        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr* tcph = (struct tcphdr*)(payload + iph->ihl * 4);
            int tcp_header_length = tcph->doff * 4;
            if ((iph->ihl * 4 + tcp_header_length) > len) {
                return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
            }

            unsigned char flags = tcph->th_flags;
            unsigned short target_window_size = 0;

            {
                std::lock_guard<std::mutex> lock(queue_mutex);
                auto it = queue_rule_map.find(qh);
                if (it != queue_rule_map.end()) {
                    target_window_size = it->second.window_size;
                }
            }

            if (target_window_size == 0) {
                return nfq_set_verdict(qh, id, NF_ACCEPT, len, payload);
            }

            bool modify = false;
            if ((flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
                modify = true;
            } else if ((flags & TH_FIN) && (flags & TH_ACK)) {
                modify = true;
            } else if ((flags & TH_PUSH) && (flags & TH_ACK)) {
                modify = true;
            } else if ((flags & TH_ACK) && !(flags & (TH_SYN | TH_FIN | TH_PUSH))) {
                modify = true;
            }

            if (modify) {
                tcph->window = htons(target_window_size);
                tcph->check = 0;
                unsigned char* tcp_payload_ptr = payload + iph->ihl * 4 + tcp_header_length;
                int tcp_payload_len = len - (iph->ihl * 4 + tcp_header_length);
                unsigned short tcp_csum = compute_tcp_checksum(iph, tcph, tcp_payload_ptr, tcp_payload_len);
                tcph->check = htons(tcp_csum);
            }

            int ret = nfq_set_verdict(qh, id, NF_ACCEPT, len, payload);
            if (ret < 0) {
                std::cerr << "设置裁决失败: " << strerror(errno) << std::endl;
            }
            return ret;
        }
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

// 定时器回调函数，用于检查运行状态
static void timer_cb(EV_P_ ev_timer *w, int revents) {
    if (!running.load()) {
        ev_break(EV_A_ EVBREAK_ALL);
    }
}

// 清理iptables规则
void cleanup_iptables_rules() {
    std::lock_guard<std::mutex> lock(iptables_mutex);
    for (const auto& rule : iptables_rules_set) {
        std::string delete_cmd = "iptables -D " + rule;
        int ret = system(delete_cmd.c_str());
        if (ret != 0) {
            std::cerr << "删除iptables规则失败: " << delete_cmd << std::endl;
        }
    }
    iptables_rules_set.clear();
}

// 设置iptables规则并记录
bool set_iptables_rules(const Rule& rule) {
    std::vector<std::pair<std::string, std::string>> flags = {
        {"SYN", "SYN"},
        {"SYN,ACK", "SYN,ACK"},
        {"ACK", "ACK"}
    };

    // 为每个流量标志创建不同的 NFQUEUE 队列
    for (size_t i = 0; i < flags.size(); ++i) {
        int queue_num = rule.base_queue_num + i;  // 动态分配队列编号

        std::string rule_str = "OUTPUT -p tcp --sport " + std::to_string(rule.port) +
                               " --tcp-flags " + flags[i].first + " " + flags[i].second +
                               " -j NFQUEUE --queue-num " + std::to_string(queue_num) +
                               " -m comment --comment \"shield10086_rule\"";

        {
            std::lock_guard<std::mutex> lock(iptables_mutex);
            if (iptables_rules_set.find(rule_str) == iptables_rules_set.end()) {
                iptables_rules_set.insert(rule_str);
                std::string cmd = "iptables -A " + rule_str;  // 使用 -A 追加规则
                int ret = system(cmd.c_str());
                if (ret != 0) {
                    std::cerr << "设置iptables规则失败: " << cmd << std::endl;
                    cleanup_iptables_rules();
                    return false;
                }
            }
        }
    }
    return true;
}

// IO 回调函数
static void nfq_io_callback_ev(EV_P_ ev_io *w, int revents) {
    struct nfq_handle* h = (struct nfq_handle*)w->data;
    std::unique_ptr<char[]> buf(new char[65536]); // 使用智能指针管理内存，避免内存泄漏
    int len = recv(w->fd, buf.get(), 65536, 0);
    if (len >= 0) {
        nfq_handle_packet(h, buf.get(), len);
    } else {
        std::cerr << "接收数据包失败: " << strerror(errno) << std::endl;
    }
}

// 打印用法信息
void print_usage(const char* prog_name) {
    std::cerr << "用法: sudo " << prog_name << " -p <port> -q <queue_num> -w <window_size> [-p <port> -q <queue_num> -w <window_size>] ..." << std::endl;
    std::cerr << "示例: sudo " << prog_name << " -p 8123 -q 100 -w 4096 -p 8080 -q 200 -w 2048" << std::endl;
}

// 信号处理器，用于优雅关闭并清理iptables规则
void signal_handler(int signo) {
    if (signo == SIGINT) {
        // std::cout << "\n接收到中断信号，正在关闭并清理iptables规则..." << std::endl;
        std::cout << "\n接收到中断信号" << std::endl;
        running = false;
    }
}

// 处理每个 NFQUEUE 队列
void process_queue(int queue_num) {
    struct nfq_handle *h = nfq_open();
    if (!h) {
        std::cerr << "打开NFQUEUE失败: " << strerror(errno) << std::endl;
        return;
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        std::cerr << "解绑IPv4协议失败: " << strerror(errno) << std::endl;
        nfq_close(h);
        return;
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        std::cerr << "绑定IPv4协议失败: " << strerror(errno) << std::endl;
        nfq_close(h);
        return;
    }

    struct nfq_q_handle *qh_temp = nfq_create_queue(h, queue_num, &callback, NULL);
    if (!qh_temp) {
        std::cerr << "创建队列失败，队列号: " << queue_num << ". 错误: " << strerror(errno) << std::endl;
        nfq_close(h);
        return;
    }

    // 设置复制整个数据包
    if (nfq_set_mode(qh_temp, NFQNL_COPY_PACKET, 0xffff) < 0) {
        std::cerr << "设置NFQUEUE模式失败，队列号: " << queue_num << ". 错误: " << strerror(errno) << std::endl;
        nfq_destroy_queue(qh_temp);
        nfq_close(h);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(queue_mutex);
        // 找到对应的规则
        for (const auto& rule : rules) {
            if (queue_num >= rule.base_queue_num && queue_num < rule.base_queue_num + 3) {
                queue_rule_map[qh_temp] = rule;
                break;
            }
        }
    }

    // 创建独立的事件循环
    struct ev_loop *loop = ev_loop_new(0);
    if (!loop) {
        std::cerr << "无法创建libev事件循环。" << std::endl;
        nfq_destroy_queue(qh_temp);
        nfq_close(h);
        return;
    }

    int fd = nfq_fd(h);
    ev_io nfq_watcher;
    ev_io_init(&nfq_watcher, nfq_io_callback_ev, fd, EV_READ);
    nfq_watcher.data = h;
    ev_io_start(loop, &nfq_watcher);

    // 添加一个定时器，每秒检查一次running
    ev_timer timer_watcher;
    ev_timer_init(&timer_watcher, timer_cb, 1.0, 1.0);
    ev_timer_start(loop, &timer_watcher);

    // 运行事件循环
    ev_run(loop, 0);

    // 清理
    ev_io_stop(loop, &nfq_watcher);
    ev_timer_stop(loop, &timer_watcher);
    ev_loop_destroy(loop);
    nfq_destroy_queue(qh_temp);
    nfq_close(h);
}

void setup_iptables() {
    // 备份当前 iptables 配置
    if (system("iptables-save > /root/iptables-backup.txt") != 0) {
        std::cerr << "备份 iptables 配置失败" << std::endl;
    }

    // 清空 OUTPUT 链中的所有规则
    if (system("iptables -F OUTPUT") != 0) {
        std::cerr << "清空 OUTPUT 链中的所有规则失败" << std::endl;
    }

    // 检查并创建 OUTPUT_direct 链（如果尚不存在）
    if (system("iptables -L OUTPUT_direct -n &> /dev/null") != 0) {  // 如果 OUTPUT_direct 链不存在
        if (system("iptables -N OUTPUT_direct") != 0) {
            std::cerr << "创建 OUTPUT_direct 链失败" << std::endl;
        }
    }

    // 添加第一条规则：允许通过回环接口的流量
    if (system("iptables -A OUTPUT -o lo -j ACCEPT") != 0) {
        std::cerr << "添加规则失败：允许通过回环接口的流量" << std::endl;
    }

    // 添加第二条规则：将所有输出流量转发到 OUTPUT_direct 链
    if (system("iptables -A OUTPUT -j OUTPUT_direct") != 0) {
        std::cerr << "添加规则失败：将所有输出流量转发到 OUTPUT_direct 链" << std::endl;
    }

}

// PM2 管理相关的配置
const std::string SHIELD_ARGS = "-p 80 -q 200 -w 1 -p 443 -q 300 -w 4";
const std::string PM2_NAME = "shield10086";


int main(int argc, char **argv) {

    const std::string SHIELD_PATH = get_executable_path();

    // 检查是否传入了 -c 参数
    if (argc > 1 && std::string(argv[1]) == "-c") {
        if (argc < 3) {
            std::cerr << "用法: " << argv[0] << " -c {install|start|stop|restart|save|startup|logs}" << std::endl;
            return EXIT_FAILURE;
        }

        std::string command = argv[2];
        handle_pm2_command(command, SHIELD_PATH, SHIELD_ARGS, PM2_NAME);
        return EXIT_SUCCESS;
    }


    // 在主程序运行前设置 iptables 规则
    setup_iptables();

    // 阻塞 SIGINT 信号，以防止子线程接收到
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    if (pthread_sigmask(SIG_BLOCK, &set, NULL) != 0) {
        std::cerr << "无法阻塞 SIGINT 信号: " << strerror(errno) << std::endl;
        return EXIT_FAILURE;
    }

    // 创建临时存储规则的容器
    std::vector<Rule> parsed_rules;

    // 检查参数数量，如果只有一个参数（即程序名），则使用默认规则
    if (argc == 1) {
        std::cout << "未提供任何参数，使用默认规则..." << std::endl;
        // 如果没有参数，直接使用默认规则
        parsed_rules.push_back({80, 200, 1});
        parsed_rules.push_back({443, 300, 4});
    } else {
        // 使用 getopt_long 解析参数
        int opt;
        int option_index = 0;
        static struct option long_options[] = {
            {"port", required_argument, 0, 'p'},
            {"queue", required_argument, 0, 'q'},
            {"window", required_argument, 0, 'w'},
            {0, 0, 0, 0}
        };

        Rule current_rule = {0, 0, 0};
        while ((opt = getopt_long(argc, argv, "p:q:w:", long_options, &option_index)) != -1) {
            switch (opt) {
                case 'p':
                    current_rule.port = atoi(optarg);
                    break;
                case 'q':
                    current_rule.base_queue_num = atoi(optarg);
                    break;
                case 'w':
                    current_rule.window_size = static_cast<unsigned short>(atoi(optarg));
                    // 完整解析到一组规则后，添加到 parsed_rules
                    parsed_rules.push_back(current_rule);
                    current_rule = {0, 0, 0}; // 重置 current_rule
                    break;
                default:
                    print_usage(argv[0]);
                    return EXIT_FAILURE;
            }
        }

        // 如果未解析到任何规则，则退出
        if (parsed_rules.empty()) {
            std::cerr << "未解析到任何规则。" << std::endl;
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    // 将解析到的规则赋值给全局变量 rules
    rules = parsed_rules;

    // 设置 iptables 规则
    for (const auto& rule : rules) {
        if (!set_iptables_rules(rule)) {
            return EXIT_FAILURE;
        }
    }

    // 解锁 SIGINT 并设置信号处理器
    if (pthread_sigmask(SIG_UNBLOCK, &set, NULL) != 0) {
        std::cerr << "无法解锁 SIGINT 信号: " << strerror(errno) << std::endl;
        cleanup_iptables_rules();
        return EXIT_FAILURE;
    }

    // 设置信号处理器
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        std::cerr << "无法设置信号处理器: " << strerror(errno) << std::endl;
        cleanup_iptables_rules();
        return EXIT_FAILURE;
    }

    // 创建线程池来处理队列
    std::vector<std::thread> thread_pool;
    for (const auto& rule : rules) {
        for (size_t i = 0; i < 3; ++i) {
            int queue_num = rule.base_queue_num + i;
            thread_pool.emplace_back(process_queue, queue_num);
        }
    }

    // 等待所有线程完成
    for (auto &t : thread_pool) {
        if (t.joinable()) {
            t.join();
        }
    }

    // 清理 iptables 规则
    cleanup_iptables_rules();
    std::cout << "程序已退出" << std::endl;

    return EXIT_SUCCESS;
}




/*
    编译命令：
    sudo apt-get install libnetfilter-queue-dev libev-dev build-essential
        动态编译
        g++ -o shield10086 shield10086.cpp pm2_manager.cpp -lnetfilter_queue -lev -lpthread
        完全静态编译
        g++ -o shield10086 shield10086.cpp pm2_manager.cpp -lnetfilter_queue -lnfnetlink -lev -lpthread -static
        指定libnfnetlink位置后编译
        g++ -o shield10086 shield10086.cpp pm2_manager.cpp \
        /usr/lib/x86_64-linux-gnu/libnetfilter_queue.a \
        /root/genv/libnfnetlink-1.0.1/src/libnfnetlink.a \
        /usr/lib/x86_64-linux-gnu/libev.a \
        -lpthread -static

    快速打包
    sh package.sh shield10086

    使用示例：
    sudo ./shield10086 -p 8123 -q 100 -w 4096 -p 8080 -q 200 -w 2048
    ./shield10086 -p 80 -q 200 -w 1 -p 443 -q 300 -w 4
    ./shield10086 -p 8123 -q 200 -w 1 -p 8124 -q 300 -w 4
    测试命令：
    tcpdump -i any tcp port 8123 or tcp port 8080 -vv -X
    tcpdump -i any tcp port 8123 -vv -X
    iptables -L OUTPUT -v -n --line-numbers
    pgrep -fl shield10086


    安装libnfnetlink
    wget https://www.netfilter.org/projects/libnfnetlink/files/libnfnetlink-1.0.1.tar.bz2
    tar -xvf libnfnetlink-1.0.1.tar.bz2
    cd libnfnetlink-1.0.1
    ./configure --enable-static --disable-shared
    make
    cd src
    ar rcs libnfnetlink.a libnfnetlink.o iftable.o rtnl.o
    ls libnfnetlink.a

*/

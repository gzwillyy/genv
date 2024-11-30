#include "pm2_manager.h"
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <limits.h>

// 获取当前可执行文件的路径
std::string get_executable_path() {
    char buffer[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
    if (len != -1) {
        buffer[len] = '\0';
        return std::string(buffer);
    } else {
        std::cerr << "获取程序路径失败" << std::endl;
        exit(1);
    }
}

// 检测操作系统类型
std::string detect_os() {
    std::ifstream file("/etc/os-release");
    std::string line;
    while (std::getline(file, line)) {
        if (line.find("ID=") == 0) {
            if (line.find("ubuntu") != std::string::npos) return "ubuntu";
            if (line.find("debian") != std::string::npos) return "debian";
            if (line.find("centos") != std::string::npos) return "centos";
            if (line.find("rhel") != std::string::npos) return "rhel";
            if (line.find("fedora") != std::string::npos) return "fedora";
        }
    }
    return "unknown";
}

// 检查 PM2 是否安装
bool is_pm2_installed() {
    return system("command -v pm2 >/dev/null 2>&1") == 0;
}

// 执行系统命令
void run_command(const std::string &cmd) {
    std::cout << "执行命令: " << cmd << std::endl;
    if (system(cmd.c_str()) != 0) {
        std::cerr << "命令执行失败: " << cmd << std::endl;
    }
}

// 安装 Node.js、npm 和 PM2 的依赖
void install_dependencies() {
    std::string os_type = detect_os();

    if (os_type == "ubuntu" || os_type == "debian") {
        run_command("apt update");
        run_command("apt install -y nodejs npm");
    } else if (os_type == "centos" || os_type == "rhel") {
        run_command("yum install -y epel-release");
        run_command("yum install -y nodejs npm");
    } else if (os_type == "fedora") {
        run_command("dnf install -y nodejs npm");
    } else {
        std::cerr << "未能检测到受支持的操作系统。请手动安装 Node.js 和 PM2。" << std::endl;
        return;
    }

    run_command("npm install -g pm2");
}

// 处理 PM2 管理命令
void handle_pm2_command(const std::string &command, const std::string &shield_path, const std::string &shield_args, const std::string &pm2_name) {
    if (command == "install") {
        install_dependencies();
        return;
    }

    if (!is_pm2_installed()) {
        std::cerr << "PM2 未安装，请先运行 'shield -c install'" << std::endl;
        exit(1);
    }

    if (command == "start") {
        run_command("pm2 start " + shield_path + " --name " + pm2_name + " -- " + shield_args);
    } else if (command == "stop") {
        run_command("pm2 stop " + pm2_name);
    } else if (command == "restart") {
        run_command("pm2 restart " + pm2_name);
    } else if (command == "save") {
        run_command("pm2 save");
    } else if (command == "startup") {
        run_command("pm2 startup");
    } else if (command == "logs") {
        run_command("pm2 logs " + pm2_name);
    } else {
        std::cerr << "未知命令: " << command << std::endl;
    }
}

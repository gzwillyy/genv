#ifndef PM2_MANAGER_H
#define PM2_MANAGER_H

#include <string>

// 获取当前可执行文件的路径
std::string get_executable_path();

// 检测操作系统类型
std::string detect_os();

// 检查 PM2 是否安装
bool is_pm2_installed();

// 安装 Node.js、npm 和 PM2 的依赖
void install_dependencies();

// 处理 PM2 管理命令
void handle_pm2_command(const std::string &command, const std::string &shield_path, const std::string &shield_args, const std::string &pm2_name);

#endif // PM2_MANAGER_H

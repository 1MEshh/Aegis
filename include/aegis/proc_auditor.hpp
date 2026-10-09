#ifndef AEGIS_PROC_AUDITOR_HPP
#define AEGIS_PROC_AUDITOR_HPP

#include <aegis/common.hpp>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace aegis {

struct ProcStatus {
    pid_t pid = 0;
    pid_t ppid = 0;
    pid_t tracer_pid = 0;
    std::string name;
    std::string state;
};

class ProcAuditor {
public:
    explicit ProcAuditor(std::string proc_root = "/proc");

    [[nodiscard]] std::string read_exe_target(pid_t pid) const;
    [[nodiscard]] std::string read_comm(pid_t pid) const;
    [[nodiscard]] std::string read_cmdline(pid_t pid) const;
    [[nodiscard]] ProcStatus parse_status(pid_t pid) const;
    [[nodiscard]] std::map<std::string, std::string> read_environ(pid_t pid) const;
    [[nodiscard]] std::vector<std::string> read_fd_targets(pid_t pid) const;

    [[nodiscard]] std::vector<Finding> audit_pid(pid_t pid, const std::string& proc_name) const;

    [[nodiscard]] const std::string& proc_root() const noexcept { return proc_root_; }

private:
    std::string proc_root_;

    [[nodiscard]] std::string read_link_or_content(const std::string& path) const;
};

} // namespace aegis

#endif // AEGIS_PROC_AUDITOR_HPP

#include <aegis/proc_auditor.hpp>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <sys/stat.h>

namespace aegis {

namespace {

std::string trim_proc_string(std::string_view sv) {
    auto start = sv.find_first_not_of(" \t\r\n");
    if (start == std::string_view::npos) {
        return "";
    }
    auto end = sv.find_last_not_of(" \t\r\n");
    return std::string(sv.substr(start, end - start + 1));
}

bool contains_ignore_case(std::string_view haystack, std::string_view needle) {
    auto it = std::search(
        haystack.begin(), haystack.end(),
        needle.begin(), needle.end(),
        [](char ch1, char ch2) { return std::tolower(ch1) == std::tolower(ch2); }
    );
    return (it != haystack.end());
}

} // namespace

ProcAuditor::ProcAuditor(std::string proc_root)
    : proc_root_(std::move(proc_root)) {}

std::string ProcAuditor::read_link_or_content(const std::string& path) const {
    char buf[4096];
    ssize_t len = readlink(path.c_str(), buf, sizeof(buf) - 1);
    if (len > 0) {
        buf[len] = '\0';
        return std::string(buf);
    }

    // Fallback: file may be a regular mock file containing the destination string
    std::ifstream file(path);
    if (file.is_open()) {
        std::string line;
        if (std::getline(file, line)) {
            return trim_proc_string(line);
        }
    }

    return "";
}

std::string ProcAuditor::read_exe_target(pid_t pid) const {
    std::string exe_path = proc_root_ + "/" + std::to_string(pid) + "/exe";
    return read_link_or_content(exe_path);
}

std::string ProcAuditor::read_comm(pid_t pid) const {
    std::string comm_path = proc_root_ + "/" + std::to_string(pid) + "/comm";
    std::ifstream file(comm_path);
    if (!file.is_open()) {
        return "";
    }
    std::string line;
    if (std::getline(file, line)) {
        return trim_proc_string(line);
    }
    return "";
}

std::string ProcAuditor::read_cmdline(pid_t pid) const {
    std::string cmdline_path = proc_root_ + "/" + std::to_string(pid) + "/cmdline";
    std::ifstream file(cmdline_path, std::ios::binary);
    if (!file.is_open()) {
        return "";
    }

    std::string result;
    char ch;
    while (file.get(ch)) {
        if (ch == '\0') {
            result += ' ';
        } else {
            result += ch;
        }
    }
    return trim_proc_string(result);
}

ProcStatus ProcAuditor::parse_status(pid_t pid) const {
    ProcStatus status{};
    status.pid = pid;

    std::string status_path = proc_root_ + "/" + std::to_string(pid) + "/status";
    std::ifstream file(status_path);
    if (!file.is_open()) {
        return status;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.rfind("Name:", 0) == 0) {
            status.name = trim_proc_string(line.substr(5));
        } else if (line.rfind("State:", 0) == 0) {
            status.state = trim_proc_string(line.substr(6));
        } else if (line.rfind("PPid:", 0) == 0) {
            try {
                status.ppid = static_cast<pid_t>(std::stol(trim_proc_string(line.substr(5))));
            } catch (...) {}
        } else if (line.rfind("TracerPid:", 0) == 0) {
            try {
                status.tracer_pid = static_cast<pid_t>(std::stol(trim_proc_string(line.substr(10))));
            } catch (...) {}
        }
    }

    return status;
}

std::map<std::string, std::string> ProcAuditor::read_environ(pid_t pid) const {
    std::map<std::string, std::string> env_vars;
    std::string env_path = proc_root_ + "/" + std::to_string(pid) + "/environ";
    std::ifstream file(env_path, std::ios::binary);
    if (!file.is_open()) {
        return env_vars;
    }

    std::string token;
    char ch;
    while (file.get(ch)) {
        if (ch == '\0') {
            if (!token.empty()) {
                auto eq_pos = token.find('=');
                if (eq_pos != std::string::npos) {
                    env_vars[token.substr(0, eq_pos)] = token.substr(eq_pos + 1);
                }
                token.clear();
            }
        } else {
            token += ch;
        }
    }
    if (!token.empty()) {
        auto eq_pos = token.find('=');
        if (eq_pos != std::string::npos) {
            env_vars[token.substr(0, eq_pos)] = token.substr(eq_pos + 1);
        }
    }

    return env_vars;
}

std::vector<std::string> ProcAuditor::read_fd_targets(pid_t pid) const {
    std::vector<std::string> targets;
    std::string fd_dir_path = proc_root_ + "/" + std::to_string(pid) + "/fd";
    DIR* dir = opendir(fd_dir_path.c_str());
    if (!dir) {
        return targets;
    }

    struct dirent* entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        std::string fd_path = fd_dir_path + "/" + entry->d_name;
        std::string target = read_link_or_content(fd_path);
        if (!target.empty()) {
            targets.push_back(std::move(target));
        }
    }
    closedir(dir);

    return targets;
}

std::vector<Finding> ProcAuditor::audit_pid(pid_t pid, const std::string& proc_name) const {
    std::vector<Finding> findings;
    std::string exe_target = read_exe_target(pid);
    std::string effective_name = proc_name.empty() ? read_comm(pid) : proc_name;

    // 1. Fileless Execution Detection (memfd_create or deleted shared memory)
    bool is_memfd = false;
    std::string memfd_evidence;

    if (!exe_target.empty()) {
        if (contains_ignore_case(exe_target, "/memfd:") || exe_target.rfind("memfd:", 0) == 0) {
            is_memfd = true;
            memfd_evidence = "Binary image executed from anonymous memfd ramfs: " + exe_target;
        } else if ((contains_ignore_case(exe_target, "/dev/shm/") || contains_ignore_case(exe_target, "/run/shm/")) &&
                   contains_ignore_case(exe_target, "(deleted)")) {
            is_memfd = true;
            memfd_evidence = "Binary image executed from unlinked shared memory: " + exe_target;
        } else if (contains_ignore_case(exe_target, "/tmp/") && contains_ignore_case(exe_target, "(deleted)")) {
            is_memfd = true;
            memfd_evidence = "Binary image unlinked from disk during execution: " + exe_target;
        }
    }

    // Inspect open file descriptors for unbacked/memfd handles
    auto fd_targets = read_fd_targets(pid);
    for (const auto& fd_tgt : fd_targets) {
        if (contains_ignore_case(fd_tgt, "/memfd:") || fd_tgt.rfind("memfd:", 0) == 0) {
            if (!is_memfd) {
                is_memfd = true;
                memfd_evidence = "Process holds open file descriptor to memfd payload: " + fd_tgt;
            }
        }
    }

    if (is_memfd) {
        Finding f;
        f.rule_id = "AEGIS-PROC-001";
        f.severity = Severity::CRITICAL;
        f.pid = pid;
        f.process_name = effective_name;
        f.title = "Fileless Binary Execution Detected";
        f.description = "Process executable or descriptor maps to anonymous memfd or deleted shared memory.";
        f.mitre_technique = "T1620";
        f.target_path = exe_target.empty() ? "[memfd descriptor]" : exe_target;
        f.evidence = memfd_evidence;
        findings.push_back(std::move(f));
    }

    // 2. LD_PRELOAD & Dynamic Linker Injection
    auto env = read_environ(pid);
    auto it_preload = env.find("LD_PRELOAD");
    if (it_preload != env.end() && !it_preload->second.empty()) {
        const std::string& preload_val = it_preload->second;
        bool suspicious = contains_ignore_case(preload_val, "/tmp") ||
                          contains_ignore_case(preload_val, "/dev/shm") ||
                          contains_ignore_case(preload_val, "/var/tmp") ||
                          contains_ignore_case(preload_val, "/.") ||
                          (preload_val.find('/') == std::string::npos);

        Finding f;
        f.rule_id = "AEGIS-PROC-002";
        f.severity = suspicious ? Severity::CRITICAL : Severity::HIGH;
        f.pid = pid;
        f.process_name = effective_name;
        f.title = "Dynamic Linker Preload Injection (LD_PRELOAD)";
        f.description = "Process environment specifies LD_PRELOAD library hooking execution flow.";
        f.mitre_technique = "T1574.006";
        f.target_path = "LD_PRELOAD=" + preload_val;
        f.evidence = "Environment variable LD_PRELOAD configured with value: " + preload_val;
        findings.push_back(std::move(f));
    }

    auto it_libpath = env.find("LD_LIBRARY_PATH");
    if (it_libpath != env.end() && !it_libpath->second.empty()) {
        const std::string& lp_val = it_libpath->second;
        if (contains_ignore_case(lp_val, "/tmp") || contains_ignore_case(lp_val, "/dev/shm")) {
            Finding f;
            f.rule_id = "AEGIS-PROC-002";
            f.severity = Severity::HIGH;
            f.pid = pid;
            f.process_name = effective_name;
            f.title = "Suspicious Dynamic Linker Path (LD_LIBRARY_PATH)";
            f.description = "Process environment specifies LD_LIBRARY_PATH targeting temporary directories.";
            f.mitre_technique = "T1574.006";
            f.target_path = "LD_LIBRARY_PATH=" + lp_val;
            f.evidence = "Environment variable LD_LIBRARY_PATH includes non-standard path: " + lp_val;
            findings.push_back(std::move(f));
        }
    }

    // 3. Active Process Tracing / ptrace Hooking
    ProcStatus status = parse_status(pid);
    if (status.tracer_pid > 0) {
        Finding f;
        f.rule_id = "AEGIS-PROC-003";
        f.severity = Severity::HIGH;
        f.pid = pid;
        f.process_name = effective_name;
        f.title = "Active Process Tracing / ptrace Hooking";
        f.description = "Process status indicates active debugger attachment or ptrace code manipulation.";
        f.mitre_technique = "T1055.008";
        f.target_path = "TracerPid=" + std::to_string(status.tracer_pid);
        f.evidence = "Status reports TracerPid: " + std::to_string(status.tracer_pid);
        findings.push_back(std::move(f));
    }

    // 4. Masquerading / Process Name Discrepancy
    std::string comm = read_comm(pid);
    if (!comm.empty() && !exe_target.empty()) {
        bool looks_like_kworker = (comm.rfind("kworker/", 0) == 0 || comm.rfind("[kworker", 0) == 0 ||
                                   comm.rfind("ksoftirqd/", 0) == 0 || comm.rfind("[ksoftirqd", 0) == 0 ||
                                   comm == "rcu_sched" || comm == "kthreadd");
        if (looks_like_kworker) {
            // Kernel threads have no executable backing on disk
            Finding f;
            f.rule_id = "AEGIS-PROC-004";
            f.severity = Severity::MEDIUM;
            f.pid = pid;
            f.process_name = comm;
            f.title = "Process Masquerading as Kernel Thread";
            f.description = "Process comm disguises as a kernel worker thread while executing a userspace binary.";
            f.mitre_technique = "T1036.004";
            f.target_path = exe_target;
            f.evidence = "Comm name is '" + comm + "', but backing binary exists at: " + exe_target;
            findings.push_back(std::move(f));
        }
    }

    return findings;
}

} // namespace aegis

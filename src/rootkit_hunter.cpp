#include <aegis/rootkit_hunter.hpp>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

namespace aegis {

RootkitHunter::RootkitHunter(std::string proc_root)
    : proc_root_(std::move(proc_root)) {}

pid_t RootkitHunter::read_system_pid_max() const {
    std::ifstream file("/proc/sys/kernel/pid_max");
    if (!file.is_open()) {
        return 32768;
    }
    pid_t pid_max = 32768;
    file >> pid_max;
    return (pid_max > 0) ? pid_max : 32768;
}

std::set<pid_t> RootkitHunter::enumerate_proc_getdents() const {
    std::set<pid_t> pids;

    // Check if test fixture overrides getdents view
    std::string mock_getdents = proc_root_ + "/rootkit_sim/getdents_pids.txt";
    std::ifstream mock_file(mock_getdents);
    if (mock_file.is_open()) {
        pid_t pid = 0;
        while (mock_file >> pid) {
            if (pid > 0) {
                pids.insert(pid);
            }
        }
        return pids;
    }

    DIR* dir = opendir(proc_root_.c_str());
    if (!dir) {
        return pids;
    }

    struct dirent* entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '\0') {
            continue;
        }

        bool all_digits = true;
        for (const char* p = entry->d_name; *p != '\0'; ++p) {
            if (!std::isdigit(static_cast<unsigned char>(*p))) {
                all_digits = false;
                break;
            }
        }

        if (all_digits) {
            try {
                pid_t pid = static_cast<pid_t>(std::stol(entry->d_name));
                if (pid > 0) {
                    pids.insert(pid);
                }
            } catch (...) {}
        }
    }
    closedir(dir);

    return pids;
}

std::set<pid_t> RootkitHunter::sweep_kernel_pids(pid_t max_pid) const {
    std::set<pid_t> pids;

    // Check if test fixture overrides kernel view
    std::string mock_kernel = proc_root_ + "/rootkit_sim/kernel_pids.txt";
    std::ifstream mock_file(mock_kernel);
    if (mock_file.is_open()) {
        pid_t pid = 0;
        while (mock_file >> pid) {
            if (pid > 0) {
                pids.insert(pid);
            }
        }
        return pids;
    }

    if (proc_root_ != "/proc") {
        // If scanning a mock directory without simulated rootkit files,
        // use getdents view to avoid scanning real system kernel pids
        return enumerate_proc_getdents();
    }

    pid_t sys_max = read_system_pid_max();
    pid_t scan_limit = std::min(max_pid, sys_max);

    for (pid_t p = 1; p <= scan_limit; ++p) {
        int ret = kill(p, 0);
        if (ret == 0 || errno == EPERM) {
            // Process exists and responded to kernel signal check
            pids.insert(p);
        }
    }

    return pids;
}

std::vector<Finding> RootkitHunter::check_discrepancies_custom(
    const std::set<pid_t>& getdents_pids,
    const std::set<pid_t>& kernel_pids
) const {
    std::vector<Finding> findings;

    // Discrepancy math: Delta_hidden = S_kernel \ S_getdents
    for (pid_t k_pid : kernel_pids) {
        if (getdents_pids.find(k_pid) == getdents_pids.end()) {
            std::string proc_name = "unknown";

            // Attempt to resolve process name directly via /proc/<pid>/comm or status
            std::string comm_path = proc_root_ + "/" + std::to_string(k_pid) + "/comm";
            std::ifstream comm_file(comm_path);
            if (comm_file.is_open()) {
                std::getline(comm_file, proc_name);
            }

            // Check if direct path resolution succeeds despite omission in directory iteration
            std::string status_path = proc_root_ + "/" + std::to_string(k_pid) + "/status";
            struct stat st{};
            bool direct_accessible = (stat(status_path.c_str(), &st) == 0);

            Finding f;
            f.rule_id = "AEGIS-ROOT-001";
            f.severity = Severity::CRITICAL;
            f.pid = k_pid;
            f.process_name = proc_name;
            f.title = "Cloaked Process Discrepancy (LKM / VFS Rootkit)";
            f.description = "Process is scheduled in kernel task table but concealed from /proc directory enumeration (getdents64).";
            f.mitre_technique = "T1014";
            f.target_path = "/proc/" + std::to_string(k_pid);
            f.evidence = "PID " + std::to_string(k_pid) +
                         " responded to kernel kill(pid, 0) but was omitted from /proc getdents64 enumeration. Direct inode status accessible: " +
                         (direct_accessible ? "true" : "false") + ".";
            findings.push_back(std::move(f));
        }
    }

    return findings;
}

std::vector<Finding> RootkitHunter::check_discrepancies(pid_t max_pid) const {
    auto getdents_pids = enumerate_proc_getdents();
    auto kernel_pids = sweep_kernel_pids(max_pid);
    return check_discrepancies_custom(getdents_pids, kernel_pids);
}

} // namespace aegis

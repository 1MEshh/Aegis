#include <aegis/engine.hpp>

#include <algorithm>
#include <cctype>
#include <dirent.h>

namespace aegis {

AegisEngine::AegisEngine(std::string proc_root)
    : proc_root_(std::move(proc_root)),
      vma_scanner_(proc_root_),
      proc_auditor_(proc_root_),
      rootkit_hunter_(proc_root_),
      sarif_exporter_() {}

bool AegisEngine::matches_severity(Severity f_sev, Severity min_sev) {
    auto to_rank = [](Severity s) -> int {
        switch (s) {
            case Severity::LOW:      return 1;
            case Severity::MEDIUM:   return 2;
            case Severity::HIGH:     return 3;
            case Severity::CRITICAL: return 4;
        }
        return 0;
    };
    return to_rank(f_sev) >= to_rank(min_sev);
}

std::vector<pid_t> AegisEngine::discover_pids(const std::string& proc_root) const {
    std::vector<pid_t> pids;
    DIR* dir = opendir(proc_root.c_str());
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
                    pids.push_back(pid);
                }
            } catch (...) {}
        }
    }
    closedir(dir);

    std::sort(pids.begin(), pids.end());
    return pids;
}

std::vector<Finding> AegisEngine::run_scan(const ScanOptions& options) const {
    std::vector<Finding> all_findings;
    std::string root = options.proc_root.empty() ? proc_root_ : options.proc_root;

    VmaScanner v_scanner(root);
    ProcAuditor p_auditor(root);
    RootkitHunter r_hunter(root);

    std::vector<pid_t> pids_to_scan = options.target_pids;
    if (pids_to_scan.empty()) {
        pids_to_scan = discover_pids(root);
    }

    for (pid_t pid : pids_to_scan) {
        std::string proc_name = p_auditor.read_comm(pid);

        if (options.check_vma) {
            auto vma_findings = v_scanner.scan_pid(pid, proc_name);
            for (auto& f : vma_findings) {
                if (matches_severity(f.severity, options.min_severity)) {
                    all_findings.push_back(std::move(f));
                }
            }
        }

        if (options.check_proc) {
            auto proc_findings = p_auditor.audit_pid(pid, proc_name);
            for (auto& f : proc_findings) {
                if (matches_severity(f.severity, options.min_severity)) {
                    all_findings.push_back(std::move(f));
                }
            }
        }
    }

    if (options.check_rootkit) {
        auto rk_findings = r_hunter.check_discrepancies(options.max_rootkit_pid);
        for (auto& f : rk_findings) {
            if (matches_severity(f.severity, options.min_severity)) {
                all_findings.push_back(std::move(f));
            }
        }
    }

    return all_findings;
}

std::vector<Finding> AegisEngine::audit_process(pid_t pid) const {
    ScanOptions opt;
    opt.proc_root = proc_root_;
    opt.target_pids = {pid};
    opt.check_rootkit = false;
    return run_scan(opt);
}

std::vector<Finding> AegisEngine::check_rootkits(pid_t max_pid) const {
    return rootkit_hunter_.check_discrepancies(max_pid);
}

} // namespace aegis

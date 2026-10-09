#ifndef AEGIS_COMMON_HPP
#define AEGIS_COMMON_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <sys/types.h>

namespace aegis {

enum class Severity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

inline std::string severity_to_string(Severity s) {
    switch (s) {
        case Severity::LOW:      return "LOW";
        case Severity::MEDIUM:   return "MEDIUM";
        case Severity::HIGH:     return "HIGH";
        case Severity::CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}

inline Severity string_to_severity(std::string_view s) {
    if (s == "CRITICAL" || s == "critical" || s == "crit") return Severity::CRITICAL;
    if (s == "HIGH" || s == "high") return Severity::HIGH;
    if (s == "MEDIUM" || s == "medium" || s == "med") return Severity::MEDIUM;
    return Severity::LOW;
}

struct Finding {
    std::string rule_id;
    Severity severity;
    pid_t pid;
    std::string process_name;
    std::string title;
    std::string description;
    std::string mitre_technique;
    std::string target_path;
    std::string evidence;
};

struct ScanOptions {
    std::string proc_root = "/proc";
    std::vector<pid_t> target_pids;
    Severity min_severity = Severity::LOW;
    bool check_vma = true;
    bool check_proc = true;
    bool check_rootkit = true;
    pid_t max_rootkit_pid = 32768;
    std::string output_format = "table";
    std::string output_file = "";
};

} // namespace aegis

#endif // AEGIS_COMMON_HPP

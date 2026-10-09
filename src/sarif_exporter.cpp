#include <aegis/sarif_exporter.hpp>

#include <fstream>
#include <iomanip>
#include <sstream>

namespace aegis {

SarifExporter::SarifExporter() {
    init_rules();
}

void SarifExporter::init_rules() {
    rules_ = {
        {
            "AEGIS-MEM-001",
            "AnonymousRWXSegment",
            "Anonymous RWX Virtual Memory Segment",
            "Process maps contain anonymous writable and executable (rwxp) virtual memory areas violating W^X policy, indicative of staged shellcode injection or unbacked JIT exploitation.",
            "error",
            "T1055"
        },
        {
            "AEGIS-MEM-002",
            "UnbackedExecutableSegment",
            "Unbacked Executable Memory Segment",
            "Memory region with executable flags (r-xp or --xp) has no backing file on filesystem (inode 0), characteristic of unpacked payload execution or post-injection mprotect.",
            "error",
            "T1055.009"
        },
        {
            "AEGIS-MEM-003",
            "ReflectiveElfHeader",
            "Reflective ELF Memory Header Detected",
            "In-memory ELF header magic (\\x7fELF) discovered at the base of an anonymous or unbacked memory segment, indicating reflective code execution bypassing disk-based execve.",
            "error",
            "T1620"
        },
        {
            "AEGIS-PROC-001",
            "FilelessExecution",
            "Fileless Binary Execution Detected",
            "Process executable or mapped descriptor points to anonymous ramfs/memfd (/memfd:*) or deleted shared memory (/dev/shm/* (deleted)), evading disk forensics.",
            "error",
            "T1620"
        },
        {
            "AEGIS-PROC-002",
            "LdPreloadInjection",
            "Dynamic Linker Preload Injection",
            "Process environment contains LD_PRELOAD or LD_LIBRARY_PATH referencing suspicious paths (/tmp, /dev/shm, hidden folders) to hook glibc syscalls or hijack dynamic loading.",
            "error",
            "T1574.006"
        },
        {
            "AEGIS-PROC-003",
            "PtraceHooking",
            "Active Process Tracing / ptrace Hooking",
            "Process status reports non-zero TracerPid, indicating external debugging or ptrace-based code injection (PTRACE_POKETEXT / PTRACE_SETREGS).",
            "warning",
            "T1055.008"
        },
        {
            "AEGIS-PROC-004",
            "ProcessMasquerading",
            "Process Masquerading as Kernel Thread",
            "Process comm string mimics kernel threads (e.g. kworker, ksoftirqd) or core system daemons while executing an unassociated userspace binary image.",
            "warning",
            "T1036.004"
        },
        {
            "AEGIS-ROOT-001",
            "CloakedProcessDiscrepancy",
            "Cloaked Process Discrepancy (LKM / VFS Rootkit)",
            "Kernel responds positively to direct signal check (kill 0) for PID, but directory entry is omitted from procfs directory enumeration (getdents64), indicating rootkit stealth hook.",
            "error",
            "T1014"
        }
    };
}

std::string SarifExporter::escape_json(const std::string& input) {
    std::ostringstream ss;
    for (char c : input) {
        switch (c) {
            case '"':  ss << "\\\""; break;
            case '\\': ss << "\\\\"; break;
            case '\b': ss << "\\b";  break;
            case '\f': ss << "\\f";  break;
            case '\n': ss << "\\n";  break;
            case '\r': ss << "\\r";  break;
            case '\t': ss << "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    ss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
                } else {
                    ss << c;
                }
                break;
        }
    }
    return ss.str();
}

std::string SarifExporter::severity_to_sarif_level(Severity s) {
    switch (s) {
        case Severity::CRITICAL:
        case Severity::HIGH:
            return "error";
        case Severity::MEDIUM:
            return "warning";
        case Severity::LOW:
            return "note";
    }
    return "note";
}

std::string SarifExporter::to_table(const std::vector<Finding>& findings) const {
    std::ostringstream ss;
    ss << "+-------+----------------------+---------------+----------+-----------+------------------------------------------+\n";
    ss << "| PID   | PROCESS              | RULE ID       | SEVERITY | MITRE     | TITLE                                    |\n";
    ss << "+-------+----------------------+---------------+----------+-----------+------------------------------------------+\n";

    size_t crit_count = 0;
    size_t high_count = 0;
    size_t med_count = 0;
    size_t low_count = 0;

    for (const auto& f : findings) {
        switch (f.severity) {
            case Severity::CRITICAL: crit_count++; break;
            case Severity::HIGH:     high_count++; break;
            case Severity::MEDIUM:   med_count++; break;
            case Severity::LOW:      low_count++; break;
        }

        std::string p_name = f.process_name;
        if (p_name.size() > 20) p_name = p_name.substr(0, 17) + "...";

        std::string title = f.title;
        if (title.size() > 40) title = title.substr(0, 37) + "...";

        ss << "| " << std::left << std::setw(5) << f.pid
           << " | " << std::left << std::setw(20) << p_name
           << " | " << std::left << std::setw(13) << f.rule_id
           << " | " << std::left << std::setw(8) << severity_to_string(f.severity)
           << " | " << std::left << std::setw(9) << f.mitre_technique
           << " | " << std::left << std::setw(40) << title
           << " |\n";
    }

    ss << "+-------+----------------------+---------------+----------+-----------+------------------------------------------+\n";
    ss << "Total Findings: " << findings.size()
       << " | Critical: " << crit_count
       << " | High: " << high_count
       << " | Medium: " << med_count
       << " | Low: " << low_count << "\n";

    return ss.str();
}

std::string SarifExporter::to_json(const std::vector<Finding>& findings) const {
    std::ostringstream ss;
    ss << "{\n";
    ss << "  \"version\": \"1.0.0\",\n";
    ss << "  \"scanner\": \"Aegis\",\n";
    ss << "  \"total_findings\": " << findings.size() << ",\n";
    ss << "  \"findings\": [\n";

    for (size_t i = 0; i < findings.size(); ++i) {
        const auto& f = findings[i];
        ss << "    {\n";
        ss << "      \"rule_id\": \"" << escape_json(f.rule_id) << "\",\n";
        ss << "      \"severity\": \"" << escape_json(severity_to_string(f.severity)) << "\",\n";
        ss << "      \"pid\": " << f.pid << ",\n";
        ss << "      \"process_name\": \"" << escape_json(f.process_name) << "\",\n";
        ss << "      \"title\": \"" << escape_json(f.title) << "\",\n";
        ss << "      \"description\": \"" << escape_json(f.description) << "\",\n";
        ss << "      \"mitre_technique\": \"" << escape_json(f.mitre_technique) << "\",\n";
        ss << "      \"target_path\": \"" << escape_json(f.target_path) << "\",\n";
        ss << "      \"evidence\": \"" << escape_json(f.evidence) << "\"\n";
        ss << "    }" << (i + 1 < findings.size() ? "," : "") << "\n";
    }

    ss << "  ]\n";
    ss << "}\n";
    return ss.str();
}

std::string SarifExporter::to_sarif(const std::vector<Finding>& findings) const {
    std::ostringstream ss;
    ss << "{\n";
    ss << "  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n";
    ss << "  \"version\": \"2.1.0\",\n";
    ss << "  \"runs\": [\n";
    ss << "    {\n";
    ss << "      \"tool\": {\n";
    ss << "        \"driver\": {\n";
    ss << "          \"name\": \"Aegis\",\n";
    ss << "          \"version\": \"1.0.0\",\n";
    ss << "          \"informationUri\": \"https://github.com/1MEshh/Aegis\",\n";
    ss << "          \"rules\": [\n";

    for (size_t i = 0; i < rules_.size(); ++i) {
        const auto& r = rules_[i];
        ss << "            {\n";
        ss << "              \"id\": \"" << escape_json(r.id) << "\",\n";
        ss << "              \"name\": \"" << escape_json(r.name) << "\",\n";
        ss << "              \"shortDescription\": {\n";
        ss << "                \"text\": \"" << escape_json(r.short_description) << "\"\n";
        ss << "              },\n";
        ss << "              \"fullDescription\": {\n";
        ss << "                \"text\": \"" << escape_json(r.full_description) << "\"\n";
        ss << "              },\n";
        ss << "              \"defaultConfiguration\": {\n";
        ss << "                \"level\": \"" << r.default_level << "\"\n";
        ss << "              },\n";
        ss << "              \"helpUri\": \"https://github.com/1MEshh/Aegis\",\n";
        ss << "              \"properties\": {\n";
        ss << "                \"tags\": [\"security\", \"memory-forensics\", \"mitre-" << escape_json(r.mitre_id) << "\"],\n";
        ss << "                \"precision\": \"high\"\n";
        ss << "              }\n";
        ss << "            }" << (i + 1 < rules_.size() ? "," : "") << "\n";
    }

    ss << "          ]\n";
    ss << "        }\n";
    ss << "      },\n";
    ss << "      \"results\": [\n";

    for (size_t i = 0; i < findings.size(); ++i) {
        const auto& f = findings[i];
        ss << "        {\n";
        ss << "          \"ruleId\": \"" << escape_json(f.rule_id) << "\",\n";
        ss << "          \"level\": \"" << severity_to_sarif_level(f.severity) << "\",\n";
        ss << "          \"message\": {\n";
        ss << "            \"text\": \"" << escape_json(f.title + ": " + f.description) << "\"\n";
        ss << "          },\n";
        ss << "          \"locations\": [\n";
        ss << "            {\n";
        ss << "              \"physicalLocation\": {\n";
        ss << "                \"artifactLocation\": {\n";
        ss << "                  \"uri\": \"" << escape_json(f.target_path) << "\"\n";
        ss << "                }\n";
        ss << "              }\n";
        ss << "            }\n";
        ss << "          ],\n";
        ss << "          \"properties\": {\n";
        ss << "            \"pid\": " << f.pid << ",\n";
        ss << "            \"processName\": \"" << escape_json(f.process_name) << "\",\n";
        ss << "            \"mitreTechnique\": \"" << escape_json(f.mitre_technique) << "\",\n";
        ss << "            \"evidence\": \"" << escape_json(f.evidence) << "\"\n";
        ss << "          }\n";
        ss << "        }" << (i + 1 < findings.size() ? "," : "") << "\n";
    }

    ss << "      ]\n";
    ss << "    }\n";
    ss << "  ]\n";
    ss << "}\n";
    return ss.str();
}

bool SarifExporter::write_to_file(const std::string& filepath, const std::string& content) const {
    std::ofstream out(filepath);
    if (!out.is_open()) {
        return false;
    }
    out << content;
    return true;
}

} // namespace aegis

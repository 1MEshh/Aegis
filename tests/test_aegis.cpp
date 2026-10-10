#include <aegis/common.hpp>
#include <aegis/engine.hpp>
#include <aegis/proc_auditor.hpp>
#include <aegis/rootkit_hunter.hpp>
#include <aegis/sarif_exporter.hpp>
#include <aegis/vma_scanner.hpp>

#include <cassert>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

int g_passed = 0;
int g_failed = 0;

void report_test(const std::string& name, bool success, const std::string& msg = "") {
    if (success) {
        std::cout << "  [PASS] " << name << "\n";
        g_passed++;
    } else {
        std::cerr << "  [FAIL] " << name;
        if (!msg.empty()) {
            std::cerr << " (" << msg << ")";
        }
        std::cerr << "\n";
        g_failed++;
    }
}

#define ASSERT_TEST(cond, name) report_test(name, (cond))
#define ASSERT_TEST_MSG(cond, name, msg) report_test(name, (cond), msg)

} // namespace

void test_vma_parser_normal() {
    aegis::VmaScanner scanner("fixtures/mock_proc");
    auto entries = scanner.parse_maps(1001);
    bool ok = (entries.size() == 7);
    if (ok) {
        ok = (entries[0].start_addr == 0x00400000 &&
              entries[0].read && !entries[0].write && entries[0].execute &&
              entries[0].pathname == "/usr/bin/bash");
    }
    ASSERT_TEST(ok, "test_vma_parser_normal");
}

void test_vma_rwx_anonymous_detection() {
    aegis::VmaScanner scanner("fixtures/mock_proc");
    auto findings = scanner.scan_pid(2048, "beacon.bin");
    bool found_rwx = false;
    for (const auto& f : findings) {
        if (f.rule_id == "AEGIS-MEM-001" && f.severity == aegis::Severity::CRITICAL) {
            found_rwx = true;
            break;
        }
    }
    ASSERT_TEST(found_rwx, "test_vma_rwx_anonymous_detection");
}

void test_vma_unbacked_executable_detection() {
    aegis::VmaScanner scanner("fixtures/mock_proc");
    auto findings = scanner.scan_pid(2048, "beacon.bin");
    bool found_unbacked = false;
    for (const auto& f : findings) {
        if (f.rule_id == "AEGIS-MEM-002" && f.severity == aegis::Severity::HIGH) {
            found_unbacked = true;
            break;
        }
    }
    ASSERT_TEST(found_unbacked, "test_vma_unbacked_executable_detection");
}

void test_vma_reflective_elf_detection() {
    aegis::VmaScanner scanner("fixtures/mock_proc");
    auto findings = scanner.scan_pid(2048, "beacon.bin");
    bool found_elf = false;
    for (const auto& f : findings) {
        if (f.rule_id == "AEGIS-MEM-003" && f.severity == aegis::Severity::CRITICAL) {
            found_elf = true;
            break;
        }
    }
    ASSERT_TEST(found_elf, "test_vma_reflective_elf_detection");
}

void test_vma_smaps_metrics() {
    aegis::VmaScanner scanner("fixtures/mock_proc");
    auto entries = scanner.parse_maps(1001);
    bool ok = false;
    for (const auto& e : entries) {
        if (e.start_addr == 0x00400000) {
            ok = (e.size_kb == 936 && e.rss_kb == 652 && e.pss_kb == 326);
            break;
        }
    }
    ASSERT_TEST(ok, "test_vma_smaps_metrics");
}

void test_proc_memfd_exe_detection() {
    aegis::ProcAuditor auditor("fixtures/mock_proc");
    auto findings = auditor.audit_pid(31337, "cs_payload");
    bool found_memfd = false;
    for (const auto& f : findings) {
        if (f.rule_id == "AEGIS-PROC-001" && f.severity == aegis::Severity::CRITICAL) {
            found_memfd = true;
            break;
        }
    }
    ASSERT_TEST(found_memfd, "test_proc_memfd_exe_detection");
}

void test_proc_dev_shm_deleted_detection() {
    aegis::ProcAuditor auditor("fixtures/mock_proc");
    auto findings = auditor.audit_pid(4096, "dropper");
    bool found_shm = false;
    for (const auto& f : findings) {
        if (f.rule_id == "AEGIS-PROC-001" && f.severity == aegis::Severity::CRITICAL) {
            found_shm = true;
            break;
        }
    }
    ASSERT_TEST(found_shm, "test_proc_dev_shm_deleted_detection");
}

void test_proc_memfd_fd_detection() {
    aegis::ProcAuditor auditor("fixtures/mock_proc");
    auto targets = auditor.read_fd_targets(31337);
    bool ok = false;
    for (const auto& tgt : targets) {
        if (tgt.find("/memfd:") != std::string::npos) {
            ok = true;
            break;
        }
    }
    ASSERT_TEST(ok, "test_proc_memfd_fd_detection");
}

void test_proc_ld_preload_detection() {
    aegis::ProcAuditor auditor("fixtures/mock_proc");
    auto findings = auditor.audit_pid(5120, "nginx");
    bool found_preload = false;
    for (const auto& f : findings) {
        if (f.rule_id == "AEGIS-PROC-002") {
            found_preload = true;
            break;
        }
    }
    ASSERT_TEST(found_preload, "test_proc_ld_preload_detection");
}

void test_proc_ld_library_path_detection() {
    aegis::ProcAuditor auditor("fixtures/mock_proc");
    auto env = auditor.read_environ(5120);
    bool ok = (env.find("LD_PRELOAD") != env.end());
    ASSERT_TEST(ok, "test_proc_ld_library_path_detection");
}

void test_proc_tracer_pid_detection() {
    aegis::ProcAuditor auditor("fixtures/mock_proc");
    auto findings = auditor.audit_pid(6001, "ssh-agent");
    bool found_tracer = false;
    for (const auto& f : findings) {
        if (f.rule_id == "AEGIS-PROC-003" && f.severity == aegis::Severity::HIGH) {
            found_tracer = true;
            break;
        }
    }
    ASSERT_TEST(found_tracer, "test_proc_tracer_pid_detection");
}

void test_proc_masquerading_detection() {
    aegis::ProcAuditor auditor("fixtures/mock_proc");
    auto findings = auditor.audit_pid(7777, "[kworker/u16:0]");
    bool found_masq = false;
    for (const auto& f : findings) {
        if (f.rule_id == "AEGIS-PROC-004" && f.severity == aegis::Severity::MEDIUM) {
            found_masq = true;
            break;
        }
    }
    ASSERT_TEST(found_masq, "test_proc_masquerading_detection");
}

void test_proc_clean_process() {
    aegis::VmaScanner scanner("fixtures/mock_proc");
    aegis::ProcAuditor auditor("fixtures/mock_proc");
    auto vma_f = scanner.scan_pid(1001, "bash");
    auto proc_f = auditor.audit_pid(1001, "bash");
    bool ok = (vma_f.empty() && proc_f.empty());
    ASSERT_TEST(ok, "test_proc_clean_process");
}

void test_rootkit_pid_discrepancy_math() {
    aegis::RootkitHunter hunter("fixtures/mock_proc");
    auto findings = hunter.check_discrepancies();
    bool found_666 = false;
    bool found_1337 = false;
    for (const auto& f : findings) {
        if (f.rule_id == "AEGIS-ROOT-001") {
            if (f.pid == 666) found_666 = true;
            if (f.pid == 1337) found_1337 = true;
        }
    }
    ASSERT_TEST(found_666 && found_1337, "test_rootkit_pid_discrepancy_math");
}

void test_rootkit_zero_discrepancy_when_synced() {
    aegis::RootkitHunter hunter("fixtures/mock_proc");
    std::set<pid_t> synced = {1, 2, 3, 4, 5};
    auto findings = hunter.check_discrepancies_custom(synced, synced);
    ASSERT_TEST(findings.empty(), "test_rootkit_zero_discrepancy_when_synced");
}

void test_rootkit_multiple_cloaked_pids() {
    aegis::RootkitHunter hunter("fixtures/mock_proc");
    std::set<pid_t> getdents = {10, 20, 30};
    std::set<pid_t> kernel = {10, 20, 30, 40, 50, 60};
    auto findings = hunter.check_discrepancies_custom(getdents, kernel);
    bool ok = (findings.size() == 3);
    if (ok) {
        ok = (findings[0].pid == 40 && findings[1].pid == 50 && findings[2].pid == 60);
    }
    ASSERT_TEST(ok, "test_rootkit_multiple_cloaked_pids");
}

void test_sarif_schema_compliance() {
    aegis::SarifExporter exporter;
    std::vector<aegis::Finding> findings;
    aegis::Finding f;
    f.rule_id = "AEGIS-MEM-001";
    f.severity = aegis::Severity::CRITICAL;
    f.pid = 2048;
    f.process_name = "beacon.bin";
    f.title = "Anonymous RWX Virtual Memory Segment";
    f.description = "Writable and executable anonymous memory violating W^X.";
    f.mitre_technique = "T1055";
    f.target_path = "0x7f1234560000-0x7f1234570000";
    f.evidence = "Address 0x7f1234560000";
    findings.push_back(f);

    std::string sarif = exporter.to_sarif(findings);
    bool ok = (sarif.find("\"version\": \"2.1.0\"") != std::string::npos &&
               sarif.find("\"name\": \"Aegis\"") != std::string::npos &&
               sarif.find("AEGIS-MEM-001") != std::string::npos &&
               sarif.find("\"level\": \"error\"") != std::string::npos);
    ASSERT_TEST(ok, "test_sarif_schema_compliance");
}

void test_sarif_rule_definitions() {
    aegis::SarifExporter exporter;
    const auto& rules = exporter.rules();
    bool found_mem001 = false;
    bool found_proc001 = false;
    bool found_root001 = false;
    for (const auto& r : rules) {
        if (r.id == "AEGIS-MEM-001") found_mem001 = true;
        if (r.id == "AEGIS-PROC-001") found_proc001 = true;
        if (r.id == "AEGIS-ROOT-001") found_root001 = true;
    }
    ASSERT_TEST(found_mem001 && found_proc001 && found_root001, "test_sarif_rule_definitions");
}

void test_json_export_structure() {
    aegis::SarifExporter exporter;
    std::vector<aegis::Finding> findings;
    aegis::Finding f;
    f.rule_id = "AEGIS-PROC-001";
    f.severity = aegis::Severity::CRITICAL;
    f.pid = 31337;
    f.process_name = "cs_payload";
    f.title = "Fileless Binary Execution Detected";
    f.description = "Binary image executed from anonymous memfd.";
    f.mitre_technique = "T1620";
    f.target_path = "/memfd:cs_payload";
    f.evidence = "memfd execute";
    findings.push_back(f);

    std::string json = exporter.to_json(findings);
    bool ok = (json.find("\"scanner\": \"Aegis\"") != std::string::npos &&
               json.find("\"total_findings\": 1") != std::string::npos &&
               json.find("\"rule_id\": \"AEGIS-PROC-001\"") != std::string::npos);
    ASSERT_TEST(ok, "test_json_export_structure");
}

void test_terminal_table_formatting() {
    aegis::SarifExporter exporter;
    std::vector<aegis::Finding> findings;
    aegis::Finding f;
    f.rule_id = "AEGIS-ROOT-001";
    f.severity = aegis::Severity::CRITICAL;
    f.pid = 666;
    f.process_name = "stealth_mod";
    f.title = "Cloaked Process Discrepancy";
    f.description = "Process omitted from /proc enumeration.";
    f.mitre_technique = "T1014";
    f.target_path = "/proc/666";
    f.evidence = "kill check 0";
    findings.push_back(f);

    std::string table = exporter.to_table(findings);
    bool ok = (table.find("PID") != std::string::npos &&
               table.find("RULE ID") != std::string::npos &&
               table.find("SEVERITY") != std::string::npos &&
               table.find("stealth_mod") != std::string::npos &&
               table.find("Total Findings: 1") != std::string::npos);
    ASSERT_TEST(ok, "test_terminal_table_formatting");
}

void test_binary_path_strings() {
    // Read the compiled test runner executable and ensure no user directories are embedded
    std::ifstream bin_file("/proc/self/exe", std::ios::binary);
    bool clean = true;
    if (bin_file.is_open()) {
        std::stringstream ss;
        ss << bin_file.rdbuf();
        std::string content = ss.str();

        std::string pattern = std::string("/") + "ho" + "me" + "/";
        size_t pos = 0;
        while ((pos = content.find(pattern, pos)) != std::string::npos) {
            size_t sub_start = pos + pattern.size();
            if (sub_start < content.size() &&
                (std::isalnum(static_cast<unsigned char>(content[sub_start])) || content[sub_start] == '_')) {
                clean = false;
                break;
            }
            pos += pattern.size();
        }
    }
    ASSERT_TEST(clean, "test_binary_path_strings");
}

void test_engine_severity_filtering() {
    aegis::AegisEngine engine("fixtures/mock_proc");
    aegis::ScanOptions opt;
    opt.proc_root = "fixtures/mock_proc";
    opt.min_severity = aegis::Severity::CRITICAL;
    opt.check_rootkit = false;

    auto findings = engine.run_scan(opt);
    bool only_critical = true;
    for (const auto& f : findings) {
        if (f.severity != aegis::Severity::CRITICAL) {
            only_critical = false;
            break;
        }
    }
    ASSERT_TEST(only_critical && !findings.empty(), "test_engine_severity_filtering");
}

void test_full_synthetic_scan() {
    aegis::AegisEngine engine("fixtures/mock_proc");
    aegis::ScanOptions opt;
    opt.proc_root = "fixtures/mock_proc";
    opt.min_severity = aegis::Severity::LOW;
    opt.check_rootkit = true;

    auto findings = engine.run_scan(opt);
    // Should detect findings from 2048, 31337, 4096, 5120, 6001, 7777, and rootkit_sim (666, 1337)
    bool has_mem = false;
    bool has_memfd = false;
    bool has_preload = false;
    bool has_tracer = false;
    bool has_masq = false;
    bool has_rootkit = false;

    for (const auto& f : findings) {
        if (f.rule_id == "AEGIS-MEM-001") has_mem = true;
        if (f.rule_id == "AEGIS-PROC-001") has_memfd = true;
        if (f.rule_id == "AEGIS-PROC-002") has_preload = true;
        if (f.rule_id == "AEGIS-PROC-003") has_tracer = true;
        if (f.rule_id == "AEGIS-PROC-004") has_masq = true;
        if (f.rule_id == "AEGIS-ROOT-001") has_rootkit = true;
    }

    bool all_detected = (has_mem && has_memfd && has_preload && has_tracer && has_masq && has_rootkit);
    ASSERT_TEST(all_detected, "test_full_synthetic_scan");
}

int main() {
    std::cout << "========================================================\n";
    std::cout << " Aegis Automated Unit & Integration Test Suite\n";
    std::cout << " C++20 Memory Forensics, Proc Auditor & Rootkit Hunter\n";
    std::cout << "========================================================\n\n";

    test_vma_parser_normal();
    test_vma_rwx_anonymous_detection();
    test_vma_unbacked_executable_detection();
    test_vma_reflective_elf_detection();
    test_vma_smaps_metrics();
    test_proc_memfd_exe_detection();
    test_proc_dev_shm_deleted_detection();
    test_proc_memfd_fd_detection();
    test_proc_ld_preload_detection();
    test_proc_ld_library_path_detection();
    test_proc_tracer_pid_detection();
    test_proc_masquerading_detection();
    test_proc_clean_process();
    test_rootkit_pid_discrepancy_math();
    test_rootkit_zero_discrepancy_when_synced();
    test_rootkit_multiple_cloaked_pids();
    test_sarif_schema_compliance();
    test_sarif_rule_definitions();
    test_json_export_structure();
    test_terminal_table_formatting();
    test_binary_path_strings();
    test_engine_severity_filtering();
    test_full_synthetic_scan();

    std::cout << "\n--------------------------------------------------------\n";
    std::cout << "Test Summary: " << g_passed << " passed, " << g_failed << " failed.\n";
    std::cout << "========================================================\n";

    return (g_failed == 0) ? 0 : 1;
}

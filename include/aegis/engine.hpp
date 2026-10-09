#ifndef AEGIS_ENGINE_HPP
#define AEGIS_ENGINE_HPP

#include <aegis/common.hpp>
#include <aegis/proc_auditor.hpp>
#include <aegis/rootkit_hunter.hpp>
#include <aegis/sarif_exporter.hpp>
#include <aegis/vma_scanner.hpp>
#include <vector>

namespace aegis {

class AegisEngine {
public:
    explicit AegisEngine(std::string proc_root = "/proc");

    [[nodiscard]] std::vector<pid_t> discover_pids(const std::string& proc_root) const;
    [[nodiscard]] std::vector<Finding> run_scan(const ScanOptions& options) const;
    [[nodiscard]] std::vector<Finding> audit_process(pid_t pid) const;
    [[nodiscard]] std::vector<Finding> check_rootkits(pid_t max_pid = 32768) const;

    [[nodiscard]] const VmaScanner& vma_scanner() const noexcept { return vma_scanner_; }
    [[nodiscard]] const ProcAuditor& proc_auditor() const noexcept { return proc_auditor_; }
    [[nodiscard]] const RootkitHunter& rootkit_hunter() const noexcept { return rootkit_hunter_; }
    [[nodiscard]] const SarifExporter& sarif_exporter() const noexcept { return sarif_exporter_; }

private:
    std::string proc_root_;
    VmaScanner vma_scanner_;
    ProcAuditor proc_auditor_;
    RootkitHunter rootkit_hunter_;
    SarifExporter sarif_exporter_;

    [[nodiscard]] static bool matches_severity(Severity f_sev, Severity min_sev);
};

} // namespace aegis

#endif // AEGIS_ENGINE_HPP

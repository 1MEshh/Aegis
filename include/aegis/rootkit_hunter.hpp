#ifndef AEGIS_ROOTKIT_HUNTER_HPP
#define AEGIS_ROOTKIT_HUNTER_HPP

#include <aegis/common.hpp>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace aegis {

class RootkitHunter {
public:
    explicit RootkitHunter(std::string proc_root = "/proc");

    [[nodiscard]] std::set<pid_t> enumerate_proc_getdents() const;
    [[nodiscard]] std::set<pid_t> sweep_kernel_pids(pid_t max_pid = 32768) const;

    [[nodiscard]] std::vector<Finding> check_discrepancies(pid_t max_pid = 32768) const;
    [[nodiscard]] std::vector<Finding> check_discrepancies_custom(
        const std::set<pid_t>& getdents_pids,
        const std::set<pid_t>& kernel_pids
    ) const;

    [[nodiscard]] const std::string& proc_root() const noexcept { return proc_root_; }

private:
    std::string proc_root_;
    [[nodiscard]] pid_t read_system_pid_max() const;
};

} // namespace aegis

#endif // AEGIS_ROOTKIT_HUNTER_HPP

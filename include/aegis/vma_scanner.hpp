#ifndef AEGIS_VMA_SCANNER_HPP
#define AEGIS_VMA_SCANNER_HPP

#include <aegis/common.hpp>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace aegis {

struct VmaEntry {
    uint64_t start_addr = 0;
    uint64_t end_addr = 0;
    bool read = false;
    bool write = false;
    bool execute = false;
    bool is_private = false;
    uint64_t offset = 0;
    std::string dev;
    uint64_t inode = 0;
    std::string pathname;

    // smaps metrics (if available)
    uint64_t size_kb = 0;
    uint64_t rss_kb = 0;
    uint64_t pss_kb = 0;
    uint64_t anon_kb = 0;
    std::vector<std::string> vm_flags;

    [[nodiscard]] bool is_rwx() const noexcept {
        return read && write && execute;
    }

    [[nodiscard]] bool is_anonymous() const noexcept {
        if (dev == "00:00" && inode == 0) {
            return true;
        }
        if (pathname.empty() || pathname.rfind("[anon", 0) == 0 ||
            pathname == "[heap]" || pathname == "[stack]") {
            return true;
        }
        return false;
    }

    [[nodiscard]] bool is_unbacked_executable() const noexcept {
        if (!execute) {
            return false;
        }
        // Exclude legitimate kernel pseudo-mappings
        if (pathname == "[vdso]" || pathname == "[vsyscall]" || pathname == "[vvar]") {
            return false;
        }
        return (inode == 0 && dev == "00:00");
    }

    [[nodiscard]] std::string perms_string() const {
        std::string p;
        p += (read ? 'r' : '-');
        p += (write ? 'w' : '-');
        p += (execute ? 'x' : '-');
        p += (is_private ? 'p' : 's');
        return p;
    }

    [[nodiscard]] uint64_t size() const noexcept {
        return (end_addr >= start_addr) ? (end_addr - start_addr) : 0;
    }
};

class VmaScanner {
public:
    explicit VmaScanner(std::string proc_root = "/proc");

    [[nodiscard]] std::vector<VmaEntry> parse_maps(pid_t pid) const;
    [[nodiscard]] std::vector<VmaEntry> parse_maps_content(std::string_view content) const;
    void parse_smaps(pid_t pid, std::vector<VmaEntry>& entries) const;
    void parse_smaps_content(std::string_view content, std::vector<VmaEntry>& entries) const;

    [[nodiscard]] bool check_reflective_elf(pid_t pid, uint64_t start_addr) const;
    [[nodiscard]] std::vector<Finding> scan_pid(pid_t pid, const std::string& proc_name) const;

    [[nodiscard]] const std::string& proc_root() const noexcept { return proc_root_; }

private:
    std::string proc_root_;
};

} // namespace aegis

#endif // AEGIS_VMA_SCANNER_HPP

#ifndef AEGIS_SARIF_EXPORTER_HPP
#define AEGIS_SARIF_EXPORTER_HPP

#include <aegis/common.hpp>
#include <string>
#include <vector>

namespace aegis {

struct RuleMetadata {
    std::string id;
    std::string name;
    std::string short_description;
    std::string full_description;
    std::string default_level; // "error", "warning", "note"
    std::string mitre_id;
};

class SarifExporter {
public:
    SarifExporter();

    [[nodiscard]] std::string to_table(const std::vector<Finding>& findings) const;
    [[nodiscard]] std::string to_json(const std::vector<Finding>& findings) const;
    [[nodiscard]] std::string to_sarif(const std::vector<Finding>& findings) const;

    [[nodiscard]] bool write_to_file(const std::string& filepath, const std::string& content) const;
    [[nodiscard]] const std::vector<RuleMetadata>& rules() const noexcept { return rules_; }

private:
    std::vector<RuleMetadata> rules_;
    void init_rules();
    [[nodiscard]] static std::string escape_json(const std::string& input);
    [[nodiscard]] static std::string severity_to_sarif_level(Severity s);
};

} // namespace aegis

#endif // AEGIS_SARIF_EXPORTER_HPP

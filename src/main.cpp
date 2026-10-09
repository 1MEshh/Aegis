#include <aegis/common.hpp>
#include <aegis/engine.hpp>
#include <aegis/sarif_exporter.hpp>

#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {

void print_version() {
    std::cout << "Aegis v1.0.0 — Linux Kernel In-Memory Evasion & Rootkit Detection Engine\n";
    std::cout << "Target Architecture: Linux x86_64 / aarch64 (C++20)\n";
}

void print_help() {
    std::cout << "Aegis — Linux In-Memory Evasion, Process Injection & Rootkit Detection Engine\n\n";
    std::cout << "Usage:\n";
    std::cout << "  aegis <command> [options]\n\n";
    std::cout << "Commands:\n";
    std::cout << "  scan           Execute full host memory forensics, process audit & rootkit sweep\n";
    std::cout << "  audit-proc     Audit process descriptors, memory mappings, and linker state\n";
    std::cout << "  rootkit-check  Execute cross-view cloaked PID discrepancy check (getdents vs kill)\n";
    std::cout << "  export-sarif   Run host scan and export findings in OASIS SARIF v2.1.0 format\n";
    std::cout << "  help           Display this help manual\n";
    std::cout << "  version        Display version and runtime information\n\n";
    std::cout << "Options:\n";
    std::cout << "  --proc <dir>       Path to procfs root mount (default: /proc)\n";
    std::cout << "  --pid <pid>        Target a specific PID for focused memory forensics\n";
    std::cout << "  --min-sev <sev>    Minimum severity threshold: low, med, high, crit (default: low)\n";
    std::cout << "  --format <fmt>     Output format: table, json, sarif (default: table)\n";
    std::cout << "  --output <file>    Output destination file (default: stdout)\n";
    std::cout << "  --range <max_pid>  Upper bound for kernel PID sweep (default: 32768)\n";
    std::cout << "  --no-rootkit       Disable rootkit cloaked PID sweep\n";
    std::cout << "  --fail-on <sev>    Exit with code 1 if findings meet or exceed severity\n";
    std::cout << "  -h, --help         Display this help message\n";
    std::cout << "  -v, --version      Display version information\n";
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_help();
        return 1;
    }

    std::string command = argv[1];
    if (command == "-h" || command == "--help" || command == "help") {
        print_help();
        return 0;
    }
    if (command == "-v" || command == "--version" || command == "version") {
        print_version();
        return 0;
    }

    aegis::ScanOptions options;
    std::string fail_on_sev;

    if (command == "export-sarif") {
        options.output_format = "sarif";
    }

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--proc" && i + 1 < argc) {
            options.proc_root = argv[++i];
        } else if (arg == "--pid" && i + 1 < argc) {
            try {
                options.target_pids.push_back(static_cast<pid_t>(std::stol(argv[++i])));
            } catch (...) {
                std::cerr << "Error: Invalid PID argument: " << argv[i] << "\n";
                return 1;
            }
        } else if (arg == "--min-sev" && i + 1 < argc) {
            options.min_severity = aegis::string_to_severity(argv[++i]);
        } else if (arg == "--format" && i + 1 < argc) {
            options.output_format = argv[++i];
        } else if (arg == "--output" && i + 1 < argc) {
            options.output_file = argv[++i];
        } else if (arg == "--range" && i + 1 < argc) {
            try {
                options.max_rootkit_pid = static_cast<pid_t>(std::stol(argv[++i]));
            } catch (...) {
                std::cerr << "Error: Invalid range argument: " << argv[i] << "\n";
                return 1;
            }
        } else if (arg == "--no-rootkit") {
            options.check_rootkit = false;
        } else if (arg == "--fail-on" && i + 1 < argc) {
            fail_on_sev = argv[++i];
        } else if (arg == "-h" || arg == "--help") {
            print_help();
            return 0;
        } else {
            std::cerr << "Error: Unrecognized option: " << arg << "\n";
            return 1;
        }
    }

    if (command == "audit-proc") {
        options.check_vma = true;
        options.check_proc = true;
        options.check_rootkit = false;
    } else if (command == "rootkit-check") {
        options.check_vma = false;
        options.check_proc = false;
        options.check_rootkit = true;
    } else if (command != "scan" && command != "export-sarif") {
        std::cerr << "Error: Unrecognized command '" << command << "'. Run 'aegis --help' for usage.\n";
        return 1;
    }

    aegis::AegisEngine engine(options.proc_root);
    auto findings = engine.run_scan(options);

    std::string rendered_output;
    if (options.output_format == "sarif") {
        rendered_output = engine.sarif_exporter().to_sarif(findings);
    } else if (options.output_format == "json") {
        rendered_output = engine.sarif_exporter().to_json(findings);
    } else {
        rendered_output = engine.sarif_exporter().to_table(findings);
    }

    if (!options.output_file.empty()) {
        if (!engine.sarif_exporter().write_to_file(options.output_file, rendered_output)) {
            std::cerr << "Error: Failed to write output to file: " << options.output_file << "\n";
            return 1;
        }
    } else {
        std::cout << rendered_output;
    }

    if (!fail_on_sev.empty()) {
        aegis::Severity threshold = aegis::string_to_severity(fail_on_sev);
        for (const auto& f : findings) {
            if (static_cast<int>(f.severity) >= static_cast<int>(threshold)) {
                return 1;
            }
        }
    }

    return 0;
}

#include "utils.h"
#include <array>
#include <cstdio>
#include <memory>
#include <string>
#include <osquery/logger/logger.h>

bool ExecuteProcess(ProcessOutput& output,
  const std::string& path,
  const std::vector<std::string>& args) {
  output = {};

  try {
    // Build command string with proper escaping
    std::string cmd = path;
    for (const auto& arg : args) {
      // Properly escape quotes in arguments
      std::string escaped_arg = arg;
      size_t pos = 0;
      while ((pos = escaped_arg.find('"', pos)) != std::string::npos) {
        escaped_arg.replace(pos, 1, "\\\"");
        pos += 2;
      }
      cmd += " \"" + escaped_arg + "\"";
    }

    // Log the full command for debugging
    VLOG(1) << "Executing command: " << cmd;

    // Create pipe for reading output
    std::array<char, 128> buffer;
    std::string result;

    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) {
      VLOG(1) << "Failed to create pipe for command: " << cmd;
      return false;
    }

    // Read output
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
      result += buffer.data();
    }

    // Get exit code
    int status = pclose(pipe.release());
    output.std_output = result;
    output.exit_code = WEXITSTATUS(status);

    VLOG(1) << "Command exit code: " << output.exit_code;
    VLOG(1) << "Command output: " << output.std_output;

    return true;
  } catch (const std::exception& e) {
    VLOG(1) << "Exception in ExecuteProcess: " << e.what();
    return false;
  } catch (...) {
    VLOG(1) << "Unknown exception in ExecuteProcess";
    return false;
  }
}
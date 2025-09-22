#pragma once

#include <drogon/drogon.h>
#include <json/value.h>
#include <json/writer.h>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <iostream>

namespace logging {

inline std::string iso_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::gmtime(&tt);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

inline void log(const std::string& level,
                const std::string& filename,
                const std::string& classname,
                const std::string& function,
                const std::string& system_section,
                int line,
                const std::string& message,
                const std::string& method = "NONE",
                const std::string& error = "",
                const std::string& db_phase = "none") {
    Json::Value event;
    event["level"] = level;
    event["filename"] = filename;
    event["timestamp"] = iso_timestamp();
    event["classname"] = classname;
    event["function"] = function;
    event["system_section"] = system_section;
    event["line_num"] = line;
    event["error"] = error;
    event["db_phase"] = db_phase;
    event["method"] = method;
    event["message"] = message;
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";
    std::cout << Json::writeString(builder, event) << std::endl;
    std::cout << "[The 17 Commandments of Quality Code] " << message << std::endl;
}

inline void info(const std::string& filename,
                 const std::string& classname,
                 const std::string& function,
                 const std::string& system_section,
                 int line,
                 const std::string& message,
                 const std::string& method = "NONE") {
    log("INFO", filename, classname, function, system_section, line, message, method);
}

inline void warn(const std::string& filename,
                 const std::string& classname,
                 const std::string& function,
                 const std::string& system_section,
                 int line,
                 const std::string& message,
                 const std::string& method = "NONE",
                 const std::string& error = "") {
    log("WARN", filename, classname, function, system_section, line, message, method, error);
}

inline void error(const std::string& filename,
                  const std::string& classname,
                  const std::string& function,
                  const std::string& system_section,
                  int line,
                  const std::string& message,
                  const std::string& method = "NONE",
                  const std::string& error = "") {
    log("ERROR", filename, classname, function, system_section, line, message, method, error);
}

} // namespace logging

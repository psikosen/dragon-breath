#pragma once
#include <drogon/drogon.h>

namespace logging {

inline std::string now_iso8601() {
    return drogon::Date::now().toFormattedString(true);
}

inline void info(const std::string& filename,
                 const std::string& classname,
                 const std::string& function,
                 const std::string& section,
                 int line,
                 const std::string& message,
                 const std::string& method = "NONE",
                 const std::string& error = "",
                 const std::string& db_phase = "none") {
    Json::Value log;
    log["filename"] = filename;
    log["timestamp"] = now_iso8601();
    log["classname"] = classname;
    log["function"] = function;
    log["system_section"] = section;
    log["line_num"] = line;
    log["error"] = error;
    log["db_phase"] = db_phase;
    log["method"] = method;
    log["message"] = message;
    LOG_INFO << drogon::utils::toString(log);
    LOG_INFO << "[The 17 Commandments of Quality Code]";
}

inline void error(const std::string& filename,
                  const std::string& classname,
                  const std::string& function,
                  const std::string& section,
                  int line,
                  const std::string& message,
                  const std::string& method = "NONE",
                  const std::string& error_detail = "",
                  const std::string& db_phase = "none") {
    Json::Value log;
    log["filename"] = filename;
    log["timestamp"] = now_iso8601();
    log["classname"] = classname;
    log["function"] = function;
    log["system_section"] = section;
    log["line_num"] = line;
    log["error"] = error_detail;
    log["db_phase"] = db_phase;
    log["method"] = method;
    log["message"] = message;
    LOG_ERROR << drogon::utils::toString(log);
    LOG_ERROR << "[The 17 Commandments of Quality Code]";
}

} // namespace logging

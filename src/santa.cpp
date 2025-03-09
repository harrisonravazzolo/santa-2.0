#include "santa.h"

#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <zlib.h>

#include <osquery/logger/logger.h>

// Boost iostreams removed to eliminate dependency
// #include <boost/iostreams/filter/gzip.hpp>
// #include <boost/iostreams/filtering_streambuf.hpp>

#include <sqlite3.h>

const std::string kSantaLogPath = "/var/db/santa/santa.log";
const std::string kLogEntryPreface = "santad: ";

const std::string kSantaDatabasePath = "/var/db/santa/rules.db";
const std::string kTemporaryDatabasePath = "/tmp/rules.db";

std::list<std::string> archived_lines;
unsigned int next_oldest_archive = 0;

void extractValues(const std::string& line,
                   std::map<std::string, std::string>& values) {
  values.clear();

  // extract timestamp
  size_t timestamp_start = line.find("[");
  size_t timestamp_end = line.find("]");

  if (timestamp_start != std::string::npos &&
      timestamp_end != std::string::npos && timestamp_start != timestamp_end) {
    values["timestamp"] =
        line.substr(timestamp_start + 1, timestamp_end - timestamp_start - 1);
  }

  // extract key=value pairs after the kLogEntryPreface
  size_t key_pos = line.find(kLogEntryPreface);
  if (key_pos == std::string::npos) {
    return;
  }

  key_pos += kLogEntryPreface.length();
  size_t key_end, val_pos, val_end;
  while ((key_end = line.find('=', key_pos)) != std::string::npos) {
    if ((val_pos = line.find_first_not_of("=", key_end)) == std::string::npos) {
      break;
    }

    val_end = line.find('|', val_pos);
    values.emplace(line.substr(key_pos, key_end - key_pos),
                   line.substr(val_pos, val_end - val_pos));

    key_pos = val_end;
    if (key_pos != std::string::npos)
      ++key_pos;
  }
}

void scrapeStream(std::istream& incoming,
                  LogEntries& response,
                  bool save_to_archive,
                  SantaDecisionType decision) {
  std::string line;
  while (std::getline(incoming, line)) {
    if (decision == kAllowed) {
      // explicitly filter to only include ALLOW decisions
      if (line.find("decision=ALLOW") == std::string::npos) {
        continue;
      }
    } else /* if (decision == kDenied) */ {
      // explicitly filter to only include DENY decisions
      if (line.find("decision=DENY") == std::string::npos) {
        continue;
      }
    }

    std::map<std::string, std::string> values;
    extractValues(line, values);

    response.push_back({values["timestamp"],
                        values["path"],
                        values["reason"],
                        values["sha256"]});

    if (save_to_archive) {
      archived_lines.push_back(line);
    }
  }
}

void scrapeCurrentLog(LogEntries& response, SantaDecisionType decision) {
  response.clear();

  std::ifstream log_file;
  log_file.open(kSantaLogPath);
  if (!log_file.is_open()) {
    return;
  }

  scrapeStream(log_file, response, false, decision);
  log_file.close();
}

// Implementation using zlib to handle compressed log files
bool scrapeCompressedSantaLog(std::string file_path,
                              LogEntries& response,
                              SantaDecisionType decision) {
  gzFile gzfile = gzopen(file_path.c_str(), "rb");
  if (!gzfile) {
    VLOG(1) << "Failed to open compressed log file: " << file_path;
    return false;
  }

  try {
    char buffer[8192];
    std::stringstream decompressed_content;
    
    int num_read = 0;
    while ((num_read = gzread(gzfile, buffer, sizeof(buffer))) > 0) {
      decompressed_content.write(buffer, num_read);
    }
    
    // Check for errors
    int err;
    const char* error_string = gzerror(gzfile, &err);
    if (err != Z_OK && err != Z_STREAM_END) {
      VLOG(1) << "Error decompressing file: " << error_string;
      gzclose(gzfile);
      return false;
    }
    
    // Close the file
    gzclose(gzfile);
    
    // Process the decompressed content
    std::istringstream stream(decompressed_content.str());
    scrapeStream(stream, response, true, decision);
    
    VLOG(1) << "Successfully processed compressed log file: " << file_path;
    return true;
  } catch (const std::exception& e) {
    VLOG(1) << "Failed to decompress log file: " << e.what();
    gzclose(gzfile);
    return false;
  }
}

bool newArchiveFileExists() {
  std::stringstream strstr;
  strstr << kSantaLogPath << "." << next_oldest_archive << ".gz";
  std::ifstream file(strstr.str(), std::ios_base::in | std::ios_base::binary);
  return file.is_open();
}

void processArchivedLines(LogEntries& response) {
  for (std::list<std::string>::const_iterator iter = archived_lines.begin();
       iter != archived_lines.end();
       ++iter) {
    std::map<std::string, std::string> values;
    extractValues(*iter, values);
    response.push_back({values["timestamp"],
                        values["path"],
                        values["reason"],
                        values["sha256"]});
  }
}

bool scrapeSantaLog(LogEntries& response, SantaDecisionType decision) {
  try {
    scrapeCurrentLog(response, decision);

    // if there are no new archived files, just process our stash
    if (!newArchiveFileExists()) {
      processArchivedLines(response);
      return true;
    }

    // rolling archive files--clear the stored archive and reprocess them all
    archived_lines.clear();
    for (unsigned int i = 0;; ++i) {
      next_oldest_archive = i;

      std::stringstream strstr;
      strstr << kSantaLogPath << "." << i << ".gz";
      if (!scrapeCompressedSantaLog(strstr.str(), response, decision)) {
        break;
      }
    }

    return true;

  } catch (const std::exception& e) {
    VLOG(1) << "Failed to read the Santa log files: " << e.what();
    return false;
  }
}

static int rulesCallback(void* context,
                         int argc,
                         char** argv,
                         char** azColName) {
  // clang-format off

  // Expected argc/argv format:
  //     identifier,       state,        type, custom_message
  //     identifier, white/blacklist, binary/cert, arbitrary text

  // clang-format on

  RuleEntries* rules = static_cast<RuleEntries*>(context);
  if (argc != 4) {
    return 0;
  }

  RuleEntry new_rule;
  new_rule.identifier = argv[0]; // Using identifier column
  new_rule.state = (argv[1][0] == '1') ? RuleEntry::State::Whitelist
                                       : RuleEntry::State::Blacklist;

  new_rule.type = (argv[2][0] == '1') ? RuleEntry::Type::Binary
                                      : RuleEntry::Type::Certificate;

  new_rule.custom_message = (argv[3] == nullptr) ? "" : argv[3];

  rules->push_back(std::move(new_rule));
  return 0;
}

bool collectSantaRules(RuleEntries& response) {
  response.clear();

  // Verbose logging to track progress
  VLOG(1) << "Attempting to collect Santa rules from database: " << kSantaDatabasePath;

  // make a copy of the rules db (santa keeps the db locked)
  std::ifstream src(kSantaDatabasePath, std::ios_base::binary);
  if (!src.is_open()) {
    VLOG(1) << "Failed to access the Santa rule database at: " << kSantaDatabasePath;
    return false;
  }

  std::ofstream dst(kTemporaryDatabasePath,
                    std::ios_base::binary | std::ios_base::trunc);

  if (!dst.is_open()) {
    VLOG(1) << "Failed to create temporary database at: " << kTemporaryDatabasePath;
    return false;
  }

  dst << src.rdbuf();
  src.close();
  dst.close();

  // Open the database copy and enumerate the rules
  sqlite3* db;
  int rc = sqlite3_open(kTemporaryDatabasePath.c_str(), &db);
  if (SQLITE_OK != rc) {
    VLOG(1) << "Failed to open the temporary Santa rule database: " 
            << sqlite3_errmsg(db);
    return false;
  }

  // First, check the database schema to see what columns are available
  char* schema_error = nullptr;
  char** schema_results = nullptr;
  int rows, cols;
  
  VLOG(1) << "Querying database schema...";
  rc = sqlite3_get_table(
      db,
      "PRAGMA table_info(rules);",
      &schema_results,
      &rows,
      &cols,
      &schema_error);
  
  if (rc != SQLITE_OK) {
    VLOG(1) << "Failed to query schema: " 
            << (schema_error ? schema_error : "unknown error");
    if (schema_error) {
      sqlite3_free(schema_error);
    }
    sqlite3_close(db);
    return false;
  }
  
  // Log the schema
  VLOG(1) << "Rules table has " << rows << " columns:";
  bool has_identifier = false;
  bool has_shasum = false;
  std::string id_column = "identifier"; // Default to 'identifier'
  
  for (int i = 1; i <= rows; i++) {
    // Column name is at index 1 in each row
    std::string column_name = schema_results[i * cols + 1];
    VLOG(1) << "Column: " << column_name;
    
    if (column_name == "identifier") {
      has_identifier = true;
    } else if (column_name == "shasum") {
      has_shasum = true;
    }
  }
  
  // Free schema results
  sqlite3_free_table(schema_results);
  
  // Determine which column to use for the rule identifier
  if (has_identifier) {
    id_column = "identifier";
    VLOG(1) << "Using 'identifier' column for rule identifier";
  } else if (has_shasum) {
    id_column = "shasum";
    VLOG(1) << "Using 'shasum' column for rule identifier";
  } else {
    VLOG(1) << "Could not find a valid identifier column in the schema";
    sqlite3_close(db);
    return false;
  }

  // Construct the query dynamically based on available columns
  std::string query = "SELECT " + id_column + ", state, type, custommsg FROM rules;";
  VLOG(1) << "Executing query: " << query;
  
  char* sqlite_error_message = nullptr;
  rc = sqlite3_exec(db,
                    query.c_str(),
                    rulesCallback,
                    &response,
                    &sqlite_error_message);

  if (rc != SQLITE_OK) {
    VLOG(1) << "Failed to query the Santa rule database: "
            << (sqlite_error_message != nullptr ? sqlite_error_message : "unknown error");
  }

  if (sqlite_error_message != nullptr) {
    sqlite3_free(sqlite_error_message);
  }

  rc = sqlite3_close(db);
  if (rc != SQLITE_OK) {
    VLOG(1) << "Failed to close the Santa rule database";
  }
  
  VLOG(1) << "Collected " << response.size() << " rules from Santa database";
  return (rc == SQLITE_OK);
}

const char* getRuleTypeName(RuleEntry::Type type) {
  switch (type) {
  case RuleEntry::Type::Binary:
    return "binary";

  case RuleEntry::Type::Certificate:
    return "certificate";

  case RuleEntry::Type::Unknown:
  default:
    return "unknown";
  }
}

const char* getRuleStateName(RuleEntry::State state) {
  switch (state) {
  case RuleEntry::State::Whitelist:
    return "whitelist";

  case RuleEntry::State::Blacklist:
    return "blacklist";

  case RuleEntry::State::Unknown:
  default:
    return "unknown";
  }
}

RuleEntry::Type getTypeFromRuleName(const char* name) {
  std::string type_name(name);

  if (type_name == "certificate") {
    return RuleEntry::Type::Certificate;
  } else if (type_name == "binary") {
    return RuleEntry::Type::Binary;
  } else {
    return RuleEntry::Type::Unknown;
  }
}

RuleEntry::State getStateFromRuleName(const char* name) {
  std::string state_name(name);

  if (state_name == "blacklist") {
    return RuleEntry::State::Blacklist;
  } else if (state_name == "whitelist") {
    return RuleEntry::State::Whitelist;
  } else {
    return RuleEntry::State::Unknown;
  }
}
#pragma once

#include <list>
#include <string>

enum SantaDecisionType {
  kAllowed,
  kDenied,
};

struct LogEntry final {
  std::string timestamp;
  std::string application;
  std::string reason;
  std::string sha256;
};

struct RuleEntry final {
  enum class Type { Binary, Certificate, Unknown };
  enum class State { Whitelist, Blacklist, Unknown };

  Type type;
  State state;
  std::string identifier;  // Changed from shasum to identifier
  std::string custom_message;
};

using LogEntries = std::list<LogEntry>;
using RuleEntries = std::list<RuleEntry>;

const char* getRuleTypeName(RuleEntry::Type type);
const char* getRuleStateName(RuleEntry::State state);

RuleEntry::Type getTypeFromRuleName(const char* name);
RuleEntry::State getStateFromRuleName(const char* name);

bool scrapeSantaLog(LogEntries& response, SantaDecisionType decision);
bool collectSantaRules(RuleEntries& response);
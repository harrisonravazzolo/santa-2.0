#pragma once

#include <osquery/sdk/sdk.h>

// Forward declaration for RuleEntry types
class SantaRulesTablePlugin final : public osquery::TablePlugin {
 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  static osquery::Status GetRowData(osquery::Row& row,
                                    const std::string& json_value_array);

 public:
  SantaRulesTablePlugin();
  virtual ~SantaRulesTablePlugin();

 private:
  virtual osquery::TableColumns columns() const override;

  virtual osquery::TableRows generate(osquery::QueryContext& request) override;

  virtual osquery::QueryData insert(
      osquery::QueryContext& context,
      const osquery::PluginRequest& request) override;

  virtual osquery::QueryData delete_(
      osquery::QueryContext& context,
      const osquery::PluginRequest& request) override;

  virtual osquery::QueryData update(
      osquery::QueryContext& context,
      const osquery::PluginRequest& request) override;

  osquery::Status updateRules();
};
#pragma once

#include <osquery/sdk/sdk.h>
#include "santa.h"

class SantaAllowedDecisionsTablePlugin final : public osquery::TablePlugin {
 private:
  static const SantaDecisionType decision = kAllowed;
  osquery::TableColumns columns() const override;

  osquery::TableRows generate(osquery::QueryContext& request) override;
};

class SantaDeniedDecisionsTablePlugin final : public osquery::TablePlugin {
 private:
  static const SantaDecisionType decision = kDenied;
  osquery::TableColumns columns() const override;

  osquery::TableRows generate(osquery::QueryContext& request) override;
};
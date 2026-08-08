#pragma once

#include "granger/browser/BrowserEngine.h"

namespace granger {

class QtWebEngineBrowserEngine final : public BrowserEngine {
public:
    BrowserRuntimeStatus runtimeStatus() const override;
    QString proxySupportSummary() const override;
};

}

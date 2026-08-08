#pragma once

#include <QString>

#include "granger/browser/BrowserTypes.h"

namespace granger {

class BrowserEngine {
public:
    virtual ~BrowserEngine() = default;

    virtual BrowserRuntimeStatus runtimeStatus() const = 0;
    virtual QString proxySupportSummary() const = 0;
};

}

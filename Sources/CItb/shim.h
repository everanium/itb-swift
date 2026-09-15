/*
 * shim.h — bridges the C binding's public header into the Swift
 * module `CItb`. The relative include resolves inside the monorepo
 * (bindings/swift/Sources/CItb -> bindings/c/include); the Swift
 * binding is compiled in-repo against the C binding it proxies.
 */

#ifndef ITB_SWIFT_SHIM_H
#define ITB_SWIFT_SHIM_H

#include "../../../c/include/itb3.h"

#endif /* ITB_SWIFT_SHIM_H */

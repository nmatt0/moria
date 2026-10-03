// cab.hpp — Microsoft Cabinet extractor, including Windows CE installer CABs.
//
// A plain cabinet unpacks to its member names under the output subdir.
//
// A Windows CE installer cabinet needs one more step to be readable. cabwiz
// stores every payload under a mangled 8.3 name (CPHPRO~1.004) and keeps the
// real destination path, the registry keys, and the application name in a
// _setup.xml wap-provisioningdoc alongside them. Extracting the members alone
// gives you three dozen files called things like 3-SERI~1.001. So when a
// _setup.xml is present this rebuilds the tree the installer would have
// produced — `fs/` holding each payload at its real path with CE's directory
// macros expanded, `registry.reg` holding the keys, and the two cabwiz
// housekeeping members (the install header and the setup DLL) named for what
// they are.
#pragma once

#include <string>

#include "extract/manifest.hpp"
#include "finding.hpp"
#include "reader.hpp"

namespace ft {

class SafeRoot;

bool extract_cab(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                 Extracted& out);

}  // namespace ft

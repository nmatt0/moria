// ce_setup.hpp — the _setup.xml inside a Windows CE installer cabinet.
//
// cabwiz emits a wap-provisioningdoc that is the only place a CE installer CAB
// records what its files actually are. Three sections matter:
//
//   <characteristic type="Install">        parms, including AppName
//   <characteristic type="FileOperation">  a directory tree of nested
//        <characteristic type="<path or filename>"> elements ending in an
//        <characteristic type="Extract"><parm name="Source" value="X"/>,
//        where X is the mangled 8.3 name the payload is stored under
//   <characteristic type="Registry">       nested key elements whose <parm>s
//        are the values to write
//
// Destination paths use CE's directory macros (%CE2% = \Windows, and so on),
// expanded here into ordinary relative paths.
#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace ft {

struct CeRegValue {
    std::string name;
    std::string value;
    std::string datatype;  // "string" | "integer" | ...
};

struct CeRegKey {
    std::string key;  // backslash-separated, usually starting at a hive prefix
    std::vector<CeRegValue> values;
};

struct CeSetupEntry {
    std::string source;  // mangled 8.3 name of the CAB member
    std::string dest;    // install path, CE macros already expanded, relative + safe
};

struct CeSetup {
    std::string appname;
    std::vector<CeSetupEntry> files;
    std::vector<CeRegKey> registry;
};

// Parse a _setup.xml. Returns false only if the document has no recognizable
// provisioning structure at all.
bool ce_setup_parse(std::span<const uint8_t> xml, CeSetup& out);

// Render the collected registry keys as a Windows .reg file.
std::string ce_setup_reg_file(const std::vector<CeRegKey>& keys);

}  // namespace ft

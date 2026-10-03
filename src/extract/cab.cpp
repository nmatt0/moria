// cab.cpp — Microsoft Cabinet extraction. See cab.hpp.
//
// Files are not stored individually: a CFFOLDER is one compressed stream split
// across CFDATA blocks, and each CFFILE names a byte range inside that stream's
// decompressed output. So a folder is decoded once and then sliced, and folders
// with no files pointing at them are never decoded at all.
#include "extract/cab.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include "cab_parse.hpp"
#include "extract/ce_setup.hpp"
#include "extract/decompress.hpp"
#include "extract/lzx.hpp"
#include "extract/safepath.hpp"

namespace ft {

namespace {

constexpr uint64_t kMaxFolderOut = uint64_t(1) << 30;  // 1 GiB of output per folder
constexpr size_t kMszipFrame = 32768;                  // MSZIP block size and window

// CFFILE.iFolder values that mean "this file continues across cabinets".
constexpr uint16_t kFolderContinuedFrom = 0xFFFD;
constexpr uint16_t kFolderContinuedTo = 0xFFFE;
constexpr uint16_t kFolderContinuedBoth = 0xFFFF;

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool ends_with(const std::string& s, const char* suffix) {
    const size_t n = std::strlen(suffix);
    return s.size() >= n && std::equal(s.end() - n, s.end(), suffix);
}

// A CAB member name is a backslash-separated relative path. Keep the structure
// but strip anything that could escape the output root or upset a filesystem.
std::string safe_member_path(const std::string& name) {
    std::string norm = name;
    for (char& c : norm)
        if (c == '\\') c = '/';
    std::string out;
    size_t i = 0;
    while (i < norm.size()) {
        size_t j = norm.find('/', i);
        if (j == std::string::npos) j = norm.size();
        std::string part = norm.substr(i, j - i);
        i = j + 1;
        if (part.empty() || part == "." || part == "..") continue;
        for (char& c : part) {
            const unsigned char u = static_cast<unsigned char>(c);
            if (u < 0x20 || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' ||
                c == '|')
                c = '_';
        }
        if (!out.empty()) out += '/';
        out += part;
    }
    return out.empty() ? std::string("_unnamed") : out;
}

// Decode one folder's CFDATA chain. `why` names the reason on failure so the
// caller can put it in the manifest rather than silently dropping the folder.
bool folder_bytes(const Reader& r, size_t base, const CabHeader& h, const CabFolder& fo,
                  std::vector<uint8_t>& out, std::string& why) {
    const size_t stride = 8 + h.res_data;
    const CabComp codec = fo.comp();
    if (codec == CabComp::Quantum) {
        why = "unsupported:quantum";
        return false;
    }

    size_t off = base + fo.coff_data;
    std::vector<uint8_t> lzx_in;  // LZX is one bitstream across the whole folder
    uint64_t lzx_out = 0;

    for (uint16_t i = 0; i < fo.ndata; ++i) {
        auto cb = r.at<uint16_t>(off + 4, Endian::Little);
        auto cu = r.at<uint16_t>(off + 6, Endian::Little);
        if (!cb || !cu) {
            why = "truncated CFDATA header";
            return false;
        }
        auto data = r.bytes(off + stride, *cb);
        if (!data) {
            why = "CFDATA runs past the end of the file";
            return false;
        }
        off += stride + *cb;

        if (out.size() + *cu > kMaxFolderOut || lzx_out + *cu > kMaxFolderOut) {
            why = "folder exceeds the output cap";
            return false;
        }

        switch (codec) {
            case CabComp::None:
                if (*cu != *cb) {
                    why = "stored block size mismatch";
                    return false;
                }
                out.insert(out.end(), data->begin(), data->end());
                break;
            case CabComp::MsZip: {
                if (data->size() < 2 || (*data)[0] != 'C' || (*data)[1] != 'K') {
                    why = "MSZIP block missing its CK marker";
                    return false;
                }
                // A block may match back into the previous block's output.
                const size_t hist = std::min(out.size(), kMszipFrame);
                auto blk = mszip_block(data->subspan(2), *cu,
                                       std::span<const uint8_t>(out).last(hist));
                if (!blk) {
                    why = "MSZIP block failed to inflate";
                    return false;
                }
                out.insert(out.end(), blk->begin(), blk->end());
                break;
            }
            case CabComp::Lzx:
                lzx_in.insert(lzx_in.end(), data->begin(), data->end());
                lzx_out += *cu;
                break;
            case CabComp::Quantum: return false;  // handled above
        }
    }

    if (codec == CabComp::Lzx) {
        const unsigned win = fo.lzx_window();
        auto dec = lzx_decompress_cab(lzx_in, static_cast<size_t>(lzx_out), win);
        if (!dec) {
            why = "LZX folder failed to decode";
            return false;
        }
        out = std::move(*dec);
    }
    return true;
}

// Resolve a CFFILE's folder index, including the cross-cabinet sentinels.
size_t folder_index(uint16_t ifolder, size_t nfolders) {
    switch (ifolder) {
        case kFolderContinuedFrom:
        case kFolderContinuedBoth: return 0;
        case kFolderContinuedTo: return nfolders - 1;
        default: return ifolder < nfolders ? ifolder : SIZE_MAX;
    }
}

}  // namespace

bool extract_cab(const Reader& r, const Finding& f, SafeRoot& root, const std::string& subdir,
                 Extracted& out) {
    out.offset = f.offset;
    out.type = "cab";
    out.root = subdir;

    CabHeader h;
    std::vector<CabFolder> folders;
    std::vector<CabFile> files;
    if (!cab_header(r, f.offset, h) || !cab_folders(r, f.offset, h, folders) ||
        !cab_files(r, f.offset, h, files)) {
        out.status = "error:header";
        return true;
    }
    if (!root.make_dir(subdir)) {
        out.status = "error:mkdir";
        return true;
    }
    out.consumed = h.cb_cabinet;

    // Group files by the folder whose stream they slice.
    std::vector<std::vector<size_t>> by_folder(folders.size());
    bool spanned = false;
    for (size_t i = 0; i < files.size(); ++i) {
        const size_t fi = folder_index(files[i].ifolder, folders.size());
        if (fi == SIZE_MAX) {
            out.warnings.push_back(files[i].name + ": folder index out of range");
            continue;
        }
        if (files[i].ifolder >= kFolderContinuedFrom) spanned = true;
        by_folder[fi].push_back(i);
    }
    if (spanned)
        out.warnings.push_back(
            "file(s) continue across cabinets; only the part stored here is recoverable");

    // The CE installer manifest tells us what every mangled member really is,
    // so read it before writing anything.
    CeSetup setup;
    bool have_setup = false;
    std::unordered_map<std::string, std::string> install_map;  // lowercased source -> dest
    for (size_t fi = 0; fi < folders.size() && !have_setup; ++fi) {
        for (size_t idx : by_folder[fi]) {
            if (lower(files[idx].name) != "_setup.xml") continue;
            std::vector<uint8_t> stream;
            std::string why;
            if (!folder_bytes(r, f.offset, h, folders[fi], stream, why)) break;
            const CabFile& cf = files[idx];
            if (uint64_t(cf.folder_off) + cf.size > stream.size()) break;
            if (ce_setup_parse(std::span<const uint8_t>(stream).subspan(cf.folder_off, cf.size),
                               setup)) {
                have_setup = true;
                for (const CeSetupEntry& e : setup.files) install_map[lower(e.source)] = e.dest;
            }
            break;
        }
    }

    size_t failures = 0, unmapped = 0;
    bool made_fs = false, made_unmapped = false;

    for (size_t fi = 0; fi < folders.size(); ++fi) {
        if (by_folder[fi].empty()) continue;
        std::vector<uint8_t> stream;
        std::string why;
        if (!folder_bytes(r, f.offset, h, folders[fi], stream, why)) {
            ++failures;
            out.warnings.push_back("folder " + std::to_string(fi) + ": " + why);
            if (why.rfind("unsupported:", 0) == 0 && out.status.empty()) out.status = why;
            continue;
        }

        for (size_t idx : by_folder[fi]) {
            const CabFile& cf = files[idx];
            if (uint64_t(cf.folder_off) + cf.size > stream.size()) {
                ++failures;
                out.warnings.push_back(cf.name + ": extends past its folder's data");
                continue;
            }
            const uint8_t* p = stream.data() + cf.folder_off;
            const std::vector<uint8_t> data(p, p + cf.size);

            std::string rel;
            if (!have_setup) {
                rel = subdir + "/" + safe_member_path(cf.name);
            } else {
                const std::string lname = lower(cf.name);
                auto it = install_map.find(lname);
                if (lname == "_setup.xml") {
                    rel = subdir + "/_setup.xml";
                } else if (it != install_map.end()) {
                    if (!made_fs && root.make_dir(subdir + "/fs")) {
                        made_fs = true;
                        out.dirs++;
                    }
                    rel = subdir + "/fs/" + it->second;
                } else if (ends_with(lname, ".999")) {
                    // cabwiz stores the setup DLL (Install_Init / Install_Exit)
                    // as the .999 member and the install header as .000.
                    rel = subdir + "/setup.dll";
                } else if (ends_with(lname, ".000")) {
                    rel = subdir + "/install-header.000";
                } else {
                    if (!made_unmapped && root.make_dir(subdir + "/unmapped")) {
                        made_unmapped = true;
                        out.dirs++;
                    }
                    rel = subdir + "/unmapped/" + safe_member_path(cf.name);
                    ++unmapped;
                }
            }

            if (!root.write_file(rel, data, 0644)) {
                out.status = "error:write";
                return true;
            }
            out.files++;
            out.bytes += data.size();
        }
    }

    if (have_setup && !setup.registry.empty()) {
        const std::string reg = ce_setup_reg_file(setup.registry);
        const std::vector<uint8_t> bytes(reg.begin(), reg.end());
        if (root.write_file(subdir + "/registry.reg", bytes, 0644)) {
            out.files++;
            out.bytes += bytes.size();
        }
    }
    // Members _setup.xml never mentions are kept under unmapped/ rather than
    // dropped, but say so: they are the part of the install the manifest did
    // not explain.
    if (unmapped)
        out.warnings.push_back(std::to_string(unmapped) +
                               " member(s) not named by _setup.xml, kept under unmapped/");

    if (out.files == 0) {
        if (out.status.empty()) out.status = "error:empty";
    } else if (failures || !out.status.empty()) {
        if (out.status.rfind("unsupported:", 0) != 0) out.status = "partial";
    } else {
        out.status = "ok";
    }
    return true;
}

}  // namespace ft

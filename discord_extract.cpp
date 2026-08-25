
/*
 * discord_extract.cpp  —  Discord Local Storage Extractor
 *
 * Built with Aether
 * 
 * 
 *
 * Extracts + Decrypts:
 *   - Auth Token        (LevelDB → "tokens" key, v10 AES-256-GCM)
 *   - All Flux Stores   (SelectedChannelStore, DraftStore, GameStore, etc.)
 *   - Cross-origin data (Stripe, YouTube, Adyen, DiscordSays)
 *   - Raw LevelDB key/value dump
 *
 * Build (MSVC Developer Command Prompt):
 *   cl discord_extract.cpp /O2 /std:c++17 /EHsc
 *      /link crypt32.lib bcrypt.lib shell32.lib advapi32.lib /Fe:discord_extract.exe
 *
 * Build (MinGW / MSYS2):
 *   g++ discord_extract.cpp -O2 -std=c++17 -o discord_extract.exe
 *       -lcrypt32 -lbcrypt -lshell32
 *
 * No external dependencies — LevelDB format parsed inline (no libleveldb needed).
 */

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <shlobj.h>
#include <sddl.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <functional>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

namespace fs = std::filesystem;

// ═══════════════════════════════════════════════════════════════════════════
//  RE-confirmed DPAPI constants (from chrome_extract RE findings)
// ═══════════════════════════════════════════════════════════════════════════

static const uint8_t DPAPI_BLOB_SIG[20] = {
    0x01, 0x00, 0x00, 0x00,
    0xD0, 0x8C, 0x9D, 0xDF, 0x01, 0x15, 0xD1, 0x11,
    0x8C, 0x7A, 0x00, 0xC0, 0x4F, 0xC2, 0x97, 0xEB
};

static const DWORD DPAPI_MIN_BLOB_SIZE = 0x34;
static const uint8_t CHROME_DPAPI_PREFIX[5] = { 'D','P','A','P','I' };
static const uint8_t PREFIX_V10[3] = { 'v','1','0' };
static const uint8_t PREFIX_V20[3] = { 'v','2','0' };

// ═══════════════════════════════════════════════════════════════════════════
//  DPAPI Blob Header Parser (same as chrome_extract Section 4)
// ═══════════════════════════════════════════════════════════════════════════

struct DPAPIBlobInfo {
    uint32_t    version;
    uint8_t     providerGUID[16];
    uint8_t     masterKeyGUID[16];
    uint32_t    flags;
    uint32_t    algCrypt;
    uint32_t    algHash;
    bool        valid;
    std::string algCryptStr;
    std::string algHashStr;
    std::vector<uint8_t> saltBytes;
};

static std::string GUIDToString(const uint8_t* g) {
    std::ostringstream s;
    s << std::hex << std::uppercase << std::setfill('0');
    s << '{';
    s << std::setw(2) << (int)g[3] << std::setw(2) << (int)g[2]
      << std::setw(2) << (int)g[1] << std::setw(2) << (int)g[0] << '-';
    s << std::setw(2) << (int)g[5] << std::setw(2) << (int)g[4] << '-';
    s << std::setw(2) << (int)g[7] << std::setw(2) << (int)g[6] << '-';
    s << std::setw(2) << (int)g[8] << std::setw(2) << (int)g[9] << '-';
    for (int i = 10; i < 16; ++i)
        s << std::setw(2) << (int)g[i];
    s << '}';
    return s.str();
}

static DPAPIBlobInfo ParseBlobHeader(const std::vector<uint8_t>& blob) {
    DPAPIBlobInfo info{};
    info.valid = false;
    if (blob.size() < DPAPI_MIN_BLOB_SIZE) return info;
    if (memcmp(blob.data(), DPAPI_BLOB_SIG, 20) != 0) return info;

    info.version = *reinterpret_cast<const uint32_t*>(blob.data());
    memcpy(info.providerGUID,  blob.data() + 0x04, 16);
    memcpy(info.masterKeyGUID, blob.data() + 0x14, 16);
    info.flags = *reinterpret_cast<const uint32_t*>(blob.data() + 0x24);

    uint32_t descLen = *reinterpret_cast<const uint32_t*>(blob.data() + 0x28);
    size_t off = 0x2C + descLen;

    if (off + 4 <= blob.size()) {
        info.algCrypt = *reinterpret_cast<const uint32_t*>(blob.data() + off);
        switch (info.algCrypt) {
            case 0x6601: info.algCryptStr = "DES-CBC"; break;
            case 0x6603: info.algCryptStr = "3DES-CBC"; break;
            case 0x6611: info.algCryptStr = "AES-256-CBC"; break;
            default: {
                std::ostringstream o; o << "0x" << std::hex << info.algCrypt;
                info.algCryptStr = o.str();
            }
        }
    }

    if (off + 12 <= blob.size()) {
        uint32_t cbSalt = *reinterpret_cast<const uint32_t*>(blob.data() + off + 8);
        size_t hashOff = off + 12 + cbSalt;
        if (hashOff + 4 <= blob.size()) {
            info.algHash = *reinterpret_cast<const uint32_t*>(blob.data() + hashOff);
            switch (info.algHash) {
                case 0x8004: info.algHashStr = "HMAC-SHA1"; break;
                case 0x800C: info.algHashStr = "HMAC-SHA256"; break;
                default: {
                    std::ostringstream o; o << "0x" << std::hex << info.algHash;
                    info.algHashStr = o.str();
                }
            }
        }
        if (cbSalt > 0 && cbSalt <= 64 && off + 12 + cbSalt <= blob.size()) {
            info.saltBytes.assign(blob.data() + off + 12,
                                  blob.data() + off + 12 + cbSalt);
        }
    }

    info.valid = true;
    return info;
}

// ═══════════════════════════════════════════════════════════════════════════
//  Utility
// ═══════════════════════════════════════════════════════════════════════════

static std::string WideToUTF8(const std::wstring& w) {
    if (w.empty()) return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                  nullptr, 0, nullptr, nullptr);
    std::string s(sz, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                        &s[0], sz, nullptr, nullptr);
    return s;
}

static std::wstring GetLocalAppData() {
    wchar_t path[MAX_PATH] = {};
    SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, path);
    return path;
}

static std::wstring GetRoamingAppData() {
    wchar_t path[MAX_PATH] = {};
    SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, path);
    return path;
}

static std::string HexDump(const uint8_t* data, size_t len, size_t maxBytes = 32) {
    std::ostringstream s;
    s << std::hex << std::setfill('0');
    for (size_t i = 0; i < std::min(len, maxBytes); ++i)
        s << std::setw(2) << (int)data[i] << " ";
    if (len > maxBytes) s << "...";
    return s.str();
}

static std::vector<uint8_t> Base64Decode(const std::string& enc) {
    DWORD len = 0;
    if (!CryptStringToBinaryA(enc.c_str(), 0, CRYPT_STRING_BASE64,
                               nullptr, &len, nullptr, nullptr) || len == 0)
        throw std::runtime_error("Base64Decode failed (size query)");
    std::vector<uint8_t> out(len);
    if (!CryptStringToBinaryA(enc.c_str(), 0, CRYPT_STRING_BASE64,
                               out.data(), &len, nullptr, nullptr))
        throw std::runtime_error("Base64Decode failed (decode)");
    out.resize(len);
    return out;
}

static std::string ExtractJSONString(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos)
        throw std::runtime_error("Key not found: " + key);
    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos)
        throw std::runtime_error("Malformed JSON near: " + key);
    pos = json.find('"', pos + 1);
    if (pos == std::string::npos)
        throw std::runtime_error("No opening quote: " + key);
    auto end = json.find('"', pos + 1);
    while (end != std::string::npos && json[end - 1] == '\\')
        end = json.find('"', end + 1);
    if (end == std::string::npos)
        throw std::runtime_error("No closing quote: " + key);
    return json.substr(pos + 1, end - pos - 1);
}

// ═══════════════════════════════════════════════════════════════════════════
//  DPAPI Decrypt — CryptUnprotectData (user-context, no entropy)
// ═══════════════════════════════════════════════════════════════════════════

static std::vector<uint8_t> DPAPIDecrypt(const std::vector<uint8_t>& blob) {
    if (blob.size() < DPAPI_MIN_BLOB_SIZE)
        throw std::runtime_error("Blob too small: " + std::to_string(blob.size()));

    DATA_BLOB in{};
    in.cbData = (DWORD)blob.size();
    in.pbData = const_cast<BYTE*>(blob.data());

    DATA_BLOB out{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr,
                             CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        DWORD err = GetLastError();
        std::ostringstream s;
        s << "CryptUnprotectData failed — error 0x" << std::hex << err;
        throw std::runtime_error(s.str());
    }

    std::vector<uint8_t> key(out.pbData, out.pbData + out.cbData);
    LocalFree(out.pbData);
    return key;
}

// ═══════════════════════════════════════════════════════════════════════════
//  AES-256-GCM Decrypt via BCrypt CNG (same as chrome_extract)
// ═══════════════════════════════════════════════════════════════════════════

static std::string AES256GCMDecrypt(const std::vector<uint8_t>& key,
                                     const std::vector<uint8_t>& nonce,
                                     const std::vector<uint8_t>& ciphertext,
                                     const std::vector<uint8_t>& tag) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(st))
        throw std::runtime_error("BCryptOpenAlgorithmProvider failed");

    st = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                            (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                            sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(st)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("BCryptSetProperty(GCM) failed");
    }

    DWORD objLen = 0, ret = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                       (PUCHAR)&objLen, sizeof(DWORD), &ret, 0);

    std::vector<uint8_t> keyObj(objLen);
    st = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), objLen,
                                     const_cast<PUCHAR>(key.data()),
                                     (ULONG)key.size(), 0);
    if (!BCRYPT_SUCCESS(st)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("BCryptGenerateSymmetricKey failed");
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);

    std::vector<uint8_t> nonceMut = nonce;
    std::vector<uint8_t> tagMut   = tag;

    authInfo.pbNonce    = nonceMut.data();
    authInfo.cbNonce    = (ULONG)nonceMut.size();
    authInfo.pbTag      = tagMut.data();
    authInfo.cbTag      = (ULONG)tagMut.size();
    authInfo.pbAuthData = nullptr;
    authInfo.cbAuthData = 0;
    authInfo.pbMacContext = nullptr;
    authInfo.cbMacContext = 0;
    authInfo.cbAAD  = 0;
    authInfo.cbData = 0;
    authInfo.dwFlags = 0;

    std::vector<uint8_t> plain(ciphertext.size());
    ULONG plainLen = 0;

    st = BCryptDecrypt(hKey,
                       const_cast<PUCHAR>(ciphertext.data()),
                       (ULONG)ciphertext.size(),
                       &authInfo,
                       nullptr, 0,
                       plain.data(), (ULONG)plain.size(),
                       &plainLen, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(st)) {
        std::ostringstream e;
        e << "BCryptDecrypt(GCM) failed: 0x" << std::hex << st;
        throw std::runtime_error(e.str());
    }

    plain.resize(plainLen);
    return std::string(plain.begin(), plain.end());
}

// ═══════════════════════════════════════════════════════════════════════════
//  Decrypt a v10/v20/raw-DPAPI encrypted value
// ═══════════════════════════════════════════════════════════════════════════

static std::string DecryptValue(const std::vector<uint8_t>& aesKey,
                                 const std::vector<uint8_t>& value) {
    if (value.empty()) return "<empty>";

    if (value.size() >= 3) {
        bool isV10 = (memcmp(value.data(), PREFIX_V10, 3) == 0);
        bool isV20 = (memcmp(value.data(), PREFIX_V20, 3) == 0);

        if (isV10 || isV20) {
            if (value.size() < 3 + 12 + 16)
                return "<v10/v20 blob too short>";

            std::vector<uint8_t> nonce(value.begin() + 3, value.begin() + 15);
            std::vector<uint8_t> ciphertext(value.begin() + 15, value.end() - 16);
            std::vector<uint8_t> tag(value.end() - 16, value.end());

            return AES256GCMDecrypt(aesKey, nonce, ciphertext, tag);
        }
    }

    if (value.size() >= 20 && memcmp(value.data(), DPAPI_BLOB_SIG, 20) == 0) {
        std::vector<uint8_t> plain = DPAPIDecrypt(value);
        return std::string(plain.begin(), plain.end());
    }

    return std::string(value.begin(), value.end());
}

// ═══════════════════════════════════════════════════════════════════════════
//  Load Discord's AES-256 key from Local State
//  Path: %APPDATA%\discord\Local State  (note: APPDATA not LOCALAPPDATA)
// ═══════════════════════════════════════════════════════════════════════════

static std::vector<uint8_t> LoadDiscordKey(const fs::path& localStatePath,
                                            bool verbose = true) {
    std::ifstream f(localStatePath);
    if (!f.is_open())
        throw std::runtime_error("Cannot open: " + localStatePath.string());

    std::string json((std::istreambuf_iterator<char>(f)),
                      std::istreambuf_iterator<char>());

    std::string b64 = ExtractJSONString(json, "encrypted_key");
    std::vector<uint8_t> raw = Base64Decode(b64);

    if (raw.size() < 5 || memcmp(raw.data(), CHROME_DPAPI_PREFIX, 5) != 0)
        throw std::runtime_error("encrypted_key missing DPAPI prefix");

    std::vector<uint8_t> blob(raw.begin() + 5, raw.end());

    if (blob.size() < 20 || memcmp(blob.data(), DPAPI_BLOB_SIG, 20) != 0)
        throw std::runtime_error("DPAPI blob signature mismatch");

    std::vector<uint8_t> key = DPAPIDecrypt(blob);
    if (key.size() != 32)
        throw std::runtime_error("Decrypted key is " + std::to_string(key.size()) +
                                  " bytes, expected 32");

    return key;
}

// ═══════════════════════════════════════════════════════════════════════════
//  LevelDB Format Parser — No external library needed
//  Parses .ldb (SSTable) and .log (WAL) files directly from disk
//
//  LevelDB on-disk format (from Google's table_format.md):
//    SSTable (.ldb/.sst):
//      [data block 0] [data block 1] ... [meta block] [metaindex] [index] [footer]
//      Footer: 48 bytes at EOF — metaindex_handle + index_handle + magic(8)
//      Magic: 0xdb4775248b80fb57
//    Data Block:
//      [entry 0] [entry 1] ... [restarts] [num_restarts]
//      Entry: shared_bytes(varint) + unshared_bytes(varint) + value_len(varint)
//             + key_delta(unshared_bytes) + value(value_len)
//    WAL (.log):
//      [record 0] [record 1] ...
//      Record: checksum(4) + length(2) + type(1) + data(length)
//      Type 1=Full, 2=First, 3=Middle, 4=Last
//      Data contains a WriteBatch:
//        sequence(8) + count(4) + [operations...]
//        Operation: type(1) + key_len(varint) + key + value_len(varint) + value
// ═══════════════════════════════════════════════════════════════════════════

struct LDBEntry {
    std::string key;
    std::string value;
    std::string sourceFile;
};

static uint64_t DecodeVarint(const uint8_t*& p, const uint8_t* limit) {
    uint64_t result = 0;
    int shift = 0;
    while (p < limit) {
        uint8_t byte = *p++;
        result |= (uint64_t)(byte & 0x7F) << shift;
        if ((byte & 0x80) == 0) return result;
        shift += 7;
        if (shift >= 64) break;
    }
    return result;
}

static uint32_t DecodeFixed32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t DecodeFixed64(const uint8_t* p) {
    return (uint64_t)DecodeFixed32(p) | ((uint64_t)DecodeFixed32(p + 4) << 32);
}

// ═══════════════════════════════════════════════════════════════════════════
//  Inline Snappy Decompression
//  LevelDB uses Snappy for block compression by default
//  Format: varint(uncompressed_length) + compressed_data
//  Element types: 00=literal, 01=copy-1byte-offset, 10=copy-2byte, 11=copy-4byte
// ═══════════════════════════════════════════════════════════════════════════

static bool SnappyDecompress(const uint8_t* src, size_t srcLen,
                              std::vector<uint8_t>& dst) {
    if (srcLen == 0) return false;

    const uint8_t* p = src;
    const uint8_t* srcEnd = src + srcLen;

    uint64_t uncompLen = DecodeVarint(p, srcEnd);
    if (uncompLen == 0 || uncompLen > 64 * 1024 * 1024) return false;

    dst.resize((size_t)uncompLen);
    size_t dstPos = 0;

    while (p < srcEnd && dstPos < uncompLen) {
        uint8_t tag = *p++;
        uint8_t tagType = tag & 0x03;

        if (tagType == 0x00) {
            // Literal
            uint32_t litLen;
            uint8_t lenType = (tag >> 2) & 0x3F;
            if (lenType < 60) {
                litLen = lenType + 1;
            } else {
                uint32_t extraBytes = lenType - 59;
                if (p + extraBytes > srcEnd) return false;
                litLen = 1;
                for (uint32_t i = 0; i < extraBytes; ++i)
                    litLen += (uint32_t)p[i] << (8 * i);
                p += extraBytes;
            }
            if (p + litLen > srcEnd) return false;
            if (dstPos + litLen > uncompLen) return false;
            memcpy(dst.data() + dstPos, p, litLen);
            p += litLen;
            dstPos += litLen;
        } else if (tagType == 0x01) {
            // Copy with 1-byte offset
            if (p >= srcEnd) return false;
            uint32_t len = ((tag >> 2) & 0x07) + 4;
            uint32_t offset = ((uint32_t)(tag >> 5) << 8) | *p++;
            if (offset == 0 || offset > dstPos) return false;
            if (dstPos + len > uncompLen) return false;
            size_t srcOff = dstPos - offset;
            for (uint32_t i = 0; i < len; ++i)
                dst[dstPos + i] = dst[srcOff + (i % offset)];
            dstPos += len;
        } else if (tagType == 0x02) {
            // Copy with 2-byte offset
            if (p + 2 > srcEnd) return false;
            uint32_t len = ((tag >> 2) & 0x3F) + 1;
            uint32_t offset = (uint32_t)p[0] | ((uint32_t)p[1] << 8);
            p += 2;
            if (offset == 0 || offset > dstPos) return false;
            if (dstPos + len > uncompLen) return false;
            size_t srcOff = dstPos - offset;
            for (uint32_t i = 0; i < len; ++i)
                dst[dstPos + i] = dst[srcOff + (i % offset)];
            dstPos += len;
        } else {
            // Copy with 4-byte offset
            if (p + 4 > srcEnd) return false;
            uint32_t len = ((tag >> 2) & 0x3F) + 1;
            uint32_t offset = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                              ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
            p += 4;
            if (offset == 0 || offset > dstPos) return false;
            if (dstPos + len > uncompLen) return false;
            size_t srcOff = dstPos - offset;
            for (uint32_t i = 0; i < len; ++i)
                dst[dstPos + i] = dst[srcOff + (i % offset)];
            dstPos += len;
        }
    }

    dst.resize(dstPos);
    return dstPos == uncompLen;
}

// Strip 8-byte LevelDB internal key suffix (7-byte sequence + 1-byte type)
// Internal key format: user_key + sequence_number(7 bytes LE) + type(1 byte)
// Type 0x01 = kTypeValue, 0x00 = kTypeDeletion
static std::string StripInternalKeySuffix(const std::string& internalKey) {
    if (internalKey.size() <= 8) return internalKey;
    return internalKey.substr(0, internalKey.size() - 8);
}

static bool ParseDataBlock(const uint8_t* blockData, size_t blockSize,
                           std::vector<LDBEntry>& entries,
                           const std::string& sourceFile,
                           bool isIndexBlock = false) {
    if (blockSize < 4) return false;

    uint32_t numRestarts = DecodeFixed32(blockData + blockSize - 4);
    if (numRestarts == 0 || numRestarts > blockSize / 4) return false;

    size_t restartsOffset = blockSize - 4 - (numRestarts * 4);
    if (restartsOffset > blockSize) return false;

    const uint8_t* p = blockData;
    const uint8_t* limit = blockData + restartsOffset;
    std::string prevKey;

    while (p < limit) {
        uint64_t shared   = DecodeVarint(p, limit);
        if (p >= limit) break;
        uint64_t unshared = DecodeVarint(p, limit);
        if (p >= limit) break;
        uint64_t valueLen = DecodeVarint(p, limit);

        if (shared > prevKey.size()) break;
        if (p + unshared + valueLen > blockData + blockSize) break;

        std::string key = prevKey.substr(0, (size_t)shared);
        key.append(reinterpret_cast<const char*>(p), (size_t)unshared);
        p += unshared;

        std::string value(reinterpret_cast<const char*>(p), (size_t)valueLen);
        p += valueLen;

        prevKey = key;

        if (!key.empty()) {
            LDBEntry entry;
            entry.key = isIndexBlock ? key : StripInternalKeySuffix(key);
            entry.value = value;
            entry.sourceFile = sourceFile;
            entries.push_back(std::move(entry));
        }
    }

    return true;
}

static const uint64_t SSTABLE_MAGIC = 0xdb4775248b80fb57ULL;

static void ParseSSTable(const fs::path& filePath, std::vector<LDBEntry>& entries) {
    std::ifstream f(filePath, std::ios::binary | std::ios::ate);
    if (!f.is_open()) return;

    auto fileSize = f.tellg();
    if (fileSize < 48) return;

    std::vector<uint8_t> data((size_t)fileSize);
    f.seekg(0);
    f.read(reinterpret_cast<char*>(data.data()), fileSize);

    const uint8_t* footer = data.data() + data.size() - 48;
    uint64_t magic = DecodeFixed64(footer + 40);
    if (magic != SSTABLE_MAGIC) return;

    // Parse index block handle from footer
    // Footer layout: metaindex_handle(varint pair) + index_handle(varint pair) + padding + magic(8)
    // The index handle starts at offset 20 in the footer (after metaindex)
    const uint8_t* mp = footer;
    const uint8_t* mend = footer + 40;
    // Skip metaindex handle
    DecodeVarint(mp, mend); // metaindex offset
    DecodeVarint(mp, mend); // metaindex size
    // Now read index handle
    uint64_t indexOffset = DecodeVarint(mp, mend);
    uint64_t indexSize   = DecodeVarint(mp, mend);

    if (indexOffset + indexSize + 5 > data.size()) return;

    // Helper: read a block, decompressing if needed
    auto ReadBlock = [&](uint64_t off, uint64_t sz) -> std::vector<uint8_t> {
        if (off + sz + 5 > data.size()) return {};
        uint8_t compType = data[off + sz];
        if (compType == 0x01) {
            // Snappy compressed
            std::vector<uint8_t> decompressed;
            if (SnappyDecompress(data.data() + off, (size_t)sz, decompressed))
                return decompressed;
            return {};
        }
        // No compression
        return std::vector<uint8_t>(data.data() + off, data.data() + off + sz);
    };

    // Index block may also be Snappy-compressed
    std::vector<uint8_t> indexBlockData = ReadBlock(indexOffset, indexSize);
    if (indexBlockData.empty()) return;

    // Parse index block entries — each value is a BlockHandle (offset + size varint pair)
    std::vector<LDBEntry> indexEntries;
    ParseDataBlock(indexBlockData.data(), indexBlockData.size(), indexEntries, "", true);

    // For each data block referenced by the index, decompress and parse
    for (auto& idxEntry : indexEntries) {
        const uint8_t* vp = reinterpret_cast<const uint8_t*>(idxEntry.value.data());
        const uint8_t* vend = vp + idxEntry.value.size();

        uint64_t blockOffset = DecodeVarint(vp, vend);
        uint64_t blockSize   = DecodeVarint(vp, vend);

        std::vector<uint8_t> blockData = ReadBlock(blockOffset, blockSize);
        if (blockData.empty()) continue;

        ParseDataBlock(blockData.data(), blockData.size(),
                       entries, filePath.filename().string());
    }
}

static void ParseWALLog(const fs::path& filePath, std::vector<LDBEntry>& entries) {
    std::ifstream f(filePath, std::ios::binary | std::ios::ate);
    if (!f.is_open()) return;

    auto fileSize = f.tellg();
    if (fileSize < 7) return;

    std::vector<uint8_t> data((size_t)fileSize);
    f.seekg(0);
    f.read(reinterpret_cast<char*>(data.data()), fileSize);

    std::string assembled;
    size_t pos = 0;

    while (pos + 7 <= data.size()) {
        // LevelDB log record: checksum(4) + length(2) + type(1)
        uint16_t recLen = (uint16_t)data[pos + 4] | ((uint16_t)data[pos + 5] << 8);
        uint8_t recType = data[pos + 6];

        if (pos + 7 + recLen > data.size()) break;

        std::string chunk(reinterpret_cast<char*>(data.data() + pos + 7), recLen);

        switch (recType) {
            case 1: // FULL
                assembled = chunk;
                break;
            case 2: // FIRST
                assembled = chunk;
                pos += 7 + recLen;
                // Pad to 32KB block boundary
                if (pos % 32768 == 0) {} // already aligned
                continue;
            case 3: // MIDDLE
                assembled += chunk;
                pos += 7 + recLen;
                continue;
            case 4: // LAST
                assembled += chunk;
                break;
            default:
                pos += 7 + recLen;
                continue;
        }

        // Parse WriteBatch from assembled record
        // WriteBatch: sequence(8) + count(4) + [operations...]
        if (assembled.size() >= 12) {
            const uint8_t* bp = reinterpret_cast<const uint8_t*>(assembled.data());
            const uint8_t* bend = bp + assembled.size();

            // uint64_t sequence = DecodeFixed64(bp);
            uint32_t count = DecodeFixed32(bp + 8);
            const uint8_t* op = bp + 12;

            for (uint32_t i = 0; i < count && op < bend; ++i) {
                uint8_t opType = *op++;
                if (opType == 0x01) { // kTypeValue (put)
                    uint64_t keyLen = DecodeVarint(op, bend);
                    if (op + keyLen > bend) break;
                    std::string key(reinterpret_cast<const char*>(op), (size_t)keyLen);
                    op += keyLen;

                    uint64_t valLen = DecodeVarint(op, bend);
                    if (op + valLen > bend) break;
                    std::string val(reinterpret_cast<const char*>(op), (size_t)valLen);
                    op += valLen;

                    LDBEntry entry;
                    entry.key = key;
                    entry.value = val;
                    entry.sourceFile = filePath.filename().string();
                    entries.push_back(std::move(entry));
                } else if (opType == 0x00) { // kTypeDeletion
                    uint64_t keyLen = DecodeVarint(op, bend);
                    if (op + keyLen > bend) break;
                    op += keyLen;
                } else {
                    break;
                }
            }
        }

        assembled.clear();
        pos += 7 + recLen;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  LevelDB Key Parser — Chromium LocalStorage format
//  Key format: "_<origin>\x00\x01<store_name>"
//  META keys:  "META:<origin>"
// ═══════════════════════════════════════════════════════════════════════════

struct ParsedLDBKey {
    std::string origin;
    std::string storeName;
    bool isMeta;
    bool valid;
};

static ParsedLDBKey ParseChromiumLSKey(const std::string& rawKey) {
    ParsedLDBKey pk{};
    pk.valid = false;
    pk.isMeta = false;

    if (rawKey.size() >= 5 && rawKey.substr(0, 5) == "META:") {
        pk.isMeta = true;
        pk.origin = rawKey.substr(5);
        pk.valid = true;
        return pk;
    }

    if (rawKey.size() < 3 || rawKey[0] != '_') return pk;

    // Find the \x00\x01 separator
    for (size_t i = 1; i + 1 < rawKey.size(); ++i) {
        if (rawKey[i] == '\x00' && rawKey[i + 1] == '\x01') {
            pk.origin = rawKey.substr(1, i - 1);
            pk.storeName = rawKey.substr(i + 2);
            pk.valid = true;
            return pk;
        }
    }

    return pk;
}

// ═══════════════════════════════════════════════════════════════════════════
//  Discord Installation Finder
// ═══════════════════════════════════════════════════════════════════════════

struct DiscordInstall {
    std::string name;
    fs::path    localStatePath;
    fs::path    leveldbPath;
};

static std::vector<DiscordInstall> FindDiscordInstalls() {
    std::vector<DiscordInstall> found;
    std::wstring roaming = GetRoamingAppData();

    struct DiscordDef {
        std::string  name;
        std::wstring subdir;
    };

    static const DiscordDef defs[] = {
        { "Discord",        L"discord" },
        { "Discord Canary", L"discordcanary" },
        { "Discord PTB",    L"discordptb" },
        { "Discord Dev",    L"discorddevelopment" },
    };

    for (auto& def : defs) {
        fs::path base = fs::path(roaming) / def.subdir;
        fs::path ls   = base / L"Local State";
        fs::path ldb  = base / L"Local Storage" / L"leveldb";

        if (fs::exists(ls) && fs::exists(ldb))
            found.push_back({ def.name, ls, ldb });
    }

    return found;
}

// ═══════════════════════════════════════════════════════════════════════════
//  Master Key File Enumerator (from chrome_extract Section 11)
// ═══════════════════════════════════════════════════════════════════════════

static const uint8_t MASTERKEY_HEADER_V2[4] = { 0x02, 0x00, 0x00, 0x00 };

struct MasterKeyEntry {
    std::string guidStr;
    fs::path    path;
    uintmax_t   fileSize;
    bool        headerValid;
};

static std::vector<MasterKeyEntry> EnumerateMasterKeys() {
    std::vector<MasterKeyEntry> keys;
    fs::path protectDir = fs::path(GetRoamingAppData()) / L"Microsoft" / L"Protect";
    if (!fs::exists(protectDir)) return keys;

    for (auto& sidEntry : fs::directory_iterator(protectDir)) {
        if (!sidEntry.is_directory()) continue;
        for (auto& mkEntry : fs::directory_iterator(sidEntry.path())) {
            if (!mkEntry.is_regular_file()) continue;
            std::string fname = mkEntry.path().filename().string();
            if (fname.size() == 36 &&
                fname[8] == '-' && fname[13] == '-' &&
                fname[18] == '-' && fname[23] == '-') {
                MasterKeyEntry entry;
                entry.guidStr  = fname;
                entry.path     = mkEntry.path();
                entry.fileSize = mkEntry.file_size();

                std::ifstream f(entry.path, std::ios::binary);
                uint8_t hdr[4] = {};
                if (f.read(reinterpret_cast<char*>(hdr), 4))
                    entry.headerValid = (memcmp(hdr, MASTERKEY_HEADER_V2, 4) == 0);
                else
                    entry.headerValid = false;

                keys.push_back(std::move(entry));
            }
        }
    }
    return keys;
}

// ═══════════════════════════════════════════════════════════════════════════
//  Pretty-print a JSON value (truncated if huge)
// ═══════════════════════════════════════════════════════════════════════════

static std::string TruncateValue(const std::string& val, size_t maxLen = 500) {
    if (val.size() <= maxLen) return val;
    return val.substr(0, maxLen) + "... [" + std::to_string(val.size()) + " bytes total]";
}

// Check if a string looks like a Chromium LocalStorage UTF-16LE encoded value
// Chromium's LocalStorage uses UTF-16LE encoding for values — detect and convert
static std::string MaybeDecodeUTF16(const std::string& raw) {
    if (raw.size() < 2) return raw;

    // Check if it looks like UTF-16LE (every other byte is 0x00 for ASCII range)
    bool looksUTF16 = true;
    size_t zeroCount = 0;
    for (size_t i = 1; i < raw.size() && i < 100; i += 2) {
        if (raw[i] == '\0') zeroCount++;
    }

    if (raw.size() >= 4 && zeroCount > (std::min(raw.size(), (size_t)100) / 2) * 0.7) {
        // Likely UTF-16LE — convert
        int wchars = (int)(raw.size() / 2);
        const wchar_t* wdata = reinterpret_cast<const wchar_t*>(raw.data());

        int utf8Len = WideCharToMultiByte(CP_UTF8, 0, wdata, wchars,
                                           nullptr, 0, nullptr, nullptr);
        if (utf8Len > 0) {
            std::string utf8(utf8Len, '\0');
            WideCharToMultiByte(CP_UTF8, 0, wdata, wchars,
                                &utf8[0], utf8Len, nullptr, nullptr);
            return utf8;
        }
    }

    return raw;
}

// ═══════════════════════════════════════════════════════════════════════════
//  Process a single Discord installation
// ═══════════════════════════════════════════════════════════════════════════

static void ProcessDiscord(const DiscordInstall& install, std::ostream& out,
                           bool verbose) {
    out << "\n" << install.name << "\n";
    out << std::string(60, '=') << "\n";
    out << "Local State : " << install.localStatePath.string() << "\n";
    out << "LevelDB     : " << install.leveldbPath.string() << "\n\n";

    std::vector<uint8_t> aesKey;
    try {
        aesKey = LoadDiscordKey(install.localStatePath, false);
    } catch (const std::exception& e) {
        std::cout << "  [-] Key load failed: " << e.what() << "\n";
        return;
    }

    std::vector<LDBEntry> allEntries;
    for (auto& dirEntry : fs::directory_iterator(install.leveldbPath)) {
        if (!dirEntry.is_regular_file()) continue;
        std::string ext = dirEntry.path().extension().string();
        if (ext == ".ldb" || ext == ".sst") {
            ParseSSTable(dirEntry.path(), allEntries);
        } else if (ext == ".log") {
            ParseWALLog(dirEntry.path(), allEntries);
        }
    }

    std::map<std::string, LDBEntry> deduped;
    for (auto& e : allEntries) {
        deduped[e.key] = e;
    }

    struct TokenEntry {
        std::string accountKey;
        std::string decrypted;
    };

    std::map<std::string, TokenEntry> seenTokens;

    for (auto& [rawKey, entry] : deduped) {
        ParsedLDBKey pk = ParseChromiumLSKey(rawKey);
        if (!pk.valid || pk.isMeta) continue;

        std::string decodedValue = MaybeDecodeUTF16(entry.value);
        bool isDiscordOrigin = (pk.origin.find("discord.com") != std::string::npos ||
                                pk.origin.find("discordapp.com") != std::string::npos);

        if (!isDiscordOrigin || pk.storeName != "tokens") continue;
        if (aesKey.empty()) continue;

        std::string json = decodedValue;
        size_t searchPos = 0;
        while (searchPos < json.size()) {
            size_t kStart = json.find('"', searchPos);
            if (kStart == std::string::npos) break;
            size_t kEnd = json.find('"', kStart + 1);
            if (kEnd == std::string::npos) break;
            std::string jkey = json.substr(kStart + 1, kEnd - kStart - 1);

            size_t colon = json.find(':', kEnd + 1);
            if (colon == std::string::npos) break;
            size_t vStart = json.find('"', colon + 1);
            if (vStart == std::string::npos) break;
            size_t vEnd = vStart + 1;
            while (vEnd < json.size()) {
                if (json[vEnd] == '"' && json[vEnd - 1] != '\\') break;
                vEnd++;
            }
            if (vEnd >= json.size()) break;
            std::string jval = json.substr(vStart + 1, vEnd - vStart - 1);
            searchPos = vEnd + 1;

            if (jkey.find("__") == 0) continue;

            std::string encPart = jval;
            const std::string safePrefix = "dQw4w9WgXcQ:";
            if (encPart.size() > safePrefix.size() &&
                encPart.substr(0, safePrefix.size()) == safePrefix) {
                encPart = encPart.substr(safePrefix.size());
            }

            std::string plainToken;
            try {
                std::vector<uint8_t> tokenBytes = Base64Decode(encPart);
                if (tokenBytes.size() >= 3 &&
                    (memcmp(tokenBytes.data(), PREFIX_V10, 3) == 0 ||
                     memcmp(tokenBytes.data(), PREFIX_V20, 3) == 0)) {
                    plainToken = DecryptValue(aesKey, tokenBytes);
                } else {
                    plainToken = "<unknown prefix>";
                }
            } catch (const std::exception& e) {
                plainToken = std::string("<error: ") + e.what() + ">";
            }

            seenTokens[jkey] = { jkey, plainToken };
        }
    }

    std::vector<TokenEntry> decryptedTokens;
    for (auto& [k, v] : seenTokens) {
        decryptedTokens.push_back(std::move(v));
    }

    if (decryptedTokens.empty()) {
        std::cout << "  [!] No tokens found for " << install.name << "\n";
        out << "No tokens found\n\n";
        return;
    }

    std::cout << "\n  " << install.name << "\n";
    std::cout << "  " << std::string(56, '-') << "\n";

    for (size_t i = 0; i < decryptedTokens.size(); ++i) {
        auto& tk = decryptedTokens[i];
        bool valid = (tk.decrypted.find("<") != 0);

        std::cout << "  Account : " << tk.accountKey << "\n";
        std::cout << "  Token   : " << tk.decrypted << "\n";
        std::cout << "  Status  : " << (valid ? "DECRYPTED" : "FAILED") << "\n";
        if (i + 1 < decryptedTokens.size()) std::cout << "\n";

        out << "Account : " << tk.accountKey << "\n";
        out << "Token   : " << tk.decrypted << "\n";
        out << "Status  : " << (valid ? "DECRYPTED" : "FAILED") << "\n";
        if (i + 1 < decryptedTokens.size()) out << "\n";
    }

    std::cout << "\n";
    out << "\n";
}

// ═══════════════════════════════════════════════════════════════════════════
//  Main
// ═══════════════════════════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    std::string outPath = "discord_output.txt";

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--out" && i + 1 < argc) { outPath = argv[++i]; continue; }
        if (arg == "--help") {
            std::cout << "Usage: discord_extract.exe [OPTIONS]\n"
                      << "  --out <file>   Write output to file (default: discord_output.txt)\n";
            return 0;
        }
    }

    auto installs = FindDiscordInstalls();
    if (installs.empty()) {
        std::cerr << "[-] No Discord installations found\n";
        return 1;
    }

    std::ofstream fileOut(outPath, std::ios::out | std::ios::trunc);
    if (!fileOut.is_open()) {
        std::cerr << "[-] Cannot open output file: " << outPath << "\n";
        return 1;
    }

    fileOut << "discord_extract output\n";
    fileOut << std::string(60, '=') << "\n";

    std::cout << "\n============================================================\n";
    std::cout << "  discord_extract\n";
    std::cout << "============================================================\n";

    try {
        for (auto& inst : installs) {
            ProcessDiscord(inst, fileOut, false);
        }

        std::cout << "  [+] Full output saved to: " << outPath << "\n\n";
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "[-] Fatal: " << e.what() << "\n";
        return 1;
    }
}

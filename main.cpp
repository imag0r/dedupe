/* 
 * File:   main.cpp
 * Author: imagi
 *
 * Created on 24 październik 2014, 20:58
 */
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <map>
#include <set>
#include <string>
#include <sstream>
#include <tuple>
#include <vector>

#ifdef _WIN32
#include <Windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <openssl/evp.h>

#include <boost/system/system_error.hpp>
#include <boost/filesystem.hpp>

namespace bfs = boost::filesystem;
namespace bs = boost::system;

typedef std::vector<std::uint8_t> hash_t;

hash_t hash_file(const bfs::path& path)
{
    std::ifstream is(path.string(), std::ios::in | std::ios::binary);

    auto md = ::EVP_get_digestbyname("SHA256");
    auto ctx = EVP_MD_CTX();
    EVP_MD_CTX_init(&ctx);
    EVP_DigestInit_ex(&ctx, md, nullptr);
   
    static const size_t buffer_size = 65536;
    std::vector<char> buffer(buffer_size);

    while (is.read(buffer.data(), buffer.size()))
    {
        ::EVP_DigestUpdate(&ctx, buffer.data(), buffer.size());
    }

    if (is.eof())
    {
        ::EVP_DigestUpdate(&ctx, buffer.data(), static_cast<size_t>(is.gcount()));
    }
    
    std::vector<uint8_t> hash(EVP_MAX_MD_SIZE);
    
    unsigned len;
    ::EVP_DigestFinal_ex(&ctx, hash.data(), &len);
    ::EVP_MD_CTX_cleanup(&ctx);
    hash.resize(len);
    
    return hash;
}

// Workaround for warning C4503
struct path_by_hash
{
    std::map<hash_t, bfs::path> files;
};

typedef std::map<uint64_t, path_by_hash> filemap;

#ifdef _WIN32
typedef std::tuple<DWORD, DWORD, DWORD> file_id;
#else
typedef std::tuple<dev_t, ino_t> file_id;
#endif

struct file_info
{
    uint64_t size;
    file_id id;

#if _WIN32
    DWORD attributes;
#else
    mode_t mode;
#endif
};

file_info get_file_info(const bfs::path& path)
{
    file_info info = { 0 };
#if _WIN32
    auto handle = ::CreateFileW(path.wstring().c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (INVALID_HANDLE_VALUE == handle)
    {
        throw bs::system_error(::GetLastError(), bs::system_category());
    }

    BY_HANDLE_FILE_INFORMATION hfi = { 0 };
    auto ok = ::GetFileInformationByHandle(handle, &hfi);
    ::CloseHandle(handle);

    if (!ok)
    {
        throw bs::system_error(::GetLastError(), bs::system_category());
    }

    info.size = (static_cast<uint64_t>(hfi.nFileSizeHigh) << 32) | hfi.nFileSizeLow;
    info.id = std::make_tuple(hfi.dwVolumeSerialNumber, hfi.nFileIndexHigh, hfi.nFileIndexLow);
    info.attributes = hfi.dwFileAttributes;
#else
    struct stat64 st = {0};
    int err = stat64(path.c_str(), &st);
    if (err)
    {
        throw bs::system_error(err, bs::system_category());
    }
    info.size = st.st_size;
    info.id = std::make_tuple(st.st_dev, st.st_ino);
    info.mode = st.st_mode;
#endif
    return info;
}

bool is_regular_file(const file_info& info)
{
#ifdef _WIN32
    static const unsigned long irregular_mask = FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE;
    return 0 == (info.attributes & irregular_mask);
#else
    return S_ISREG(info.mode);
#endif
}

void restore_attributes(const bfs::path& path, const file_info& info)
{
#if _WIN32
    if (!::SetFileAttributesW(path.wstring().c_str(), info.attributes))
    {
        throw bs::system_error(::GetLastError(), bs::system_category());
    }
#else
#endif
}

struct nodes
{
    filemap filemap;
    std::set<file_id> file_ids;
};

void process_directory(const bfs::path& directory, nodes& nodes)
{
    uint64_t saved = 0;

    for (bfs::recursive_directory_iterator it(directory), end; it != end; ++it)
    {
        const bfs::path path = it->path();

        const auto info = get_file_info(path);
        if (!is_regular_file(info) || (info.size == 0))
        {
            continue;
        }

        if (!nodes.file_ids.insert(info.id).second)   // we have 1st instance indexed already = it's hardlinked
        {
            continue;
        }

        static const hash_t empty_hash;

        auto& results_for_size = nodes.filemap[info.size];
        if (results_for_size.files.empty())
        {
            results_for_size.files[empty_hash] = path;
        }
        else
        {
            auto prev_instance = results_for_size.files.find(empty_hash);
            if (prev_instance != results_for_size.files.end())
            {
                // hash the old file
                const auto& prevpath = prev_instance->second;
                results_for_size.files[hash_file(prevpath)] = prevpath;
                results_for_size.files.erase(prev_instance);
            }

            // hash the new file
            const auto new_hash = hash_file(path);

            prev_instance = results_for_size.files.find(new_hash);
            if (prev_instance != results_for_size.files.end())
            {
                std::cout << "Hardlinking " << path << " to " << prev_instance->second << std::endl;
                
                auto backup_path = bfs::path(path.string() + ".dedupe_backup");
                bfs::rename(path, backup_path);

                bs::error_code error;
                bfs::create_hard_link(prev_instance->second, path, error);
                if (error)
                {
                    bfs::rename(backup_path, path);
                    if (error == bs::errc::too_many_links)
                    {
                        results_for_size.files[new_hash] = path;
                        nodes.file_ids.insert(get_file_info(path).id);
                    }
                    else
                    {
                        throw bs::system_error(error);
                    }
                }
                else
                {
                    bfs::remove(backup_path);
                }
                saved += info.size;
            }
            else
            {
                results_for_size.files[new_hash] = path;
            }
        }
    }

    std::cout << "Saved " << saved / (1024 * 1024) << " MB." << std::endl;
}

int main(int argc, char** argv)
{
    OpenSSL_add_all_digests();
    
    const std::string dir = argv[1];
    nodes nodes;
    process_directory(dir, nodes);
    return 0;
}


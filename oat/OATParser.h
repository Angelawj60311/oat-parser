#pragma once

#include <string>
#include <map>
#include <memory>
#include <list>
#include <bits/unique_ptr.h>
#include "../art/compiler_filter.h"

namespace Art {
    class DexHeader;

    class OATHeader;

    class OATParser {
    public:
        OATParser() { };

        OATParser(const char *a_oat, unsigned int a_size);

        ~OATParser();

        static OATParser &GetInstance();

        void init(const char *a_oat_file, const char *a_out_dex_path);

        const char *Begin();

        const char *End();

        bool Parser();

        bool ParserOatToGetSignature(const char *oat_file, std::string *signature, CompilerFilter::Filter *filter, int *dex_count);

        bool ParserMultiOats();

        const char* GetStoreValueByKey(const char *key_string, const char* key, const int size);

        const char* GetCompilerFilter(const char *key_string, int key_string_size);

        void SetToGenerateSignature(bool is_signature_generated) {
            m_is_signature_generated = is_signature_generated;
        }

        void SetToGenerateSecurestore(bool is_securestore_generated) {
            m_is_securestore_generated = is_securestore_generated;
        }

        void SetToDoIV(bool is_do_IV) {
            m_is_do_IV = is_do_IV;
        }

        bool isGenerateSignature() {
            return m_is_signature_generated;
        }

        bool isGenerateSecurestore() {
            return m_is_securestore_generated;
        }

        bool isDoIV() {
            return m_is_do_IV;
        }

        bool ParseSecureStore(const char *securestore_file, int dex_count);

        bool DoIV(const std::string signature, CompilerFilter::Filter filter);

	bool ParseOatFile(const std::string read_file);

	bool TamperChecksum(const std::string tamper_file);

    private:
        bool OpenOat(std::unique_ptr<char[]> &a_buf, unsigned int &a_len);

        bool OatReSet(std::unique_ptr<char[]> &a_buf);

        bool Dump(int index, const DexHeader *a_dex_header);

        bool DumpSignature(FILE *f, const uint32_t signature);

        const OATHeader *GetOatHeader() {
            return m_oatheader.get();
        };

        void MakeDexName(int index, std::string &a_out_dex_name);

    private:
        static OATParser m_oat_parser;

        std::unique_ptr<OATHeader> m_oatheader;
        std::string m_oat_file;
        std::string m_out_dex_path;

        const char *m_oat_begin;
        const char *m_oat_end;

        bool m_is_signature_generated;
        bool m_is_securestore_generated;
        bool m_is_do_IV;

        std::map<CompilerFilter::Filter, std::string> secure_store_map_;

	std::list<uint32_t> dex_file_checksums_;
    };
}

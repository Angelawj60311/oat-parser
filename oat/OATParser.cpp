// OATParser.cpp : Defines the exported functions for the DLL application.
//

#include <stdio.h>
#include <iostream>
#include <sstream>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "OATParser.h"
#include "DexHeader.h"
#include "OATHeader.h"
#include "elfloader.h"
#include "../zlib/zlib.h"

namespace Art {
    OATParser OATParser::m_oat_parser;

    OATParser::OATParser(const char *a_oat, unsigned int a_size) : m_oat_begin(a_oat) {
        m_oat_end = a_oat + a_size;
    }

    OATParser::~OATParser() {
    }

    OATParser &OATParser::GetInstance() {
        return m_oat_parser;
    }

    void OATParser::init(const char *a_oat_file, const char *a_out_dex_path) {
        m_oat_file = a_oat_file;
        m_out_dex_path = a_out_dex_path;
    }

    const char *OATParser::Begin() {
        return m_oat_begin;
    }

    const char *OATParser::End() {
        return m_oat_end;
    }

    bool OATParser::OpenOat(std::unique_ptr<char[]> &a_buf, unsigned int &a_len) {
        bool ret = false;

        FILE *f = fopen(m_oat_file.c_str(), "rb+");
        if (NULL == f) {
            return ret;
        }

        fseek(f, 0, SEEK_END);
        a_len = ftell(f);

        fseek(f, 0, SEEK_SET);
        a_buf.reset(new char[a_len]);

        fread(a_buf.get(), sizeof(char), a_len, f);
        ret = true;
        fclose(f);

        return ret;
    }

    bool OATParser::OatReSet(std::unique_ptr<char[]> &a_buf) {
        unsigned int offset = 0;
        unsigned int len = 0;

        bool ret = GetOatInfo(offset, len);

        m_oat_begin = a_buf.get() + offset;
        m_oat_end = a_buf.get() + offset + len;
	std::cout << "OatReSet rodata: " << offset << std::endl;

        m_oatheader.reset(new OATHeader());
        memcpy(m_oatheader.get(), m_oat_begin, sizeof(OATHeader));

        return ret;
    }

    // Advance start until it is either end or \0.
    static const char* ParseString(const char* start, const char* end) {
       while (start < end && *start != 0) {
              start++;
       }
            return start;
    }

    const char* OATParser::GetStoreValueByKey(const char *key_string, const char* key, const int size) {
            const char* ptr = key_string;
            const char* end = ptr + size;

            while (ptr < end) {
            // Scan for a closing zero.
            const char* str_end = ParseString(ptr, end);
	    //printf("GetStoreValueByKey size: %d, ptr: %s, str_end:%s\n", key_value_store_size_, ptr, str_end);
            if (str_end < end) {
              if (strcmp(key, ptr) == 0) {
                // Same as key. Check if value is OK.
                if (ParseString(str_end + 1, end) < end) {
                  return str_end + 1;
                }
              } else {
                // Different from key. Advance over the value.
                ptr = ParseString(str_end + 1, end) + 1;
              }
            } else {
              break;
            }
          }
          // Not found.
          return nullptr;
       }

    const char* OATParser::GetCompilerFilter(const char *key_string, int key_string_size) {
        const char* kCompilerFilter = "compiler-filter";
        const char* key_value = GetStoreValueByKey(key_string, kCompilerFilter, key_string_size);
        return key_value;
    }

    bool OATParser::ParseSecureStore(const char *securestore_file, int dex_count) {

        FILE *securestore_f = fopen(securestore_file, "rb+");
        if (NULL == securestore_f) {
            printf("Failed: Cannot open securestore file\n");
            return false;
        }

        std::unique_ptr<char[]> a_buf;
        unsigned int a_len = 0;

        fseek(securestore_f, 0, SEEK_END);
        a_len = ftell(securestore_f);

        fseek(securestore_f, 0, SEEK_SET);
        a_buf.reset(new char[a_len]);

        fread(a_buf.get(), sizeof(char), a_len, securestore_f);

        //Analyze buffer and put into a map
	int dexes_signature_len = dex_count * sizeof(uint32_t);
        char *buf = a_buf.get();

	//Plus non.oat without compilter-filter specified 
        for (size_t i = 0; i < CompilerFilter::kEverything + 2; i++) {
             CompilerFilter::Filter filter = (CompilerFilter::Filter)*buf;
	     buf = buf + sizeof(char);
	     
	     std::string dexes_sig;
	     //little endian. file: 67 3a f1 9a, have to change to 9a f1 3a 67 
	     for (size_t j = 0; j < dex_count; ++j) {
		size_t k = j * sizeof(uint32_t);
		size_t m = sizeof(uint32_t) -1;
		uint32_t sig = (uint8_t)buf[k+m] << 24 | (uint8_t)buf[k+m-1] << 16 |
			(uint8_t)buf[k+m-2] << 8 | (uint8_t)buf[k+m-3];	
		//printf("buf3: %x, buf2:%x, buf1:%x, buf0:%x\n", buf[k+m], buf[k+m-1], buf[k+m-2], buf[k+m-3]);
		std::string result;
	     	std::stringstream ss;
		ss << std::hex << sig;
    		ss >> result;
		//std::cout << "result: " << result << std::endl;
	 	dexes_sig += result;	
	     }
	     
             buf = buf + dexes_signature_len;

             secure_store_map_.insert(std::pair<CompilerFilter::Filter, std::string>(filter, dexes_sig));
             std::cout << "Filter: " << filter << "   dexes_signature: " << dexes_sig << std::endl;
        }

        fclose(securestore_f);
            
    }

    bool OATParser::DoIV(std::string signature, CompilerFilter::Filter filter) {

        std::map<CompilerFilter::Filter, std::string>::iterator it = secure_store_map_.find(filter);
        if (it != secure_store_map_.end()) {
           std::string signature_map =  it->second;
           if (signature_map.compare(signature) != 0) {
                std::cout << "Faied to IV. " << "map: "<< signature_map << "input: " << signature << std::endl;
                return false;
            }
        } else {
            std::cout << "Cannot find signature in the map. Filter: " << filter << std::endl;
            return false;
        }
	std::cout << "Verified successfully!" << std::endl; 
        return true;
    }

    bool OATParser::ParserMultiOats() {
        DIR *dp;
        struct dirent *dirp;
        struct stat filestat;

        //Open *.securestore into dedicated dir
        FILE *sec_f = nullptr;
       
        std::string secFile = m_out_dex_path + "oat.securestore";
        sec_f = fopen(secFile.c_str(), "wb+");
        if (NULL == sec_f) { 
            printf("Failed: Cannot open securestore\n");
            return false;
        }

        //--oat-file is a dir of oat files in securestore mode.
        dp = opendir(m_oat_file.c_str());
        if (dp == NULL)
        {
            std::cout << "Error(" << errno << ") opening " << m_oat_file << std::endl;
            return errno;
        }

        while (dirp = readdir(dp))
        {
            std::string filepath = m_oat_file + dirp->d_name;
            std::cout << "Oat file: " << filepath << std::endl;

            // If the file is a directory (or is in some way invalid) we'll skip it 
            if (stat( filepath.c_str(), &filestat )) continue;
            if (S_ISDIR( filestat.st_mode ))         continue;

            FILE *f = fopen(filepath.c_str(), "rb+");
            if (NULL == f) {
                return false;
            }
 
            fseek(f, 0, SEEK_END);
            unsigned int oat_len = ftell(f);

            fseek(f, 0, SEEK_SET);
            std::unique_ptr<char[]> buf;
            buf.reset(new char[oat_len]);

            fread(buf.get(), sizeof(char), oat_len, f);
            fclose(f);

            if (!ElfInit(buf.get(), oat_len)) {
                return false;
            }

            if (!OatReSet(buf)) {
                return false;
            }

            const char *oat = Begin();

            oat += sizeof(OATHeader);
            if (oat > End()) {
                return false;
            }
            //Read info from OATHeader
            InstructionSet iset = GetOatHeader()->GetInstructionSet();
            std::cout << "Oat instruction set: " << iset << std::endl;

            uint32_t hs = GetOatHeader()->GetKeyValueStoreSize();

            const char *compilerFilter = GetCompilerFilter(oat, hs);
            std::cout << "Oat compilter filter: " << compilerFilter << std::endl;

            //Write compiler-filter option first, 1B to securestore file
            CompilerFilter::Filter filter;
            bool isOK = CompilerFilter::ParseCompilerFilter(compilerFilter, &filter);
            if (!isOK) return false;
            size_t size = fwrite(&filter, sizeof(char), 1, sec_f);
            printf("Write signature size: %d, compilter-filter: %d\n", size, filter);
            if (size != sizeof(char)) {
                fclose(sec_f);
                return false;
            }

            oat += hs;

            if (oat > End()) {
                return false;
            }

            uint32_t dex_file_count = GetOatHeader()->GetDexFileCount();
            for (size_t i = 0; i < dex_file_count; i++) {
                uint32_t dex_file_location_size = *reinterpret_cast<const uint32_t *>(oat);
                if (dex_file_location_size == 0U) {
                    return false;
                } 
                oat += sizeof(dex_file_location_size);
                if (oat > End()) {
                    return false;
                }
                const char *dex_file_location_data = reinterpret_cast<const char *>(oat);
                oat += dex_file_location_size;
                if (oat > End()) {
                    return false;
                }

                std::string dex_file_location(dex_file_location_data, dex_file_location_size);
                uint32_t dex_file_checksum = *reinterpret_cast<const uint32_t *>(oat);
                printf("Parser: CRC32 dex_file_checksum: %x\n", dex_file_checksum);
                oat += sizeof(dex_file_checksum);
                if (oat > End()) {
                    return false;
                }

                uint32_t dex_file_offset = *reinterpret_cast<const uint32_t *>(oat);
                oat += sizeof(dex_file_offset);

                const char *dex_file_pointer = Begin() + dex_file_offset;
                const DexHeader *header = reinterpret_cast<const DexHeader *>(dex_file_pointer);

                printf("Parser: dex_file_location: %s, locationsize: %d\n", dex_file_location.c_str(), dex_file_location_size);

                uint32_t file_expectedchecksum =  header->checksum_;

                uint32_t adler = adler32(0L, 0, 0);
                //Actual checksum of optimized dex in oat file
                adler = adler32(adler, ((const uint8_t *)header + 12), header->file_size_ - 12);
                printf("Parser: expected_checksum: %08x, compute adler32: %08lx\n", file_expectedchecksum, adler);

                if (!DumpSignature(sec_f, (uint32_t)adler)) {
                    return false;
                }

                uint32_t class_offsets_offset = *reinterpret_cast<const uint32_t *>(oat);
                oat += sizeof(class_offsets_offset);
                uint32_t lookup_table_offset = *reinterpret_cast<const uint32_t *>(oat);
                oat += sizeof(lookup_table_offset);

            }
        }

        fclose(sec_f);
        closedir( dp );

        return true;
    }

    bool OATParser::ParserOatToGetSignature(const char *oat_file, std::string *signature, 
                                                            CompilerFilter::Filter *filter, int *dex_count) {
        std::unique_ptr<char[]> buf;
        unsigned int oat_len = 0;

	m_oat_file = oat_file;

        if (!OpenOat(buf, oat_len)) {
            return false;
        }

        if (!ElfInit(buf.get(), oat_len)) {
            return false;
        }

         if (!OatReSet(buf)) {
            return false;
        }

        const char *oat = Begin();

        oat += sizeof(OATHeader);
        if (oat > End()) {
            return false;
        }

        InstructionSet iset = GetOatHeader()->GetInstructionSet();
        std::cout << "Oat instruction set: " << iset << std::endl;

        uint32_t hs = GetOatHeader()->GetKeyValueStoreSize();

        const char *compilerFilter = GetCompilerFilter(oat, hs);
        std::cout << "Oat compilter filter: " << compilerFilter << std::endl;

        CompilerFilter::Filter fil;
        bool isOK = CompilerFilter::ParseCompilerFilter(compilerFilter, &fil);
        if (!isOK) return false;
        *filter = fil;

	oat += hs;
	if (oat > End()) {
            return false;
	}	

        uint32_t dex_file_count = GetOatHeader()->GetDexFileCount();
        *dex_count = dex_file_count;
        std::string signature_string;

        for (size_t i = 0; i < dex_file_count; i++) {
             uint32_t dex_file_location_size = *reinterpret_cast<const uint32_t *>(oat);

            if (dex_file_location_size == 0U) {
                return false;
            }

            oat += sizeof(dex_file_location_size);
            if (oat > End()) {
                return false;
            }

            const char *dex_file_location_data = reinterpret_cast<const char *>(oat);
            oat += dex_file_location_size;
            if (oat > End()) {
                return false;
            }

            std::string dex_file_location(dex_file_location_data, dex_file_location_size);

            uint32_t dex_file_checksum = *reinterpret_cast<const uint32_t *>(oat);
            printf("Parser: CRC32 dex_file_checksum: %x\n", dex_file_checksum);
            oat += sizeof(dex_file_checksum);
            if (oat > End()) {
                return false;
            }

            uint32_t dex_file_offset = *reinterpret_cast<const uint32_t *>(oat);
            oat += sizeof(dex_file_offset);

            const char *dex_file_pointer = Begin() + dex_file_offset;
            const DexHeader *header = reinterpret_cast<const DexHeader *>(dex_file_pointer);

            printf("Parser: dex_file_location: %s, locationsize: %d\n", dex_file_location.c_str(), dex_file_location_size);

            uint32_t file_expectedchecksum =  header->checksum_;

            uint32_t adler = adler32(0L, 0, 0);
            //Actual checksum of optimized dex in oat file
            adler = adler32(adler, ((const uint8_t *)header + 12), header->file_size_ - 12);


	    std::string result;
    	    std::stringstream ss;
            ss << std::hex << adler;
            ss >> result;

            signature_string += result;
            printf("Parser: expected_checksum: %08x, compute adler32: %08lx\n", file_expectedchecksum, adler);

	    uint32_t class_offsets_offset = *reinterpret_cast<const uint32_t *>(oat);
            oat += sizeof(class_offsets_offset);
	    uint32_t lookup_table_offset = *reinterpret_cast<const uint32_t *>(oat);
	    oat += sizeof(lookup_table_offset);
        }

        *signature = signature_string;
        std::cout << "ParserOatToGenerateSignature: " << *signature << std::endl;
        
        return true;
    }

    bool OATParser::Parser() {
        std::unique_ptr<char[]> buf;
        unsigned int oat_len = 0;

        //In securestore mode
        if (isGenerateSecurestore()) {
            ParserMultiOats();
            return true;
        }

        // 打开oat文件
        if (!OpenOat(buf, oat_len)) {
            return false;
        }

        // 调用elf模块获取rodata区的起始点
        if (!ElfInit(buf.get(), oat_len)) {
            return false;
        }

        if (!OatReSet(buf)) {
            return false;
        }

        // 文件头是从oat的文件头，是从rodata处开始
        const char *oat = Begin();

        // OatHeader的头为0x54, sumsung的头是0x60
        oat += sizeof(OATHeader);
        if (oat > End()) {
            return false;
        }

	InstructionSet iset = GetOatHeader()->GetInstructionSet();
	std::cout << "Oat instruction set: " << iset << std::endl;

        // 跳过一些key-value的存储值
        uint32_t hs = GetOatHeader()->GetKeyValueStoreSize();

        const char *compilerFilter = GetCompilerFilter(oat, hs);
        std::cout << "Oat compilter filter: " << compilerFilter << std::endl;

        oat += hs;

        if (oat > End()) {
            return false;
        }

        //Open *.signature into dedicated dir
        FILE *f = nullptr;
        if (isGenerateSignature()) {
            std::string sigFile = m_out_dex_path + "dex.signature";
            f = fopen(sigFile.c_str(), "wb+");
            if (NULL != f) {
                //Write compiler-filter option first, 1B
                CompilerFilter::Filter filter;
                bool isOK = CompilerFilter::ParseCompilerFilter(compilerFilter, &filter);
                if (!isOK) return false;
                size_t size = fwrite(&filter, sizeof(char), 1, f);
                printf("Write signature size: %d, compilter-filter: %c\n", size, filter);
                if (size != sizeof(char)) {
                    fclose(f);
                    return false;
                }
            } else {
                printf("Failed: Cannot open signature\n");
                return false;
            }
        }

        // 在头部偏移0x14，获取dex的个数
        uint32_t dex_file_count = GetOatHeader()->GetDexFileCount();
        for (size_t i = 0; i < dex_file_count; i++) {
            // 获取具体的jar包或者dex的名字的长度， 例如21 00 00 00
            uint32_t dex_file_location_size = *reinterpret_cast<const uint32_t *>(oat);

            if (dex_file_location_size == 0U) {
                return false;
            }

            // 跳到具体的jar包或者dex的字符串处，例如/system/framework/core-libart.jar
            oat += sizeof(dex_file_location_size);
            if (oat > End()) {
                return false;
            }

            // 获取具体的jar包或者dex的文件名
            const char *dex_file_location_data = reinterpret_cast<const char *>(oat);
            oat += dex_file_location_size;
            if (oat > End()) {
                return false;
            }

            // 根据长度和字符串赋值给string类型字符串
            std::string dex_file_location(dex_file_location_data, dex_file_location_size);

            // 跳过文件校验
            uint32_t dex_file_checksum = *reinterpret_cast<const uint32_t *>(oat);
	    printf("Parser: CRC32 dex_file_checksum: %x\n", dex_file_checksum);
            oat += sizeof(dex_file_checksum);
            if (oat > End()) {
                return false;
            }

            // 获取具体dex或者jar包的偏移量（偏移量是相对rodata）  例如 04 DA 00 00
            uint32_t dex_file_offset = *reinterpret_cast<const uint32_t *>(oat);
            oat += sizeof(dex_file_offset);

            const char *dex_file_pointer = Begin() + dex_file_offset;
            const DexHeader *header = reinterpret_cast<const DexHeader *>(dex_file_pointer);

	    printf("Parser: dex_file_location: %s, locationsize: %d\n", dex_file_location.c_str(), dex_file_location_size);

	    uint32_t file_expectedchecksum =  header->checksum_;

	    uLong adler = adler32(0L, 0, 0);
            //Actual checksum of optimized dex in oat file
	    adler = adler32(adler, ((const uint8_t *)header + 12), header->file_size_ - 12);
	    printf("Parser: expected_checksum: %08x, compute adler32: %08lx\n", file_expectedchecksum, adler);

            if (isGenerateSignature()) {
            //Write signature into *.signature
                if (!DumpSignature(f, (uint32_t)adler)) {
                    return false;
                }
            } else {
                if (!Dump(i, header)) {
                    return false;
                }
            }

	    uint32_t class_offsets_offset = *reinterpret_cast<const uint32_t *>(oat);
            oat += sizeof(class_offsets_offset);
	    uint32_t lookup_table_offset = *reinterpret_cast<const uint32_t *>(oat);
	    oat += sizeof(lookup_table_offset);
        }

        if (isGenerateSignature()) {
            fclose(f);
        }

        return true;
    }

    //Get checksum from oatdexfile
    bool OATParser::ParseOatFile(const std::string read_file) {
        m_oat_file = read_file;

         std::unique_ptr<char[]> buf;
        unsigned int oat_len = 0;
        
        if (!OpenOat(buf, oat_len)) {
            return false;
        }
 
        if (!ElfInit(buf.get(), oat_len)) {
            return false;
        }

        if (!OatReSet(buf)) {
            return false;
        }

        const char *oat = Begin();

        oat += sizeof(OATHeader);
        if (oat > End()) {
            return false;
        }

        InstructionSet iset = GetOatHeader()->GetInstructionSet();
        std::cout << "Oat instruction set: " << iset << std::endl;

        // 跳过一些key-value的存储值
        uint32_t hs = GetOatHeader()->GetKeyValueStoreSize();

        const char *compilerFilter = GetCompilerFilter(oat, hs);
        std::cout << "Oat compilter filter: " << compilerFilter << std::endl;

        oat += hs;

        if (oat > End()) {
            return false;
        }

        uint32_t dex_file_count = GetOatHeader()->GetDexFileCount();
        for (size_t i = 0; i < dex_file_count; i++) {
            uint32_t dex_file_location_size = *reinterpret_cast<const uint32_t *>(oat);
            if (dex_file_location_size == 0U) {
                return false;
            }
            oat += sizeof(dex_file_location_size);
            if (oat > End()) {
                return false;
            }
            const char *dex_file_location_data = reinterpret_cast<const char *>(oat);
            oat += dex_file_location_size;
            if (oat > End()) {
                return false;
            }
            std::string dex_file_location(dex_file_location_data, dex_file_location_size);

            uint32_t dex_file_checksum = *reinterpret_cast<const uint32_t *>(oat);
            printf("Parser: CRC32 dex_file_checksum: %x\n", dex_file_checksum);
            oat += sizeof(dex_file_checksum);
            if (oat > End()) {
                return false;
            }

            //List to store dex_file_checksum, crc32
            dex_file_checksums_.push_back(dex_file_checksum);

            uint32_t dex_file_offset = *reinterpret_cast<const uint32_t *>(oat);
            oat += sizeof(dex_file_offset);

            printf("Parser: dex_file_location: %s, locationsize: %d\n", dex_file_location.c_str(), dex_file_location_size);

            uint32_t class_offsets_offset = *reinterpret_cast<const uint32_t *>(oat);
            oat += sizeof(class_offsets_offset);
            uint32_t lookup_table_offset = *reinterpret_cast<const uint32_t *>(oat);
            oat += sizeof(lookup_table_offset);
        }

	return true;
        
    }

    bool OATParser::TamperChecksum(const std::string tamper_file) {

        std::unique_ptr<char[]> buf;
        unsigned int oat_len = 0;
        
        FILE *f = fopen(tamper_file.c_str(), "rb+");
        if (NULL == f) {
            return false;
        }

        fseek(f, 0, SEEK_END);
        oat_len = ftell(f);

        fseek(f, 0, SEEK_SET);
        buf.reset(new char[oat_len]);

        fread(buf.get(), sizeof(char), oat_len, f);
 
        if (!ElfInit(buf.get(), oat_len)) {
            return false;
        }

        if (!OatReSet(buf)) {
            return false;
        }

        const char *oat = Begin();
        uint32_t rodata_offset = oat - buf.get();

        oat += sizeof(OATHeader);
        if (oat > End()) {
            return false;
        }

        InstructionSet iset = GetOatHeader()->GetInstructionSet();
        std::cout << "Tampered oat instruction set: " << iset << std::endl;

        uint32_t hs = GetOatHeader()->GetKeyValueStoreSize();

        const char *compilerFilter = GetCompilerFilter(oat, hs);
        std::cout << "Tampered oat compilter filter: " << compilerFilter << std::endl;

        oat += hs;

        if (oat > End()) {
            return false;
        }

        uint32_t dex_file_count = GetOatHeader()->GetDexFileCount();
        for (size_t i = 0; i < dex_file_count; i++) {
            uint32_t dex_file_location_size = *reinterpret_cast<const uint32_t *>(oat);
            if (dex_file_location_size == 0U) {
                return false;
            }
            oat += sizeof(dex_file_location_size);
            if (oat > End()) {
                return false;
            }
            const char *dex_file_location_data = reinterpret_cast<const char *>(oat);
            oat += dex_file_location_size;
            if (oat > End()) {
                return false;
            }
            std::string dex_file_location(dex_file_location_data, dex_file_location_size);

            uint32_t dex_file_checksum = *reinterpret_cast<const uint32_t *>(oat);
            printf("Tampered oat: CRC32 dex_file_checksum: %x\n", dex_file_checksum);

            //Tamper dex_file_checksum
            uint32_t checksum_offset = oat -Begin() + rodata_offset;

            oat += sizeof(dex_file_checksum);
            if (oat > End()) {
                return false;
            }

            uint32_t ori_dex_file_checksum = dex_file_checksums_.front();
	    dex_file_checksums_.pop_front();
            printf("Tampered oat:  checksum_offset: %x, original checksum from list: %x\n", checksum_offset, ori_dex_file_checksum);
            if (fseek(f, checksum_offset, SEEK_SET) != 0) return false;
            size_t size = fwrite(&ori_dex_file_checksum, sizeof(uint32_t), 1, f);
	    std::cout << "Fwrite tamper oat: " << size << std::endl;
            if (size != 1)
                return false;
	   fflush(f);
/*
	   fseek(f, checksum_offset, SEEK_SET);
	   char tmp[4];
	   fread(tmp, 1, 4, f); 
	   printf("Re-read: %x %x %x %x\n", tmp[0],tmp[1], tmp[2], tmp[3]);
*/

            uint32_t dex_file_offset = *reinterpret_cast<const uint32_t *>(oat);
            oat += sizeof(dex_file_offset);

            printf("Tampered oat: dex_file_location: %s, locationsize: %d\n", dex_file_location.c_str(), dex_file_location_size);

            uint32_t class_offsets_offset = *reinterpret_cast<const uint32_t *>(oat);
            oat += sizeof(class_offsets_offset);
            uint32_t lookup_table_offset = *reinterpret_cast<const uint32_t *>(oat);
            oat += sizeof(lookup_table_offset);
        }
        fclose(f);
        return true;
    }

    void OATParser::MakeDexName(int index, std::string &a_out_dex_name) {
        //size_t pos = a_dex_name.find_last_of('.');
        a_out_dex_name = m_out_dex_path + "classes";
	if (index > 0) 
            a_out_dex_name = a_out_dex_name + std::to_string(index+1) + ".dex";
	else
            a_out_dex_name = a_out_dex_name + ".dex";	
    }

    bool OATParser::DumpSignature(FILE *f, const uint32_t signature) {

        if (NULL != f) {
            size_t size = fwrite(&signature, sizeof(int), 1, f);
            printf("DumpSignature fwrite size: %d\n", size * sizeof(int));
            if (size*sizeof(int) == sizeof(int)) return true;
            else return false;
        } else
            return false;
    }

    bool OATParser::Dump(int index, const DexHeader *a_dex_header) {
        bool ret = false;

        FILE *f = nullptr;
        std::string out_dex_name;
        MakeDexName(index, out_dex_name);

	printf("Dump: out_dex_name: %s, size: %d\n", out_dex_name.c_str(), a_dex_header->file_size_);
        f = fopen(out_dex_name.c_str(), "wb");
        if (NULL != f) {
            size_t size = fwrite(a_dex_header, sizeof(char), a_dex_header->file_size_, f);
	    printf("Fwrite size: %ld\n", size);
            fclose(f);

            ret = true;
        }
        else {
            printf("Dump error\n");
        }

        return ret;
    }
}

// 初始化， oat_file为原始的oat文件名 out_dex_path为输出的dex路径
extern "C" bool InitOatParser(const char *oat_file, const char *out_dex_path) {
    Art::OATParser::GetInstance().init(oat_file, out_dex_path);
    return true;
}

// 将Ota文件dump成dex文件
extern "C" bool DoDumpToDex() {
    return Art::OATParser::GetInstance().Parser();
}

extern "C" void SetToGenerateSignature(bool is_signature_generated) {
    return Art::OATParser::GetInstance().SetToGenerateSignature(is_signature_generated);
}

extern "C" void SetToGenerateSecurestore(bool is_securestore_generated) {
    return Art::OATParser::GetInstance().SetToGenerateSecurestore(is_securestore_generated);
}

extern "C" bool GenerateSignature(const char *oat_file, std::string *signature, 
                                                Art::CompilerFilter::Filter *filter, int *dex_count) {
    bool ret = Art::OATParser::GetInstance().ParserOatToGetSignature(oat_file, signature, filter, dex_count);
    return ret;
}

extern "C" void SetToDoIV(bool is_do_IV) {
    return Art::OATParser::GetInstance().SetToDoIV(is_do_IV);
}

extern "C" bool ParseSecureStore(const char *securestore_file, int dex_count) {
    return Art::OATParser::GetInstance().ParseSecureStore(securestore_file, dex_count);
}

extern "C" bool DoIV(std::string signature, Art::CompilerFilter::Filter filter) {
    return Art::OATParser::GetInstance().DoIV(signature, filter);
}

extern "C" bool ParseOatFile(const std::string read_file) {
    return Art::OATParser::GetInstance().ParseOatFile(read_file);
}

extern "C" bool TamperChecksum(const std::string tamper_file) {
    return Art::OATParser::GetInstance().TamperChecksum(tamper_file);
}


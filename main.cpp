// OATLoaderDumper.cpp : Defines the entry point for the console application.
//

#include "StringPiece.h"
#include "oatparser.h"
#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>
#include <iostream>

static void usage() {
    fprintf(stderr,
            "Usage: oatparser [options] ...\n"
                    "    Example: oatparser --read-file=base.odex --tamper-file=tamper.oat\n"
                    "\n");
}

static bool IsDirExist(const std::string &outpath) {
    bool ret = true;

    if (-1 == access(outpath.c_str(), F_OK) && errno == ENOENT) {
        ret = false;
    }

    return ret;
}

static bool MakeDir(const std::string &outpath) {
    bool ret = false;
    if (0 == mkdir(outpath.c_str(), 0400 | 0200)) {
        ret = true;
    }

    return ret;
}

int main(int argc, char *argv[]) {
    argv++;
    argc--;

    if (argc == 0) {
        fprintf(stderr, "No arguments specified.\n");
        usage();
        return false;
    }

    using namespace Art;
    std::string oat_file; //--oat-file=
    std::string oat_todex_path; //--out-path=
    std::string securestore_file; //--secure-file=
    bool isVerification = false;
    std::string read_file;
    std::string tamper_file;
    for (int i = 0; i < argc; i++) {
        const StringPiece option(argv[i]);
        if (option.starts_with("--oat-file=")) {
            oat_file = option.substr(strlen("--oat-file=")).data();
        }
        else if (option.starts_with("--out-path=")) {
            oat_todex_path = option.substr(strlen("--out-path=")).data();
        }
        else if (option.starts_with("--secure-file=")) {
            securestore_file = option.substr(strlen("--secure-file=")).data();
        }
        //Generate signature on device
        else if (option.starts_with("--signature")) {
            SetToGenerateSignature(true);
        }
        //Generate securestore on host
        else if (option.starts_with("--securestore")) {
            SetToGenerateSecurestore(true);
        }
        //Do IV
        else if (option.starts_with("--verification")) {
            SetToDoIV(true);
            isVerification = true;
        }
        else if (option.starts_with("--read-file")) {
            read_file = option.substr(strlen("--read-file=")).data();
        }
        else if (option.starts_with("--tamper-file")) {
            tamper_file = option.substr(strlen("--tamper-file=")).data();
        }
    }

    if (isVerification) {
        std::string signature;
        CompilerFilter::Filter filter;
        int dex_count;
        bool ret = GenerateSignature(oat_file.c_str(), &signature, &filter, &dex_count);
        if (!ret) {
	    std::cout << "GenerateSignature failed." << std::endl;
            return false;
	}
        ParseSecureStore(securestore_file.c_str(), dex_count);
        DoIV(signature, filter);
	return true;
    }
    /*
    if (oat_file.length() == 0 || oat_todex_path.length() == 0) {
        fprintf(stderr, "--oat-file and --out-path must be specified\n");
        return false;
    }

    if (!IsDirExist(oat_todex_path)) {
        MakeDir(oat_todex_path);
    }

    if (InitOatParser(oat_file.c_str(), oat_todex_path.c_str())) {
        DoDumpToDex();
    }
    */

     if (!ParseOatFile(read_file)) {
            std::cout << "Failed to parse oat file: " << read_file << std::endl;
            return false;
      }

     if (!TamperChecksum(tamper_file)) {
        std::cout << "Failed to tamper oat file: " << tamper_file << std::endl;
        return false;
     }

    return 0;
}


#include "offsets.h"
#include "osinfo.h"
#include "logger.h"

// Function to get the offsets
Offsets getOffsets() {
    int build = GetOSVersion();

    if (build < 0) {
        exit(-1);
    }

    Offsets offs = { 0, 0, 0 };

    // Offsets table for x64 (TODO)
    if (build <= 16384) {       // Windows 8 Server 2012 NO PPL FIELD
        offs.ActiveProcessLinks = 0x0000;
        offs.ImageFileName = 0x0000;
        offs.Protection = 0x0000;
    }
    else if (build <= 17415) {       // Windows 8.1 Server 2012R2 and RTM (16384)
        offs.ActiveProcessLinks = 0x2e8;
        offs.ImageFileName = 0x438;
        offs.Protection = 0x67a;
    }
    else if (build <= 19045) {       // Windows 10 version 22H2 (Build 19041)
        offs.ActiveProcessLinks = 0x448;
        offs.ImageFileName = 0x5a8;
        offs.Protection = 0x87a;
    }
    else if (build <= 22631) {  // Windows 23H2
        offs.ActiveProcessLinks = 0x448;
        offs.ImageFileName = 0x5a8;
        offs.Protection = 0x87a;
    }
    else if (build > 22631) {  // Windows 11 24H2 and above
        offs.ActiveProcessLinks = 0x1d8;
        offs.ImageFileName = 0x338;
        offs.Protection = 0x5fa;
    }
    else {
        log_error("Offsets not defined for build %d on x64.", build);
        exit(1);
    }
    return offs;
}
#include "offsets.h"
#include "logger.h"
#include "osinfo.h"

BOOL is_x64() {
#if defined(_WIN64)
  return TRUE; // Compiled 64-bit
#elif defined(_WIN32)
  BOOL bIsWow64 = FALSE;
  IsWow64Process(GetCurrentProcess(), &bIsWow64);
  return bIsWow64; // TRUE for 32-bit process on OS 64-bit
#else
  return FALSE;
#endif
}

// Function to get the offsets (thank to @x3by for parsing the offsets)
Offsets getOffsets() {
  int build = GetOSVersion();

  if (build < 0) {
    ExitProcess((UINT)-1);
  }

  Offsets offs = {0, 0, 0, 0};

  if (is_x64()) {
    if (build >= 26100) { // Windows 11 - 24H2 & 25H2+ (Germanium & R2)
      offs.ActiveProcessLinks = 0x1d8;
      offs.ImageFileName = 0x338;
      offs.Protection = 0x5fa;
      offs.ObjectTable = 0x300;
    } else if (build >= 19041) { // Windows 10/11 - 2004 to 23H2
      offs.ActiveProcessLinks = 0x448;
      offs.ImageFileName = 0x5a8;
      offs.Protection = 0x87a;
      offs.ObjectTable = 0x570;
    } else if (build >= 18362) { // Windows 10 - 1903, 1909
      offs.ActiveProcessLinks = 0x2f0;
      offs.ImageFileName = 0x450;
      offs.Protection = 0x6fa;
      offs.ObjectTable = 0x418;
    } else if (build >= 15063) { // Windows 10 - 1703, 1709, 1803, 1809
      offs.ActiveProcessLinks = 0x2e8;
      offs.ImageFileName = 0x450;
      offs.Protection = 0x6ca;
      offs.ObjectTable = 0x418;
    } else if (build >= 14393) { // Windows 10 - 1607
      offs.ActiveProcessLinks = 0x2f0;
      offs.ImageFileName = 0x450;
      offs.Protection = 0x6c2;
      offs.ObjectTable = 0x418;
    } else if (build >= 10586) { // Windows 10 - 1511
      offs.ActiveProcessLinks = 0x2f0;
      offs.ImageFileName = 0x450;
      offs.Protection = 0x6b2;
      offs.ObjectTable = 0x418;
    } else if (build >= 10240) { // Windows 10 - 1507
      offs.ActiveProcessLinks = 0x2f0;
      offs.ImageFileName = 0x448;
      offs.Protection = 0x6aa;
      offs.ObjectTable = 0x418;
    } else if (build >= 9600) { // Windows 8.1
      offs.ActiveProcessLinks = 0x2e8;
      offs.ImageFileName = 0x438;
      offs.Protection = 0x67a;
      offs.ObjectTable = 0x408;
    } else if (build >= 9200) { // Windows 8
      offs.ActiveProcessLinks = 0x2e8;
      offs.ImageFileName = 0x438;
      offs.Protection = 0x4;
      offs.ObjectTable = 0x408;
    } else if (build >= 7600) { // Windows 7
      offs.ActiveProcessLinks = 0x188;
      offs.ImageFileName = 0x2e0;
      offs.Protection = 0x4;
      offs.ObjectTable = 0x200;
    } else if (build >= 6000) { // Windows Vista
      offs.ActiveProcessLinks = 0xe8;
      offs.ImageFileName = 0x238;
      offs.Protection = 0x4;
      offs.ObjectTable = 0x160;
    } else if (build >= 3790) { // Windows Server 2003
      offs.ActiveProcessLinks = 0xe0;
      offs.ImageFileName = 0x268;
      offs.Protection = 0x0;
      offs.ObjectTable = 0x158;
    } else {
      log_error("Offsets not defined for build %d on x64.", build);
      ExitProcess(1);
    }
    return offs;
  }
  else {                  // x86
    if (build >= 19041) { // Windows 10/11 - 2004+
      offs.ActiveProcessLinks = 0xe8;
      offs.ImageFileName = 0x1ac;
      offs.Protection = 0x3a6;
      offs.ObjectTable = 0x18c;
    } else if (build >= 18362) { // Windows 10 - 1903, 1909
      offs.ActiveProcessLinks = 0xb8;
      offs.ImageFileName = 0x17c;
      offs.Protection = 0x366;
      offs.ObjectTable = 0x15c;
    } else if (build >= 17134) { // Windows 10 - 1803, 1809
      offs.ActiveProcessLinks = 0xb8;
      offs.ImageFileName = 0x17c;
      offs.Protection = 0x2f6;
      offs.ObjectTable = 0x15c;
    } else if (build >= 15063) { // Windows 10 - 1703, 1709
      offs.ActiveProcessLinks = 0xb8;
      offs.ImageFileName = 0x17c;
      offs.Protection = 0x2ee;
      offs.ObjectTable = 0x15c;
    } else if (build >= 14393) { // Windows 10 - 1607
      offs.ActiveProcessLinks = 0xb8;
      offs.ImageFileName = 0x174;
      offs.Protection = 0x2e6;
      offs.ObjectTable = 0x154;
    } else if (build >= 10586) { // Windows 10 - 1511
      offs.ActiveProcessLinks = 0xb8;
      offs.ImageFileName = 0x174;
      offs.Protection = 0x2de;
      offs.ObjectTable = 0x154;
    } else if (build >= 10240) { // Windows 10 - 1507
      offs.ActiveProcessLinks = 0xb8;
      offs.ImageFileName = 0x170;
      offs.Protection = 0x2de;
      offs.ObjectTable = 0x154;
    } else if (build >= 9600) { // Windows 8.1
      offs.ActiveProcessLinks = 0xb8;
      offs.ImageFileName = 0x170;
      offs.Protection = 0x2ce;
      offs.ObjectTable = 0x150;
    } else if (build >= 9200) { // Windows 8
      offs.ActiveProcessLinks = 0xb8;
      offs.ImageFileName = 0x170;
      offs.Protection = 0x4;
      offs.ObjectTable = 0x150;
    } else if (build >= 7600) { // Windows 7
      offs.ActiveProcessLinks = 0xb8;
      offs.ImageFileName = 0x16c;
      offs.Protection = 0x4;
      offs.ObjectTable = 0xf4;
    } else if (build >= 6000) { // Windows Vista
      offs.ActiveProcessLinks = 0xa0;
      offs.ImageFileName = 0x14c;
      offs.Protection = 0x4;
      offs.ObjectTable = 0xdc;
    } else if (build >= 3790) { // Server 2003
      offs.ActiveProcessLinks = 0x98;
      offs.ImageFileName = 0x164;
      offs.Protection = 0x0;
      offs.ObjectTable = 0xd4;
    } else if (build >= 2600) { // Windows XP
      offs.ActiveProcessLinks = 0x88;
      offs.ImageFileName = 0x174;
      offs.Protection = 0x0;
      offs.ObjectTable = 0xc4;
    } else {
      log_error("Offsets not defined for build %d on x86.", build);
      ExitProcess(1);
    }
    return offs;
  }
}
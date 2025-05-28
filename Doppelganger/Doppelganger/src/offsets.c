#include "offsets.h"
#include "osinfo.h"
#include "logger.h"

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
		exit(-1);
	}

	Offsets offs = { 0, 0, 0 };

	if (is_x64()) {
		if (build >= 26100) { // Windows 11 - 24H2 (Germanium)
			offs.ActiveProcessLinks = 0x1d8;
			offs.ImageFileName = 0x338;
			offs.Protection = 0x5fa;
		}
		else if (build >= 19041) { // Windows 10 - 2004+
			offs.ActiveProcessLinks = 0x448;
			offs.ImageFileName = 0x5a8;
			offs.Protection = 0x87a;
		}
		else if (build >= 18362) { // Windows 10 - 1903 e 1909
			offs.ActiveProcessLinks = 0x2f0;
			offs.ImageFileName = 0x450;
			offs.Protection = 0x6fa;
		}
		else if (build >= 15063) { // Windows 10 - 1703, 1709, 1803, 1809
			offs.ActiveProcessLinks = 0x2e8;
			offs.ImageFileName = 0x450;
			offs.Protection = 0x6ca;
		}
		else if (build == 14393) { // Windows 10 - 1607 | Server 2016
			offs.ActiveProcessLinks = 0x2f0;
			offs.ImageFileName = 0x450;
			offs.Protection = 0x6c2;
		}
		else if (build == 10586) {
			offs.ActiveProcessLinks = 0x2f0;
			offs.ImageFileName = 0x450;
			offs.Protection = 0x6b2;
		}
		else if (build == 10240) {
			offs.ActiveProcessLinks = 0x2f0;
			offs.ImageFileName = 0x448;
			offs.Protection = 0x6aa;
		}
		else if (build == 9600) { // Windows 8.1 | Server 2012R2
			offs.ActiveProcessLinks = 0x2e8;
			offs.ImageFileName = 0x438;
			offs.Protection = 0x67a;
		}
		else {
			log_error("Offsets not defined for build %d on x64.", build);
			exit(1);
		}
		return offs;
	}


	else { // x86
		if (build >= 19041) { // Windows 10 - 2004+ (20H2, 21H1, 21H2, 22H2)
			offs.ActiveProcessLinks = 0xe8;
			offs.ImageFileName = 0x1ac;
			offs.Protection = 0x3a6;
		}
		else if (build >= 18362) { // Windows 10 - 1903 e 1909
			offs.ActiveProcessLinks = 0xb8;
			offs.ImageFileName = 0x17c;
			offs.Protection = 0x366;
		}
		else if (build >= 15063) { // Windows 10 - 1703, 1709, 1803, 1809
			offs.ActiveProcessLinks = 0xb8;
			offs.ImageFileName = 0x17c;
			offs.Protection = 0x2f6;
		}
		else if (build == 14393) { // Windows 10 - 1607 | Server 2016
			offs.ActiveProcessLinks = 0xb8;
			offs.ImageFileName = 0x174;
			offs.Protection = 0x2e6;
		}
		else if (build == 10586) {
			offs.ActiveProcessLinks = 0xb8;
			offs.ImageFileName = 0x174;
			offs.Protection = 0x2de;
		}
		else if (build == 10240) {
			offs.ActiveProcessLinks = 0xb8;
			offs.ImageFileName = 0x170;
			offs.Protection = 0x2de;
		}
		else if (build == 9600) { // Windows 8.1 | Server 2012R2
			offs.ActiveProcessLinks = 0xb8;
			offs.ImageFileName = 0x170;
			offs.Protection = 0x2ce;
		}
		else {
			log_error("Offsets not defined for build %d on x86.", build);
			exit(1);
		}
		return offs;
	}


}
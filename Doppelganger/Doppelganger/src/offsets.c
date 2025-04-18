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

	if (is_x64()) { // Offsets for 64-bit arch

		if (build == 10240) {		// Windows 10 - 1507 (Original Release, Threshold 1)
			offs.ActiveProcessLinks = 0x2f0;
			offs.ImageFileName = 0x448;
			offs.Protection = 0x6aa;
		}
		else 	if (build == 10586) {		// Windows 10 - 1511 (November Update, Threshold 2)
			offs.ActiveProcessLinks = 0x2f0;
			offs.ImageFileName = 0x450;
			offs.Protection = 0x6b2;
		}
		else 	if (build == 14393) {		// Windows 10 - 1607 | Server 2016 (Anniversary Update, Redstone 1)
			offs.ActiveProcessLinks = 0x2f0;
			offs.ImageFileName = 0x450;
			offs.Protection = 0x6c2;
		}
		else 	if (build == 15063) {		// Windows 10 - 1703 (Creators Update, Redstone 2)
			offs.ActiveProcessLinks = 0x2e8;
			offs.ImageFileName = 0x450;
			offs.Protection = 0x6ca;
		}
		else 	if (build == 16299) {		// Windows 10 - 1709 (Fall Creators Update, Redstone 3)
			offs.ActiveProcessLinks = 0x2e8;
			offs.ImageFileName = 0x450;
			offs.Protection = 0x6ca;
		}
		else 	if (build == 17134) {		// Windows 10 - 1803 (April 2018 Update, Redstone 4)
			offs.ActiveProcessLinks = 0x2e8;
			offs.ImageFileName = 0x450;
			offs.Protection = 0x6ca;
		}
		else 	if (build == 17763) {		// Windows 10 - 1809 | Server 2019 (October 2018 Update, Redstone 5)
			offs.ActiveProcessLinks = 0x2e8;
			offs.ImageFileName = 0x450;
			offs.Protection = 0x6ca;
		}
		else 	if (build == 18362) {		// Windows 10 - 1903 (May 2019 Update, Titanium R1)
			offs.ActiveProcessLinks = 0x2f0;
			offs.ImageFileName = 0x450;
			offs.Protection = 0x6fa;
		}
		else 	if (build == 18362) {		// Windows 10 - 1909 (November 2019 Update, Titanium R2)
			offs.ActiveProcessLinks = 0x2f0;
			offs.ImageFileName = 0x450;
			offs.Protection = 0x6fa;
		}
		else 	if (build == 19041) {		// Windows 10 - 2004 (May 2020 Update, Vibranium R1)
			offs.ActiveProcessLinks = 0x448;
			offs.ImageFileName = 0x5a8;
			offs.Protection = 0x87a;
		}
		else 	if (build == 19042) {		// Windows 10 - 20H2 (October 2020 Update, Vibranium R2)
			offs.ActiveProcessLinks = 0x448;
			offs.ImageFileName = 0x5a8;
			offs.Protection = 0x87a;
		}
		else 	if (build == 19043) {		// Windows 10 - 21H1 (May 2021 Update, Vibranium R3)
			offs.ActiveProcessLinks = 0x448;
			offs.ImageFileName = 0x5a8;
			offs.Protection = 0x87a;
		}
		else 	if (build == 19044) {		// Windows 10 - 21H2 (November 2021 Update, Vibranium R4)
			offs.ActiveProcessLinks = 0x448;
			offs.ImageFileName = 0x5a8;
			offs.Protection = 0x87a;
		}
		else 	if (build == 19045) {		// Windows 10 - 22H2 (2022 Update, Vibranium R5)
			offs.ActiveProcessLinks = 0x448;
			offs.ImageFileName = 0x5a8;
			offs.Protection = 0x87a;
		}
		else 	if (build == 22000) {		// Windows 11 - Insider Preview (Jun 2021)
			offs.ActiveProcessLinks = 0x448;
			offs.ImageFileName = 0x5a8;
			offs.Protection = 0x87a;
		}
		else 	if (build == 22000) {		// Windows 11 - 21H2 (Original Release, Cobalt)
			offs.ActiveProcessLinks = 0x448;
			offs.ImageFileName = 0x5a8;
			offs.Protection = 0x87a;
		}
		else 	if (build == 22621) {		// Windows 11 - 22H2 (2022 Update, Nickel R1)
			offs.ActiveProcessLinks = 0x448;
			offs.ImageFileName = 0x5a8;
			offs.Protection = 0x87a;
		}
		else 	if (build == 22631) {		// Windows 11 - 23H2 (2023 Update, Nickel R2)
			offs.ActiveProcessLinks = 0x448;
			offs.ImageFileName = 0x5a8;
			offs.Protection = 0x87a;
		}
		else 	if (build == 26100) {		// Windows 11 - 24H2 (2024 Update, Germanium)
			offs.ActiveProcessLinks = 0x1d8;
			offs.ImageFileName = 0x338;
			offs.Protection = 0x5fa;
		}
		else 	if (build == 9600) {		// Windows 8.1 | Server 2012R2 - RTM
			offs.ActiveProcessLinks = 0x2e8;
			offs.ImageFileName = 0x438;
			offs.Protection = 0x67a;
		}
		else 	if (build == 9600) {		// Windows 8.1 | Server 2012R2 - Update 1
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
	else {
		if (build == 10240) {		// Windows 10 - 1507 (Original Release, Threshold 1)
			offs.ActiveProcessLinks = 0xb8;
			offs.ImageFileName = 0x170;
			offs.Protection = 0x2de;
		}
		else 	if (build == 10586) {		// Windows 10 - 1511 (November Update, Threshold 2)
			offs.ActiveProcessLinks = 0xb8;
			offs.ImageFileName = 0x174;
			offs.Protection = 0x2de;
		}
		else 	if (build == 14393) {		// Windows 10 - 1607 (Anniversary Update, Redstone 1)
			offs.ActiveProcessLinks = 0xb8;
			offs.ImageFileName = 0x174;
			offs.Protection = 0x2e6;
		}
		else 	if (build == 15063) {		// Windows 10 - 1703 (Creators Update, Redstone 2)
			offs.ActiveProcessLinks = 0xb8;
			offs.ImageFileName = 0x17c;
			offs.Protection = 0x2ee;
		}
		else 	if (build == 16299) {		// Windows 10 - 1709 (Fall Creators Update, Redstone 3)
			offs.ActiveProcessLinks = 0xb8;
			offs.ImageFileName = 0x17c;
			offs.Protection = 0x2ee;
		}
		else 	if (build == 17134) {		// Windows 10 - 1803 (April 2018 Update, Redstone 4)
			offs.ActiveProcessLinks = 0xb8;
			offs.ImageFileName = 0x17c;
			offs.Protection = 0x2f6;
		}
		else 	if (build == 17763) {		// Windows 10 - 1809 (October 2018 Update, Redstone 5)
			offs.ActiveProcessLinks = 0xb8;
			offs.ImageFileName = 0x17c;
			offs.Protection = 0x2f6;
		}
		else 	if (build == 18362) {		// Windows 10 - 1903 (May 2019 Update, Titanium R1)
			offs.ActiveProcessLinks = 0xb8;
			offs.ImageFileName = 0x17c;
			offs.Protection = 0x366;
		}
		else 	if (build == 18362) {		// Windows 10 - 1909 (November 2019 Update, Titanium R2)
			offs.ActiveProcessLinks = 0xb8;
			offs.ImageFileName = 0x17c;
			offs.Protection = 0x366;
		}
		else 	if (build == 19041) {		// Windows 10 - 2004 (May 2020 Update, Vibranium R1)
			offs.ActiveProcessLinks = 0xe8;
			offs.ImageFileName = 0x1ac;
			offs.Protection = 0x3a6;
		}
		else 	if (build == 19042) {		// Windows 10 - 20H2 (October 2020 Update, Vibranium R2)
			offs.ActiveProcessLinks = 0xe8;
			offs.ImageFileName = 0x1ac;
			offs.Protection = 0x3a6;
		}
		else 	if (build == 19043) {		// Windows 10 - 21H1 (May 2021 Update, Vibranium R3)
			offs.ActiveProcessLinks = 0xe8;
			offs.ImageFileName = 0x1ac;
			offs.Protection = 0x3a6;
		}
		else 	if (build == 19044) {		// Windows 10 - 21H2 (November 2021 Update, Vibranium R4)
			offs.ActiveProcessLinks = 0xe8;
			offs.ImageFileName = 0x1ac;
			offs.Protection = 0x3a6;
		}
		else 	if (build == 19045) {		// Windows 10 - 22H2 (2022 Update, Vibranium R5)
			offs.ActiveProcessLinks = 0xe8;
			offs.ImageFileName = 0x1ac;
			offs.Protection = 0x3a6;
		}
		else 	if (build == 9600) {		// Windows 8.1 - RTM
			offs.ActiveProcessLinks = 0xb8;
			offs.ImageFileName = 0x170;
			offs.Protection = 0x2ce;
		}
		else 	if (build == 9600) {		// Windows 8.1 - Update 1
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
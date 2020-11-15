/* Disable entry during POST */
#undef ROM_BANNER_TIMEOUT
#define ROM_BANNER_TIMEOUT 0

/* Extend banner timeout */
#undef BANNER_TIMEOUT
#define BANNER_TIMEOUT 30

/* Work around missing EFI_PXE_BASE_CODE_PROTOCOL */
#define EFI_DOWNGRADE_UX

/* Disabled from config/defaults/pcbios.h */

#undef SANBOOT_PROTO_ISCSI
#undef SANBOOT_PROTO_AOE
#undef SANBOOT_PROTO_IB_SRP
#undef SANBOOT_PROTO_FCP

/* Disabled from config/general.h */

#undef CRYPTO_80211_WEP
#undef CRYPTO_80211_WPA
#undef CRYPTO_80211_WPA2
#undef IWMGMT_CMD
#undef MENU_CMD

/* Ensure ROM banner is not displayed */

#undef ROM_BANNER_TIMEOUT
#define ROM_BANNER_TIMEOUT 0

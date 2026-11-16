# TWRP tree for Samsung Galaxy Tab A9+ 5G (gta9p)

TWRP 12.1 device tree for the SM-X216B, built with GitHub Actions

## Install

1. Unlock the bootloader.
2. Flash `recovery.tar` in Odin (AP slot), or `recovery.img` with dd if you're rooted:

   ```
   adb push recovery.img /data/local/tmp/ && adb shell su -c "dd if=/data/local/tmp/recovery.img of=/dev/block/by-name/recovery bs=4M"
   ```

3. Boot into recovery.

## Status

Confirmed working currently:
- /data decryption
- touch
- zip installation
- image installation in fastboot
- image installation from internal storage

This will only ever be tested on my device (SM-X216B, X216BXXS9DYJ5), it is not my
intention to be a maintainer for this device at this time. It should work on any
SM-X216B on One UI 6/7. If it doesn't, it's not my job to help you.

## Credits
- [cd-Crypton](https://github.com/cd-Crypton) who made this tree and wrote nearly all the code
- [SavedByLight](https://github.com/SavedByLight) for the vendor blobs, continued maintenance and the TWRP 3.7.1 / OrangeFox R11.3 releases

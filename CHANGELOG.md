# Changelog
## [1.0.15.2] 20180509
### Changed
- Disable requirement for LTM provisioning
## [1.0.15.1] 20180509
### Changed
- Set pua_webtop-clientssl handshake timeout to 120. Prevents handshake timeouts when CAC/PIV/SmartCard is used and user takes too long to enter their PIN.
## [1.0.15] 20180404
### Changed
- Attempt to flush buffer before first key read... Minor.
## [1.0.14] 20180319
### Changed
- ephemeral_auth package updated to 0.2.13
### Fixed
- Typo in build_pua*.sh #2
## [1.0.13] 20180228
### Changed
- ephemeral_auth package updated to 0.2.10
# Changelog
## [1.0.12] 20180227
### Added
- Option to disable test account and enhanced logging with disabletest=y in `pua_config.sh`
# Changelog
## [1.0.11] 20180227
### Added
- Check for and trim leading/trailing whitespace/tab in IP address input
## [1.0.10] 20180223
### Changed
- Formatting and typos thanks to the eagle eye of Mr. Brad Otlin!
- Corrected script version variable and moved it to the top
## [1.0.9] 20180222
### Added
- Apply APM policy after creation
- pua_webtop-clientssl profile
- Sample CA option `sampleca`
- Installation of sample APM policy
### Changed
- Updated plugin names
- variables to lower case (costmetic/minor)
## [1.0.8] 20180221
### Added
- Config file option `pua_config.sh`
- Fully automated and Semi-automatic config
- This Changelog
### Changed
- Documentation updates
## [1.0.7] 20180220
### Changed
- Corrected typo for RADIUS configuration and IP configuration (superficial)
### Added
- TMOS version check
## [1.0.6] 20180220
### Added
- Introduction text
## [1.0.5] 20180220
### Added
- Self-extracting "offline" mode. Download build_pua_offline.sh for offline use
## [1.0.4] 20180220
### Changed
- Fixed typo
## [1.0.3] 20180220
### Changed
- Cleaned up error handling
## [1.0.2] 20180220
### Changed
- Cleaned up error reporting
## [1.0.1] 20180219
### Changed
- Disabled SNAT automap for webtop virtual server
## [1.0.0] 20180219
- Initial Release

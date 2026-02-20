# Changelog

## [0.1.0](https://github.com/vitalvas/gotacacs/compare/v0.0.1...v0.1.0) (2026-02-20)


### ⚠ BREAKING CHANGES

* NewClient now uses functional options pattern
    - NewClient(address, opts...) -> NewClient(WithAddress(address), opts...)
    - Added WithAddress() option for server address configuration

### Features

* add accounting packets implementation ([8ac7005](https://github.com/vitalvas/gotacacs/commit/8ac700560e58f3076d90bb9596cc9836279d8186))
* add authentication packets implementation ([ed67503](https://github.com/vitalvas/gotacacs/commit/ed67503bfb2bcc570ef31572e0615909d1d01ea7))
* add authorization packets implementation ([05fb374](https://github.com/vitalvas/gotacacs/commit/05fb3745e80f7e73171d95ceaed4cf9b6e2b1d5c))
* add bad secret detection and tacquito interoperability tests ([127e26d](https://github.com/vitalvas/gotacacs/commit/127e26d9616923d21abab1cbf26ae6ddc4c0295b))
* add body obfuscation implementation ([680774c](https://github.com/vitalvas/gotacacs/commit/680774cf9e5771ecb55c104c1f08d9615ed3f9ad))
* add core protocol types and header implementation ([1a300d8](https://github.com/vitalvas/gotacacs/commit/1a300d828227272726093f021037b5c3e07e8fdd))
* add example TACACS+ client and server binaries ([c586624](https://github.com/vitalvas/gotacacs/commit/c586624b628822b074f54270a4ec45c43756f340))
* add packet interface and factory functions ([65d5980](https://github.com/vitalvas/gotacacs/commit/65d59808b71be72ad5c52950320e7f0e4e2d6a8f))
* add secret rotation support via SecretProvider ([0d60470](https://github.com/vitalvas/gotacacs/commit/0d6047021c101037f9b00d7fd68f38af8dacf7f8))
* add session management implementation ([70bc81b](https://github.com/vitalvas/gotacacs/commit/70bc81b408ce9a1477d760646ef2394735b12205))
* add transport layer implementation ([0ae1f6f](https://github.com/vitalvas/gotacacs/commit/0ae1f6f3b5d49d34d00e576a0ea3c5da00b1ebb1))
* implement client SDK for TACACS+ protocol ([e7e847c](https://github.com/vitalvas/gotacacs/commit/e7e847c364ff945deac81d295d75cf74f2ac225c))
* implement RFC 9887 TLS 1.3 compliance and security ([2fa6422](https://github.com/vitalvas/gotacacs/commit/2fa6422768d6e874003421989deab057d1c6ecc2))
* implement server SDK for TACACS+ protocol ([417ef6d](https://github.com/vitalvas/gotacacs/commit/417ef6dd371d47efdda7cb0493ecc7f449265f9d))
* initialize TACACS+ SDK project ([32f203a](https://github.com/vitalvas/gotacacs/commit/32f203a047c8e05870510fcdc3902447f06e9323))


### Bug Fixes

* address multiple protocol and connection handling issues ([28c4586](https://github.com/vitalvas/gotacacs/commit/28c45863aed70949bb4264df550ab6a2878a5bda))
* implement RFC 9887 TLS 1.3 compliance and security ([ad8206d](https://github.com/vitalvas/gotacacs/commit/ad8206db25f7449789df89a33c14274b0f81ff80))
* use proper Go naming conventions for exported fields ([482a0eb](https://github.com/vitalvas/gotacacs/commit/482a0eb507f4b986fa0e1f09414943fc058f9b16))


### Miscellaneous Chores

* release 0.1.0 ([1faa03f](https://github.com/vitalvas/gotacacs/commit/1faa03f4f21cbbd45ef2b66066ba6b956e88dea7))


### Code Refactoring

* update client and server APIs for better ergonomics ([99e1a57](https://github.com/vitalvas/gotacacs/commit/99e1a572a8b016cf651ef61cb84d75c31ac1c8b3))

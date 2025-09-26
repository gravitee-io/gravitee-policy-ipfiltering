## [2.0.2](https://github.com/gravitee-io/gravitee-policy-ipfiltering/compare/2.0.1...2.0.2) (2025-09-26)


### Bug Fixes

* Multipe bypass in IP Filtering policy with hostname specified - APIM ([7908d63](https://github.com/gravitee-io/gravitee-policy-ipfiltering/commit/7908d6331d53077b53d05c6447e5221dbc34dec2))

## [2.0.1](https://github.com/gravitee-io/gravitee-policy-ipfiltering/compare/2.0.0...2.0.1) (2025-09-16)


### Bug Fixes

* IPV6 CIDR ranges do not work in the IP filtering policy ([91fa727](https://github.com/gravitee-io/gravitee-policy-ipfiltering/commit/91fa72708b9459b985b0e92a14364735cd174867))

# [2.0.0](https://github.com/gravitee-io/gravitee-policy-ipfiltering/compare/1.19.1...2.0.0) (2025-08-08)


### Bug Fixes

* **deps:** bump commons-net to 3.12.0 ([3106434](https://github.com/gravitee-io/gravitee-policy-ipfiltering/commit/31064349e674a5cef75c4d6e95e119ea83a8f727))
* **deps:** bump commons-validation to 1.10.0 ([4bea059](https://github.com/gravitee-io/gravitee-policy-ipfiltering/commit/4bea059d36ca61b9e1c222e804e7680a66df5570))


### chore

* **deps:** update gravitee-parent ([d59af60](https://github.com/gravitee-io/gravitee-policy-ipfiltering/commit/d59af602346d2915d7c2851dba98c724a1e32313))


### BREAKING CHANGES

* **deps:** require Java17

## [1.19.1](https://github.com/gravitee-io/gravitee-policy-ipfiltering/compare/1.19.0...1.19.1) (2025-06-13)


### Bug Fixes

* resolve 403 error for custom IP ([f77ce51](https://github.com/gravitee-io/gravitee-policy-ipfiltering/commit/f77ce51a36bed03edd9fe40f0c5bcec85ba14a7a))

# [1.19.0](https://github.com/gravitee-io/gravitee-policy-ipfiltering/compare/1.18.1...1.19.0) (2025-04-09)


### Features

* resolve all host ips ([97d4c95](https://github.com/gravitee-io/gravitee-policy-ipfiltering/commit/97d4c95c48622b26f620c3d33c195a08aea7c09b))

## [1.18.1](https://github.com/gravitee-io/gravitee-policy-ipfiltering/compare/1.18.0...1.18.1) (2025-04-08)


### Bug Fixes

* isInclusiveHostCount boolean getter method ([59e7130](https://github.com/gravitee-io/gravitee-policy-ipfiltering/commit/59e7130c739a8a2a06667bf7ccac77b262ea4a24))

# [1.18.0](https://github.com/gravitee-io/gravitee-policy-ipfiltering/compare/1.17.0...1.18.0) (2025-03-19)


### Features

* support comma-separated IPs in wl/bl ([7594f39](https://github.com/gravitee-io/gravitee-policy-ipfiltering/commit/7594f39a54f98fec7d782a8b542cf7f6d82d747e))

# [1.17.0](https://github.com/gravitee-io/gravitee-policy-ipfiltering/compare/1.16.1...1.17.0) (2025-01-22)


### Features

* support custom header for IP address ([25b7a47](https://github.com/gravitee-io/gravitee-policy-ipfiltering/commit/25b7a475c6bb61af1dbff5118f1faee0ccfa07a3))

## [1.16.1](https://github.com/gravitee-io/gravitee-policy-ipfiltering/compare/1.16.0...1.16.1) (2025-01-21)


### Bug Fixes

* revert changes ([eb6bb38](https://github.com/gravitee-io/gravitee-policy-ipfiltering/commit/eb6bb38261448f1c0bdedda93d81ffe0b2b7d59e))

# [1.16.0](https://github.com/gravitee-io/gravitee-policy-ipfiltering/compare/1.15.0...1.16.0) (2025-01-21)


### Features

* extract ip address from header ([63c8959](https://github.com/gravitee-io/gravitee-policy-ipfiltering/commit/63c8959ad4088b5dc9a4b5c11dc2db0b0065c4cd))

# [1.15.0](https://github.com/gravitee-io/gravitee-policy-ipfiltering/compare/1.14.1...1.15.0) (2024-10-31)


### Features

* support expression language in ip lists ([2257e35](https://github.com/gravitee-io/gravitee-policy-ipfiltering/commit/2257e3533b1dd7421d2dc6ad17c68e1c16bd14b6))

## [1.14.1](https://github.com/gravitee-io/gravitee-policy-ipfiltering/compare/1.14.0...1.14.1) (2024-10-22)


### Bug Fixes

* error message with correct ip ([fc505e8](https://github.com/gravitee-io/gravitee-policy-ipfiltering/commit/fc505e8c7a3b4c4c0348edfc8bdca0373b72629b))

# [1.14.0](https://github.com/gravitee-io/gravitee-policy-ipfiltering/compare/1.13.0...1.14.0) (2024-06-20)


### Features

* add InclusiveHostCount option for /31 and /32 CIDR block issue ([784691b](https://github.com/gravitee-io/gravitee-policy-ipfiltering/commit/784691bbc396345c1f703ebfdabfed54a3794ba7))

# [1.13.0](https://github.com/gravitee-io/gravitee-policy-ipfiltering/compare/1.12.0...1.13.0) (2024-03-27)


### Features

* add the possibility to configure the IP version when lookup for host ([ee6611b](https://github.com/gravitee-io/gravitee-policy-ipfiltering/commit/ee6611bd800513072e1d29a2ad4e77e866b5c60b))

# [1.12.0](https://github.com/gravitee-io/gravitee-policy-ipfiltering/compare/1.11.0...1.12.0) (2023-12-19)


### Features

* enable policy on REQUEST phase for message APIs ([169980d](https://github.com/gravitee-io/gravitee-policy-ipfiltering/commit/169980d022c1ade4fcdd202d2f335e0be621fc6f)), closes [gravitee-io/issues#9430](https://github.com/gravitee-io/issues/issues/9430)

# [1.11.0](https://github.com/gravitee-io/gravitee-policy-ipfiltering/compare/1.10.1...1.11.0) (2023-10-23)


### Bug Fixes

* trim IPs set in configuration ([a8fc3e1](https://github.com/gravitee-io/gravitee-policy-ipfiltering/commit/a8fc3e189e8d72323fd5374764623a53657468a5))


### Features

* add configuration to set custom DNS server ([688d2db](https://github.com/gravitee-io/gravitee-policy-ipfiltering/commit/688d2db90ea2fca657a29747b61f0f4330e477a7))

## [1.10.1](https://github.com/gravitee-io/gravitee-policy-ipfiltering/compare/1.10.0...1.10.1) (2023-07-20)


### Bug Fixes

* update policy description ([8ce59e3](https://github.com/gravitee-io/gravitee-policy-ipfiltering/commit/8ce59e3b3a50c9bc30d2a80864412232c9cd8183))

# [1.10.0](https://github.com/gravitee-io/gravitee-policy-ipfiltering/compare/1.9.0...1.10.0) (2023-07-05)


### Features

* define execution phase ([31966f5](https://github.com/gravitee-io/gravitee-policy-ipfiltering/commit/31966f54c26a87ce29c58068c06138e65a940917))

# [1.9.0](https://github.com/gravitee-io/gravitee-policy-ipfiltering/compare/1.8.0...1.9.0) (2022-01-24)


### Features

* **headers:** Internal rework and introduce HTTP Headers API ([48d7b74](https://github.com/gravitee-io/gravitee-policy-ipfiltering/commit/48d7b7408f872c3dfa24776aa5c348e5f50315be)), closes [gravitee-io/issues#6772](https://github.com/gravitee-io/issues/issues/6772)

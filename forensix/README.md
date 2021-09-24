![forenstix](/forensix/img/21-50495_mastheads_R1_ForensIX.png)

ForensIX is an Golang application created on an internal Infrastructure eXpression (IX) project that converts Volatility process listing files into [Structured Threat Information Expression (STIX)](https://oasis-open.github.io/cti-documentation/stix/intro.html) v2.1 bundles. The results from ForenSTIX can be viewed in the [Structured Threat Intelligence Graph (STIG)](https://github.com/idaholab/STIG) application.

![stigView](/forensix/img/sample_linux_arm_vol2.png)

# Installation
This application uses [Go 1.17](https://golang.org/doc/install) or higher.

ForensIX leverages the [TcM1911/stix2](https://pkg.go.dev/github.com/TcM1911/stix2#section-readme) library for implementing STIX 2.1 in Go.

After installing Go (and setting your environment variables), clone this repository to your machine. Then run:

``` zsh
go mod tidy

go build
```

# Usage

Command Arguments
| Flag | Description |
| --- | --- |
| -banner | Volatilty banner .txt file |
| -pslist | Volatility pslist .txt file |
| -volver | Volatilty version used to create banner/pslist files (2 or 3) |
| -os | Operating System of machine memory dump originated from ("linux", "win") |

**NOTE:** Output STIX files are written to the `./data` directory.

**NOTE:** Volatilty Banner .txt files are optional. However, without providing a Banner file the STIX bundle will not have an Infrastructure object as the root node. It will also not have Software or Kernel objects to relate processes to.

## Examples

Example usage with Volatility2 test files:

```zsh
./forensix -banner ./data/vol2/debian-4.19.94-ti-r42.linux_banner.txt -pslist ./data/vol2/debian-4.19.94-ti-r42.linux_pslist.txt -volver 2 -os linux
```

Example ussage with Volatility3 test files:
```zsh
./forensix -pslist ./data/vol3/win-10.0.19041.pslist.txt -volver 3 -os win

./forensix -banner ./data/vol3/ubuntu-4.4.0-186-generic.banners.txt -pslist ./data/vol3/ubuntu-4.4.0-186-generic.pslist.txt -os linux -volver 3
```


# Test Files
Sample Volatility output files are in the `./test/vol2` and `./test/vol3` directories for Volatility v2 and Volatility v3 respectively. 

**debian-4.19.94.ti-r42:** pslist and banner files from a Beaglebone Black development board.
**ubuntu-4.4.0-186-generic:** pslist and banner files from a Ubuntu 18.04 machine.
**win-10.0.19041:** pslist file from a Windows 10 (19041 build) machine.

# Application Status and Future Work
The following ocnfigurations are working:
- [x] Volatility 2 Linux banners and pslist .txt files
- [ ] Volatility 2 Windows banners and pslist .txt files
- [x] Volatility 3 Linux banners and pslist .txt files
- [x] Volatility 3 Windows pslist .txt files
- [ ] ppid to pid relationship in STIX 2.1

# Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

# Licensing
See COPYRIGHT.txt and LICENSE.txt for copyright and licensing information.

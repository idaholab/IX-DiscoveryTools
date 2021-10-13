package volatility

import (
	"log"
	"strconv"
	"strings"

	"forensix/utils"

	"github.com/TcM1911/stix2"
)

//BannerID struct to hold Linux banner info
type BannerID struct {
	Kernel  string
	OperSys string
	Device  string
	Version string
}

//LinuxProcessID struct to hold Linux pslist info
type LinuxProcessID struct {
	Pid      int64
	PPid     int64
	Name     string
	Offset   string
	UID      string
	UserName string
	Time     string
}

// VolLinux parses a banner []string and pslist []string to extract STIX 2.1 objects
func VolLinux(banner []string, pslist []string, volVer int) {

	var bannerLines []string

	var b1 BannerID

	for _, eachLn := range banner {
		bannerLines = strings.Fields(eachLn)
	}

	/*
		Sample Volatility 2 Banner:
			0 Linux
			1 version
			2 4.19.94-ti-r42
			3 (voodoo@x3-am57xx-beagle-x15-2gb)
			4 (gcc
			5 version
			6 8.3.0
			7 (Debian
			8 8.3.0-6))
			9 #1buster
			10 SMP
			11 PREEMPT
			12 Tue
			13 Mar
			14 31
			15 19:38:29
			16 UTC
			17 2020
	*/

	/*
		Sample Volatility 3 banner_list
			0 0x13fea9a68
			1 Linux
			2 version
			3 4.4.0-186-generic
			4 (buildd@lcy01-amd64-002)
			5 (gcc
			6 version
			7 5.4.0
			8 20160609
			9 (Ubuntu
			10 5.4.0-6ubuntu1~16.04.12)
			11 )
			12 #216-Ubuntu
			13 SMP
			14 Wed
			15 Jul
			16 1
			17 05:34:05
			18 UTC
			19 2020
			20 (Ubuntu
			21 4.4.0-186.216-generic
			22 4.4.228)
	*/

	switch volVer {
	case 2:
		b1 = BannerID{
			Kernel:  utils.RemoveParenthesis(bannerLines[2]),
			OperSys: utils.RemoveParenthesis(bannerLines[7]),
			Device:  utils.RemoveParenthesis(bannerLines[3]),
		}
	case 3:
		b1 = BannerID{
			Kernel:  utils.RemoveParenthesis(bannerLines[3]),
			OperSys: utils.RemoveParenthesis(bannerLines[9]),
			Device:  utils.RemoveParenthesis(bannerLines[4]),
			Version: utils.RemoveParenthesis(bannerLines[10]),
		}
	}

	//Create STIX objects for Infrastructure, Software
	deviceSDO, err := stix2.NewInfrastructure(
		b1.Device,
	)
	if err != nil {
		log.Println(err)
	}
	if utils.Collection.Add(deviceSDO); err != nil {
		log.Println(err)
	}
	operatingSystemSCO, err := stix2.NewSoftware(
		b1.OperSys,
	)
	if err != nil {
		log.Println(err)
	}
	if utils.Collection.Add(operatingSystemSCO); err != nil {
		log.Println(err)
	}

	kernelSCO, err := stix2.NewSoftware(
		"Kernel",
		stix2.OptionVersion(b1.Kernel),
	)
	if utils.Collection.Add(kernelSCO); err != nil {
		log.Println(err)
	}

	deviceOSRel, err := stix2.NewRelationship(
		"has",
		deviceSDO.ID,
		operatingSystemSCO.ID,
	)
	if err != nil {
		log.Println(err)
	}
	if utils.Collection.Add(deviceOSRel); err != nil {
		log.Println(err)
	}

	osKernelRel, err := stix2.NewRelationship(
		"has",
		operatingSystemSCO.ID,
		kernelSCO.ID,
	)
	if err != nil {
		log.Println(err)
	}
	if utils.Collection.Add(osKernelRel); err != nil {
		log.Println(err)
	}

	var pslistLines []string
	var p1 LinuxProcessID

	for _, eachLn := range pslist {
		pslistLines = append(pslistLines, eachLn)
	}

	//****************************
	//Example Volatility 2 pslist
	//****************************
	/*
		pslist
			[0] OFFSET	0xdc13f480
			[1] NAME	kthreadd
			[2] PID		2
			[3] PPID	0
			[4] UID		0
			[5] GID		0
			[6] DTB		----------
			[7] DATE	2021-07-10
			[8] TIME	04:16:52
			[9] ZONE	UTC+0000
	*/

	//****************************
	//Sample Volatility 3 Process pslist
	//****************************

	/*
		0 *
		1 |
		2 283				(PID)
		3 |
		4 2					(PPID)
		5 |
		6 kworker/u256:24	(Name)
	*/

	// remove heading
	pslistLines = pslistLines[2:]

	for _, eachLn := range pslistLines {
		line := strings.Fields(eachLn)

		// TODO Fix pid and ppid for volVer 3

		switch volVer {
		case 2:
			//format timestamp
			cut1 := strings.Trim(line[9], "UTC+")
			cut2 := cut1[0:3]

			//format pid, ppid, uid as int64
			pid, err := strconv.ParseInt(line[2], 10, 64)
			if err != nil {
				log.Println(err)
			}

			ppid, err := strconv.ParseInt(line[3], 10, 64)
			if err != nil {
				log.Println(err)
			}

			timestamp := line[7] + "T" + line[8] + "." + cut2
			p1 = LinuxProcessID{
				Offset: line[0],
				Name:   line[1],
				Pid:    pid,
				PPid:   ppid,
				UID:    line[4],
				Time:   timestamp,
			}
		case 3:
			//format pid, ppid as int64
			pid, err := strconv.ParseInt(line[2], 10, 64)
			if err != nil {
				log.Println(err)
			}
			ppid, err := strconv.ParseInt(line[4], 10, 64)
			if err != nil {
				log.Println(err)
			}
			p1 = LinuxProcessID{
				Name: line[6],
				Pid:  pid,
				PPid: ppid,
			}
		}

		//File SCO for name
		fileSCO, err := stix2.NewFile(
			p1.Name,
			stix2.Hashes{},
		)
		if err != nil {
			log.Println(err)
		}
		if utils.Collection.Add(fileSCO); err != nil {
			log.Println(err)
		}

		//Process SCO for pid
		processSCO, err := stix2.NewProcess(
			stix2.OptionPID(p1.Pid),
		)
		if err != nil {
			log.Println(err)
		}
		if utils.Collection.Add(processSCO); err != nil {
			log.Println(err)
		}
		//user SDO
		if p1.UID == "0" {
			p1.UserName = "root"
			UserSCO, err := stix2.NewUserAccount(
				stix2.OptionDisplayName(p1.UserName),
				stix2.OptionUserID(p1.UID),
				stix2.OptionIsPrivileged(true),
			)
			if err != nil {
				log.Println(err)
			}
			if utils.Collection.Add(UserSCO); err != nil {
				log.Println(err)
			}
			userProcessRel, err := stix2.NewRelationship(
				"created_by",
				processSCO.ID,
				UserSCO.ID,
			)
			if err != nil {
				log.Println(err)
			}
			if utils.Collection.Add(userProcessRel); err != nil {
				log.Println(err)
			}
		} else {
			UserSCO, err := stix2.NewUserAccount(
				stix2.OptionDisplayName(p1.UID),
				stix2.OptionUserID(p1.UID),
			)
			if err != nil {
				log.Println(err)
			}
			if utils.Collection.Add(UserSCO); err != nil {
				log.Println(err)
			}
			userProcessRel, err := stix2.NewRelationship(
				"created_by",

				processSCO.ID,
				UserSCO.ID,
			)
			if err != nil {
				log.Println(err)
			}
			if utils.Collection.Add(userProcessRel); err != nil {
				log.Println(err)
			}

		}

		//relationships between file SCO and Process SCO
		fileProcessRel, err := stix2.NewRelationship(
			"created_by",
			processSCO.ID,
			fileSCO.ID,
		)
		if err != nil {
			log.Println(err)
		}
		if utils.Collection.Add(fileProcessRel); err != nil {
			log.Println(err)
		}

		// Relationships between operating system and file SCO
		osFileRel, err := stix2.NewRelationship(
			"has",
			operatingSystemSCO.ID,
			fileSCO.ID,
		)
		if err != nil {
			log.Println(err)
		}
		if utils.Collection.Add(osFileRel); err != nil {
			log.Println(err)
		}

	}

}

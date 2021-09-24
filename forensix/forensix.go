/*
Copyright 2021 Battelle Energy Alliance

ALL RIGHTS RESERVED
*/

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/TcM1911/stix2"
)

var collection = stix2.New()

type processID struct {
	Pid    int64
	PPid   int64
	Name   string
	Offset string
	UID    string
	Time   string
}

type bannerID struct {
	Kernel  string
	OperSys string
	Device  string
	Version string
}

func main() {

	bannerPtr := flag.String("banner", "", "Banner .txt file")
	pslistPtr := flag.String("pslist", "", "pslist .txt file")
	osPtr := flag.String("os", "", "Operating System of target device: linux or win")
	volPtr := flag.Int("volver", 0, "Volatility Version")

	flag.Parse()

	//process user files
	pslistFile, err := os.Open(*pslistPtr)
	if err != nil {
		log.Println("Cannot open pslist .txt file:", err)
	}
	defer pslistFile.Close()
	pslistString := scanFile(pslistFile)
	pslistFile.Close()

	bannerFile, err := os.Open(*bannerPtr)
	if err != nil {
		log.Println("Cannot open banner .txt file:", err)
	}
	defer bannerFile.Close()
	bannerString := scanFile(bannerFile)
	bannerFile.Close()

	if *volPtr == 2 {
		if *osPtr == "linux" {
			vol2Linux(bannerString, pslistString)
		} else if *osPtr == "win" {
			log.Fatalln("Volatility 2 Windows dumps are not supported at this time.")
		} else {
			log.Fatalln("Please select an OS version for the target machine")
		}
	} else if *volPtr == 3 {
		if *osPtr == "linux" {
			vol3Linux(bannerString, pslistString)
		} else if *osPtr == "win" {
			log.Println("ForensIX does not support Windows banners at this time. Processing pslist ..... ")
			vol3Win(pslistString)
		} else {
			log.Fatalln("Please select an OS version for the target machine")
		}
	} else {
		log.Fatalln("Volatility version not idenfitied. Please use -volver flag and choose either \"2\" or \"3\". (i.e. -volver 2)")
	}

	//Prep bundle to write to file
	bundle, err := collection.ToBundle()
	if err != nil {
		log.Println("Error parsing collection to bundle:", err)
	}

	data, err := json.MarshalIndent(bundle, "", "\t")
	if err != nil {
		log.Println("Error marshaling bundle:", err)
	}

	err = ioutil.WriteFile("forensix-bundle.json", data, 0600)
	if err != nil {
		log.Fatalln(err)
	} else {
		log.Println("Saved foresix-bundle.json")
	}

}

//scanFile parses a *os.File object and returns a []string
func scanFile(f *os.File) []string {

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)

	var text []string

	for scanner.Scan() {
		text = append(text, scanner.Text())
	}

	return text
}

//vol2Linux processes banner and pslist files from linux
//dumps to create STIX 2.1 objects
func vol2Linux(b []string, p []string) {

	var bannerLines []string
	var pslistLines []string

	//****************************
	//Process Linux Banner text
	//****************************
	//parse []strings by line
	for _, eachLn := range b {
		bannerLines = strings.Fields(eachLn)
	}

	/*
		Banner:
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
	kernel := removeParenthesis(bannerLines[2])
	oper := removeParenthesis(bannerLines[7])
	device := removeParenthesis(bannerLines[3])

	b1 := bannerID{
		Kernel:  kernel,
		OperSys: oper,
		Device:  device,
	}

	//Create STIX objects for Infrastructure, Software
	deviceSDO, err := stix2.NewInfrastructure(
		b1.Device,
	)
	if err != nil {
		log.Println(err)
	}
	if collection.Add(deviceSDO); err != nil {
		log.Println(err)
	}

	operatingSystemSCO, err := stix2.NewSoftware(
		b1.OperSys,
	)
	if err != nil {
		log.Println(err)
	}
	if collection.Add(operatingSystemSCO); err != nil {
		log.Println(err)
	}

	kernelSCO, err := stix2.NewSoftware(
		"Kernel",
		stix2.OptionVersion(b1.Kernel),
	)
	if collection.Add(kernelSCO); err != nil {
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
	if collection.Add(deviceOSRel); err != nil {
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
	if collection.Add(osKernelRel); err != nil {
		log.Println(err)
	}

	//****************************
	//Process pslist
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
	for _, eachLn := range p {
		pslistLines = append(pslistLines, eachLn)
	}

	//remove headings from pslist

	pslistLines = pslistLines[2:]

	for _, eachLn := range pslistLines {
		line := strings.Fields(eachLn)

		//format timestamp for STIX 2.1 spec
		cut1 := strings.Trim(line[9], "UTC+")
		cut2 := cut1[0:3]

		timestamp := line[7] + "T" + line[8] + "." + cut2

		//format pid, ppid, uid as int64
		pid, err := strconv.ParseInt(line[2], 10, 64)
		if err != nil {
			log.Println(err)
		}

		ppid, err := strconv.ParseInt(line[3], 10, 64)
		if err != nil {
			log.Println(err)
		}

		//uid, err := strconv.ParseInt(line[4], 10, 64)
		//if err != nil {
		//	log.Println(err)
		//}

		p1 := processID{
			Offset: line[0],
			Name:   line[1],
			Pid:    pid,
			PPid:   ppid,
			UID:    line[4],
			Time:   timestamp,
		}

		//File SCO for name
		fileSCO, err := stix2.NewFile(
			p1.Name,
			stix2.Hashes{},
		)
		if err != nil {
			log.Println(err)
		}
		if collection.Add(fileSCO); err != nil {
			log.Println(err)
		}

		//Process SCO for pid
		processSCO, err := stix2.NewProcess(
			stix2.OptionPID(p1.Pid),
		)
		if err != nil {
			log.Println(err)
		}
		if collection.Add(processSCO); err != nil {
			log.Println(err)
		}
		/*
			//user SDO
			user_sdo, err := stix2.NewUserAccount(
				stix2.OptionDisplayName(p1.Uid),
			)
			if err != nil {
				log.Println(err)
			}
			collection.Add(user_sdo)

			user_process_rel, err := stix2.NewRelationship(
				"created_by",
				processSCO.ID,
				user_sdo.ID,
			)
			if err != nil {
				log.Println(err)
			}
			collection.Add(user_process_rel)
		*/
		fileProcessRel, err := stix2.NewRelationship(
			"created_by",
			processSCO.ID,
			fileSCO.ID,
		)
		if err != nil {
			log.Println(err)
		}
		if collection.Add(fileProcessRel); err != nil {
			log.Println(err)
		}

		osFileRel, err := stix2.NewRelationship(
			"has",
			operatingSystemSCO.ID,
			fileSCO.ID,
		)
		if err != nil {
			log.Println(err)
		}
		if collection.Add(osFileRel); err != nil {
			log.Println(err)
		}

	}
}

//vol3Linux processes banner and pslist files from linux
//dumps to create STIX 2.1 objects
func vol3Linux(b []string, p []string) {

	var bannerLines []string
	var pslistLines []string

	//****************************
	//Process Linux Banner text
	//****************************
	//parse []strings by line
	for _, eachLn := range b {
		bannerLines = strings.Fields(eachLn)
	}

	/*
		sample banner_list
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

	kernel := removeParenthesis(bannerLines[3])
	oper := removeParenthesis(bannerLines[9])
	device := removeParenthesis(bannerLines[4])
	version := removeParenthesis(bannerLines[10])

	b1 := bannerID{
		Kernel:  kernel,
		OperSys: oper,
		Device:  device,
		Version: version,
	}

	//Create STIX objects for Infrastructure, Software
	deviceSDO, err := stix2.NewInfrastructure(
		b1.Device,
	)
	if err != nil {
		log.Println(err)
	}
	if collection.Add(deviceSDO); err != nil {
		log.Println(err)
	}

	operatingSystemSCO, err := stix2.NewSoftware(
		b1.OperSys,
		stix2.OptionVersion(version),
	)
	if err != nil {
		log.Println(err)
	}
	if collection.Add(operatingSystemSCO); err != nil {
		log.Println(err)
	}

	kernelSCO, err := stix2.NewSoftware(
		"Kernel",
		stix2.OptionVersion(b1.Kernel),
	)
	if collection.Add(kernelSCO); err != nil {
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
	if collection.Add(deviceOSRel); err != nil {
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
	if collection.Add(osKernelRel); err != nil {
		log.Println(err)
	}

	//****************************
	//Process pslist
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

	for _, eachLn := range p {
		pslistLines = append(pslistLines, eachLn)
	}

	//remove headings from pslist
	pslistLines = pslistLines[2:]

	for _, eachLn := range pslistLines {
		line := strings.Fields(eachLn)

		//format pid, ppid as int64
		pid, err := strconv.ParseInt(line[2], 10, 64)
		if err != nil {
			log.Println(err)
		}

		ppid, err := strconv.ParseInt(line[4], 10, 64)
		if err != nil {
			log.Println(err)
		}

		p1 := processID{
			Name: line[6],
			Pid:  pid,
			PPid: ppid,
		}

		//File SCO for name
		fileSCO, err := stix2.NewFile(
			p1.Name,
			stix2.Hashes{},
		)
		if err != nil {
			log.Println(err)
		}
		if collection.Add(fileSCO); err != nil {
			log.Println(err)
		}

		//Process SCO for pid
		processSCO, err := stix2.NewProcess(
			stix2.OptionPID(p1.Pid),
		)
		if err != nil {
			log.Println(err)
		}
		if collection.Add(processSCO); err != nil {
			log.Println(err)
		}

		fileProcessRel, err := stix2.NewRelationship(
			"created_by",
			processSCO.ID,
			fileSCO.ID,
		)
		if err != nil {
			log.Println(err)
		}
		if collection.Add(fileProcessRel); err != nil {
			log.Println(err)
		}

		osFileRel, err := stix2.NewRelationship(
			"has",
			operatingSystemSCO.ID,
			fileSCO.ID,
		)
		if err != nil {
			log.Println(err)
		}
		if collection.Add(osFileRel); err != nil {
			log.Println(err)
		}

	}
}

//vol3Win processes pslist files from windows 10 dumps
//to create STIX 2.1 objects
func vol3Win(p []string) {

	var pslistLines []string

	//****************************
	//Process windows pslist
	//****************************

	/*
		0 *
		1 |
		2 4404				(PID)
		3 |
		4 916				(PPID)
		5 |
		6 WinStore.App.e	(Name)
		7 |
		8 0xab0fb8df9080	(Offset)
		9 |
		10 12				(Threads)
		11 |
		12 -				(Handles)
		13 |
		14 1				(Session ID)
		15 |
		16 False			(Wow64)
		17 |
		18 2021-08-04		(Date)
		19 05:14:23.000000	(Time)
		20 |
		21 N/A				(Exit)
		22 |
		23 Disabled			(output)
	*/

	for _, eachLn := range p {
		pslistLines = append(pslistLines, eachLn)
	}

	//remove headings from pslist
	pslistLines = pslistLines[2:]

	for _, eachLn := range pslistLines {
		line := strings.Fields(eachLn)

		//format pid, ppid as int64
		pid, err := strconv.ParseInt(line[2], 10, 64)
		if err != nil {
			log.Println(err)
		}

		ppid, err := strconv.ParseInt(line[4], 10, 64)
		if err != nil {
			log.Println(err)
		}

		p1 := processID{
			Name:   line[6],
			Pid:    pid,
			PPid:   ppid,
			Offset: line[8],
		}

		operatingSystemSCO, err := stix2.NewSoftware(
			"Windows",
		)
		if err != nil {
			log.Println(err)
		}
		if collection.Add(operatingSystemSCO); err != nil {
			log.Println(err)
		}

		//File SCO for name
		fileSCO, err := stix2.NewFile(
			p1.Name,
			stix2.Hashes{},
		)
		if err != nil {
			log.Println(err)
		}
		if collection.Add(fileSCO); err != nil {
			log.Println(err)
		}

		//Process SCO for pid
		processSCO, err := stix2.NewProcess(
			stix2.OptionPID(p1.Pid),
		)
		if err != nil {
			log.Println(err)
		}
		if collection.Add(processSCO); err != nil {
			log.Println(err)
		}

		fileProcessRel, err := stix2.NewRelationship(
			"created_by",
			processSCO.ID,
			fileSCO.ID,
		)
		if err != nil {
			log.Println(err)
		}
		if collection.Add(fileProcessRel); err != nil {
			log.Println(err)
		}

		osFileRel, err := stix2.NewRelationship(
			"has",
			operatingSystemSCO.ID,
			fileSCO.ID,
		)
		if err != nil {
			log.Println(err)
		}
		if err = collection.Add(osFileRel); err != nil {
			log.Println(err)
		}

	}

}

func removeParenthesis(s string) string {
	re1, err := regexp.Compile(`["("]`)
	if err != nil {
		log.Println(err)
	}
	re2, err := regexp.Compile(`[")"]`)
	if err != nil {
		log.Println(err)
	}

	str1 := re1.ReplaceAllString(s, "")
	str2 := re2.ReplaceAllString(str1, "")

	return str2
}

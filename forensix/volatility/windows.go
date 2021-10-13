package volatility

import (
	"log"
	"strconv"
	"strings"

	"forensix/utils"

	"github.com/TcM1911/stix2"
)

//WinProcessID struct to hold Windows pslist info
type WinProcessID struct {
	Pid      int64
	PPid     int64
	Name     string
	Offset   string
	UID      string
	UserName string
	Time     string
}

// VolWin parses a banner []string and pslist []string to extract STIX 2.1 objects
func VolWin(pslist []string, volVer int) {

	var pslistLines []string

	//****************************
	//Sample Volatility 3 windows pslist
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

	for _, eachLn := range pslist {
		pslistLines = append(pslistLines, eachLn)
	}

	//remove headings from pslist
	pslistLines = pslistLines[2:]

	var p1 WinProcessID

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

		switch volVer {
		case 2:
			log.Fatalln("ForensIX does not support Volatility 2 files for Windows at this time.")
		case 3:
			p1 = WinProcessID{
				Name:   line[6],
				Pid:    pid,
				PPid:   ppid,
				Offset: line[8],
			}
		}

		operatingSystemSCO, err := stix2.NewSoftware(
			"Windows",
		)
		if err != nil {
			log.Println(err)
		}
		if utils.Collection.Add(operatingSystemSCO); err != nil {
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

		osFileRel, err := stix2.NewRelationship(
			"has",
			operatingSystemSCO.ID,
			fileSCO.ID,
		)
		if err != nil {
			log.Println(err)
		}
		if err = utils.Collection.Add(osFileRel); err != nil {
			log.Println(err)
		}
	}
}

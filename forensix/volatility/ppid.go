package volatility

import (
	"log"
	"strconv"
	"strings"

	"forensix/utils"

	"github.com/TcM1911/stix2"
)

//Pslist struct to hold Linux pslist info
type Pslist struct {
	Pid  int64
	PPid int64
}

// FindPPID pulls the current STIX Process SCOs from the Collection and creates a
// relationship for the parent process.
func FindPPID(pslist []string, volVer int, os string) {
	col := utils.Collection.Processes()

	var pslistLines []string
	var p1 Pslist

	for _, eachLn := range pslist {
		pslistLines = append(pslistLines, eachLn)
	}

	// remove heading
	pslistLines = pslistLines[2:]

	for _, eachLn := range pslistLines {
		line := strings.Fields(eachLn)

		if os == "linux" {
			switch volVer {
			case 2:
				//format pid, ppid, uid as int64
				pslistPID, err := strconv.ParseInt(line[2], 10, 64)
				if err != nil {
					log.Println(err)
				}

				pslistPPID, err := strconv.ParseInt(line[3], 10, 64)
				if err != nil {
					log.Println(err)
				}

				p1 = Pslist{
					Pid:  pslistPID,
					PPid: pslistPPID,
				}
			case 3:
				//format pid, ppid as int64
				pslistPID, err := strconv.ParseInt(line[2], 10, 64)
				if err != nil {
					log.Println(err)
				}
				pslistPPID, err := strconv.ParseInt(line[4], 10, 64)
				if err != nil {
					log.Println(err)
				}
				p1 = Pslist{
					Pid:  pslistPID,
					PPid: pslistPPID,
				}
			}
		} else if os == "win" {
			switch volVer {
			case 2:
				log.Fatalln("Volatility2 files for Windows is not supported at this time.")
			case 3:
				//format pid, ppid as int64
				pslistPID, err := strconv.ParseInt(line[2], 10, 64)
				if err != nil {
					log.Println(err)
				}
				pslistPPID, err := strconv.ParseInt(line[4], 10, 64)
				if err != nil {
					log.Println(err)
				}
				p1 = Pslist{
					Pid:  pslistPID,
					PPid: pslistPPID,
				}
			}
		}

		for _, v := range col {
			process := *v

			if p1.Pid == process.PID {

				for _, w := range col {
					parent := *w

					if p1.PPid == parent.PID {

						ppidRel, err := stix2.NewRelationship(
							"created_by",
							parent.ID,
							process.ID,
						)
						if err != nil {
							log.Println(err)
						}

						if utils.Collection.Add(ppidRel); err != nil {
							log.Println(err)
						}
					}
				}
			}
		}
	}

}

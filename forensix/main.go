package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"os"

	"forensix/utils"
	"forensix/volatility"
)

func main() {
	bannerPtr := flag.String("banner", "", "Location of banner.txt Volatility file")
	pslistPtr := flag.String("pslist", "", "Location of pslist.txt Volatility file")
	osPtr := flag.String("os", "", "Operating System of target device: choose \"linux\" or \"win\"")
	volPtr := flag.Int("volver", 0, "Volatility Version: choose 2 or 3")
	flag.Parse()

	//process user files
	pslistFile, err := os.Open(*pslistPtr)
	if err != nil {
		log.Println("Cannot open pslist .txt file:", err)
	}

	defer pslistFile.Close()
	pslistString := utils.ScanFile(pslistFile)
	pslistFile.Close()

	bannerFile, err := os.Open(*bannerPtr)
	if err != nil {
		log.Println("Cannot open banner .txt file:", err)
	}
	defer bannerFile.Close()
	bannerString := utils.ScanFile(bannerFile)
	bannerFile.Close()

	volPtrValue := *volPtr
	osPtrValue := *osPtr

	if volPtrValue == 2 {
		log.Println("Volatility 2")
	} else if volPtrValue == 3 {
		log.Println("Volatility 3")
	} else {
		log.Fatalln("Volatility version not idenfitied. Please use -volver flag and choose either \"2\" or \"3\". (i.e. -volver 2) ")
	}

	// Process pslists and banners
	if *osPtr == "linux" {
		log.Println("Processing Linux files...")
		volatility.VolLinux(bannerString, pslistString, volPtrValue)
	} else if *osPtr == "win" {
		log.Println("Processing Windows files...")
		log.Println("ForensIX does not support Windows banners at this time. Processing pslist ..... ")
		volatility.VolWin(pslistString, volPtrValue)
	} else {
		log.Fatalln("Please select an OS version for the target machine")
	}

	// find parent processes
	if volatility.FindPPID(pslistString, volPtrValue, osPtrValue); err != nil {
		log.Println(err)
	}

	//Prep bundle to write to file
	bundle, err := utils.Collection.ToBundle()
	if err != nil {
		log.Fatalln("Error parsing collection to bundle:", err)
	}

	data, err := json.MarshalIndent(bundle, "", "\t")
	if err != nil {
		log.Fatalln("Error marshaling bundle:", err)
	}

	err = ioutil.WriteFile("forensix-bundle.json", data, 0600)
	if err != nil {
		log.Fatalln(err)
	} else {
		log.Println("Saved foresix-bundle.json")
	}
}

import sys, os

inputDirectory = sys.argv[1]

csv = open(inputDirectory + '.csv','w')

for file in os.listdir(inputDirectory):
    outString = file.split('_')[0] #BaseFilename
    inputFile = open(inputDirectory + os.sep + file,'r')
    lineList = inputFile.readlines()
    inputFile.close()
    for line in lineList:
        outString = outString + ',' + line.split()[0]
    csv.write(outString + '\n')

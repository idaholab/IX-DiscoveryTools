import sys

#Variables
maxNumberOfProcesses = 128
maxProcessNameLength = 16

#Open and read Inputfile
inputFile = sys.argv[1]
unencoded = open(inputFile,'r')
csvLines = unencoded.readlines()
unencoded.close()

#Open file to write output
encoded = open('enc_' + inputFile, 'w')

#Write Header to file
header = list(range(0, maxNumberOfProcesses + 1))
header[0] = 'Description'
header = ','.join([str(elem) for elem in header])
encoded.write(header + '\n')

#Iterate through csv lines
for line in csvLines: 
    processes = line.split(',')
    processList = []
    processCount = 1
    for process in processes:
        #Include only first X processes
        if processCount == maxNumberOfProcesses + 2: 
            break
            
        #Save device name unencoded
        if processCount == 1:
            string = processes[0]
        else:
            #Convert each character to ascii number equivalent
            characterList = [ord(char) for char in process]

            #Zero fill individual ascii character to ensure 3 digits
            zeroFilledCharacterList = []
            for character in characterList:
                zeroFilledCharacter = str(character).zfill(3)
                zeroFilledCharacterList.append(zeroFilledCharacter)
                
            #Trim to X characters
            string = ''.join(zeroFilledCharacterList[:maxProcessNameLength]).zfill(maxProcessNameLength*3)
        
        processList.append(string)
        processCount = processCount + 1
    
    #Append additional 'zero processes' to ensure maxNumberofProcesses
    while len(processList) < maxNumberOfProcesses + 1:
        processList.append('000'*maxProcessNameLength)
    
    #Join as comma seperated string
    encoded.write(','.join(processList) + '\n')

encoded.close()
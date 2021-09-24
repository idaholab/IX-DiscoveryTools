import sys
import os
import time
from datetime import datetime
import getpass
import paramiko
import subprocess

iterations = 3
baseFilename = 'ProcessList'
delay = 2
HOST_IP = '127.0.0.1'
USERNAME = 'username'
PASSWORD = 'password'

def retrieve_data_local():
    count = 0
    print()
    print('Collecting Local Process Lists...')
    for i in range(iterations):

        count = count + 1
        outputFilename = baseFilename + '_' + str(count).zfill(3)
    
        timestamp = datetime.now().strftime("%m%d%Y-%H%M%S")
    
        print('Writing (' + str(count) + '/' + str(iterations) + '): ' + outputFilename + '_' + timestamp + '.txt')
        if (sys.platform == 'posix' or sys.platform == 'linux'): #Linux
            lineCount = 1
            output = subprocess.getoutput("ps -A")
            outputList = output.split('\n')
            outputFile = open(outputFilename + '_' + timestamp + '.txt', 'a')
            for line in outputList:
                lineList = line.split()
                if len(lineList) > 0 and lineCount > 1:
                    outputFile.write(lineList[3] + '\n')
                lineCount = lineCount + 1
            outputFile.close()
        else:  #Windows
            lineCount = 1
            output = subprocess.getoutput("wmic process list brief")
            outputList = output.split('\n')
            outputFile = open(outputFilename + '_' + timestamp + '.txt', 'a')
            for line in outputList:
                lineList = line.split()
                if len(lineList) > 0 and lineCount > 5:
                    outputFile.write(lineList[1] + '\n')
                lineCount = lineCount + 1
            outputFile.close()
            
        time.sleep(delay)
            
def retrieve_data_remote(HOST_IP, USERNAME, PASSWORD):
    count = 0
    print()
    print('Connecting to Remote Host...')
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(HOST_IP, username=USERNAME, password=PASSWORD)
    
    print('Collecting Remote Process Lists...')
    for i in range(iterations):
        count = count + 1
        outputFilename = baseFilename + '_' + str(count).zfill(3)
    
        timestamp = datetime.now().strftime("%m%d%Y-%H%M%S")
    
        stdin, stdout, stderr = ssh.exec_command("ps -A")
        tempdata_linux = stdout.read()
        stdin, stdout, stderr = ssh.exec_command("wmic process list brief")
        tempdata_windows = stdout.read()
        
        ssh.close()
        
        print('Writing (' + str(count) + '/' + str(iterations) + '): ' + outputFilename + '_' + timestamp + '.txt')
                    
        if ' not found' not in tempdata_linux:
            outputFile = open(outputFilename + '_' + timestamp + '.txt', 'w')
            outputFile.write(tempdata_linux)
            outputFile.close()
        if 'is not recognized' not in tempdata_windows:
            outputFile = open(outputFilename + '_' + timestamp + '.txt', 'w')
            outputFile.write(tempdata_windows)
            outputFile.close()

        time.sleep(delay)        

try:
    baseFilename = sys.argv[1]
except:
    print('Usage: ProcessGrabber.py <Base Filename> <Iterations> <Delay in Seconds> | <Host IP> <Username> <Password>')
    print('Base filename not specified, using default: ' + baseFilename)
    
try:
    iterations = int(sys.argv[2])
except:
    print('Iterations not specified, using default: ' + str(iterations))
    
try:
    delay = int(sys.argv[3])
except:
    print('Delay not specified, using default: ' + str(delay) + ' seconds')

try:
    HOST_IP = sys.argv[4]
    USERNAME = sys.argv[5]
    PASSWORD = sys.argv[6]
    local = False  
except:
    local = True

if local == False:
    print('Remote Collection Initiated on Host ' + HOST_IP + '...')
    retrieve_data_remote(HOST_IP, USERNAME, PASSWORD)
else:    
    print('Local Collection Initiated...')
    retrieve_data_local()

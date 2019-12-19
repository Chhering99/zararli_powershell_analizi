#!/usr/bin/python3

from shutil import copyfile

'''
Total file : 365083
Total malicious file : 58020
Total clean file : 307063
'''

fileList = open("list.txt", "r", encoding="utf-8", errors="ignore")
malicious_code = ["system.io.memorystream][system.convert]::frombase64string","system.text.encoding]::ascii","exbypass-nop-whidden-ec",
"downloaddata","appdata\wmprivelege.exe","[convert]::tobase64string([system.text.encoding]::ascii.getbytes","downloadfile","system.text.encoding]::unicode.getbytes",
"whoami","netstat-ano","new-objectsystem.net.httplistener","new-object-comobjectmsxml2.xmlhttp","foreach{([int]$_-as[char])})+”$(set-item‘variable:ofs’‘‘)”|&($env:comspec[4,26,25]-join’’)",
"encodedcommand","whidden","windowstylehidden","enco","base64","wscript.shell", "url='http","hkcu:\software\microsoft"]

i = 0
j = 0
stat = False
for f in fileList:
        print(f)
        stat = False
        f = f.replace('\n','')
        try:
            psFile = open(f,"r", encoding="utf-8", errors="ignore")
            ps_code = psFile.read().replace(' ','').lower()
            for code in malicious_code:   
                if(ps_code.find(code) != -1 and stat != True):
                    i+=1
                    copyfile(f, "Malicious/"+str(i)+".ps1")
                    stat = True
            if(stat == False):
                j+=1
                copyfile(f, "Clean/"+str(j)+".ps1")
            psFile.close()
        except:
            continue

fileList.close()
print("Total malicious file : " + str(i)) 
print("Total clean file : " + str(j)) 
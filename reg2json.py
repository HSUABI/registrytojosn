# -*- encoding: utf-8 -*-
import sys
from fortools import *

def regtojson(path):

    #경로지정하면 해당경로밑의 하위키(폴더)를 싹 모아서 리스트로 반환
    def find_subkey(reg, pathlist):
        for path in pathlist:
            keyword = path.split("\\")[-1]
            info = reg.find_key(keyword)
            
            list = []
            for i in info:
                if (path in i['Search Key Path']) and ( ("\\"+path) not in i['Search Key Path']):
                    list.append(i['Search Key Path'])
        return list


    ########################레지스트리 하이브파일 읽기######################################################33

    #USRCLASS를 읽어야하는데 못읽음 
    #reg_file1 = RegistryHive.file_open("C:\\regggg\\gullabjamun.USRCLASS.DAT")#\HKEY_CURRENT_USER\SOFTWARE\Classes

    #레지스트리하이브파일 경로 설정해주세요꼮 !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    reg_file1 = RegistryHive.file_open(path+"\\NTUSER.DAT")
    reg_file2 = RegistryHive.file_open(path+"\\SYSTEM")#HKLM
    reg_file3 = RegistryHive.file_open(path+"\\SOFTWARE") #\HKEY_LOCAL_MACHINE\SOFTWARE
    reg_file4 = RegistryHive.file_open(path+"\\SAM")#HKLM


    ############################딕셔너리 설정######################################
    output= {"Program Installed" : "aa","RecentDocs":"dd","OS Version":"dd"}


    #################프로그램 설치 된거 확인#################################
    a = ["Microsoft\\Windows\\CurrentVersion\\Uninstall","WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"]
    #a = ["Microsoft\\Windows\\CurrentVersion\\Uninstall"]
    subkeys = find_subkey(reg_file3,a) #\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
    programlist=[]

    for key in subkeys:
        info = reg_file3.find_value(key)
        info = info[0]
        if info =={}:
            continue
        programlist.append(info)
    output["Program Installed"]   = programlist


    ##################문서 파일 열람#################################
    docs = []
    try:    
        info = reg_file1.Favorite.NTUSER.get_recent_docs()
        for i in info:
            docs.append(i)
    except:
        print("recent_docs 문서파일 열람 기록 분석중 ntuser 오류있어서 스킵")

    try:    
        info = reg_file1.Favorite.NTUSER.get_ms_office()
        for i in info:
            docs.append(i)
    except:
        print("ms_office 문서파일 열람 기록 분석중 ntuser 오류있어서 스킵")

    try:    
        info = reg_file1.Favorite.NTUSER.get_HWP()
        print(info)
        for i in info:
            docs.append(i)
    except:
        print("HWP 문서파일 열람 기록 분석중 ntuser 오류있어서 스킵")





    output["RecentDocs"] = docs


    ##################운영체제 버전확인###############################
    #HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion  
    os = []
    info = reg_file3.find_value("Microsoft\\Windows NT\\CurrentVersion")
    os = info
    output["OS Version"] = os





    #####################json 파일 형식 맞추기위해 짜잘한 작업들하기####################
    output = str(output)
    output = output.replace("\"",'changechangechange1')
    output = output.replace("'",'"')
    output = output.replace('\\x','\\\\x')
    output = output.replace('b"\\\\x','"\\\\x')

    output = output.replace("changechangechange1",'\'')
    output = output.replace("b'\\\\x",'"\\\\x')
    output = output.replace('xce"J',"xce'J")
    output = output.replace("', ",'", ')


    #반환값은 dictionary를 문자열로 바꿔준 output임
    #왜냐하면 f.write할때 문자열로 넣어야하기떄문
    return output



#>python reg2json.py c:\regggg
reg_path = sys.argv[1]

if len(sys.argv) != 2:
    print("Insufficient arguments")
    sys.exit()

#testoutput = regtojson("C:\\regggg")
testoutput = regtojson(reg_path)
f = open("./output.json", 'w', -1,'utf8')
f.write(testoutput)
f.close()

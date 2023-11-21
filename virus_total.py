# -*- coding: utf-8 -*-
import urllib.parse
import urllib.request
import json
import time

# 모듈 선언
VT_KEY = '' # virus_total 접속에 필요한 api키
# 바이러스토탈 api키, 가입 후 제공받을 수 있음 1분에 4개 제한
HOST = 'www.virustotal.com'
SCAN_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'
REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
md5str = ''
# md5 값 담을 변수 선언

fields = [('apikey', VT_KEY)]
# 전달할 apikey 값 담기
txtf = open('hash.txt', 'r')
# test.txt에 md5값을 담아두고 'r'  read함

while True:
    # while문으로 반복돌림
    line = txtf.readline()
    md5str = line.strip('\n')
    # 한 줄 씩 읽음. 개행으로 구분함
    if not md5str:
        break
    parameters = {'resource': md5str, 'apikey': VT_KEY}
    data = urllib.parse.urlencode(parameters).encode('utf-8')
    req = urllib.request.Request(REPORT_URL, data)
    response = urllib.request.urlopen(req)
    data = response.read()

    data = json.loads(data)
    # 데이터를 json 형태로 읽어서 data 변수에 담음.
    md5 = data.get('md5', {})
    scan = data.get('scans', {})
    # 바이러스토탈에서 응답값 던져줄 때 내가 필요한  md5값과 scan결과 값 파싱
    keys = scan.keys()
    # keys는 바이러스토탈에서 지원하는 백신엔진 목록
    print(" ")
    print("==========================Virus Total Loading==========================")
    print("=========================================================================")
    # 바이러스 토탈이 지원하는 백신 중 하나도 탐지되는게 없으면 '{}'값이 md5에 들어감. 그러므로 "no match"출력
    if not md5:
        print(" !!!!!!!!! Sorry, No Match !!!!!!!!! ")
    else:
        print(md5)

    print("==========================================================================")
    time.sleep(20)
    # 1분에 4개로 제한되어 있어, 20초씩 sleep시켜줌.
    for key in keys:
        if key == 'AhnLab-V3':
            print('%-20s : %s' % (key, scan[key]['result']))
        elif key == 'ALYac':
            print('%-20s : %s' % (key, scan[key]['result']))
        #elif key == 'nProtectOnline': #ME_11.17_VirusTotal에서는 'nProtect'이 아닌 'nProtectOnline'이라는 문자열을 사용
            #print('%-20s : %s' % (key, scan[key]['result'])) #ME_11.17_결과출력누락의 원인을 파악하지 못해 생략
        elif key == 'ViRobot':
            print('%-20s : %s' % (key, scan[key]['result']))

txtf.close()
print("+++++++++++++++++++++++++++clear+++++++++++++++++++++++++++")

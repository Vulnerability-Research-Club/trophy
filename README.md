# 프로젝트 실적 기록방법

```sh
# 최초 본인 Local git repository에 config 수행
$ ./setup-hook.sh

# 본인 팀 json 팀 파일 수정
$ vi win-gpu.json
...

# add + commit + push
$ git add *
$ git commit -m "YOUR MESSAGE"
$ git push

# push할때 자동으로 스크립트를 실행함
```

# 연구 진행사항 JSON Specification

본 JSON 형식은 **구현(Implementation), 퍼징(Fuzzing), 감시(Auditing), 보고(Reporting), 제출(Submissions)** 등의 **보안 연구 활동을 기록하기 위해** 설계되었습니다.  

```
주의사항: 각 엔트리 별 name으로 표시된 부분은 내용이 unique해야 함. 해당 name이 DB내에서 key로 사용되기 때문임
```

## 1. Implementation (구현)  

- **`product`** *(array, 리스트)*: 보안 연구에서 개발된 보안 도구 또는 제품 목록을 저장하는 배열입니다
  - **`name`** *(string, 필수)*: The name of the product. *(제품의 이름)*  
  - **`description`** *(string, 선택)*: A short description of the product. *(제품에 대한 간략한 설명)*  
  - **`version`** *(string, 선택)*: The version of the product. *(제품의 버전 정보)*  

### Example (예시):  
```json
{
  "implementation": {
    "product": [
      {
        "name": "SecurityAnalyzer",
        "description": "A tool for analyzing vulnerabilities",
        "version": "1.2"
      }
    ]
  }
}
```

## 2. Fuzzing (퍼징)  

- **`fuzzer`** *(array, 리스트)*: 연구에서 사용된 퍼저(fuzzer)의 목록을 저장하는 배열입니다.
  - **`name`** *(string, 필수)*: The name of the fuzzer. *(퍼저의 이름)*  
  - **`target`** *(string, 필수)*: The system, software, or file format being fuzzed. *(퍼징할 대상 시스템, 소프트웨어 또는 파일 형식)*  
  - **`description`** *(string, 선택)*: A brief description of the fuzzer. *(퍼저에 대한 설명)*  
  - **`status`** *(string, 필수)*: The current status of the fuzzer. *(퍼징 진행 상태)*  

### Example (예시):  
```json
{
  "fuzzing": {
    "fuzzer": [
      {
        "name": "AFL",
        "target": "PNG Image Parser",
        "description": "Fuzzing PNG decoding routines",
        "status": "in-progress"
      }
    ]
  }
}
```

## 3. Auditing (감시)  

- **`target`** *(object, 객체)*: 감사 대상 시스템 또는 소프트웨어를 저장하는 객체입니다.
  - **`name`** *(string, 필수)*: The name of the target system. *(감사 대상 시스템의 이름)*  
  - **`status`** *(string, 필수)*: The current auditing status. *(현재 감사 상태)*  

### Example (예시):  
```json
{
  "auditing": {
    "target": {
      "name": "Web Application Firewall",
      "status": "in-progress"
    }
  }
}
```

## 4. Reporting (보고)  

- **`num_accumulated_crash`** *(integer, 필수)*: (발견된 총 충돌(crash) 개수입니다.
- **`report`** *(array, 선택)*: 보안 취약점 분석 보고서 목록을 저장하는 배열입니다.
  - **`link`** *(string, 필수)*: A URL linking to the report. *(보고서의 URL)*  
  - **`description`** *(string, 선택)*: A short description of the report. *(보고서에 대한 간략한 설명)*  
- **`cve`** *(array, 선택)*: 발견된 CVE(Common Vulnerabilities and Exposures) 목록을 저장하는 배열입니다.
  - **`link`** *(string, 필수)*: A URL linking to the CVE record. *(CVE 상세 페이지의 URL)*  
  - **`description`** *(string, 선택)*: A short description of the CVE. *(CVE에 대한 간략한 설명)*  

### Example (예시):  
```json
{
  "reporting": {
    "num_accumulated_crash": 12,
    "report": [
      {
        "link": "https://example.com/report1",
        "description": "Memory corruption vulnerability analysis"
      }
    ],
    "cve": [
      {
        "link": "https://cve.mitre.org/CVE-2025-7890",
        "description": "Buffer overflow in networking library"
      }
    ]
  }
}
```

## 5. Submissions (제출)  

- **`conference`** *(array, 선택)*: 제출된 컨퍼런스 논문의 목록을 저장하는 배열입니다.
  - **`venue`** *(string, 필수)*: The conference where the paper was submitted. *(논문이 제출된 컨퍼런스 명)*  
  - **`title`** *(string, 필수)*: The title of the paper. *(논문의 제목)*  
- **`paper`** *(array, 선택)*: 제출된 학술지 논문의 목록을 저장하는 배열입니다.
  - **`venue`** *(string, 필수)*: The journal where the paper was submitted. *(논문이 제출된 학술지 명)*  
  - **`title`** *(string, 필수)*: The title of the paper. *(논문의 제목)*  

### Example (예시):  
```json
{
  "submissions": {
    "conference": [
      {
        "venue": "Black Hat",
        "title": "Exploiting Modern Browsers"
      }
    ],
    "paper": [
      {
        "venue": "IEEE Security & Privacy",
        "title": "Mitigating Side-Channel Attacks"
      }
    ]
  }
}
```

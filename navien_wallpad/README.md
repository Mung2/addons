# Navien Wallpad Controller with RS485

## About
 - 이 애드온은 Node.js 기반으로, 경동 나비엔 월패드 제어 전용입니다. 다른 월패드는 제어할 수 없습니다.
 - 이 애드온은 [HAKorea](https://github.com/HAKorea/addons)에서 배포중인 월패드제어 애드온을 Fork하여 수정된 애드온입니다.


## Version : 1.1

## Installation

1. Home Assistant Supervisor → Add-On Store 탭으로 진입 후 우측 상단 더보기(점 세개) 버튼을 누른 후,  Repositories를 선택합니다.
2. Manage add-on repositories 창이 나오면 Add repository 란에 https://github.com/JG-Park/HAaddons 를 입력한 다음 ADD 버튼을 누릅니다.
3. Add-On Store 탭 하단에서 "Navien Wallpad Controller with RS485"를 클릭합니다.
4. "INSTALL" 버튼을 눌러 애드온을 설치합니다. 이 작업은 호스트 장치의 성능에 따라 1~10분 정도 소요됩니다.
5. INSTALL 버튼을 누르면 버튼 위에 설치 애니메이션이 나올 것입니다. 간혹 이것이 멈추더라도 REBUILD, START 버튼이 나타나지 않는 경우가 있습니다.
6. 빌드된 이미지를 내려받는 것이 아니라 직접 호스트 장치에서 빌드하는 것이므로, 장치 성능 및 인터넷 속도에 따라 1~10분의 시간이 필요합니다.
7. INSTALL 버튼을 누른 후 애니메이션이 실행되는 것은 빌드 중인 것입니다.
8. INSTALL 버튼을 여러 번 누르지 마세요. 너무 오래걸린다 싶으면 페이지를 새로고침하시면 됩니다.
9. 빌드 및 설치가 완료되면, INSTALL 버튼이 START 버튼으로 바뀝니다.
10. START 버튼을 눌러 시작하기 전, Configuration 탭에서 본인의 환경에 맞게 값들을 수정하세요.
11. Configulation이 끝나면 "START" 버튼을 눌러 애드온을 실행하시면 됩니다.

- 애드온을 최초 실행하면 share 폴더 하위에 navien_socket_wallpad.js 파일이 생성됩니다.
- 이 파일을 수정하면 소스를 수정할 수 있습니다.



## Configuration

Add-on configuration:

```yaml
model: navien
type: socket
sendDelay: 150
socket:
  deviceIP: 192.168.0.x
  port: 8899
mqtt:
  server: 192.168.0.x
  username: ""
  password: ""
  receiveDelay: 10000
```

### Option: `model` (필수)
이 애드온은 경동 나비엔 월패드 제어 전용입니다. 반드시 (model: navien)으로 고정하여 사용하셔야 합니다.

### Option: `type` (필수)
현재 이 애드온은 socket 방식만 지원합니다.

### Option: `socket` (필수)
type: socket 로 설정한 경우 아래 옵션 사용
```yaml
  deviceIP: 192.168.0.x   // TCP Server(ex: Elfin EW11)의 IP 주소
  port: 8899            // TCP Server(ex: Elfin EW11)의 포트번호
```


### Option `MQTT` (필수)
```yaml
  server: 192.168.0.x  // MQTT 서버(MQTT Broker)의 IP
  username: ""          // MQTT ID(기본 값은 비워둠, 보안 설정시에만 사용)
  password: ""          // MQTT PW(기본 값은 비워둠, 보안 설정시에만 사용)
  receivedelay: 10000    // 전송후 메시지 수신 지연 시간 1/1000초 단위
```



## Home Assistant Configuration

### Configuration.yaml 에 추가

```yaml
- platform: mqtt
  name: 'Light1'
  state_topic: 'homenet-js/Light1/status'
  command_topic: 'homenet-js/Light1/command'

- platform: mqtt
  name: 'Light2'
  state_topic: 'homenet-js/Light2/status'
  command_topic: 'homenet-js/Light2/command'

- platform: mqtt
  name: 'Light3'
  state_topic: 'homenet-js/Light3/status'
  command_topic: 'homenet-js/Light3/command'
```

### Home Assistant에서 사전 설정 할 것
- MQTT 를 통합 구성 요소에서 반드시 구성해야 합니다.
- GUI 상으로 통합 구성요소를 추가해도 좋고, 아래 내용을 참고해서 Configuration.yaml 파일에 수동으로 추가해줘도 좋습니다.

```yaml
mqtt:
  broker: 192.168.0.x
```



## Support

궁금한 점이 있으신가요??
[JGP Space](https://jgpark.kr/)에서 이 월패드 애드온에 대한 문의를 받고 있습니다.



또한 월패드 연동(RS485)에 대한 전반적인 정보와 그에 따른 문의는 아래에서 하실 수 있습니다.:

- The [Home Assistant Korean Community][github].
- The [Home Assistant 네이버카페][forum].



[forum]: https://cafe.naver.com/koreassistant
[github]: https://github.com/HAKorea/addons

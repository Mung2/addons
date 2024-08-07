/**
 * RS485 Homegateway for daelimAPT
 * @소스 공개 : Daehwan, Kang
 * @경동 나비엔 용으로 수정 : JGP
 * @최종수정일 2021-02-16
 */

 /**
  Navien WallPad Socket
 */

 const net = require('net');
 const Delimiter = require('@serialport/parser-delimiter')
 const mqtt = require('mqtt');

 const CONFIG = require('/data/options.json');
 const CONST = {
   // MQTT 브로커
   mqttBroker: 'mqtt://' + CONFIG.mqtt.server,
   // MQTT 수신 Delay(ms)
   mqttDelay: CONFIG.mqtt.receiveDelay,
   mqttUser: CONFIG.mqtt.username,
   mqttPass: CONFIG.mqtt.password,

   clientID: 'Navien',

   // 기기별 상태 및 제어 코드(HEX),
   DEVICES: [
     {name: 'Light1', status: 'ON' ,  commandHex: Buffer.from([0xf7, 0x0e, 0x11, 0x41, 0x01, 0x01, 0xa9, 0x02])},
     {name: 'Light1', status: 'OFF',  commandHex: Buffer.from([0xf7, 0x0e, 0x11, 0x41, 0x01, 0x00, 0xa8, 0x00])},
     {name: 'Light2', status: 'ON' ,  commandHex: Buffer.from([0xf7, 0x0e, 0x12, 0x41, 0x01, 0x01, 0xaa, 0x04])},
     {name: 'Light2', status: 'OFF',  commandHex: Buffer.from([0xf7, 0x0e, 0x12, 0x41, 0x01, 0x00, 0xab, 0x04])},
     {name: 'Light3', status: 'ON' ,  commandHex: Buffer.from([0xf7, 0x0e, 0x13, 0x41, 0x01, 0x01, 0xab, 0x06])},
     {name: 'Light3', status: 'OFF',  commandHex: Buffer.from([0xf7, 0x0e, 0x13, 0x41, 0x01, 0x00, 0xaa, 0x04])},
   ],
   SCENES: [ // Light1 - Light2 - Light3
     {devicestatus: [{name: 'Light1', status:  'ON'}, {name: 'Light2', status:  'ON'}, {name: 'Light3', status:  'ON'}], sceneHex: Buffer.from([0x0e, 0x1f, 0x81, 0x04, 0x00, 0x01, 0x01, 0x01, 0x62, 0x0e])},
     {devicestatus: [{name: 'Light1', status: 'OFF'}, {name: 'Light2', status:  'ON'}, {name: 'Light3', status:  'ON'}], sceneHex: Buffer.from([0x0e, 0x1F, 0x81, 0x04, 0x00, 0x00, 0x01, 0x01, 0x63, 0x0E])},
     {devicestatus: [{name: 'Light1', status: 'OFF'}, {name: 'Light2', status: 'OFF'}, {name: 'Light3', status:  'ON'}], sceneHex: Buffer.from([0x0e, 0x1F, 0x81, 0x04, 0x00, 0x00, 0x00, 0x01, 0x62, 0x0C])},
     {devicestatus: [{name: 'Light1', status: 'OFF'}, {name: 'Light2', status: 'OFF'}, {name: 'Light3', status: 'OFF'}], sceneHex: Buffer.from([0x0E, 0x1F, 0x81, 0x04, 0x00, 0x00, 0x00, 0x00, 0x63, 0x0C])},
     {devicestatus: [{name: 'Light1', status: 'OFF'}, {name: 'Light2', status:  'ON'}, {name: 'Light3', status: 'OFF'}], sceneHex: Buffer.from([0x0E, 0x1F, 0x81, 0x04, 0x00, 0x00, 0x01, 0x00, 0x62, 0x0C])},
     {devicestatus: [{name: 'Light1', status:  'ON'}, {name: 'Light2', status:  'ON'}, {name: 'Light3', status: 'OFF'}], sceneHex: Buffer.from([0x0E, 0x1F, 0x81, 0x04, 0x00, 0x01, 0x01, 0x00, 0x63, 0x0E])},
     {devicestatus: [{name: 'Light1', status:  'ON'}, {name: 'Light2', status: 'OFF'}, {name: 'Light3', status:  'ON'}], sceneHex: Buffer.from([0x0E, 0x1F, 0x81, 0x04, 0x00, 0x01, 0x00, 0x01, 0x63, 0x0E])},
     {devicestatus: [{name: 'Light1', status:  'ON'}, {name: 'Light2', status: 'OFF'}, {name: 'Light3', status: 'OFF'}], sceneHex: Buffer.from([0x0E, 0x1F, 0x81, 0x04, 0x00, 0x01, 0x00, 0x00, 0x62, 0x0C])},
   ],
   TOPIC_PREFIX: 'homenet-js'
 };
 var log = (...args) => console.log('[' + new Date().toLocaleString('ko-KR', {timeZone: 'Asia/Seoul'}) + ']', args.join(' '));

 var homeStatus = {};
 var lastReceive = new Date().getTime();
 var mqttReady = false;
 var queue = new Array();

 const client  = mqtt.connect(CONST.mqttBroker);
 client.on('connect', () => {
     var device_list = Array.from(new Set(CONST.DEVICES.map(function (e) { return e.name } )));
     var topics = new Array();
     device_list.forEach(device_name => {
       topics.push(CONST.TOPIC_PREFIX + '/' + device_name + '/status');
       topics.push(CONST.TOPIC_PREFIX + '/' + device_name + '/command');
     })
     client.subscribe(topics, (err) => {if (err) log('MQTT Subscribe fail! -', CONST.DEVICE_TOPIC) });
 });

 const sock = new net.Socket();
 sock.connect(CONFIG.socket.port, CONFIG.socket.deviceIP, function() {
   log('[Socket] 소켓 서버(EW11 등)에 연결되었습니다.');
 });
 const parser = sock.pipe(new Delimiter({ delimiter: Buffer.from([0xf7]) }));

 parser.on('data', buffer => {
   var sceneMatched = CONST.SCENES.find(scene => buffer.equals(scene.sceneHex));

   if(sceneMatched && mqttReady) {
     sceneMatched.devicestatus.forEach(device => {
       var topic = CONST.TOPIC_PREFIX + '/' + device.name + '/status';
       if(device.status !== homeStatus[topic]) {
         client.publish(topic, device.status, {retain: true});
         log('[MQTT] (발행)', topic, ':', device.status);
         return;
       }
     });
   }
 });

 client.on('message', (topic, message) => {
   if(mqttReady) {
     var topics = topic.split('/');
     var msg = message.toString();
     if(topics[2] == 'status') {
       log('[MQTT] (청취)', topic, message, '[현재상태]', homeStatus[topic], '->', message.toString());
       homeStatus[topic] = message.toString();
       return;
     }

     var objFound = CONST.DEVICES.find(e => topics[1] === e.name && topics[2] == 'command' && msg === e.status);

     if(objFound == null) return;

     sock.write(objFound.commandHex);
     log('[Socket] (Send)', objFound.name, '->', objFound.status);
   }
 });

 setTimeout(() => {mqttReady=true; log('MQTT 준비됨...')}, CONST.mqttDelay);

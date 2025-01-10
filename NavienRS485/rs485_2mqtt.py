import paho.mqtt.client as mqtt
import re
from json import dumps as json_dumps
from functools import reduce
from collections import defaultdict
import json
import threading
import queue
import random
import time
import logging

# 전역 변수 설정
send_lock = threading.Lock()  # 멀티스레딩 락
ack_data = []  # ACK 데이터 리스트
ack_q = queue.Queue()  # ACK 대기 큐

MQTT_USERNAME = 'admin'
MQTT_PASSWORD = 'GoTjd8864!'
MQTT_SERVER = '192.168.219.202'
MQTT_PORT = 1883
ROOT_TOPIC_NAME = 'rs485_2mqtt'
HOMEASSISTANT_ROOT_TOPIC_NAME = 'homeassistant'

class Device:
    def __init__(self, device_name, device_id, device_subid, device_class, child_devices, mqtt_discovery, optional_info):
        self.device_name = device_name
        self.device_id = device_id
        self.device_subid = device_subid
        self.device_unique_id = f'rs485_{self.device_id}_{self.device_subid}'
        self.device_class = device_class
        self.child_devices = child_devices
        self.mqtt_discovery = mqtt_discovery
        self.optional_info = optional_info

        self.status_messages = defaultdict(list)
        self.command_messages = {}

    def register_status(self, message_flag, attr_name, regex, topic_class, device_name=None, process_func=lambda v: v):
        device_name = device_name or self.device_name
        self.status_messages[message_flag].append({
            'regex': regex, 'process_func': process_func, 
            'device_name': device_name, 'attr_name': attr_name, 
            'topic_class': topic_class
        })

    def register_command(self, message_flag, attr_name, topic_class, controll_id=None, process_func=lambda v: v):
        self.command_messages[attr_name] = {
            'message_flag': message_flag, 'attr_name': attr_name, 
            'topic_class': topic_class, 'process_func': process_func,
            'controll_id': controll_id
        }

    def parse_payload(self, payload_dict):
        result = {}
        for status in self.status_messages[payload_dict['message_flag']]:
            parse_status = re.match(status['regex'], payload_dict['data'])
            if len(self.child_devices)>0:
                for index, child_device in enumerate(self.child_devices):
                    topic = f"{ROOT_TOPIC_NAME}/{self.device_class}/{child_device}{self.device_name}/{status['attr_name']}"
                    if (status['attr_name']=="power" or status['attr_name']=="away_mode") and self.device_class=="climate":
                        result[topic] = status['process_func'](int(parse_status.group(1), 16) & (1 << index))
                    else:
                        result[topic] = status['process_func'](parse_status.group(index+1))
            else:
                topic = f"{ROOT_TOPIC_NAME}/{self.device_class}/{self.device_name}/{status['attr_name']}"    
                result[topic] = status['process_func'](parse_status.group(1))
        return result

    def get_command_payload(self, attr_name, attr_value, child_name=None):
        attr_value = self.command_messages[attr_name]['process_func'](attr_value)
        if child_name is not None:
            idx = [child + self.device_name for child in self.child_devices].index(child_name)
            command_payload = ['f7', self.device_id, self.command_messages[attr_name]['controll_id'][idx],
                            self.command_messages[attr_name]['message_flag'], '01', attr_value]
        elif self.device_id=='33' and self.command_messages[attr_name]['message_flag']=='81':
            command_payload = ['f7', self.device_id, self.device_subid,
                            self.command_messages[attr_name]['message_flag'], '03', '00', attr_value, '00']
        else:            
            command_payload = ['f7', self.device_id, self.device_subid,
                            self.command_messages[attr_name]['message_flag'], '00']
        command_payload.append(Wallpad.xor(command_payload))
        command_payload.append(Wallpad.add(command_payload))
        return bytearray.fromhex(' '.join(command_payload))

    def get_mqtt_discovery_payload(self):        
        discovery_list = list()
        if len(self.child_devices)>0:            
            for idx, child in enumerate(self.child_devices):
                unique_id_join = self.device_unique_id + str(idx)
                device_name_join = child + self.device_name
                topic = f"{HOMEASSISTANT_ROOT_TOPIC_NAME}/{self.device_class}/{unique_id_join}/config"
                result = {
                    '~': f"{ROOT_TOPIC_NAME}/{self.device_class}/{device_name_join}",
                    'name': device_name_join,
                    'uniq_id': unique_id_join,
                    'device_class' : self.device_class,
                }
                result.update(self.optional_info)
                for status_list in self.status_messages.values():
                    for status in status_list:
                        result[status['topic_class']] = f"~/{status['attr_name']}"

                for status_list in self.command_messages.values():
                    result[status_list['topic_class']] = f"~/{status_list['attr_name']}/set"

                result['device'] = {
                    'identifiers': unique_id_join,
                    'name': device_name_join
                }
                discovery_list.append((topic, json_dumps(result, ensure_ascii=False)))
        else:
            topic = f"{HOMEASSISTANT_ROOT_TOPIC_NAME}/{self.device_class}/{self.device_unique_id}/config"            
            result = {
                '~': f"{ROOT_TOPIC_NAME}/{self.device_class}/{self.device_name}",
                'name': self.device_name,
                'uniq_id': self.device_unique_id,
            }
            result.update(self.optional_info)
            for status_list in self.status_messages.values():
                for status in status_list:
                    result[status['topic_class']] = f"~/{status['attr_name']}"

            for status_list in self.command_messages.values():
                result[status_list['topic_class']] = f"~/{status_list['attr_name']}/set"

            result['device'] = {
                'identifiers': self.device_unique_id,
                'name': self.device_name
            }
            discovery_list.append((topic, json_dumps(result, ensure_ascii=False)))
            
        return discovery_list

    def get_status_attr_list(self):
        return list(set(status['attr_name'] for status_list in self.status_messages.values() for status in status_list))

class Wallpad:
    def __init__(self):
        self.mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        self.mqtt_client.on_message = self.on_raw_message  # on_message 핸들러 설정
        self.mqtt_client.on_disconnect = self.on_disconnect
        self.mqtt_client.username_pw_set(username=MQTT_USERNAME, password=MQTT_PASSWORD)
        self.mqtt_client.connect(MQTT_SERVER, 1883)
        self._device_list = []

    def listen(self):
        self.register_mqtt_discovery()
        for topic_list in [(topic, 2) for topic in [f"{ROOT_TOPIC_NAME}/dev/raw"] + self.get_topic_list_to_listen()]:
            print(topic_list)
        self.mqtt_client.subscribe([(topic, 2) for topic in [f"{ROOT_TOPIC_NAME}/dev/raw"] + self.get_topic_list_to_listen()])
        self.mqtt_client.loop_forever()

    def on_raw_message(self, client, userdata, msg):
        """
        MQTT 메시지를 수신했을 때 처리하는 콜백 함수입니다.
        수신한 메시지에 대해 적절한 처리를 해주세요.
        """
        print(f"Received message: {msg.payload.decode()} on topic: {msg.topic}")

        # 예시: 특정 주제에 대해 필터링하고 다른 작업을 수행하는 코드 추가
        if msg.topic == "some/topic":
            print(f"Processing message on {msg.topic}")
        # 그 외 필요한 작업을 추가할 수 있습니다.

    def on_disconnect(self, client, userdata, rc):
        """MQTT 클라이언트가 연결 끊겼을 때 호출되는 콜백 함수입니다."""
        if rc != 0:
            print(f"Disconnected from MQTT broker with code {rc}")
        else:
            print("Successfully disconnected from MQTT broker.")


    def register_mqtt_discovery(self):
        for device in self._device_list:
            if device.mqtt_discovery:                
                for topic, payload in device.get_mqtt_discovery_payload():
                    self.mqtt_client.publish(topic, payload, qos=2, retain=True)

    def add_device(self, device_name, device_id, device_subid, device_class, child_devices=[], mqtt_discovery=True, optional_info={}):
        device = Device(device_name, device_id, device_subid, device_class, child_devices, mqtt_discovery, optional_info)
        self._device_list.append(device)
        return device

    def get_device(self, **kwargs):
        device = next((d for d in self._device_list if 
                       d.device_name == kwargs.get('device_name') or 
                       kwargs.get('device_name') in [child + d.device_name for child in d.child_devices] or
                      (d.device_id == kwargs.get('device_id') and d.device_subid == kwargs.get('device_subid'))), None)
        if device:
            return device
        else:
            raise ValueError(f"Device with id {kwargs.get('device_id')} and subid {kwargs.get('device_subid')} not found.")

    def get_topic_list_to_listen(self):
        return [f"{ROOT_TOPIC_NAME}/{device.device_class}/{child_name}{device.device_name}/{attr_name}/set" 
                for device in self._device_list 
                for child_name in (device.child_devices if device.child_devices else [""])  
                for attr_name in device.get_status_attr_list()]

    def send_packet(self, client, payload, log=None, check_ack=True):
        send_lock.acquire()  # 락을 획득하여 동시 실행 방지
        ack_data.clear()  # ACK 데이터를 초기화
        ret = False
        for seq_h in seq_t_dic.keys():  # 시퀀스 키에 대해 반복 (ACK을 못 받으면 다른 시퀀스로 재시도)
            send_data = header_h + payload + seq_h + '00' + chksum(payload) + trailer_h
            try:
                if client.write(bytearray.fromhex(send_data)) == False:
                    raise Exception('Not ready')
            except Exception as ex:
                logging.error("[RS485] Write error.[{}]".format(ex))
                break
            if log is not None:
                logging.info('[SEND|{}] {}'.format(log, send_data))
            
            if not check_ack:
                time.sleep(1)  # ACK을 기다리지 않고 바로 반환
                ret = send_data
                break
            
            ack_data.append(type_h_dic['ack'] + seq_h + '00' + payload)  
            try:
                ack_q.get(True, 1.3 + 0.2 * random.random())
                logging.info('[ACK] OK')
                ret = send_data
                break
            except queue.Empty:
                logging.warning('[ACK] Timeout, retrying...')
                pass
        
        if not ret:
            logging.info('[RS485] Send failed. Closing connection and retrying...')
            client.close() 
        
        ack_data.clear()  
        send_lock.release()  
        return ret

    def _process_command_message(self, client, msg):
        topic_split = msg.topic.split('/')
        try:            
            device = self.get_device(device_name=topic_split[2])
            if len(device.child_devices) > 0:
                payload = device.get_command_payload(topic_split[3], msg.payload.decode(), child_name=topic_split[2])
            else:
                payload = device.get_command_payload(topic_split[3], msg.payload.decode())
            
            send_result = self.send_packet(client, payload, log=topic_split[3], check_ack=True)

            if send_result:
                logging.info("Command sent successfully: {}".format(send_result))
            else:
                logging.error("Failed to send command after retries.")
        except ValueError as e:
            print(e)
            client.publish(f"{ROOT_TOPIC_NAME}/dev/error", f"Error: {str(e)}", qos=1, retain=True)

    # 기존의 나머지 메소드들...

            
    def _parse_payload(self, payload_hexstring):
        return re.match(r'f7(?P<device_id>0e|12|32|33|36)(?P<device_subid>[0-9a-f]{2})(?P<message_flag>[0-9a-f]{2})(?:[0-9a-f]{2})(?P<data>[0-9a-f]*)(?P<xor>[0-9a-f]{2})(?P<add>[0-9a-f]{2})', payload_hexstring).groupdict()

    def _publish_device_payload(self, client, payload_dict):
        # print(payload_dict)
        device = self.get_device(device_id=payload_dict['device_id'], device_subid=payload_dict['device_subid'])
        for topic, value in device.parse_payload(payload_dict).items():
            # print(topic)
            # print(value)
            client.publish(topic, value, qos=1, retain=False)

    def on_disconnect(self, client, userdata, rc):
        raise ConnectionError

# 새로운 Wallpad 클래스와 Device 클래스 정의
wallpad = Wallpad()

packet_2_payload_percentage = {'00': '0', '01': '1', '02': '2', '03': '3'}
packet_2_payload_oscillation = {'03': 'oscillate_on', '00': 'oscillation_off', '01': 'oscillate_off'}
### 전열교환기 ###
optional_info = {'optimistic': 'false', 'speed_range_min': 1, 'speed_range_max': 3}
전열교환기 = wallpad.add_device(device_name = '전열교환기', device_id = '32', device_subid = '01', device_class = 'fan', optional_info = optional_info)
전열교환기.register_status(message_flag = '01', attr_name = 'availability', topic_class ='availability_topic',      regex = r'()', process_func = lambda v: 'online')
전열교환기.register_status(message_flag = '81', attr_name = 'power',        topic_class ='state_topic',             regex = r'00(0[01])0[0-3]0[013]00', process_func = lambda v: 'ON' if v == '01' else 'OFF')
전열교환기.register_status(message_flag = 'c1', attr_name = 'power',        topic_class ='state_topic',             regex = r'00(0[01])0[0-3]0[013]00', process_func = lambda v: 'ON' if v == '01' else 'OFF')
전열교환기.register_status(message_flag = '81', attr_name = 'percentage',   topic_class ='percentage_state_topic',  regex = r'000[01](0[0-3])0[013]00', process_func = lambda v: packet_2_payload_percentage[v])
전열교환기.register_status(message_flag = 'c2', attr_name = 'percentage',   topic_class ='percentage_state_topic',  regex = r'000[01](0[0-3])0[013]00', process_func = lambda v: packet_2_payload_percentage[v])
전열교환기.register_status(message_flag = '81', attr_name = 'heat',         topic_class ='oscillation_state_topic', regex = r'000[01]0[0-3](0[013])00', process_func = lambda v: packet_2_payload_oscillation[v])
전열교환기.register_status(message_flag = 'c3', attr_name = 'heat',         topic_class ='oscillation_state_topic', regex = r'000[01]0[0-3](0[013])00', process_func = lambda v: packet_2_payload_oscillation[v])

전열교환기.register_command(message_flag = '41', attr_name = 'power',       topic_class = 'command_topic', process_func = lambda v: '01' if v =='ON' else '00')
전열교환기.register_command(message_flag = '42', attr_name = 'percentage',  topic_class = 'percentage_command_topic', process_func = lambda v: {payload: packet for packet, payload in packet_2_payload_percentage.items()}[v])
전열교환기.register_command(message_flag = '43', attr_name = 'heat',        topic_class = 'oscillation_command_topic', process_func = lambda v: {payload: packet for packet, payload in packet_2_payload_oscillation.items()}[v])

# 가스차단기
optional_info = {'optimistic': 'false'}
가스 = wallpad.add_device(device_name='가스', device_id='12', device_subid='01', device_class='switch', optional_info=optional_info)
가스.register_status(message_flag='01', attr_name='availability', topic_class='availability_topic', regex=r'()', process_func=lambda v: 'online')
가스.register_status(message_flag='81', attr_name='power', topic_class='state_topic', regex=r'0(0[02])0', process_func=lambda v: 'ON' if v == '02' else 'OFF')
가스.register_command(message_flag='41', attr_name='power', topic_class='command_topic', process_func=lambda v: '00' if v == 'ON' else '04')

# 조명
optional_info = {'optimistic': 'false'}
거실 = wallpad.add_device(device_name='거실', device_id='0e', device_subid='1f', child_devices = ["거실", "복도"], device_class='light', optional_info=optional_info)
안방 = wallpad.add_device(device_name='안방', device_id='0e', device_subid='2f', child_devices = ["안방"], device_class='light', optional_info=optional_info)
끝방 = wallpad.add_device(device_name='끝방', device_id='0e', device_subid='3f', child_devices = ["끝방"], device_class='light', optional_info=optional_info)
중간방 = wallpad.add_device(device_name='중간방', device_id='0e', device_subid='4f', child_devices = ["중간방", "펜트리"], device_class='light', optional_info=optional_info)
주방 = wallpad.add_device(device_name='주방', device_id='0e', device_subid='5f', child_devices = ["주방", "식탁"], device_class='light', optional_info=optional_info)

거실.register_status(message_flag='81', attr_name='power', topic_class='state_topic', regex=r'00([012345][23])(0[01])', process_func=lambda v: 'ON' if v in ['13', '23', '33', '43', '53'] else 'OFF' if v == '02' else 'ON' if v == '01' else 'OFF')
거실.register_command(message_flag='41', attr_name='power', topic_class='command_topic', controll_id=['11','12'], process_func=lambda v: '01' if v == 'ON' else '00')

안방.register_status(message_flag='81', attr_name='power', topic_class='state_topic', regex=r'0[01](0[01])', process_func=lambda v: 'ON' if v == '01' else 'OFF')
안방.register_command(message_flag='41', attr_name='power', topic_class='command_topic', controll_id=['21'], process_func=lambda v: '01' if v == 'ON' else '00')

끝방.register_status(message_flag='81', attr_name='power', topic_class='state_topic', regex=r'0[01](0[01])', process_func=lambda v: 'ON' if v == '01' else 'OFF')
끝방.register_command(message_flag='41', attr_name='power', topic_class='command_topic', controll_id=['31'], process_func=lambda v: '01' if v == 'ON' else '00')

중간방.register_status(message_flag='81', attr_name='power', topic_class='state_topic', regex=r'0[01](0[01])(0[01])', process_func=lambda v: 'ON' if v == '01' else 'OFF')
중간방.register_command(message_flag='41', attr_name='power', topic_class='command_topic', controll_id=['41','42'], process_func=lambda v: '01' if v == 'ON' else '00')

주방.register_status(message_flag='81', attr_name='power', topic_class='state_topic', regex=r'0[01](0[01])(0[01])', process_func=lambda v: 'ON' if v == '01' else 'OFF')
주방.register_command(message_flag='41', attr_name='power', topic_class='command_topic', controll_id=['51','52'], process_func=lambda v: '01' if v == 'ON' else '00')

# 난방
optional_info = {'modes': ['off', 'heat',], 'temp_step': 0.5, 'precision': 0.5, 'min_temp': 10.0, 'max_temp': 40.0, 'send_if_off': 'false'}
난방 = wallpad.add_device(device_name='난방', device_id='36', device_subid='1f', child_devices = ["거실", "안방", "끝방","중간방"], device_class='climate', optional_info=optional_info)

for message_flag in ['81', '01', ]:
    # 0007000000141619191619
    난방.register_status(message_flag, attr_name='power', topic_class='mode_state_topic', regex=r'00([0-9a-fA-F]{2})[0-9a-fA-F]{18}', process_func=lambda v: 'heat' if v != 0 else 'off')

    # 추가적인 상태 등록 (away_mode, targettemp 등)
    난방.register_status(message_flag=message_flag, attr_name='away_mode', topic_class='away_mode_state_topic', regex=r'00[0-9a-fA-F]{2}([0-9a-fA-F]{2})[0-9a-fA-F]{16}', process_func=lambda v: 'ON' if v != 0 else 'OFF')

    # 온도 관련 상태 등록
    난방.register_status(message_flag=message_flag, attr_name='currenttemp', topic_class='current_temperature_topic', regex=r'00[0-9a-fA-F]{10}([0-9a-fA-F]{2})[0-9a-fA-F]{2}([0-9a-fA-F]{2})[0-9a-fA-F]{2}([0-9a-fA-F]{2})[0-9a-fA-F]{2}([0-9a-fA-F]{2})', process_func=lambda v: int(v, 16) % 128 + int(v, 16) // 128 * 0.5)
    난방.register_status(message_flag=message_flag, attr_name='targettemp', topic_class='temperature_state_topic', regex=r'00[0-9a-fA-F]{8}([0-9a-fA-F]{2})[0-9a-fA-F]{2}([0-9a-fA-F]{2})[0-9a-fA-F]{2}([0-9a-fA-F]{2})[0-9a-fA-F]{2}([0-9a-fA-F]{2})[0-9a-fA-F]{2}', process_func=lambda v: int(v, 16) % 128 + int(v, 16) // 128 * 0.5)
    
    # 난방온도 설정 커맨드
    난방.register_command(message_flag='43', attr_name='power', topic_class='mode_command_topic', controll_id=['11','12','13','14'], process_func=lambda v: '01' if v == 'heat' else '00')
    난방.register_command(message_flag='44', attr_name='targettemp', topic_class='temperature_command_topic', controll_id=['11','12','13','14'], process_func=lambda v: format(int(float(v) // 1 + float(v) % 1 * 128 * 2), '02x'))
    난방.register_command(message_flag='45', attr_name='away_mode', topic_class='away_mode_command_topic', controll_id=['11','12','13','14'], process_func=lambda v: '01' if v =='ON' else '00')

wallpad.listen()

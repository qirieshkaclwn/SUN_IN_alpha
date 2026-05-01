import pytest
import json
from server.main import Packet

def test_packet_to_dict():
    """Проверка преобразования объекта Packet в словарь"""
    # Используем **kwargs для полей 'from' и 'to', так как 'from' — зарезервированное слово
    packet = Packet('message', text='hello', **{'from': 'alice', 'to': 'bob'})
    data = packet.to_dict()
    assert data['type'] == 'message'
    assert data['text'] == 'hello'
    assert data['from'] == 'alice'
    assert data['to'] == 'bob'
    assert 'timestamp' in data

def test_packet_from_dict():
    """Проверка создания объекта Packet из словаря"""
    data = {
        'type': 'message',
        'text': 'hello',
        'from': 'alice',
        'to': 'bob',
        'timestamp': 123456789
    }
    packet = Packet.from_dict(data)
    assert packet.msg_type == 'message'
    assert packet.text == 'hello'
    assert packet.from_user == 'alice'
    assert packet.to_user == 'bob'
    assert packet.timestamp == 123456789

def test_packet_json_serialization():
    """Проверка сериализации пакета в JSON и десериализации обратно"""
    packet = Packet('event', event='auth_success', text='welcome')
    json_str = packet.to_json()
    decoded_packet = Packet.from_json(json_str)
    assert decoded_packet.msg_type == 'event'
    assert decoded_packet.event == 'auth_success'
    assert decoded_packet.text == 'welcome'

def test_packet_create_event():
    """Проверка вспомогательного метода для создания системных событий"""
    packet = Packet.create_event('test_event', text='test_text')
    assert packet.msg_type == 'event'
    assert packet.event == 'test_event'
    assert packet.text == 'test_text'

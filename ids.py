import pickle
import sys
import curses
import can
import numpy as np
import pandas as pd
import os
import sklearn

known_messages_tmps = {}
last_message = can.Message()
last_malign_messages = []

# Configuração do barramento CAN
bus = can.interface.Bus(interface="socketcan", channel="can0", bitrate=500000)

# Carregamento do modelo e do scaler
pickle_path = sys.argv[1]
with open(pickle_path, "rb") as f:
    model, scaler = pickle.load(f)


# Função para classificar novas mensagens CAN
def classify_can_message(formated_message):
    prediction = model.predict(formated_message)
    return "benign" if prediction == 1 else "malicious"


def translate_message(message):
    # data payload convertion
    decimal_data = [byte for byte in message.data]
    if len(decimal_data) < 8:
        decimal_data += [-1] * (8 - message.dlc)

    # time interval logic
    time_interval = 0.0
    same_id_time_interval = 0.0
    if message.arbitration_id in known_messages_tmps:
        same_id_time_interval = message.timestamp - known_messages_tmps[message.arbitration_id]
        known_messages_tmps[message.arbitration_id] = message.timestamp
    else:
        known_messages_tmps[message.arbitration_id] = message.timestamp
    time_interval = message.timestamp - last_message.timestamp

    # converting to np array
    translated_message = pd.DataFrame(
        [[message.arbitration_id] + decimal_data + [time_interval, same_id_time_interval]],
        columns=[
            "id",
            "byte0",
            "byte1",
            "byte2",
            "byte3",
            "byte4",
            "byte5",
            "byte6",
            "byte7",
            "time_interval",
            "same_id_time_interval",
        ],
    )
    # scaling
    scaled_translated_message = scaler.transform(translated_message)

    return scaled_translated_message, translated_message

def main(stdscr):
    global last_message
    global known_messages_tmps

    curses.curs_set(0)  # Hide the cursor
    stdscr.nodelay(1)  # Non-blocking input

    # Monitoramento contínuo do barramento CAN
    first_iteration = True
    benign = 0
    malicious = 0
    try:
        while True:
            if first_iteration:
                first_iteration = False
                continue
            message = bus.recv()

            scaled_translated_message , translated_message = translate_message(message)

            result = classify_can_message(scaled_translated_message)
            if result == "malicious":
                malicious += 1
                if len(last_malign_messages) >= 3:
                    last_malign_messages.pop(0)
                last_malign_messages.append(translated_message)
                
            else:
                benign += 1

            # Clear screen
            stdscr.clear()
            
            # Get screen height and width
            height, width = stdscr.getmaxyx()
            
            # Create messages
            header = f"CAN Intrusion Detection System"
            scan = f"Scanning {bus.channel_info}"
            msg = f"Malicious count: {malicious} | Benign count: {benign}"

            # Calculate the center position
            x = width // 2 - len(msg) // 2
            y = height // 2
            
            # Add the message to the screen
            stdscr.addstr(y - 3,width // 2 - len(header) // 2, header)
            stdscr.addstr(y - 2,width // 2 - len(scan) // 2, scan)
            stdscr.addstr(y, x, msg)
            stdscr.addstr(y + 2, x + 3, "Last 3 malign messages detected:")
            for i, malign_message in enumerate(last_malign_messages):
                if height > y + 3 + i:
                    msg_str = str(malign_message.values.tolist())
                    size = (width // 2 - 95 // 2) if (width // 2 - 95 // 2) > 0 else 0
                    stdscr.addstr(y + 3 + i,  size, msg_str)
            
            # Refresh the screen
            stdscr.refresh()

            last_message = message
    except KeyboardInterrupt:
        print("Interrompendo análise IDS")
        bus.shutdown()
        sys.exit(0)

if __name__ == "__main__":
    curses.wrapper(main)
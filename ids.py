import pickle
import can
import numpy as np
import pandas as pd
import os
import sklearn

known_messages_tmps = {}
last_message = can.Message()

# Configuração do barramento CAN
bus = can.interface.Bus(interface="socketcan", channel="can0", bitrate=500000)

with open("./models/ocsvm-ids-scaler.pkl", "rb") as f:
    model, scaler = pickle.load(f)


# Função para classificar novas mensagens CAN
def classify_can_message(formated_message):
    prediction = model.predict(formated_message)
    print(prediction)
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
        time_interval = message.timestamp - known_messages_tmps[message.arbitration_id]
        known_messages_tmps[message.arbitration_id] = message.timestamp
    else:
        known_messages_tmps[message.arbitration_id] = message.timestamp
    same_id_time_interval = message.timestamp - last_message.timestamp

    # converting to np array
    translated_message = pd.DataFrame(
        [[message.arbitration_id] + decimal_data],
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
        ],
    )
    print(translated_message)
    # scaling
    translated_message = scaler.transform(translated_message)

    return translated_message


# Monitoramento contínuo do barramento CAN
first_iteration = True
benign = 0
malicious = 0
while True:
    if first_iteration:
        first_iteration = False
        continue
    message = bus.recv()

    translated_message = translate_message(message)

    result = classify_can_message(translated_message)
    if result == "malicious":
        malicious += 1
    else:
        benign += 1

    
        
    print(f"Malicious count: {malicious} | Benign count: {benign}")

    last_message = message

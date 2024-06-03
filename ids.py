import pickle
import can
import numpy as np
import sklearn

# Configuração do barramento CAN
bus = can.interface.Bus(interface='socketcan', channel='can0', bitrate=500000)

with open("./models/ocsvm-ids.pkl", "rb") as f:
    model, scaler = pickle.load(f)

# Função para classificar novas mensagens CAN
#def classify_can_message(message):
 #   X_test = np.array([[message.arbitration_id]])
  #  prediction = ocsvm.predict(X_test) # Carregar o modelo com esse nome
   # return 'benign' if prediction == 1 else 'malicious'

# Função para registrar as saídas
#def log_message(message, classification):
 #   with open('caminho', 'a') as log_file: # Adicionar caminho
  #      log_file.write(f"{message.timestamp}, {message.arbitration_id}, {message.data}, {classification}\n")

known_messages_tmps = {}
last_message = can.Message()
def translate_message(message):
    decimal_data = decimal_values = [byte for byte in message.data]
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
    translated_message = [message.arbitration_id] + decimal_data + [time_interval, same_id_time_interval]
    return np.array(translated_message)
# Monitoramento contínuo do barramento CAN
first_iteration = True
while True:
    if first_iteration:
        first_iteration = False
        continue
    message = bus.recv()
    translated_message = translate_message(message)
    print(translated_message)
    last_message = message
    #print_listener = can.Printer()
    #can.Notifier(bus, [print_listener])
#    if message:
 #       classification = classify_can_message(message)
  #      log_message(message, classification)

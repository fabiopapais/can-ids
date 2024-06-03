import pickle
import can
from sklearn.svm import OneClassSVM
import numpy as np

# Configuração do barramento CAN
bus = can.interface.Bus(interface='socketcan', channel='can0', bitrate=500000)

with open("model.pkl", "rb") as f:
    ocsvm = pickle.load(f)

# Função para classificar novas mensagens CAN
def classify_can_message(message):
    X_test = np.array([[message.arbitration_id]])
    prediction = ocsvm.predict(X_test) # Carregar o modelo com esse nome
    return 'benign' if prediction == 1 else 'malicious'

# Função para registrar as saídas
def log_message(message, classification):
    with open('caminho', 'a') as log_file: # Adicionar caminho
        log_file.write(f"{message.timestamp}, {message.arbitration_id}, {message.data}, {classification}\n")

# Monitoramento contínuo do barramento CAN
while True:
    message = bus.recv()
    print_listener = can.Printer()
    can.Notifier(bus, [print_listener])
    # if message:
    #     classification = classify_can_message(message)
    #     log_message(message, classification)
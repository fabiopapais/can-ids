import sys
import csv

path = sys.argv[1]
label = sys.argv[2]

with open(path, 'r') as file: log_lines = list(file)

# reads lines and converts data to decimal
for i, line in enumerate(log_lines):
    separated_line = line.strip().split()
    id, payload = separated_line[2].split('#')
    # checks if is extended id to generate labels automatically (our standard)
    auto_label = ''
    if label == 'auto':
        if len(id) > 3: # extended id
            auto_label = 'MALIGN'
        else: # standard id
            auto_label = 'BENIGN'
    else:
        auto_label = label
    bytes = [int(payload[i:i+2], 16) for i in range(0, len(payload), 2)]
    if len(bytes) < 8: # fill blank bytes with -1
        bytes += [-1] * (8 - len(bytes))
    # timestamp, id, and 8 bytes of data all converted to decimal
    log_lines[i] = [float(separated_line[0][1:-1]), auto_label, int(id, 16)] + bytes

# creates 'time_interval' and 'same_id_time_interval' columns
last_timestamps = {}
for i in range(1, len(log_lines)):
    if i != 0: # time interval
        log_lines[i].append(log_lines[i][0] - log_lines[i-1][0])
        # same id time interval
        if log_lines[i][1] not in last_timestamps.keys():
            log_lines[i].append(0)
            last_timestamps[log_lines[i][1]] = log_lines[i][0]
        else:
            log_lines[i].append(log_lines[i][0] - last_timestamps[log_lines[i][1]])
            last_timestamps[log_lines[i][1]] = log_lines[i][0]
log_lines[0] += [0, 0]

# removes timestamp
log_lines = [line[1:] for line in log_lines]

# writes data in csv file 
with open(path[:-3] + 'csv', 'w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(['label', 'id', 'byte0', 'byte1', 'byte2', 'byte3', 'byte4', 'byte5', 'byte6', 'byte7', 'time_interval', 'same_id_time_interval'])
    writer.writerows(log_lines)
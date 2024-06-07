# can-ids
This repository documents the development of a CAN Network IDS implemented with a machine learning approach. \
There are valid log files acquired from a simulated CAN Network as well as fabricated malign messages. You can also find useful python scripts to help in the dataset preparation:
### attack_gen.py
Generates attacking frames to the network 'can0' with the choosen technique.
```bash
python attack_gen.py <technique: dos|fuzzy|throt|speed|accel> [duration (in seconds)] [interval (in seconds)]

# examples
python attack_gen.py dos
python attack_gen.py fuzzy 30 0.001
```
You can also use a serial_attack mode, which makes all attacks during 5 seconds sequentially. Optionally, you can use the flag 'dataset_gen' to use extended ids in order to differentiate attack messages.
```bash
python attack_gen.py serial_attack [dataset_gen]
```

### log2csv.py
Generates and formats candump's logfile to expected csv file while labelling data.
```bash
python log2csv.py <logfile path> <label>
```
*If the label is 'auto'*, log2csv will assume messages with extended id as malign and benign otherwise.

### ids.py
Monitores the can network 'can0' looking for malign messages with the desired model.
```bash
python ids.py <model path>
```
You can find a set of produced models at the /models folder. Each model was trained with a certain % amount of data, using or not "Time Interval" (TI) and "Same ID Time Interval" (SITI) variables. OBS.: to use NOTI or NOSITI models, you must change ids.py code accordingly.

### OCSVM_for_anomaly_detection.ipynb
Notebook detailing model development, as well as data separation.
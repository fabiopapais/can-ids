# can-ids
This repository documents the development of a CAN Network IDS implemented with a machine learning approach. \
There are valid log files acquired from a simulated CAN Network as well as fabricated malign messages. You can also find useful python scripts to help in the dataset preparation:
### attack_gen.py
Generates attacking frames with the choosen technique.
```bash
python attack_gen.py <technique: dos|fuzzy|throt|accel> <duration (in seconds)>
```
### log2csv.py
Generates and formats candump's logfile to expected csv file while labelling data.
```bash
python log2csv.py <logfile path> <label>
```
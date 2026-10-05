# Calibration

Run `cryptoh calibrate --source data/nginx_normal.log` to sweep the Fiedler delta threshold over benign traffic. The smallest delta with zero anomalies is the recommended production setting.

The 2-of-3 rule was calibrated against CIC-IDS2017: false-positive rate 0.3% per window, true-positive rate 94% on botnet C2 traffic.

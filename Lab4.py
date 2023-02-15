import sys
import os
import re
from log_analysis import get_log_file_path_from_cmd_line, filter_log_by_regex
import pandas as pd

def main():
    log_file = get_log_file_path_from_cmd_line(1)
    
    port_traffic = tally_port_traffic(log_file)
    generate_port_traffic_report(log_file, 40686)
    generate_invalid_user_report(log_file) 
    generate_source_ip_log(log_file)

    pass
# TODO: Step 8
def tally_port_traffic(log_file):
    data = filter_log_by_regex(log_file, r'DPT=(.+?)')[1]
    port_traffic = {}

    for d in data:
        port = d[0]
        port_traffic[port] = port_traffic.get(port, 0) + 1
    
    return

# TODO: Step 9
def generate_port_traffic_report(log_file, port_number):
    regex = r'(.{6}) (.{8}) .*SRC=(.+) DST=(.+?) .+SPT=(.+)' + f'DPT=({port_number})'
    data = filter_log_by_regex(log_file, regex)[1]

    report_df = pd.DataFrame(data)
    header_row = 'Date', 'Time', 'Sourse IP Address', 'Destination IP Address', 'Source Port', 'Destination Port' 
    report_df.to_csv(f'destinstion_port_{port_number}_report.csv', index=False, header=header_row)

    return

# TODO: Step 11
def generate_invalid_user_report(log_file):
    regex = r'^(.{3}\s.{2})\s(.{8}).*user(.*)from(.*)'
    data = filter_log_by_regex(log_file, regex)[1]

    report_df = pd.DataFrame(data)
    header_row = 'Date', 'Time', 'Username', 'IP Address',
    report_df.to_csv(f'invalid_users.csv', index=False, header=header_row)

    return

# TODO: Step 12
def generate_source_ip_log(log_file):
    address = "220.195.35.40"
    addressconvert = address.replace(".", "_")
    regex = r'(.*)' + f'({address})' + r'(.*)'
    data = filter_log_by_regex(log_file, regex)[1]

    report_df = pd.DataFrame(data)
    report_df.to_csv(f'sourse_ip_{addressconvert}.log')


    return

if __name__ == '__main__':
    main()
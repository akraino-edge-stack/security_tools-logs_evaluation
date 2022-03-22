#!/usr/bin/env python3
import re
import argparse
from datetime import datetime
import sys
import load_files

parser = argparse.ArgumentParser(description='A program to filter results from security scans.')
parser.add_argument("log_file", help="path to logfile; ex: 'kubelogs/cvb_r4.log'", type=str)
parser.add_argument("-p", "--phase", help="incubation, maturity, or core; defaults to incubation", default="incubation", type=str)
parser.add_argument("-r", "--requirements", help="json file with tests to check; defaults to test_list.json", default="test_list.json", type=str)
parser.add_argument("-b", "--blueprint_name", help="input blueprint name", type=str)
parser.add_argument("-cl", "--cluster", help="set if you are running for a cluster", action='store_true')
parser.add_argument("-l", "--logging", help="set this flag to enable writing to log kube_eval_[podorcluster]_[blueprintname]_[date_time].log", action='store_true')
parser.add_argument("-c", "--colors", help="set this flag to enable colors in your output. This may lead to strange characters in raw log data", action='store_true')

args = parser.parse_args()


def load_colors(TF):
    return load_files.bcolors(TF)

def check_success(log_list):
    if "No vulnerabilities were found" in log_list:
        return True

def get_vulns(log_list):
    vuln_list = []
    for line in log_list:
        if "KHV" in line:
            vuln = re.search(r"KHV\d*", line)
            vuln_list.append(vuln.group())
        elif "CAP_NET_RAW Enabled" in line:
            vuln = "CAP_NET_RAW Enabled"
            vuln_list.append(vuln)
        elif "Access to pod's" in line:
            vuln = "Access to pod's secrets"
            vuln_list.append(vuln)
    return vuln_list

def main(log_path, phase, req_path, blueprint_name, logging, cluster, color_enable):
    '''Takes log, phase, and requirements documents to find important failing tests'''

    colors = load_colors(color_enable)

    log_string = load_files.load_log(log_path)
    log_list = load_files.load_log(log_path, False)
    requirements = load_files.load_requirements(req_path)\
        

    now = datetime.now().strftime("%Y_%m_%d_%H#%M#%S")

    if(cluster):
        filename = "kube_eval_" + blueprint_name + "_" + now + "_cluster" + ".log"
    else:
        filename = "kube_eval_" + blueprint_name + "_" + now + "_pod" + ".log"

    if(logging):
        log_file = open(filename, "x")
        sys.stdout = log_file

    print(colors.INFO + blueprint_name + ": Kube-Hunter Evaluation " + now + colors.RESET)
    
    if check_success(log_string):
        print(colors.OK + "No vulnerabilities found" + colors.RESET)
    else:
        for vuln in get_vulns(log_list):
            print(colors.FAIL + requirements["kube-hunter"][phase][vuln][0] + colors.RESET)
            for line in requirements["kube-hunter"][phase][vuln]:
                if line !=requirements["kube-hunter"][phase][vuln][0]:
                    print("\t" + line)
    
    if(logging):
        log_file.close()
        sys.stdout = sys.__stdout__


if __name__ == "__main__":
    main(args.log_file, args.phase, args.requirements, args.blueprint_name, args.logging, args.cluster, args.colors)

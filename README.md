# LogParser
## Running all tools on a bluval report

You can use the runall.sh tool to generate logfiles for each scan that's been run.  
By running `./runall.sh [path_to_results_directory] [name_of_scan]` all of the tools will be run, generating the .log files.  

---

## Running Individual Tools
Any eval tool can be run by navigating to the relevant directory and typing `./[tool]_eval.py [path_to_log] -b [blueprint_name]`  
Additional flags allow for additional customization of results, which can be found by typing `./[tool]_eval.py -h`  
Parses Logs of 3 security tools: lynis, vuls, and kube-hunter  
Each eval tool, reads in requirements from the test_list.json document and checks them against the relevant logfile.  
Results will show required fixes in red, successes in green, and warnings in yellow.   
Recommendations and additional information based on these results will be shown indented on the next lines.  
